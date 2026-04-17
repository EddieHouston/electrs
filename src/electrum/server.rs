use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Instant;

use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hex::DisplayHex;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use error_chain::ChainedError;
use serde_json::{from_str, Value};

use electrs_macros::trace;

#[cfg(not(feature = "liquid"))]
use bitcoin::consensus::encode::serialize_hex;
#[cfg(feature = "liquid")]
use elements::encode::serialize_hex;
use crate::chain::Txid;
use crate::config::{Config, RpcLogging};
use crate::electrum::{get_electrum_height, ProtocolVersion};
use crate::errors::*;
use crate::metrics::{Gauge, HistogramOpts, HistogramVec, MetricOpts, Metrics};
use crate::new_index::{Query, Utxo};
use crate::util::electrum_merkle::{get_header_merkle_proof, get_id_from_pos, get_tx_merkle_proof};
use crate::util::{create_socket, full_hash, spawn_thread, BlockId, BoolThen, Channel, FullHash, HeaderEntry};

const ELECTRS_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 4);
const MAX_HEADERS: usize = 2016;
const MAX_ARRAY_BATCH: usize = 20;

#[cfg(feature = "electrum-discovery")]
use crate::electrum::{DiscoveryManager, ServerFeatures};

// TODO: Sha256dHash should be a generic hash-container (since script hash is single SHA256)
fn hash_from_value(val: Option<&Value>) -> Result<Sha256dHash> {
    let script_hash = val.chain_err(|| "missing hash")?;
    let script_hash = script_hash.as_str().chain_err(|| "non-string hash")?;
    let script_hash = script_hash.parse().chain_err(|| "non-hex hash")?;
    Ok(script_hash)
}

fn usize_from_value(val: Option<&Value>, name: &str) -> Result<usize> {
    let val = val.chain_err(|| format!("missing {}", name))?;
    let val = val.as_u64().chain_err(|| format!("non-integer {}", name))?;
    Ok(val as usize)
}

fn usize_from_value_or(val: Option<&Value>, name: &str, default: usize) -> Result<usize> {
    if val.is_none() {
        return Ok(default);
    }
    usize_from_value(val, name)
}

fn bool_from_value(val: Option<&Value>, name: &str) -> Result<bool> {
    let val = val.chain_err(|| format!("missing {}", name))?;
    let val = val.as_bool().chain_err(|| format!("not a bool {}", name))?;
    Ok(val)
}

fn bool_from_value_or(val: Option<&Value>, name: &str, default: bool) -> Result<bool> {
    if val.is_none() {
        return Ok(default);
    }
    bool_from_value(val, name)
}

// TODO: implement caching and delta updates
#[trace]
fn get_status_hash(txs: Vec<(Txid, Option<BlockId>)>, query: &Query) -> Option<FullHash> {
    if txs.is_empty() {
        None
    } else {
        let mut hash = FullHash::default();
        let mut sha2 = Sha256::new();
        for (txid, blockid) in txs {
            let is_mempool = blockid.is_none();
            let has_unconfirmed_parents = is_mempool
                .and_then(|| Some(query.has_unconfirmed_parents(&txid)))
                .unwrap_or(false);
            let height = get_electrum_height(blockid, has_unconfirmed_parents);
            let part = format!("{}:{}:", txid, height);
            sha2.input(part.as_bytes());
        }
        sha2.result(&mut hash);
        Some(hash)
    }
}

macro_rules! conditionally_log_rpc_event {
    ($self:ident, $event:expr) => {
        if $self.rpc_logging.enabled {
            $self.log_rpc_event($event);
        }
    };
}

struct Connection {
    query: Arc<Query>,
    last_header_entry: Option<HeaderEntry>,
    status_hashes: HashMap<Sha256dHash, Value>, // ScriptHash -> StatusHash
    stream: TcpStream,
    addr: SocketAddr,
    sender: SyncSender<Message>,
    stats: Arc<Stats>,
    txs_limit: usize,
    #[cfg(feature = "electrum-discovery")]
    discovery: Option<Arc<DiscoveryManager>>,
    rpc_logging: RpcLogging,
    salt: String,
}

impl Connection {
    pub fn new(
        query: Arc<Query>,
        stream: TcpStream,
        addr: SocketAddr,
        sender: SyncSender<Message>,
        stats: Arc<Stats>,
        txs_limit: usize,
        #[cfg(feature = "electrum-discovery")] discovery: Option<Arc<DiscoveryManager>>,
        rpc_logging: RpcLogging,
        salt: String,
    ) -> Connection {
        Connection {
            query,
            last_header_entry: None, // disable header subscription for now
            status_hashes: HashMap::new(),
            stream,
            addr,
            sender,
            stats,
            txs_limit,
            #[cfg(feature = "electrum-discovery")]
            discovery,
            rpc_logging,
            salt,
        }
    }

    fn blockchain_headers_subscribe(&mut self) -> Result<Value> {
        let entry = self.query.chain().best_header();
        let hex_header = serialize_hex(entry.header());
        let result = json!({"hex": hex_header, "height": entry.height()});
        self.last_header_entry = Some(entry);
        Ok(result)
    }

    fn server_version(&self) -> Result<Value> {
        Ok(json!([
            format!("electrs-esplora {}", ELECTRS_VERSION),
            PROTOCOL_VERSION
        ]))
    }

    fn server_banner(&self) -> Result<Value> {
        Ok(json!(self.query.config().electrum_banner.clone()))
    }

    #[cfg(feature = "electrum-discovery")]
    fn server_features(&self) -> Result<Value> {
        let discovery = self
            .discovery
            .as_ref()
            .chain_err(|| "discovery is disabled")?;
        Ok(json!(discovery.our_features()))
    }

    fn server_donation_address(&self) -> Result<Value> {
        Ok(Value::Null)
    }

    fn server_peers_subscribe(&self) -> Result<Value> {
        #[cfg(feature = "electrum-discovery")]
        let servers = self
            .discovery
            .as_ref()
            .map_or_else(|| json!([]), |d| json!(d.get_servers()));

        #[cfg(not(feature = "electrum-discovery"))]
        let servers = json!([]);

        Ok(servers)
    }

    #[cfg(feature = "electrum-discovery")]
    fn server_add_peer(&self, params: &[Value]) -> Result<Value> {
        let discovery = self
            .discovery
            .as_ref()
            .chain_err(|| "discovery is disabled")?;

        let features = params
            .get(0)
            .chain_err(|| "missing features param")?
            .clone();
        let features = serde_json::from_value(features).chain_err(|| "invalid features")?;

        discovery.add_server_request(self.addr.ip(), features)?;
        Ok(json!(true))
    }

    fn mempool_get_fee_histogram(&self) -> Result<Value> {
        Ok(json!(&self.query.mempool().backlog_stats().fee_histogram))
    }

    fn blockchain_block_header(&self, params: &[Value]) -> Result<Value> {
        let height = usize_from_value(params.get(0), "height")?;
        let cp_height = usize_from_value_or(params.get(1), "cp_height", 0)?;

        let raw_header_hex: String = self
            .query
            .chain()
            .header_by_height(height)
            .map(|entry| serialize_hex(entry.header()))
            .chain_err(|| "missing header")?;

        if cp_height == 0 {
            return Ok(json!(raw_header_hex));
        }
        let (branch, root) = get_header_merkle_proof(self.query.chain(), height, cp_height)?;

        Ok(json!({
            "header": raw_header_hex,
            "root": root,
            "branch": branch
        }))
    }

    fn blockchain_block_headers(&self, params: &[Value]) -> Result<Value> {
        let start_height = usize_from_value(params.get(0), "start_height")?;
        let count = MAX_HEADERS.min(usize_from_value(params.get(1), "count")?);
        let cp_height = usize_from_value_or(params.get(2), "cp_height", 0)?;
        let heights: Vec<usize> = (start_height..(start_height + count)).collect();
        let headers: Vec<String> = heights
            .into_iter()
            .filter_map(|height| {
                self.query
                    .chain()
                    .header_by_height(height)
                    .map(|entry| serialize_hex(entry.header()))
            })
            .collect();

        if count == 0 || cp_height == 0 {
            return Ok(json!({
                "count": headers.len(),
                "hex": headers.join(""),
                "max": MAX_HEADERS,
            }));
        }

        let (branch, root) =
            get_header_merkle_proof(self.query.chain(), start_height + (count - 1), cp_height)?;

        Ok(json!({
            "count": headers.len(),
            "hex": headers.join(""),
            "max": MAX_HEADERS,
            "root": root,
            "branch" : branch,
        }))
    }

    #[trace]
    fn blockchain_estimatefee(&self, params: &[Value]) -> Result<Value> {
        let conf_target = usize_from_value(params.get(0), "blocks_count")?;
        let fee_rate = self
            .query
            .estimate_fee(conf_target as u16)
            .chain_err(|| format!("cannot estimate fee for {} blocks", conf_target))?;
        // convert from sat/b to BTC/kB, as expected by Electrum clients
        Ok(json!(fee_rate / 100_000f64))
    }

    fn blockchain_relayfee(&self) -> Result<Value> {
        let relayfee = self.query.get_relayfee()?;
        // convert from sat/b to BTC/kB, as expected by Electrum clients
        Ok(json!(relayfee / 100_000f64))
    }

    fn blockchain_scripthash_subscribe(&mut self, params: &[Value]) -> Result<Value> {
        let script_hash = hash_from_value(params.get(0)).chain_err(|| "bad script_hash")?;

        let history_txids = get_history(&self.query, &script_hash[..], self.txs_limit)?;
        let status_hash = get_status_hash(history_txids, &self.query)
            .map_or(Value::Null, |h| json!(h.to_lower_hex_string()));

        if let None = self.status_hashes.insert(script_hash, status_hash.clone()) {
            self.stats.subscriptions.inc();
        }
        Ok(status_hash)
    }

    fn blockchain_scripthash_unsubscribe(&mut self, params: &[Value]) -> Result<Value> {
        let script_hash = hash_from_value(params.get(0)).chain_err(|| "bad script_hash")?;

        match self.status_hashes.remove(&script_hash) {
            None => Ok(json!(false)),
            Some(_) => {
                self.stats.subscriptions.dec();
                Ok(json!(true))
            }
        }
    }

    #[cfg(not(feature = "liquid"))]
    fn blockchain_scripthash_get_balance(&self, params: &[Value]) -> Result<Value> {
        let script_hash = hash_from_value(params.get(0)).chain_err(|| "bad script_hash")?;
        let (chain_stats, mempool_stats) = self.query.stats(&script_hash[..]);

        Ok(json!({
            "confirmed": chain_stats.funded_txo_sum - chain_stats.spent_txo_sum,
            "unconfirmed": mempool_stats.funded_txo_sum as i64 - mempool_stats.spent_txo_sum as i64,
        }))
    }

    fn blockchain_scripthash_get_history(&self, params: &[Value]) -> Result<Value> {
        let script_hash = hash_from_value(params.get(0)).chain_err(|| "bad script_hash")?;
        let history_txids = get_history(&self.query, &script_hash[..], self.txs_limit)?;

        Ok(json!(history_txids
            .into_iter()
            .map(|(txid, blockid)| {
                let is_mempool = blockid.is_none();
                let fee = is_mempool.and_then(|| self.query.get_mempool_tx_fee(&txid));
                let has_unconfirmed_parents = is_mempool
                    .and_then(|| Some(self.query.has_unconfirmed_parents(&txid)))
                    .unwrap_or(false);
                let height = get_electrum_height(blockid, has_unconfirmed_parents);
                GetHistoryResult { txid, height, fee }
            })
            .collect::<Vec<_>>()))
    }

    fn blockchain_scripthash_listunspent(&self, params: &[Value]) -> Result<Value> {
        let script_hash = hash_from_value(params.get(0)).chain_err(|| "bad script_hash")?;
        let utxos = self.query.utxo(&script_hash[..])?;

        let to_json = |utxo: Utxo| {
            let json = json!({
                "height": utxo.confirmed.map_or(0, |b| b.height),
                "tx_pos": utxo.vout,
                "tx_hash": utxo.txid,
                "value": utxo.value,
            });

            #[cfg(feature = "liquid")]
            let json = {
                let mut json = json;
                json["asset"] = json!(utxo.asset);
                json["nonce"] = json!(utxo.nonce);
                json
            };

            json
        };

        Ok(json!(Value::Array(
            utxos.into_iter().map(to_json).collect()
        )))
    }

    fn blockchain_transaction_broadcast(&self, params: &[Value]) -> Result<Value> {
        let tx = params.get(0).chain_err(|| "missing tx")?;
        let tx = tx.as_str().chain_err(|| "non-string tx")?.to_string();
        let txid = self.query.broadcast_raw(&tx)?;
        // Force a full subscription rescan after broadcast since we don't
        // yet know which scripthashes the new tx touches.
        if let Err(e) = self.sender.try_send(Message::PeriodicUpdate {
            dirty: Arc::new(HashSet::new()),
            tip_changed: true,
        }) {
            warn!("failed to issue PeriodicUpdate after broadcast: {}", e);
        }
        Ok(json!(txid))
    }

    fn blockchain_transaction_get(&self, params: &[Value]) -> Result<Value> {
        let tx_hash = Txid::from(hash_from_value(params.get(0)).chain_err(|| "bad tx_hash")?);
        let verbose = match params.get(1) {
            Some(value) => value.as_bool().chain_err(|| "non-bool verbose value")?,
            None => false,
        };

        // FIXME: implement verbose support
        if verbose {
            bail!("verbose transactions are currently unsupported");
        }

        let rawtx = self
            .query
            .lookup_raw_txn(&tx_hash)
            .chain_err(|| "missing transaction")?;
        Ok(json!(rawtx.to_lower_hex_string()))
    }

    #[trace]
    fn blockchain_transaction_get_merkle(&self, params: &[Value]) -> Result<Value> {
        let txid = Txid::from(hash_from_value(params.get(0)).chain_err(|| "bad tx_hash")?);
        let height = usize_from_value(params.get(1), "height")?;
        let blockid = self
            .query
            .chain()
            .tx_confirming_block(&txid)
            .ok_or_else(|| "tx not found or is unconfirmed")?;
        if blockid.height != height {
            bail!("invalid confirmation height provided");
        }
        let (merkle, pos) = get_tx_merkle_proof(self.query.chain(), &txid, &blockid.hash)
            .chain_err(|| "cannot create merkle proof")?;
        Ok(json!({
            "block_height": blockid.height,
            "merkle": merkle,
            "pos": pos
        }))
    }

    fn blockchain_transaction_id_from_pos(&self, params: &[Value]) -> Result<Value> {
        let height = usize_from_value(params.get(0), "height")?;
        let tx_pos = usize_from_value(params.get(1), "tx_pos")?;
        let want_merkle = bool_from_value_or(params.get(2), "merkle", false)?;

        let (txid, merkle) = get_id_from_pos(self.query.chain(), height, tx_pos, want_merkle)?;

        if !want_merkle {
            return Ok(json!(txid));
        }

        Ok(json!({
            "tx_hash": txid,
            "merkle" : merkle
        }))
    }

    #[trace(method = %method)]
    fn handle_command(&mut self, method: &str, params: &[Value], id: &Value) -> Result<Value> {
        let timer = self
            .stats
            .latency
            .with_label_values(&[method])
            .start_timer();

        let result = match method {
            "blockchain.block.header" => self.blockchain_block_header(&params),
            "blockchain.block.headers" => self.blockchain_block_headers(&params),
            "blockchain.estimatefee" => self.blockchain_estimatefee(&params),
            "blockchain.headers.subscribe" => self.blockchain_headers_subscribe(),
            "blockchain.relayfee" => self.blockchain_relayfee(),
            #[cfg(not(feature = "liquid"))]
            "blockchain.scripthash.get_balance" => self.blockchain_scripthash_get_balance(&params),
            "blockchain.scripthash.get_history" => self.blockchain_scripthash_get_history(&params),
            "blockchain.scripthash.listunspent" => self.blockchain_scripthash_listunspent(&params),
            "blockchain.scripthash.subscribe" => self.blockchain_scripthash_subscribe(&params),
            "blockchain.scripthash.unsubscribe" => self.blockchain_scripthash_unsubscribe(&params),
            "blockchain.transaction.broadcast" => self.blockchain_transaction_broadcast(&params),
            "blockchain.transaction.get" => self.blockchain_transaction_get(&params),
            "blockchain.transaction.get_merkle" => self.blockchain_transaction_get_merkle(&params),
            "blockchain.transaction.id_from_pos" => {
                self.blockchain_transaction_id_from_pos(&params)
            }
            "mempool.get_fee_histogram" => self.mempool_get_fee_histogram(),
            "server.banner" => self.server_banner(),
            "server.donation_address" => self.server_donation_address(),
            "server.peers.subscribe" => self.server_peers_subscribe(),
            "server.ping" => Ok(Value::Null),
            "server.version" => self.server_version(),

            #[cfg(feature = "electrum-discovery")]
            "server.features" => self.server_features(),
            #[cfg(feature = "electrum-discovery")]
            "server.add_peer" => self.server_add_peer(&params),

            &_ => bail!("unknown method {} {:?}", method, params),
        };
        timer.observe_duration();
        // TODO: return application errors should be sent to the client
        Ok(match result {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(e) => {
                warn!(
                    "rpc #{} {} {:?} failed: {}",
                    id,
                    method,
                    params,
                    e.display_chain()
                );
                json!({"jsonrpc": "2.0", "id": id, "error": format!("{}", e)})
            }
        })
    }

    #[trace]
    fn update_subscriptions(
        &mut self,
        dirty: &HashSet<FullHash>,
        tip_changed: bool,
    ) -> Result<Vec<Value>> {
        let timer = self
            .stats
            .latency
            .with_label_values(&["periodic_update"])
            .start_timer();
        let mut result = vec![];
        if let Some(ref mut last_entry) = self.last_header_entry {
            let entry = self.query.chain().best_header();
            if *last_entry != entry {
                *last_entry = entry;
                let hex_header = serialize_hex(last_entry.header());
                let header = json!({"hex": hex_header, "height": last_entry.height()});
                result.push(json!({
                    "jsonrpc": "2.0",
                    "method": "blockchain.headers.subscribe",
                    "params": [header]}));
            }
        }

        // Skip scripthash rescans when nothing changed. If the chain tip
        // advanced we must recheck everything (confirmed history may have
        // changed). Otherwise only rescan scripthashes dirtied by mempool
        // activity.
        if !tip_changed && dirty.is_empty() {
            timer.observe_duration();
            return Ok(result);
        }

        for (script_hash, status_hash) in self.status_hashes.iter_mut() {
            let scripthash_bytes: FullHash = full_hash(&script_hash[..]);
            if !tip_changed && !dirty.contains(&scripthash_bytes) {
                continue;
            }
            let history_txids = get_history(&self.query, &script_hash[..], self.txs_limit)?;
            let new_status_hash = get_status_hash(history_txids, &self.query)
                .map_or(Value::Null, |h| json!(h.to_lower_hex_string()));
            if new_status_hash == *status_hash {
                continue;
            }
            result.push(json!({
                "jsonrpc": "2.0",
                "method": "blockchain.scripthash.subscribe",
                "params": [script_hash, new_status_hash]}));
            *status_hash = new_status_hash;
        }
        timer.observe_duration();
        Ok(result)
    }

    fn hash_ip_with_salt(&self, ip: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.input(self.salt.as_bytes());
        hasher.input(ip.as_bytes());
        hasher.result_str()
    }

    fn log_rpc_event(&self, mut log: Value) {
        let real_ip = self.addr.ip().to_string();
        let ip_to_log = if self.rpc_logging.anonymize_ip {
            self.hash_ip_with_salt(&real_ip)
        } else {
            real_ip
        };

        log.as_object_mut().unwrap().insert(
            "source".into(),
            json!({
                "ip": ip_to_log,
                "port": self.addr.port(),
            }),
        );
        println!("{}", log);
    }

    fn send_values(&mut self, values: &[Value]) -> Result<()> {
        for value in values {
            let line = value.to_string() + "\n";
            self.stream
                .write_all(line.as_bytes())
                .chain_err(|| format!("failed to send {}", value))?;
        }
        Ok(())
    }

    #[trace]
    fn handle_replies(&mut self, receiver: Receiver<Message>) -> Result<()> {
        let empty_params = json!([]);
        loop {
            let msg = receiver.recv().chain_err(|| "channel closed")?;
            trace!("RPC {:?}", msg);
            match msg {
                Message::Request(line) => {
                    let cmd: Value = from_str(&line).chain_err(|| "invalid JSON format")?;
                    if let Value::Array(arr) = cmd {
                        if arr.len() > MAX_ARRAY_BATCH {
                            bail!(
                                "Too many elements in batch requests {} max:{}",
                                arr.len(),
                                MAX_ARRAY_BATCH
                            );
                        }
                        let mut result = Vec::with_capacity(arr.len());
                        for el in arr {
                            let reply = self.handle_value(el, &empty_params)?;
                            result.push(reply)
                        }
                        self.send_values(&[Value::Array(result)])?
                    } else {
                        let reply = self.handle_value(cmd, &empty_params)?;
                        self.send_values(&[reply])?
                    }
                }
                Message::PeriodicUpdate { dirty, tip_changed } => {
                    let values = self
                        .update_subscriptions(&dirty, tip_changed)
                        .chain_err(|| "failed to update subscriptions")?;
                    self.send_values(&values)?
                }
                Message::Done => return Ok(()),
            }
        }
    }

    fn handle_value(&mut self, cmd: Value, empty_params: &Value) -> Result<Value> {
        let start_time = Instant::now();
        Ok(
            match (
                cmd.get("method"),
                cmd.get("params").unwrap_or_else(|| empty_params),
                cmd.get("id"),
            ) {
                (Some(&Value::String(ref method)), &Value::Array(ref params), Some(ref id)) => {
                    let reply = self.handle_command(method, params, id)?;

                    conditionally_log_rpc_event!(
                        self,
                        json!({
                            "event": "rpc_response",
                            "method": method,
                            "params": if self.rpc_logging.hide_params {
                                    Value::Null
                                } else {
                                    json!(params)
                                },
                            "request_size": serde_json::to_vec(&cmd).map(|v| v.len()).unwrap_or(0),
                            "response_size": reply.to_string().as_bytes().len(),
                            "duration_micros": start_time.elapsed().as_micros(),
                            "id": id,
                        })
                    );

                    reply
                }
                _ => {
                    bail!("invalid command: {}", cmd)
                }
            },
        )
    }

    #[trace]
    fn parse_requests(mut reader: BufReader<TcpStream>, tx: &SyncSender<Message>) -> Result<()> {
        loop {
            let mut line = Vec::<u8>::new();
            reader
                .read_until(b'\n', &mut line)
                .chain_err(|| "failed to read a request")?;
            if line.is_empty() {
                return Ok(());
            } else {
                if line.starts_with(&[22, 3, 1]) {
                    // (very) naive SSL handshake detection
                    bail!("invalid request - maybe SSL-encrypted data?: {:?}", line)
                }
                match String::from_utf8(line) {
                    Ok(req) => tx
                        .send(Message::Request(req))
                        .chain_err(|| "channel closed")?,
                    Err(err) => {
                        bail!("invalid UTF8: {}", err)
                    }
                }
            }
        }
    }

    fn reader_thread(reader: BufReader<TcpStream>, tx: SyncSender<Message>) -> Result<()> {
        let result = Connection::parse_requests(reader, &tx);
        if let Err(e) = tx.send(Message::Done) {
            warn!("failed closing channel: {}", e);
        }
        result
    }

    pub fn run(mut self, receiver: Receiver<Message>) {
        self.stats.clients.inc();
        conditionally_log_rpc_event!(self, json!({ "event": "connection_established" }));

        let reader = BufReader::new(self.stream.try_clone().expect("failed to clone TcpStream"));
        let sender = self.sender.clone();
        let child = spawn_thread("reader", || Connection::reader_thread(reader, sender));
        if let Err(e) = self.handle_replies(receiver) {
            error!(
                "[{}] connection handling failed: {}",
                self.addr,
                e.display_chain().to_string()
            );
        }
        self.stats.clients.dec();
        self.stats
            .subscriptions
            .sub(self.status_hashes.len() as i64);

        debug!("[{}] shutting down connection", self.addr);
        conditionally_log_rpc_event!(self, json!({ "event": "connection_closed" }));

        let _ = self.stream.shutdown(Shutdown::Both);
        if let Err(err) = child.join().expect("receiver panicked") {
            error!("[{}] receiver failed: {}", self.addr, err);
        }
    }
}

#[trace]
fn get_history(
    query: &Query,
    scripthash: &[u8],
    txs_limit: usize,
) -> Result<Vec<(Txid, Option<BlockId>)>> {
    // to avoid silently trunacting history entries, ask for one extra more than the limit and fail if it exists
    let history_txids = query.history_txids(scripthash, txs_limit + 1);
    ensure!(history_txids.len() <= txs_limit, ErrorKind::TooPopular);
    Ok(history_txids)
}

#[derive(Serialize, Debug)]
struct GetHistoryResult {
    #[serde(rename = "tx_hash")]
    txid: Txid,
    height: isize,
    #[serde(skip_serializing_if = "Option::is_none")]
    fee: Option<u64>,
}

/// Scripthashes whose mempool state changed since the last update cycle,
/// shared across all connections via `Arc` to avoid cloning the set.
pub type DirtyScriptHashes = Arc<HashSet<FullHash>>;

#[derive(Debug)]
pub enum Message {
    Request(String),
    /// Periodic subscription check. Contains the set of scripthashes dirtied
    /// by mempool changes and whether the chain tip advanced (new block).
    PeriodicUpdate {
        dirty: DirtyScriptHashes,
        tip_changed: bool,
    },
    Done,
}

pub enum Notification {
    Periodic {
        dirty: DirtyScriptHashes,
        tip_changed: bool,
    },
    Exit,
}

pub struct RPC {
    notification: Sender<Notification>,
    server: Option<thread::JoinHandle<()>>, // so we can join the server while dropping this ojbect
}

struct Stats {
    latency: HistogramVec,
    clients: Gauge,
    subscriptions: Gauge,
}

impl RPC {
    fn start_notifier(
        notification: Channel<Notification>,
        senders: Arc<Mutex<Vec<SyncSender<Message>>>>,
        acceptor: Sender<Option<(TcpStream, SocketAddr)>>,
    ) {
        spawn_thread("notification", move || {
            for msg in notification.receiver().iter() {
                let mut senders = senders.lock().unwrap();
                match msg {
                    Notification::Periodic { dirty, tip_changed } => {
                        senders.retain(|sender| {
                            if let Err(TrySendError::Disconnected(_)) =
                                sender.try_send(Message::PeriodicUpdate {
                                    dirty: Arc::clone(&dirty),
                                    tip_changed,
                                })
                            {
                                false // drop disconnected clients
                            } else {
                                true
                            }
                        })
                    }
                    Notification::Exit => acceptor.send(None).unwrap(), // mark acceptor as done
                }
            }
        });
    }

    fn start_acceptor(addr: SocketAddr) -> Channel<Option<(TcpStream, SocketAddr)>> {
        let chan = Channel::unbounded();
        let acceptor = chan.sender();
        spawn_thread("acceptor", move || {
            let socket = create_socket(&addr);
            socket.listen(511).expect("setting backlog failed");
            socket
                .set_nonblocking(false)
                .expect("cannot set nonblocking to false");
            let listener = TcpListener::from(socket);

            info!("Electrum RPC server running on {}", addr);
            loop {
                let (stream, addr) = listener.accept().expect("accept failed");
                stream
                    .set_nonblocking(false)
                    .expect("failed to set connection as blocking");
                acceptor.send(Some((stream, addr))).expect("send failed");
            }
        });
        chan
    }

    pub fn start(
        config: Arc<Config>,
        query: Arc<Query>,
        metrics: &Metrics,
        salt_rwlock: Arc<RwLock<String>>
    ) -> RPC {
        let stats = Arc::new(Stats {
            latency: metrics.histogram_vec(
                HistogramOpts::new("electrum_rpc", "Electrum RPC latency (seconds)"),
                &["method"],
            ),
            clients: metrics.gauge(MetricOpts::new("electrum_clients", "# of Electrum clients")),
            subscriptions: metrics.gauge(MetricOpts::new(
                "electrum_subscriptions",
                "# of Electrum subscriptions",
            )),
        });
        stats.clients.set(0);
        stats.subscriptions.set(0);

        let notification = Channel::unbounded();

        // Discovery is enabled when electrum-public-hosts is set
        #[cfg(feature = "electrum-discovery")]
        let discovery = config.electrum_public_hosts.clone().map(|hosts| {
            use crate::chain::genesis_hash;
            let features = ServerFeatures {
                hosts,
                server_version: format!("electrs-esplora {}", ELECTRS_VERSION),
                genesis_hash: genesis_hash(config.network_type),
                protocol_min: PROTOCOL_VERSION,
                protocol_max: PROTOCOL_VERSION,
                hash_function: "sha256".into(),
                pruning: None,
            };
            let discovery = Arc::new(DiscoveryManager::new(
                config.network_type,
                features,
                PROTOCOL_VERSION,
                config.electrum_announce,
                config.tor_proxy,
            ));
            DiscoveryManager::spawn_jobs_thread(Arc::clone(&discovery));
            discovery
        });

        let rpc_addr = config.electrum_rpc_addr;
        let txs_limit = config.electrum_txs_limit;

        RPC {
            notification: notification.sender(),
            server: Some(spawn_thread("rpc", move || {
                let senders = Arc::new(Mutex::new(Vec::<SyncSender<Message>>::new()));

                let acceptor = RPC::start_acceptor(rpc_addr);
                RPC::start_notifier(notification, senders.clone(), acceptor.sender());

                let mut threads = HashMap::new();
                let (garbage_sender, garbage_receiver) = crossbeam_channel::unbounded();

                while let Some((stream, addr)) = acceptor.receiver().recv().unwrap() {
                    // explicitly scope the shadowed variables for the new thread
                    let query = Arc::clone(&query);
                    let stats = Arc::clone(&stats);
                    let garbage_sender = garbage_sender.clone();
                    let rpc_logging = config.rpc_logging.clone();
                    #[cfg(feature = "electrum-discovery")]
                    let discovery = discovery.clone();

                    let (sender, receiver) = mpsc::sync_channel(10);
                    senders.lock().unwrap().push(sender.clone());

                    let salt = salt_rwlock.read().unwrap().clone();

                    let spawned = spawn_thread("peer", move || {
                        info!("[{}] connected peer", addr);
                        let conn = Connection::new(
                            query,
                            stream,
                            addr,
                            sender,
                            stats,
                            txs_limit,
                            #[cfg(feature = "electrum-discovery")]
                            discovery,
                            rpc_logging,
                            salt,
                        );
                        conn.run(receiver);
                        info!("[{}] disconnected peer", addr);
                        let _ = garbage_sender.send(std::thread::current().id());
                    });

                    trace!("[{}] spawned {:?}", addr, spawned.thread().id());
                    threads.insert(spawned.thread().id(), spawned);
                    while let Ok(id) = garbage_receiver.try_recv() {
                        if let Some(thread) = threads.remove(&id) {
                            trace!("[{}] joining {:?}", addr, id);
                            if let Err(error) = thread.join() {
                                error!("failed to join {:?}: {:?}", id, error);
                            }
                        }
                    }
                }

                trace!("closing {} RPC connections", senders.lock().unwrap().len());
                for sender in senders.lock().unwrap().iter() {
                    let _ = sender.send(Message::Done);
                }

                for (id, thread) in threads {
                    trace!("joining {:?}", id);
                    if let Err(error) = thread.join() {
                        error!("failed to join {:?}: {:?}", id, error);
                    }
                }

                trace!("RPC connections are closed");
            })),
        }
    }

    pub fn notify(&self, dirty: HashSet<FullHash>, tip_changed: bool) {
        self.notification
            .send(Notification::Periodic {
                dirty: Arc::new(dirty),
                tip_changed,
            })
            .unwrap();
    }
}

impl Drop for RPC {
    fn drop(&mut self) {
        trace!("stop accepting new RPCs");
        self.notification.send(Notification::Exit).unwrap();
        if let Some(handle) = self.server.take() {
            handle.join().unwrap();
        }
        trace!("RPC server is stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hex::FromHex;
    use crate::new_index::compute_script_hash;
    use crate::chain::Script;

    /// Verify that converting a Sha256dHash (from Electrum protocol hex) to
    /// FullHash via full_hash() produces the same bytes as compute_script_hash()
    /// for the same script. A mismatch here would cause the dirty-scripthash
    /// lookup in update_subscriptions to silently fail.
    #[test]
    fn scripthash_byte_order_roundtrip() {
        // A simple P2PKH scriptPubKey (OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG)
        let script_bytes = Vec::<u8>::from_hex("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac").unwrap();
        let script = Script::from(script_bytes.clone());

        // Path 1: compute_script_hash (used by mempool dirty tracking)
        let from_compute = compute_script_hash(&script);

        // Path 2: Electrum protocol hex → Sha256dHash → full_hash
        // The Electrum protocol sends the scripthash as reversed hex (display order).
        // Sha256dHash::from_str parses display hex and reverses to internal order.
        let display_hex: String = from_compute
            .iter()
            .rev()
            .map(|b| format!("{:02x}", b))
            .collect();
        let parsed: Sha256dHash = display_hex.parse().expect("valid hex");
        let from_parsed = full_hash(&parsed[..]);

        assert_eq!(
            from_compute, from_parsed,
            "compute_script_hash and Sha256dHash→full_hash must produce identical bytes"
        );
    }

    /// Verify that full_hash conversion is consistent for a known test vector.
    /// The Electrum protocol sends scripthashes with reversed byte order compared
    /// to internal storage. This test ensures the conversion in
    /// update_subscriptions matches what the mempool dirty set contains.
    #[test]
    fn scripthash_dirty_set_membership() {
        let script_bytes = Vec::<u8>::from_hex("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac").unwrap();
        let script = Script::from(script_bytes);

        let computed = compute_script_hash(&script);

        // Simulate the dirty set (populated by mempool via compute_script_hash)
        let mut dirty: HashSet<FullHash> = HashSet::new();
        dirty.insert(computed);

        // Simulate the lookup path in update_subscriptions:
        // Sha256dHash key from status_hashes → full_hash → dirty.contains()
        let display_hex: String = computed
            .iter()
            .rev()
            .map(|b| format!("{:02x}", b))
            .collect();
        let script_hash: Sha256dHash = display_hex.parse().unwrap();
        let lookup_key = full_hash(&script_hash[..]);

        assert!(
            dirty.contains(&lookup_key),
            "scripthash from Sha256dHash must be found in dirty set populated by compute_script_hash"
        );
    }
}
