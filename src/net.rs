//! P2P mesh over iroh with mDNS discovery.
//!
//! Every running instance binds an iroh endpoint (relay servers disabled —
//! pure localhost/LAN operation), announces itself via mDNS with a user-data
//! string derived from the key id, and dials every discovered peer that
//! announces the same rendezvous string. After a `Hello` handshake that
//! validates protocol/op/key-id compatibility, peers form a full mesh.
//!
//! There is no leader: each instance waits until the op-specific quorum
//! predicate is satisfied by the set of online participants (stable for a
//! settle window), then takes a snapshot — the participant list, sorted by
//! peer id, is identical on all peers and is used to derive party indices
//! and the protocol instance id.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use futures_util::StreamExt;
use iroh::endpoint::{presets, Connection, RecvStream, RelayMode, SendStream};
use iroh::endpoint_info::UserData;
use iroh::{Endpoint, EndpointId};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::ids;
use crate::relay::{spawn_timeout_checker, MsgStore, NetRelay};

pub const ALPN: &[u8] = b"dkls23ctl/0";
const MAX_FRAME: u32 = 64 * 1024 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const SETTLE: Duration = Duration::from_millis(1500);

const KIND_HELLO: u8 = 0;
const KIND_RELAY: u8 = 1;
const KIND_DIRECT: u8 = 2;

/// First message exchanged on every connection.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Hello {
    pub proto: String,
    pub op: String,
    pub key_id: String,
    pub peer_id: String,
    /// Op-specific parameters (t/n, message hash, holder info, ...).
    pub payload: serde_json::Value,
}

impl Hello {
    pub fn new(op: &str, key_id: &str, peer_id: &str, payload: serde_json::Value) -> Self {
        Self {
            proto: ids::TOOL_ID.to_string(),
            op: op.to_string(),
            key_id: key_id.to_string(),
            peer_id: peer_id.to_string(),
            payload,
        }
    }
}

/// Validates a remote hello against ours; returns a human-readable reason on
/// mismatch. Base fields (proto/op/key_id) are checked by the session itself.
pub type CompatFn = Arc<dyn Fn(&Hello) -> std::result::Result<(), String> + Send + Sync>;

/// Quorum predicate over all online hellos (including our own).
pub type QuorumFn = Arc<dyn Fn(&[Hello]) -> bool + Send + Sync>;

pub struct SessionConfig {
    pub hello: Hello,
    pub compat: CompatFn,
    pub quorum: QuorumFn,
}

struct PeerLink {
    hello: Hello,
    tx: mpsc::UnboundedSender<(u8, Vec<u8>)>,
}

struct Shared {
    me: Hello,
    compat: CompatFn,
    store: MsgStore,
    peers: Mutex<HashMap<String, PeerLink>>,
    changed: watch::Sender<u64>,
    direct_tx: mpsc::UnboundedSender<(String, Vec<u8>)>,
    finalized: AtomicBool,
}

impl Shared {
    fn bump(&self) {
        self.changed.send_modify(|v| *v += 1);
    }

    fn hellos(&self) -> Vec<Hello> {
        let peers = self.peers.lock().unwrap();
        let mut all: Vec<Hello> = peers.values().map(|p| p.hello.clone()).collect();
        all.push(self.me.clone());
        all.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
        all
    }
}

async fn write_frame(send: &mut SendStream, kind: u8, payload: &[u8]) -> Result<()> {
    send.write_all(&[kind]).await?;
    send.write_all(&(payload.len() as u32).to_le_bytes()).await?;
    send.write_all(payload).await?;
    Ok(())
}

async fn read_frame(recv: &mut RecvStream) -> Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    recv.read_exact(&mut hdr).await?;
    let kind = hdr[0];
    let len = u32::from_le_bytes(hdr[1..5].try_into().unwrap());
    if len > MAX_FRAME {
        bail!("frame too large: {len}");
    }
    let mut payload = vec![0u8; len as usize];
    recv.read_exact(&mut payload).await?;
    Ok((kind, payload))
}

/// Performs the hello exchange and, on success, registers the peer and spawns
/// reader/writer tasks for the connection.
async fn handle_conn(shared: Arc<Shared>, conn: Connection, dialer: bool) -> Result<()> {
    let hello_bytes = serde_json::to_vec(&shared.me)?;

    let (mut send, mut recv) = if dialer {
        let (mut send, recv) = conn.open_bi().await?;
        write_frame(&mut send, KIND_HELLO, &hello_bytes).await?;
        (send, recv)
    } else {
        conn.accept_bi().await?
    };

    let (kind, payload) = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_frame(&mut recv))
        .await
        .context("handshake timeout")??;
    if kind != KIND_HELLO {
        bail!("expected hello frame, got kind {kind}");
    }
    let remote: Hello = serde_json::from_slice(&payload).context("bad hello")?;

    if !dialer {
        write_frame(&mut send, KIND_HELLO, &hello_bytes).await?;
    }

    // base compatibility
    if remote.proto != shared.me.proto
        || remote.op != shared.me.op
        || remote.key_id != shared.me.key_id
    {
        debug!(
            "ignoring incompatible peer {} (op={}, key_id={})",
            remote.peer_id, remote.op, remote.key_id
        );
        return Ok(());
    }
    if remote.peer_id == shared.me.peer_id {
        warn!(
            "peer with our own peer-id '{}' showed up; ignoring it",
            remote.peer_id
        );
        return Ok(());
    }
    if let Err(reason) = (shared.compat)(&remote) {
        warn!("rejecting peer {}: {}", remote.peer_id, reason);
        return Ok(());
    }

    let peer_id = remote.peer_id.clone();
    let (tx, mut rx) = mpsc::unbounded_channel::<(u8, Vec<u8>)>();
    {
        let mut peers = shared.peers.lock().unwrap();
        if peers.contains_key(&peer_id) {
            debug!("duplicate connection for peer {peer_id}; dropping");
            return Ok(());
        }
        if shared.finalized.load(Ordering::SeqCst) {
            debug!("session already started; ignoring late peer {peer_id}");
            return Ok(());
        }
        peers.insert(
            peer_id.clone(),
            PeerLink {
                hello: remote,
                tx,
            },
        );
    }
    shared.bump();

    // writer
    tokio::spawn(async move {
        while let Some((kind, payload)) = rx.recv().await {
            if let Err(err) = write_frame(&mut send, kind, &payload).await {
                debug!("write to {} failed: {err:#}", conn.remote_id().fmt_short());
                break;
            }
        }
    });

    // reader
    let shared2 = shared.clone();
    let pid = peer_id.clone();
    tokio::spawn(async move {
        loop {
            match read_frame(&mut recv).await {
                Ok((KIND_RELAY, msg)) => shared2.store.on_network(msg),
                Ok((KIND_DIRECT, msg)) => {
                    let _ = shared2.direct_tx.send((pid.clone(), msg));
                }
                Ok((k, _)) => debug!("unexpected frame kind {k} from {pid}"),
                Err(err) => {
                    debug!("connection to {pid} closed: {err:#}");
                    break;
                }
            }
        }
        let removed = shared2.peers.lock().unwrap().remove(&pid).is_some();
        if removed {
            if shared2.finalized.load(Ordering::SeqCst) {
                warn!("peer {pid} went offline during the protocol run");
            } else {
                info!("peer {pid} went offline");
            }
            shared2.bump();
        }
    });

    Ok(())
}

/// An established session: fixed participant set + transport.
pub struct Mesh {
    pub me: Hello,
    /// All participants (including self), sorted by peer id.
    pub participants: Vec<Hello>,
    shared: Arc<Shared>,
    pub direct_rx: mpsc::UnboundedReceiver<(String, Vec<u8>)>,
    out_tx: mpsc::UnboundedSender<Vec<u8>>,
    endpoint: Endpoint,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Mesh {
    /// Sorted peer ids of all participants, including self.
    pub fn peer_ids(&self) -> Vec<String> {
        self.participants.iter().map(|h| h.peer_id.clone()).collect()
    }

    pub fn my_index(&self) -> usize {
        self.participants
            .iter()
            .position(|h| h.peer_id == self.me.peer_id)
            .expect("self in participants")
    }

    /// A fresh Relay handle for a dkls23 protocol run.
    pub fn relay(&self) -> NetRelay {
        NetRelay::new(&self.shared.store, self.out_tx.clone())
    }

    pub fn timed_out(&self) -> bool {
        self.shared.store.timed_out()
    }

    pub fn send_direct(&self, peer_id: &str, payload: Vec<u8>) -> Result<()> {
        let peers = self.shared.peers.lock().unwrap();
        let link = peers
            .get(peer_id)
            .with_context(|| format!("peer {peer_id} is not connected"))?;
        link.tx
            .send((KIND_DIRECT, payload))
            .map_err(|_| anyhow::anyhow!("connection to {peer_id} is closed"))?;
        Ok(())
    }

    /// Receive the next direct message from a specific peer.
    pub async fn recv_direct(&mut self, from: &str, timeout: Duration) -> Result<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let msg = tokio::time::timeout_at(deadline, self.direct_rx.recv())
                .await
                .with_context(|| format!("timed out waiting for data from {from}"))?
                .context("network closed")?;
            if msg.0 == from {
                return Ok(msg.1);
            }
            debug!("ignoring direct message from unexpected peer {}", msg.0);
        }
    }

    /// Gracefully close all connections.
    pub async fn shutdown(mut self) {
        for t in self.tasks.drain(..) {
            t.abort();
        }
        self.endpoint.close().await;
    }
}

/// Bind the endpoint, discover peers via mDNS, and wait for the quorum
/// predicate to hold (stable for the settle window).
pub async fn establish(cfg: SessionConfig) -> Result<Mesh> {
    let user_data: UserData = ids::rendezvous(&cfg.hello.key_id)
        .parse()
        .map_err(|e| anyhow::anyhow!("bad user data: {e:?}"))?;

    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .context("binding iroh endpoint")?;
    let my_id = endpoint.id();
    info!("iroh endpoint {} bound", my_id.fmt_short());

    let mdns = MdnsAddressLookup::builder()
        .build(my_id)
        .context("starting mDNS discovery")?;
    endpoint
        .address_lookup()
        .map_err(|e| anyhow::anyhow!("address lookup unavailable: {e}"))?
        .add(mdns.clone());
    endpoint.set_user_data_for_address_lookup(Some(user_data.clone()));

    let (changed_tx, mut changed_rx) = watch::channel(0u64);
    let (direct_tx, direct_rx) = mpsc::unbounded_channel();
    let store = MsgStore::new();

    let shared = Arc::new(Shared {
        me: cfg.hello.clone(),
        compat: cfg.compat,
        store: store.clone(),
        peers: Mutex::new(HashMap::new()),
        changed: changed_tx,
        direct_tx,
        finalized: AtomicBool::new(false),
    });

    let mut tasks = Vec::new();

    // accept loop
    {
        let shared = shared.clone();
        let endpoint = endpoint.clone();
        tasks.push(tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let shared = shared.clone();
                tokio::spawn(async move {
                    let conn = match incoming.accept() {
                        Ok(accepting) => match accepting.await {
                            Ok(conn) => conn,
                            Err(err) => {
                                debug!("incoming connection failed: {err:#}");
                                return;
                            }
                        },
                        Err(err) => {
                            debug!("incoming connection refused: {err:#}");
                            return;
                        }
                    };
                    if let Err(err) = handle_conn(shared, conn, false).await {
                        debug!("incoming handshake failed: {err:#}");
                    }
                });
            }
        }));
    }

    // discovery + dial loop. To get exactly one connection per pair, the
    // endpoint with the smaller id dials.
    {
        let shared = shared.clone();
        let endpoint = endpoint.clone();
        let mdns = mdns.clone();
        tasks.push(tokio::spawn(async move {
            let mut dialing: HashSet<EndpointId> = HashSet::new();
            let mut events = mdns.subscribe().await;
            while let Some(event) = events.next().await {
                let DiscoveryEvent::Discovered { endpoint_info, .. } = event else {
                    continue;
                };
                if endpoint_info.data.user_data() != Some(&user_data) {
                    continue;
                }
                let remote_id = endpoint_info.endpoint_id;
                if remote_id == my_id || my_id.as_bytes() >= remote_id.as_bytes() {
                    continue;
                }
                if shared.finalized.load(Ordering::SeqCst) || !dialing.insert(remote_id) {
                    continue;
                }
                debug!("discovered peer endpoint {}", remote_id.fmt_short());
                let shared = shared.clone();
                let endpoint = endpoint.clone();
                let addr = endpoint_info.into_endpoint_addr();
                tokio::spawn(async move {
                    for attempt in 1..=60u32 {
                        if shared.finalized.load(Ordering::SeqCst) {
                            return;
                        }
                        match endpoint.connect(addr.clone(), ALPN).await {
                            Ok(conn) => {
                                if let Err(err) = handle_conn(shared.clone(), conn, true).await {
                                    debug!("handshake with {} failed: {err:#}", remote_id.fmt_short());
                                }
                                return;
                            }
                            Err(err) => {
                                debug!(
                                    "dial {} attempt {attempt} failed: {err:#}",
                                    remote_id.fmt_short()
                                );
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }
                        }
                    }
                });
            }
        }));
    }

    // wait for quorum, stable for SETTLE
    let mut last_count = 1usize;
    info!("waiting for peers (online: 1)");
    loop {
        let hellos = shared.hellos();
        if hellos.len() != last_count {
            last_count = hellos.len();
            info!(
                "online peers: {} [{}]",
                hellos.len(),
                hellos
                    .iter()
                    .map(|h| h.peer_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if (cfg.quorum)(&hellos) {
            tokio::select! {
                _ = tokio::time::sleep(SETTLE) => break,
                res = changed_rx.changed() => {
                    res.ok();
                    continue;
                }
            }
        } else {
            if changed_rx.changed().await.is_err() {
                bail!("network state channel closed");
            }
        }
    }

    shared.finalized.store(true, Ordering::SeqCst);
    let participants = shared.hellos();
    info!(
        "quorum reached: {} participants [{}]",
        participants.len(),
        participants
            .iter()
            .map(|h| h.peer_id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    // broadcast pump: everything published by the local protocol run goes to
    // every connected peer
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    {
        let shared = shared.clone();
        tasks.push(tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                let peers = shared.peers.lock().unwrap();
                for link in peers.values() {
                    let _ = link.tx.send((KIND_RELAY, msg.clone()));
                }
            }
        }));
    }

    tasks.push(spawn_timeout_checker(store));

    Ok(Mesh {
        me: cfg.hello.clone(),
        participants,
        shared,
        direct_rx,
        out_tx,
        endpoint,
        tasks,
    })
}
