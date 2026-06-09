//! Bridge between the dkls23 message-passing model and the iroh mesh.
//!
//! dkls23 protocols talk to a [`sl_mpc_mate::coord::Relay`]: a combined
//! `Stream`/`Sink` of raw messages. Every message starts with a 36-byte
//! header (32-byte message id + ttl + flags). A header-only message is an
//! "ask": the party requests delivery of the message with that id. Anything
//! longer is a publication.
//!
//! [`MsgStore`] keeps published messages and pending asks for the single
//! in-process protocol run. Published messages are also handed to the mesh
//! broadcast channel; messages received from the network are injected with
//! [`MsgStore::on_network`]. If an ask is not satisfied within its TTL the
//! consumer stream is closed, which makes the dkls23 protocol fail — this is
//! the "peer went offline" timeout behavior.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_util::{Sink, Stream};
use sl_mpc_mate::coord::{MessageSendError, Relay};
use sl_mpc_mate::message::{MsgHdr, MsgId, MESSAGE_HEADER_SIZE};
use tokio::sync::mpsc;

#[derive(Default)]
struct StoreInner {
    /// Published messages by id, with expiry.
    ready: HashMap<MsgId, (Vec<u8>, Instant)>,
    /// Pending asks of the local consumer, with deadline.
    asks: HashMap<MsgId, Instant>,
    /// Channel to the local protocol run. Dropped on timeout to signal failure.
    consumer: Option<mpsc::UnboundedSender<Vec<u8>>>,
    timed_out: bool,
}

#[derive(Clone, Default)]
pub struct MsgStore {
    inner: Arc<Mutex<StoreInner>>,
}

impl MsgStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn parse(msg: &[u8]) -> Option<(MsgId, Duration)> {
        let hdr: &MsgHdr = msg.try_into().ok()?;
        Some((*hdr.id(), hdr.ttl()))
    }

    /// Inject a message received from a remote peer.
    pub fn on_network(&self, msg: Vec<u8>) {
        if msg.len() <= MESSAGE_HEADER_SIZE {
            // ignore network noise / remote asks: we broadcast everything,
            // so remote parties never need to ask us explicitly
            return;
        }
        self.publish(msg);
    }

    fn publish(&self, msg: Vec<u8>) {
        let Some((id, ttl)) = Self::parse(&msg) else {
            return;
        };
        let mut inner = self.inner.lock().unwrap();
        if inner.asks.remove(&id).is_some() {
            if let Some(tx) = &inner.consumer {
                let _ = tx.send(msg.clone());
            }
        }
        inner
            .ready
            .entry(id)
            .or_insert_with(|| (msg, Instant::now() + ttl));
    }

    fn ask(&self, msg: &[u8]) {
        let Some((id, ttl)) = Self::parse(msg) else {
            return;
        };
        let mut inner = self.inner.lock().unwrap();
        if let Some((ready, _)) = inner.ready.get(&id) {
            let ready = ready.clone();
            if let Some(tx) = &inner.consumer {
                let _ = tx.send(ready);
            }
        } else {
            inner.asks.insert(id, Instant::now() + ttl);
        }
    }

    /// Drop expired published messages and fail the consumer if any ask
    /// passed its deadline. Returns true if a timeout fired.
    pub fn check_timeouts(&self) -> bool {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        inner.ready.retain(|_, (_, exp)| *exp > now);
        let expired: Vec<MsgId> = inner
            .asks
            .iter()
            .filter(|(_, deadline)| **deadline <= now)
            .map(|(id, _)| *id)
            .collect();
        if !expired.is_empty() {
            for id in &expired {
                tracing::error!("timed out waiting for message {:x}", id);
            }
            inner.timed_out = true;
            inner.consumer = None; // close the stream -> protocol fails
            true
        } else {
            false
        }
    }

    pub fn timed_out(&self) -> bool {
        self.inner.lock().unwrap().timed_out
    }

    fn register_consumer(&self) -> mpsc::UnboundedReceiver<Vec<u8>> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner.lock().unwrap().consumer = Some(tx);
        rx
    }
}

/// The `Relay` implementation handed to dkls23 protocol runs.
pub struct NetRelay {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    store: MsgStore,
    /// Outgoing publications, consumed by the mesh broadcast task.
    out: mpsc::UnboundedSender<Vec<u8>>,
}

impl NetRelay {
    pub fn new(store: &MsgStore, out: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self {
            rx: store.register_consumer(),
            store: store.clone(),
            out,
        }
    }
}

impl Stream for NetRelay {
    type Item = Vec<u8>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

impl Sink<Vec<u8>> for NetRelay {
    type Error = MessageSendError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        if item.len() < MESSAGE_HEADER_SIZE {
            return Err(MessageSendError);
        }
        if item.len() == MESSAGE_HEADER_SIZE {
            self.store.ask(&item);
        } else {
            // broadcast to all peers; also keep locally (harmless, and makes
            // in-process multi-party tests possible)
            let _ = self.out.send(item.clone());
            self.store.publish(item);
        }
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl Relay for NetRelay {}

/// Spawn the periodic ask-deadline checker for a store.
pub fn spawn_timeout_checker(store: MsgStore) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            if store.check_timeouts() {
                break;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use sl_mpc_mate::message::{allocate_message, AskMsg, InstanceId, MessageTag};

    fn mk_id(tag: u64) -> MsgId {
        MsgId::new(
            &InstanceId::from([7u8; 32]),
            &[1, 2, 3],
            None,
            MessageTag::tag(tag),
        )
    }

    #[tokio::test]
    async fn publish_then_ask_and_ask_then_publish() {
        let store = MsgStore::new();
        let (out, mut out_rx) = mpsc::unbounded_channel();
        let mut relay = NetRelay::new(&store, out);

        let id1 = mk_id(1);
        let m1 = allocate_message(&id1, 10, 0, b"hello");
        relay.send(m1.clone()).await.unwrap();
        // it was broadcast
        assert_eq!(out_rx.recv().await.unwrap(), m1);
        // ask after publish -> immediate delivery
        relay.send(AskMsg::allocate(&id1, 10)).await.unwrap();
        assert_eq!(relay.next().await.unwrap(), m1);

        // ask before publish -> delivered on network arrival
        let id2 = mk_id(2);
        relay.send(AskMsg::allocate(&id2, 10)).await.unwrap();
        let m2 = allocate_message(&id2, 10, 0, b"world");
        store.on_network(m2.clone());
        assert_eq!(relay.next().await.unwrap(), m2);
    }

    #[tokio::test]
    async fn ask_timeout_closes_stream() {
        let store = MsgStore::new();
        let (out, _out_rx) = mpsc::unbounded_channel();
        let mut relay = NetRelay::new(&store, out);

        let id = mk_id(3);
        // ttl 0 seconds -> expires immediately
        relay.send(AskMsg::allocate(&id, 0)).await.unwrap();
        assert!(store.check_timeouts());
        assert!(store.timed_out());
        assert_eq!(relay.next().await, None);
    }

    #[tokio::test]
    async fn network_dups_ignored() {
        let store = MsgStore::new();
        let (out, _out_rx) = mpsc::unbounded_channel();
        let mut relay = NetRelay::new(&store, out);

        let id = mk_id(4);
        let m = allocate_message(&id, 10, 0, b"x");
        store.on_network(m.clone());
        store.on_network(m.clone());
        relay.send(AskMsg::allocate(&id, 10)).await.unwrap();
        assert_eq!(relay.next().await.unwrap(), m);
        // only one delivery even though published twice
        relay.send(AskMsg::allocate(&mk_id(5), 1)).await.unwrap();
        tokio::select! {
            _ = relay.next() => panic!("unexpected message"),
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
}
