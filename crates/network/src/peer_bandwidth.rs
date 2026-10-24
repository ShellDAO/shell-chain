//! Live per-peer accounting of successful decrypted substream reads and writes.
//!
//! Counts protocol negotiation and protocol payloads, including forwarded gossip.
//! Noise handshakes, Yamux framing and TCP/IP overhead are outside this boundary.

use std::collections::BTreeMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{ready, Context, Poll};

use crate::PeerBandwidthStats;
use libp2p::core::muxing::{StreamMuxer, StreamMuxerEvent};
use libp2p::futures::{AsyncRead, AsyncWrite};

#[derive(Default)]
struct ConnectionBytes {
    inbound: AtomicU64,
    outbound: AtomicU64,
}

impl ConnectionBytes {
    fn add(counter: &AtomicU64, bytes: usize) {
        #[allow(deprecated)]
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(value.saturating_add(bytes as u64))
        });
    }
}

/// Connections own their counters. Snapshots prune dead weak references so
/// disconnected peer identities cannot accumulate in the monitoring registry.
#[derive(Default)]
pub(crate) struct PeerBandwidthTracker {
    connections: Mutex<BTreeMap<String, Vec<Weak<ConnectionBytes>>>>,
}

impl PeerBandwidthTracker {
    fn register(&self, peer_id: String) -> Arc<ConnectionBytes> {
        let counters = Arc::new(ConnectionBytes::default());
        let mut peers = self.connections.lock().unwrap_or_else(|e| e.into_inner());
        peers.retain(|_, connections| {
            connections.retain(|connection| connection.strong_count() != 0);
            !connections.is_empty()
        });
        peers
            .entry(peer_id)
            .or_default()
            .push(Arc::downgrade(&counters));
        counters
    }

    pub(crate) fn snapshot(&self) -> Vec<PeerBandwidthStats> {
        let mut peers = self.connections.lock().unwrap_or_else(|e| e.into_inner());
        let mut result = Vec::with_capacity(peers.len());
        peers.retain(|peer, connections| {
            let mut stats = PeerBandwidthStats {
                peer_id: peer.clone(),
                inbound_bytes: 0,
                outbound_bytes: 0,
            };
            connections.retain(|connection| {
                let Some(connection) = connection.upgrade() else {
                    return false;
                };
                stats.inbound_bytes = stats
                    .inbound_bytes
                    .saturating_add(connection.inbound.load(Ordering::Relaxed));
                stats.outbound_bytes = stats
                    .outbound_bytes
                    .saturating_add(connection.outbound.load(Ordering::Relaxed));
                true
            });
            if connections.is_empty() {
                false
            } else {
                result.push(stats);
                true
            }
        });
        result
    }
}

pub(crate) struct MeteredMuxer<M> {
    inner: Pin<Box<M>>,
    counters: Arc<ConnectionBytes>,
}

impl<M> MeteredMuxer<M> {
    pub(crate) fn new(inner: M, peer: String, tracker: &PeerBandwidthTracker) -> Self {
        Self {
            inner: Box::pin(inner),
            counters: tracker.register(peer),
        }
    }
}

impl<M: StreamMuxer> StreamMuxer for MeteredMuxer<M> {
    type Substream = MeteredStream<M::Substream>;
    type Error = M::Error;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<StreamMuxerEvent, Self::Error>> {
        self.get_mut().inner.as_mut().poll(cx)
    }

    fn poll_inbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let this = self.get_mut();
        let inner = ready!(this.inner.as_mut().poll_inbound(cx))?;
        Poll::Ready(Ok(MeteredStream {
            inner: Box::pin(inner),
            counters: Arc::clone(&this.counters),
        }))
    }

    fn poll_outbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let this = self.get_mut();
        let inner = ready!(this.inner.as_mut().poll_outbound(cx))?;
        Poll::Ready(Ok(MeteredStream {
            inner: Box::pin(inner),
            counters: Arc::clone(&this.counters),
        }))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().inner.as_mut().poll_close(cx)
    }
}

pub(crate) struct MeteredStream<S> {
    inner: Pin<Box<S>>,
    counters: Arc<ConnectionBytes>,
}

impl<S: AsyncRead> AsyncRead for MeteredStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let bytes = ready!(this.inner.as_mut().poll_read(cx, buffer))?;
        ConnectionBytes::add(&this.counters.inbound, bytes);
        Poll::Ready(Ok(bytes))
    }
}

impl<S: AsyncWrite> AsyncWrite for MeteredStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let bytes = ready!(this.inner.as_mut().poll_write(cx, buffer))?;
        ConnectionBytes::add(&this.counters.outbound, bytes);
        Poll::Ready(Ok(bytes))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().inner.as_mut().poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().inner.as_mut().poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::futures::{io::Cursor, AsyncReadExt, AsyncWriteExt};

    struct ShortWriter(bool);

    impl AsyncWrite for ShortWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.0 {
                Poll::Ready(Err(io::Error::other("write failed")))
            } else {
                Poll::Ready(Ok(bytes.len().min(2)))
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn partial_and_failed_writes_do_not_charge_requested_length() {
        let tracker = PeerBandwidthTracker::default();
        let mut stream = MeteredStream {
            inner: Box::pin(ShortWriter(false)),
            counters: tracker.register("peer".into()),
        };
        assert_eq!(stream.write(&[1; 100]).await.unwrap(), 2);
        stream.inner.as_mut().get_mut().0 = true;
        assert!(stream.write(&[1; 100]).await.is_err());
        assert_eq!(tracker.snapshot()[0].outbound_bytes, 2);
    }

    #[tokio::test]
    async fn counts_actual_io_and_separates_peers_and_connections() {
        let tracker = PeerBandwidthTracker::default();
        let first = tracker.register("first".into());
        let second = tracker.register("second".into());
        let another = tracker.register("first".into());
        let mut stream = MeteredStream {
            inner: Box::pin(Cursor::new(vec![1, 2, 3])),
            counters: Arc::clone(&first),
        };
        let mut buffer = [0; 20];
        assert_eq!(stream.read(&mut buffer).await.unwrap(), 3);
        assert_eq!(stream.read(&mut buffer).await.unwrap(), 0);
        stream.write_all(&[5, 6]).await.unwrap();
        ConnectionBytes::add(&another.outbound, 7);
        let stats = tracker.snapshot();
        assert_eq!(stats[0].peer_id, "first");
        assert_eq!(stats[0].inbound_bytes, 3);
        assert_eq!(stats[0].outbound_bytes, 9);
        assert_eq!(stats[1].inbound_bytes, 0);
        assert_eq!(stats[1].outbound_bytes, 0);
        drop((stream, first, another));
        assert_eq!(tracker.snapshot().len(), 1);
        drop(second);
        assert!(tracker.snapshot().is_empty());
        assert!(tracker.connections.lock().unwrap().is_empty());
    }
}
