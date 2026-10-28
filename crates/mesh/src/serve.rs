//! The accept loop: one thread per connection, at most `max_sessions` at once
//! (8, counted together with the node's outbound exchanges through
//! [`MeshNode::try_session`]), and a per-source-IP token bucket of 10
//! handshakes a minute (MESH-SI-8). Only the 16-byte preamble and handshake
//! messages of at most 1 KiB are read before a peer authenticates
//! (MESH-SI-2). Listeners come only from [`crate::bind::bind_listener`].
//!
//! The node runtime ([`crate::runtime`]) runs this beside its outbound loop;
//! `tethra mesh invite --wait` runs it alone.

use crate::bind::bind_listener;
use crate::handshake;
use crate::node::MeshNode;
use crate::pair;
use crate::replicate::{channel, log};
use crate::session::{exchange, Direction};
use crate::wire::{self, Preamble};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Bind every address (only through `bind_listener`).
pub fn bind_all(addrs: &[SocketAddr], allow_all_interfaces: bool) -> io::Result<Vec<TcpListener>> {
    addrs
        .iter()
        .map(|a| bind_listener(*a, allow_all_interfaces))
        .collect()
}

/// Counters for one `serve` run.
#[derive(Debug, Default)]
pub struct ServeStats {
    pub accepted: AtomicU64,
    pub refused_rate: AtomicU64,
    pub refused_busy: AtomicU64,
    pub failed: AtomicU64,
    pub exchanges: AtomicU64,
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

struct RateLimit {
    per_minute: f64,
    buckets: HashMap<IpAddr, Bucket>,
}

impl RateLimit {
    fn allow(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        if self.buckets.len() > 4096 {
            self.buckets
                .retain(|_, b| now.duration_since(b.at) < Duration::from_secs(120));
        }
        let cap = self.per_minute;
        let b = self.buckets.entry(ip).or_insert(Bucket {
            tokens: cap,
            at: now,
        });
        let refill = now.duration_since(b.at).as_secs_f64() * cap / 60.0;
        b.tokens = (b.tokens + refill).min(cap);
        b.at = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct Active(Arc<AtomicUsize>);

impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn handle(node: &MeshNode, mut stream: TcpStream, stats: &ServeStats) {
    let limits = node.limits();
    if stream.set_nonblocking(false).is_err()
        || stream
            .set_read_timeout(Some(limits.handshake_timeout))
            .is_err()
        || stream
            .set_write_timeout(Some(limits.handshake_timeout))
            .is_err()
    {
        return;
    }
    let outcome = match wire::read_preamble(&mut stream) {
        Ok(Preamble::Session) => handshake::respond(&mut stream, node).and_then(|(state, peer)| {
            let (r, w) = channel(stream, state, node)?;
            Ok(exchange(node, r, w, peer, Direction::Inbound))
        }),
        Ok(Preamble::Pair { hint }) => {
            pair::respond(&mut stream, node, hint).and_then(|(joiner, r, w)| {
                stream.set_read_timeout(Some(limits.idle_timeout))?;
                stream.set_write_timeout(Some(limits.idle_timeout))?;
                Ok(exchange(node, r, w, joiner, Direction::Inbound))
            })
        }
        Err(e) => Err(e.into()),
    };
    match outcome {
        Ok(report) => {
            stats.exchanges.fetch_add(1, Ordering::Relaxed);
            log(node, &report);
        }
        Err(_) => {
            stats.failed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Accept connections until `stop()` returns true, then wait (bounded by the
/// session wall time) for running exchanges to finish.
pub fn serve(
    node: Arc<MeshNode>,
    listeners: Vec<TcpListener>,
    stop: &dyn Fn() -> bool,
) -> io::Result<Arc<ServeStats>> {
    for l in &listeners {
        l.set_nonblocking(true)?;
    }
    let limits = node.limits();
    let stats = Arc::new(ServeStats::default());
    let active = Arc::new(AtomicUsize::new(0));
    let mut rate = RateLimit {
        per_minute: f64::from(limits.handshakes_per_ip_per_minute.max(1)),
        buckets: HashMap::new(),
    };
    let mut last_check = Instant::now();
    let mut stopping = stop();
    while !stopping {
        let mut idle = true;
        for l in &listeners {
            let Ok((stream, peer)) = l.accept() else {
                continue;
            };
            idle = false;
            if !rate.allow(peer.ip()) {
                stats.refused_rate.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let Some(slot) = node.try_session() else {
                stats.refused_busy.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            active.fetch_add(1, Ordering::SeqCst);
            stats.accepted.fetch_add(1, Ordering::Relaxed);
            let guard = Active(active.clone());
            let (node, stats) = (node.clone(), stats.clone());
            std::thread::spawn(move || {
                let _guard = guard;
                handle(&node, stream, &stats);
                drop(slot);
                // Release this thread's hold on the node (and its keys)
                // before the drain below can see the count reach zero.
                drop(node);
            });
        }
        if idle {
            std::thread::sleep(Duration::from_millis(20));
        }
        if last_check.elapsed() >= Duration::from_millis(200) {
            last_check = Instant::now();
            stopping = stop();
        }
    }
    drop(listeners);
    let deadline = Instant::now() + limits.max_session;
    while active.load(Ordering::SeqCst) > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(stats)
}
