//! The anti-entropy session (PROTOCOL.md §8), as a pure state machine.
//!
//! A [`Session`] consumes the peer's frames and produces [`Action`]s: frames
//! to send, one commit to apply, fork evidence and direct messages for the
//! caller, and when to close. It reads the local store but never writes it —
//! the caller applies [`Action::Commit`] with [`MeshStore::commit`]. It does
//! no I/O and reads no clock; the network crate (Increment 04) and the
//! simulator drive it.

use super::chain::Hash32;
use super::codec::MAX_ITEM_BYTES;
use super::crdt::roster::{AddRecord, Roster};
use super::crdt::SwEntry;
use super::dot::{DeviceId, MeshId};
use super::item::{ItemHash, SignedItem};
use super::kinds::{TypedItem, KNOWN_KINDS};
use super::store::{CommitBatch, ForkEvidence, MeshStore, VerifiedItem};
use super::vv::VersionVector;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;

/// The only protocol version this build speaks.
pub const PROTO_VERSION: u32 = 1;
/// Largest encoded frame.
pub const MAX_FRAME_BYTES: usize = 1 << 20;

/// Session bounds (PROTOCOL.md §11, MESH-SI-8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Items plus dots staged (and sent) per session.
    pub max_staged: usize,
    pub max_batch_items: usize,
    /// Raw item bytes per `Items` frame (base64 grows them by 4/3).
    pub max_batch_bytes: usize,
    pub max_dots_per_frame: usize,
    /// Main-path items more than this far above the receiver's VV are refused.
    pub max_gap: u64,
    pub rate_per_hour: u64,
    pub max_query_seqs: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_staged: 50_000,
            max_batch_items: 512,
            max_batch_bytes: 640 * 1024,
            max_dots_per_frame: 4096,
            max_gap: 50_000,
            rate_per_hour: 10_000,
            max_query_seqs: 64,
        }
    }
}

// ------------------------------------------------------------------ frames

/// Raw bytes written as standard base64.
#[derive(Clone, PartialEq, Eq)]
pub struct B64(pub Vec<u8>);

impl std::fmt::Debug for B64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "B64({} bytes)", self.0.len())
    }
}

impl Serialize for B64 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for B64 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map(B64)
            .map_err(|_| serde::de::Error::custom("invalid base64"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub proto_min: u32,
    pub proto_max: u32,
    pub mesh_id: MeshId,
    pub device_id: DeviceId,
    pub kinds: Vec<String>,
    pub vv: VersionVector,
    pub own_next_seq: u64,
    pub chains: BTreeMap<DeviceId, Hash32>,
    pub digests: BTreeMap<DeviceId, Hash32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Items {
    pub batch: Vec<B64>,
    pub dots: Vec<(DeviceId, u64, ItemHash)>,
    pub repair: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    pub upto: VersionVector,
    pub count: u64,
    pub batch_hash: Hash32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainQuery {
    pub origin: DeviceId,
    pub seqs: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainReply {
    pub origin: DeviceId,
    pub entries: Vec<(u64, Hash32, ItemHash)>,
}

/// Point-to-point messages, never stored or relayed as items.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload")]
pub enum DirectMsg {
    /// "I hold your history up to `held_seq`; do not mint until you have it
    /// back" (PROTOCOL.md §7.4).
    RollbackNotice { held_seq: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ByeReason {
    Done,
    MeshMismatch,
    NoCommonVersion,
    NotThePeer,
    Protocol,
    TooLarge,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum Body {
    Hello(Hello),
    Items(Items),
    Commit(Commit),
    ChainQuery(ChainQuery),
    ChainReply(ChainReply),
    Direct(DirectMsg),
    Bye { reason: ByeReason },
}

/// One frame: `{"n": …, "t": "<Tag>", …}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    pub n: u64,
    #[serde(flatten)]
    pub body: Body,
}

impl Frame {
    pub fn encode(&self) -> Result<Vec<u8>, super::error::MeshError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|_| super::error::MeshError::Malformed("frame does not serialize"))?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(super::error::MeshError::ItemTooLarge {
                size: bytes.len(),
                max: MAX_FRAME_BYTES,
            });
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, super::error::MeshError> {
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(super::error::MeshError::ItemTooLarge {
                size: bytes.len(),
                max: MAX_FRAME_BYTES,
            });
        }
        serde_json::from_slice(bytes)
            .map_err(|_| super::error::MeshError::Malformed("frame is not valid JSON"))
    }
}

// ----------------------------------------------------------------- actions

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// Both sides finished.
    Done,
    /// The peer ended the session.
    PeerBye(ByeReason),
    /// This side ended it.
    Aborted(&'static str),
}

#[derive(Clone, Debug)]
pub enum Action {
    Send(Frame),
    /// Apply with [`MeshStore::commit`]; at most one per session.
    Commit(CommitBatch),
    /// A fork found by chain bisection (PROTOCOL.md §7.2); the caller mints
    /// a `fork.report` unless it already has one at this seq or lower.
    ForkDetected(ForkEvidence),
    Direct(DirectMsg),
    Close(CloseReason),
}

// ----------------------------------------------------------------- session

#[derive(Default)]
struct OriginStage {
    items: BTreeMap<u64, VerifiedItem>,
    dots: BTreeMap<u64, ItemHash>,
    /// The lowest seq at which one of this origin's items was rejected.
    rejected_at: Option<u64>,
}

impl OriginStage {
    fn reject(&mut self, seq: u64) {
        self.rejected_at = Some(self.rejected_at.map_or(seq, |r| r.min(seq)));
        self.items.retain(|s, _| *s < seq);
        self.dots.retain(|s, _| *s < seq);
    }

    fn open(&self, seq: u64) -> bool {
        self.rejected_at.is_none_or(|r| seq < r)
    }
}

struct Pending {
    item: SignedItem,
    body: super::codec::ItemBody,
    repair: bool,
}

/// One anti-entropy session with one peer.
pub struct Session {
    limits: Limits,
    expected_peer: Option<DeviceId>,
    next_send: u64,
    next_recv: u64,
    peer: Option<Hello>,
    roster: Option<Roster>,
    staged: BTreeMap<DeviceId, OriginStage>,
    repair: Vec<VerifiedItem>,
    pending: Vec<Pending>,
    staged_total: usize,
    max_staged_seen: usize,
    recv_count: u64,
    recv_hashes: blake3::Hasher,
    rejected: u64,
    queries: BTreeMap<DeviceId, (u64, u64)>,
    sent_commit: bool,
    got_commit: bool,
    sent_bye: bool,
    got_bye: bool,
    closed: bool,
}

impl Session {
    /// `expected_peer` is the device the transport authenticated (None in
    /// tests that do not care).
    pub fn new(limits: Limits, expected_peer: Option<DeviceId>) -> Self {
        Self {
            limits,
            expected_peer,
            next_send: 0,
            next_recv: 0,
            peer: None,
            roster: None,
            staged: BTreeMap::new(),
            repair: Vec::new(),
            pending: Vec::new(),
            staged_total: 0,
            max_staged_seen: 0,
            recv_count: 0,
            recv_hashes: blake3::Hasher::new(),
            rejected: 0,
            queries: BTreeMap::new(),
            sent_commit: false,
            got_commit: false,
            sent_bye: false,
            got_bye: false,
            closed: false,
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Items rejected so far (the caller adds them to the store's counter).
    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    /// The most items and dots this session ever had staged (MESH-SI-8).
    pub fn max_staged_seen(&self) -> usize {
        self.max_staged_seen
    }

    fn frame(&mut self, body: Body) -> Action {
        let f = Frame {
            n: self.next_send,
            body,
        };
        self.next_send += 1;
        Action::Send(f)
    }

    fn close(&mut self, out: &mut Vec<Action>, bye: Option<ByeReason>, reason: CloseReason) {
        if let Some(r) = bye {
            let f = self.frame(Body::Bye { reason: r });
            out.push(f);
        }
        self.closed = true;
        out.push(Action::Close(reason));
    }

    fn abort(&mut self, why: &'static str) -> Vec<Action> {
        let mut out = Vec::new();
        self.close(
            &mut out,
            Some(ByeReason::Protocol),
            CloseReason::Aborted(why),
        );
        out
    }

    /// The opening `Hello`.
    pub fn start<S: MeshStore>(&mut self, store: &S) -> Vec<Action> {
        let vv = store.vv().clone();
        let mut chains = BTreeMap::new();
        let mut digests = BTreeMap::new();
        for (o, s) in vv.iter() {
            if let Some(c) = store.chain_at(o, *s) {
                chains.insert(*o, c);
            }
            digests.insert(*o, store.origin_digest(o));
        }
        let hello = Hello {
            proto_min: PROTO_VERSION,
            proto_max: PROTO_VERSION,
            mesh_id: store.genesis().mesh_id,
            device_id: store.self_id(),
            kinds: KNOWN_KINDS.iter().map(|k| (*k).to_owned()).collect(),
            own_next_seq: vv.get(&store.self_id()) + 1,
            vv,
            chains,
            digests,
        };
        vec![self.frame(Body::Hello(hello))]
    }

    /// Consume one frame from the peer.
    pub fn on_frame<S: MeshStore>(&mut self, frame: Frame, store: &S) -> Vec<Action> {
        if self.closed {
            return Vec::new();
        }
        if frame.n != self.next_recv {
            return self.abort("frame out of order");
        }
        self.next_recv += 1;
        if self.peer.is_none() && !matches!(frame.body, Body::Hello(_) | Body::Bye { .. }) {
            return self.abort("frame before Hello");
        }
        match frame.body {
            Body::Hello(h) => self.on_hello(h, store),
            Body::Items(i) => self.on_items(i, store),
            Body::Commit(c) => self.on_commit(c, store),
            Body::ChainQuery(q) => self.on_chain_query(q, store),
            Body::ChainReply(r) => self.on_chain_reply(r, store),
            Body::Direct(d) => vec![Action::Direct(d)],
            Body::Bye { reason } => {
                self.got_bye = true;
                let mut out = Vec::new();
                if reason == ByeReason::Done {
                    self.maybe_finish(&mut out);
                } else {
                    self.close(&mut out, None, CloseReason::PeerBye(reason));
                }
                out
            }
        }
    }

    fn on_hello<S: MeshStore>(&mut self, h: Hello, store: &S) -> Vec<Action> {
        let mut out = Vec::new();
        if self.peer.is_some() {
            return self.abort("second Hello");
        }
        if h.mesh_id != store.genesis().mesh_id {
            self.close(
                &mut out,
                Some(ByeReason::MeshMismatch),
                CloseReason::Aborted("mesh mismatch"),
            );
            return out;
        }
        if !(h.proto_min <= PROTO_VERSION && PROTO_VERSION <= h.proto_max) {
            self.close(
                &mut out,
                Some(ByeReason::NoCommonVersion),
                CloseReason::Aborted("no common protocol version"),
            );
            return out;
        }
        if self.expected_peer.is_some_and(|e| e != h.device_id) {
            self.close(
                &mut out,
                Some(ByeReason::NotThePeer),
                CloseReason::Aborted("not the peer"),
            );
            return out;
        }
        self.roster = Some(store.state().roster.clone());
        let own = store.vv().clone();

        // Rollback (§7.4).
        let held = own.get(&h.device_id);
        if held >= h.own_next_seq && held > 0 {
            let f = self.frame(Body::Direct(DirectMsg::RollbackNotice { held_seq: held }));
            out.push(f);
        }
        // Forks (§7.2).
        for (o, pv) in h.vv.iter() {
            if *pv == 0 || *pv > own.get(o) {
                continue;
            }
            let (Some(ours), Some(theirs)) = (store.chain_at(o, *pv), h.chains.get(o)) else {
                continue;
            };
            if ours != *theirs {
                self.queries.insert(*o, (0, *pv));
                let seqs = self.probes(0, *pv);
                let f = self.frame(Body::ChainQuery(ChainQuery { origin: *o, seqs }));
                out.push(f);
            }
        }
        // Stream what the peer lacks, then repair, then Commit.
        let plan = self.plan(&h, store);
        self.peer = Some(h);
        out.extend(plan);
        out
    }

    fn probes(&self, lo: u64, hi: u64) -> Vec<u64> {
        let n = self.limits.max_query_seqs.max(1) as u64;
        if hi - lo <= n {
            return (lo + 1..=hi).collect();
        }
        let mut v: Vec<u64> = (1..=n).map(|i| lo + (hi - lo) * i / n).collect();
        v.dedup();
        v
    }

    fn plan<S: MeshStore>(&mut self, peer: &Hello, store: &S) -> Vec<Action> {
        let own = store.vv();
        let mut budget = self.limits.max_staged as u64;
        let mut main: Vec<SignedItem> = Vec::new();
        let mut dots: Vec<(DeviceId, u64, ItemHash)> = Vec::new();
        let mut upto = VersionVector::new();
        for (o, ov) in own.iter() {
            let pv = peer.vv.get(o);
            // Never extend a peer's log of an origin whose chains disagree:
            // that would mix two branches before the fork is reported
            // (PROTOCOL.md §7.2). Such an origin travels by repair only.
            if *ov <= pv || budget == 0 || self.queries.contains_key(o) {
                continue;
            }
            let to = (*ov).min(pv.saturating_add(budget));
            let held = store.held_items(o, pv, to);
            let mut by_seq: BTreeMap<u64, SignedItem> = BTreeMap::new();
            for item in held {
                let Ok(body) = item.decode_unverified() else {
                    continue;
                };
                // On the main path send the item our dot log recorded; a
                // second branch's item at the same dot travels by repair.
                if store.dot_hash(o, body.seq) == Some(item.hash()) {
                    by_seq.insert(body.seq, item);
                }
            }
            for s in pv + 1..=to {
                match by_seq.remove(&s) {
                    Some(item) => main.push(item),
                    None => {
                        if let Some(h) = store.dot_hash(o, s) {
                            dots.push((*o, s, h));
                        }
                    }
                }
            }
            budget -= to - pv;
            upto.advance_to(*o, to);
        }
        let roster = &store.state().roster;
        let mut repair: Vec<SignedItem> = Vec::new();
        for (o, ov) in own.iter() {
            let differs = peer.digests.get(o) != Some(&store.origin_digest(o));
            let eligible = *ov == peer.vv.get(o) || roster.fork_seq(o).is_some();
            if differs && eligible {
                repair.extend(store.held_items(o, 0, u64::MAX));
            }
        }

        let mut out = Vec::new();
        let mut hasher = blake3::Hasher::new();
        let mut count = 0u64;
        for (items, is_repair) in [(main, false), (repair, true)] {
            let mut batch: Vec<B64> = Vec::new();
            let mut bytes = 0usize;
            for item in items {
                let wire = item.to_wire();
                if !batch.is_empty()
                    && (batch.len() >= self.limits.max_batch_items
                        || bytes + wire.len() > self.limits.max_batch_bytes)
                {
                    let f = self.frame(Body::Items(Items {
                        batch: std::mem::take(&mut batch),
                        dots: Vec::new(),
                        repair: is_repair,
                    }));
                    out.push(f);
                    bytes = 0;
                }
                hasher.update(&item.hash().0);
                count += 1;
                bytes += wire.len();
                batch.push(B64(wire));
            }
            if !batch.is_empty() {
                let f = self.frame(Body::Items(Items {
                    batch,
                    dots: Vec::new(),
                    repair: is_repair,
                }));
                out.push(f);
            }
            if !is_repair {
                for chunk in dots.chunks(self.limits.max_dots_per_frame.max(1)) {
                    let f = self.frame(Body::Items(Items {
                        batch: Vec::new(),
                        dots: chunk.to_vec(),
                        repair: false,
                    }));
                    out.push(f);
                }
            }
        }
        let f = self.frame(Body::Commit(Commit {
            upto,
            count,
            batch_hash: Hash32(*hasher.finalize().as_bytes()),
        }));
        out.push(f);
        self.sent_commit = true;
        out
    }

    fn bump_staged(&mut self) -> bool {
        self.staged_total += 1;
        self.max_staged_seen = self.max_staged_seen.max(self.staged_total);
        self.staged_total <= self.limits.max_staged
    }

    fn on_items<S: MeshStore>(&mut self, items: Items, store: &S) -> Vec<Action> {
        if self.got_commit {
            return self.abort("items after Commit");
        }
        for b in items.batch {
            self.recv_count += 1;
            self.recv_hashes.update(&ItemHash::of(&b.0).0);
            if !self.bump_staged() {
                let mut out = Vec::new();
                self.close(
                    &mut out,
                    Some(ByeReason::TooLarge),
                    CloseReason::Aborted("too many staged items"),
                );
                return out;
            }
            self.stage_bytes(&b.0, items.repair, store);
        }
        for (o, s, h) in items.dots {
            if !self.bump_staged() {
                let mut out = Vec::new();
                self.close(
                    &mut out,
                    Some(ByeReason::TooLarge),
                    CloseReason::Aborted("too many staged items"),
                );
                return out;
            }
            let stage = self.staged.entry(o).or_default();
            if !stage.open(s) {
                continue;
            }
            let clash = stage.items.get(&s).is_some_and(|v| v.item.hash() != h)
                || stage.dots.get(&s).is_some_and(|x| *x != h);
            if clash {
                stage.reject(s);
            } else {
                stage.dots.insert(s, h);
            }
        }
        self.drain_pending(store);
        Vec::new()
    }

    fn reject(&mut self, origin: DeviceId, seq: u64, repair: bool) {
        self.rejected += 1;
        if !repair {
            self.staged.entry(origin).or_default().reject(seq);
        }
    }

    fn stage_bytes<S: MeshStore>(&mut self, bytes: &[u8], repair: bool, store: &S) {
        // 1. size
        if bytes.len() > MAX_ITEM_BYTES {
            self.rejected += 1;
            return;
        }
        let Ok(item) = SignedItem::from_wire(bytes) else {
            self.rejected += 1;
            return;
        };
        // 2. parse
        let Ok(body) = item.decode_unverified() else {
            self.rejected += 1;
            return;
        };
        // 3. mesh
        if body.mesh != store.genesis().mesh_id {
            self.rejected += 1;
            return;
        }
        let (o, s) = (body.origin, body.seq);
        if !repair {
            if !self.staged.entry(o).or_default().open(s) {
                return;
            }
            // 7. gap
            if s > store.vv().get(&o).saturating_add(self.limits.max_gap) {
                self.reject(o, s, false);
                return;
            }
        }
        self.pending.push(Pending { item, body, repair });
    }

    /// Run checks 4-8 on every pending item whose origin is now known,
    /// repeating while that makes more origins known.
    fn drain_pending<S: MeshStore>(&mut self, store: &S) {
        loop {
            let mut progressed = false;
            let pending = std::mem::take(&mut self.pending);
            for p in pending {
                match self.check(&p, store) {
                    Check::Unknown => self.pending.push(p),
                    Check::Rejected => {
                        self.reject(p.body.origin, p.body.seq, p.repair);
                        progressed = true;
                    }
                    Check::Accepted(v) => {
                        self.accept(*v, p.repair);
                        progressed = true;
                    }
                }
            }
            if !progressed || self.pending.is_empty() {
                return;
            }
        }
    }

    fn check<S: MeshStore>(&self, p: &Pending, store: &S) -> Check {
        let roster = self.roster.as_ref().expect("set at Hello");
        let (o, s) = (p.body.origin, p.body.seq);
        if !p.repair && !self.staged.get(&o).is_some_and(|st| st.open(s)) {
            return Check::Rejected;
        }
        // 4. origin known (or the genesis self-add)
        let sign_pub = match roster.keys(&o) {
            Some(k) => k.sign_pub,
            None => {
                let genesis = store.genesis().genesis;
                if o == genesis
                    && p.body.kind == super::kinds::names::ROSTER_ADD
                    && p.body.key == genesis.to_hex()
                {
                    match TypedItem::parse(&p.body) {
                        Ok(TypedItem::RosterAdd(a)) => a.sign_pub,
                        _ => return Check::Rejected,
                    }
                } else {
                    return Check::Unknown;
                }
            }
        };
        // 5. signature
        let Ok(vk) = sign_pub.to_verifying_key() else {
            return Check::Rejected;
        };
        if p.item.verify_with(&vk, &store.genesis().mesh_id).is_err() {
            return Check::Rejected;
        }
        // 6. rate
        if !p.repair {
            let staged = self.staged.get(&o).map_or(0, |st| st.items.len() as u64);
            if store.ingest_rate_used(&o) + staged >= self.limits.rate_per_hour {
                return Check::Rejected;
            }
        }
        // 8. kind
        match TypedItem::parse(&p.body) {
            Ok(typed) => Check::Accepted(Box::new(VerifiedItem {
                item: p.item.clone(),
                body: p.body.clone(),
                typed,
            })),
            Err(_) => Check::Rejected,
        }
    }

    fn accept(&mut self, v: VerifiedItem, repair: bool) {
        let roster = self.roster.as_mut().expect("set at Hello");
        let (o, s, h) = (v.body.origin, v.body.seq, v.item.hash());
        match &v.typed {
            TypedItem::RosterAdd(a) => {
                roster.apply_add(o, a.device, SwEntry::new(s, h, AddRecord::from(a)));
            }
            TypedItem::RosterRemove(r) => {
                roster.apply_remove(o, r.device, SwEntry::new(s, h, r.cutoff_seq));
            }
            TypedItem::ForkReport(f) => {
                roster.apply_fork_report(o, f.device, SwEntry::new(s, h, f.seq));
            }
            _ => {}
        }
        if repair {
            self.repair.push(v);
            return;
        }
        let stage = self.staged.entry(o).or_default();
        let clash = stage.items.get(&s).is_some_and(|x| x.item.hash() != h)
            || stage.dots.get(&s).is_some_and(|x| *x != h);
        if clash {
            self.reject(o, s, false);
        } else {
            stage.items.insert(s, v);
        }
    }

    fn on_commit<S: MeshStore>(&mut self, c: Commit, store: &S) -> Vec<Action> {
        if self.got_commit {
            return self.abort("second Commit");
        }
        let got = Hash32(
            *std::mem::replace(&mut self.recv_hashes, blake3::Hasher::new())
                .finalize()
                .as_bytes(),
        );
        if c.count != self.recv_count || c.batch_hash != got {
            return self.abort("Commit does not match the items received");
        }
        self.got_commit = true;
        self.drain_pending(store);
        for p in std::mem::take(&mut self.pending) {
            self.reject(p.body.origin, p.body.seq, p.repair);
        }

        let own = store.vv();
        let mut batch = CommitBatch::default();
        for (o, pu) in c.upto.iter() {
            let Some(stage) = self.staged.get_mut(o) else {
                continue;
            };
            let cur = own.get(o);
            let mut limit = *pu;
            if let Some(r) = stage.rejected_at {
                limit = limit.min(r.saturating_sub(1));
            }
            let mut s = cur + 1;
            while s <= limit {
                if !stage.items.contains_key(&s) && !stage.dots.contains_key(&s) {
                    limit = s - 1;
                    break;
                }
                s += 1;
            }
            for (seq, v) in std::mem::take(&mut stage.items) {
                if seq <= limit {
                    batch.items.push(v);
                }
            }
            // Dots at or below our VV go too: the store compares them with
            // its log, in case another session extended it meanwhile.
            for (seq, h) in std::mem::take(&mut stage.dots) {
                if seq <= limit {
                    batch.dots.push((*o, seq, h));
                }
            }
            if limit > cur {
                batch.upto.advance_to(*o, limit);
            }
        }
        batch.repair = std::mem::take(&mut self.repair);
        let mut out = Vec::new();
        if !batch.items.is_empty() || !batch.upto.is_empty() || !batch.repair.is_empty() {
            out.push(Action::Commit(batch));
        }
        self.maybe_finish(&mut out);
        out
    }

    fn on_chain_query<S: MeshStore>(&mut self, q: ChainQuery, store: &S) -> Vec<Action> {
        if q.seqs.len() > self.limits.max_query_seqs {
            return self.abort("ChainQuery asks for too many seqs");
        }
        let entries = q
            .seqs
            .iter()
            .filter_map(|s| {
                Some((
                    *s,
                    store.chain_at(&q.origin, *s)?,
                    store.dot_hash(&q.origin, *s)?,
                ))
            })
            .collect();
        vec![self.frame(Body::ChainReply(ChainReply {
            origin: q.origin,
            entries,
        }))]
    }

    fn on_chain_reply<S: MeshStore>(&mut self, r: ChainReply, store: &S) -> Vec<Action> {
        let mut out = Vec::new();
        let Some((lo, _hi)) = self.queries.get(&r.origin).copied() else {
            return self.abort("unexpected ChainReply");
        };
        let mut entries = r.entries;
        entries.sort_by_key(|e| e.0);
        let mut new_lo = lo;
        let mut found: Option<(u64, ItemHash)> = None;
        for (seq, chain, hash) in entries {
            if seq <= lo {
                continue;
            }
            match store.chain_at(&r.origin, seq) {
                Some(ours) if ours == chain => new_lo = seq,
                Some(_) => {
                    found = Some((seq, hash));
                    break;
                }
                None => break,
            }
        }
        match found {
            None => {
                self.queries.remove(&r.origin);
            }
            Some((hi, theirs)) if hi == new_lo + 1 => {
                self.queries.remove(&r.origin);
                if let Some(ours) = store.dot_hash(&r.origin, hi) {
                    out.push(Action::ForkDetected(ForkEvidence {
                        origin: r.origin,
                        seq: hi,
                        ours,
                        theirs,
                    }));
                }
            }
            Some((hi, _)) => {
                self.queries.insert(r.origin, (new_lo, hi));
                let seqs = self.probes(new_lo, hi);
                let f = self.frame(Body::ChainQuery(ChainQuery {
                    origin: r.origin,
                    seqs,
                }));
                out.push(f);
            }
        }
        self.maybe_finish(&mut out);
        out
    }

    fn maybe_finish(&mut self, out: &mut Vec<Action>) {
        if self.closed {
            return;
        }
        if self.sent_commit && self.got_commit && self.queries.is_empty() && !self.sent_bye {
            let f = self.frame(Body::Bye {
                reason: ByeReason::Done,
            });
            out.push(f);
            self.sent_bye = true;
        }
        if self.sent_bye && self.got_bye {
            self.closed = true;
            out.push(Action::Close(CloseReason::Done));
        }
    }
}

enum Check {
    Unknown,
    Rejected,
    Accepted(Box<VerifiedItem>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::clock::ManualClock;
    use crate::mesh::kinds::{MeshSetting, RosterAdd};
    use crate::mesh::memstore::MemStore;
    use crate::mesh::sign::{derive_device_id, PublicKeyBytes, SigningKeyPair};
    use crate::mesh::store::{Draft, GenesisInfo, HlcPolicy};
    use std::sync::Arc;

    struct Dev {
        key: SigningKeyPair,
        id: DeviceId,
        store: MemStore,
    }

    fn dev(seed: u8, genesis: Option<GenesisInfo>) -> Dev {
        let key = SigningKeyPair::from_secret_bytes(&[seed; 32]);
        let id = derive_device_id(
            &key.public_key(),
            &PublicKeyBytes([1; 32]),
            &PublicKeyBytes([2; 32]),
        );
        let g = genesis.unwrap_or(GenesisInfo {
            mesh_id: MeshId::from_bytes([9; 16]),
            genesis: id,
        });
        let clock: Arc<dyn crate::mesh::clock::Clock> =
            Arc::new(ManualClock::new(1_700_000_000_000));
        Dev {
            store: MemStore::new(g, id, clock),
            key,
            id,
        }
    }

    fn add(by: &mut Dev, target: &Dev) {
        let a = RosterAdd {
            device: target.id,
            name: "dev".into(),
            sign_pub: target.key.public_key(),
            noise_pub: PublicKeyBytes([1; 32]),
            seal_pub: PublicKeyBytes([2; 32]),
            added_by: by.id,
        };
        by.store
            .mint(&by.key, Draft::of(&a, HlcPolicy::Now))
            .unwrap();
    }

    fn setting(d: &mut Dev, v: u64) {
        let m = MeshSetting {
            name: "retention_days".into(),
            value: serde_json::json!(v),
        };
        d.store
            .mint(&d.key, Draft::of(&m, HlcPolicy::After(None)))
            .unwrap();
    }

    /// A genesis device that has added a second device.
    fn pair() -> (Dev, Dev) {
        let mut g = dev(1, None);
        let genesis = g.store.genesis();
        let b = dev(2, Some(genesis));
        let me = g_clone_for_self(&g);
        add(&mut g, &me);
        add(&mut g, &b);
        (g, b)
    }

    fn g_clone_for_self(g: &Dev) -> Dev {
        Dev {
            key: SigningKeyPair::from_secret_bytes(&g.key.expose_secret_bytes()),
            id: g.id,
            store: g.store.clone(),
        }
    }

    /// Run one session between two stores to completion, applying commits.
    fn exchange(a: &mut Dev, b: &mut Dev) -> (Vec<Action>, Vec<Action>) {
        let mut sa = Session::new(Limits::default(), Some(b.id));
        let mut sb = Session::new(Limits::default(), Some(a.id));
        let mut to_b: Vec<Frame> = Vec::new();
        let mut to_a: Vec<Frame> = Vec::new();
        let (mut log_a, mut log_b) = (Vec::new(), Vec::new());
        let route = |acts: Vec<Action>,
                     out: &mut Vec<Frame>,
                     log: &mut Vec<Action>,
                     store: &mut MemStore| {
            for a in acts {
                match a {
                    Action::Send(f) => out.push(f),
                    Action::Commit(batch) => {
                        store.commit(batch).unwrap();
                    }
                    other => log.push(other),
                }
            }
        };
        let acts = sa.start(&a.store);
        route(acts, &mut to_b, &mut log_a, &mut a.store);
        let acts = sb.start(&b.store);
        route(acts, &mut to_a, &mut log_b, &mut b.store);
        for _ in 0..1000 {
            if to_a.is_empty() && to_b.is_empty() {
                break;
            }
            for f in std::mem::take(&mut to_b) {
                let acts = sb.on_frame(f, &b.store);
                route(acts, &mut to_a, &mut log_b, &mut b.store);
            }
            for f in std::mem::take(&mut to_a) {
                let acts = sa.on_frame(f, &a.store);
                route(acts, &mut to_b, &mut log_a, &mut a.store);
            }
        }
        (log_a, log_b)
    }

    #[test]
    fn frames_have_the_documented_json_shape() {
        let f = Frame {
            n: 3,
            body: Body::Bye {
                reason: ByeReason::Done,
            },
        };
        let json = String::from_utf8(f.encode().unwrap()).unwrap();
        assert_eq!(json, r#"{"n":3,"t":"Bye","reason":"Done"}"#);
        assert_eq!(Frame::decode(json.as_bytes()).unwrap(), f);
        let d = Frame {
            n: 1,
            body: Body::Direct(DirectMsg::RollbackNotice { held_seq: 7 }),
        };
        let json = String::from_utf8(d.encode().unwrap()).unwrap();
        assert_eq!(
            json,
            r#"{"n":1,"t":"Direct","kind":"RollbackNotice","payload":{"held_seq":7}}"#
        );
        assert_eq!(Frame::decode(json.as_bytes()).unwrap(), d);
        assert!(Frame::decode(&vec![b' '; MAX_FRAME_BYTES + 1]).is_err());
    }

    #[test]
    fn two_devices_converge_in_one_exchange() {
        let (mut g, mut b) = pair();
        for v in 0..20 {
            setting(&mut g, v);
        }
        let (la, lb) = exchange(&mut g, &mut b);
        assert!(la
            .iter()
            .chain(&lb)
            .any(|a| matches!(a, Action::Close(CloseReason::Done))));
        assert_eq!(b.store.vv(), g.store.vv());
        assert_eq!(b.store.state().expected(), g.store.state().expected());
        // Superseded writes travelled as dot hashes: the logs agree at every dot.
        for s in 1..=g.store.vv().get(&g.id) {
            assert_eq!(b.store.dot_hash(&g.id, s), g.store.dot_hash(&g.id, s));
        }
        // b now mints, and a second exchange brings g up to date.
        setting(&mut b, 99);
        exchange(&mut g, &mut b);
        assert_eq!(b.store.state().expected(), g.store.state().expected());
        assert_eq!(
            g.store.state().expected().settings["retention_days"],
            serde_json::json!(99)
        );
    }

    #[test]
    fn an_out_of_order_frame_aborts() {
        let (g, _b) = pair();
        let mut s = Session::new(Limits::default(), None);
        let _ = s.start(&g.store);
        let acts = s.on_frame(
            Frame {
                n: 1,
                body: Body::Bye {
                    reason: ByeReason::Done,
                },
            },
            &g.store,
        );
        assert!(acts
            .iter()
            .any(|a| matches!(a, Action::Close(CloseReason::Aborted("frame out of order")))));
        assert!(s.is_closed());
    }

    #[test]
    fn a_commit_that_does_not_match_the_items_aborts_and_applies_nothing() {
        let (mut g, b) = pair();
        setting(&mut g, 1);
        let mut peer = Session::new(Limits::default(), None);
        let hello = peer.start(&b.store);
        let mut s = Session::new(Limits::default(), None);
        let _ = s.start(&g.store);
        let Action::Send(h) = hello.into_iter().next().unwrap() else {
            panic!()
        };
        let _ = s.on_frame(h, &g.store);
        let acts = s.on_frame(
            Frame {
                n: 1,
                body: Body::Commit(Commit {
                    upto: VersionVector::new(),
                    count: 5,
                    batch_hash: Hash32::ZERO,
                }),
            },
            &g.store,
        );
        assert!(!acts.iter().any(|a| matches!(a, Action::Commit(_))));
        assert!(acts
            .iter()
            .any(|a| matches!(a, Action::Close(CloseReason::Aborted(_)))));
    }

    #[test]
    fn a_different_mesh_or_peer_is_refused_with_bye() {
        let (g, _b) = pair();
        let mut other = dev(
            5,
            Some(GenesisInfo {
                mesh_id: MeshId::from_bytes([8; 16]),
                genesis: DeviceId::from_bytes([5; 16]),
            }),
        );
        setting(&mut other, 1);
        let mut s = Session::new(Limits::default(), None);
        let _ = s.start(&g.store);
        let mut peer = Session::new(Limits::default(), None);
        let Action::Send(h) = peer.start(&other.store).into_iter().next().unwrap() else {
            panic!()
        };
        let acts = s.on_frame(h.clone(), &g.store);
        assert!(acts.iter().any(|a| matches!(
            a,
            Action::Send(Frame {
                body: Body::Bye {
                    reason: ByeReason::MeshMismatch
                },
                ..
            })
        )));
        let mut s = Session::new(Limits::default(), Some(DeviceId::from_bytes([7; 16])));
        let mut peer = Session::new(Limits::default(), None);
        let (g2, b2) = pair();
        let _ = s.start(&g2.store);
        let Action::Send(h) = peer.start(&b2.store).into_iter().next().unwrap() else {
            panic!()
        };
        let acts = s.on_frame(h, &g2.store);
        assert!(acts.iter().any(|a| matches!(
            a,
            Action::Send(Frame {
                body: Body::Bye {
                    reason: ByeReason::NotThePeer
                },
                ..
            })
        )));
    }

    #[test]
    fn a_dead_sender_leaves_nothing_half_applied() {
        let (mut g, b) = pair();
        for v in 0..5 {
            setting(&mut g, v);
        }
        let mut sg = Session::new(Limits::default(), None);
        let mut sb = Session::new(Limits::default(), None);
        let from_g = sg.start(&g.store);
        let _ = sb.start(&b.store);
        let Action::Send(hello_b) = sb_start_frame(&b) else {
            panic!()
        };
        let mut frames: Vec<Frame> = from_g
            .into_iter()
            .filter_map(|a| {
                if let Action::Send(f) = a {
                    Some(f)
                } else {
                    None
                }
            })
            .collect();
        frames.extend(sg.on_frame(hello_b, &g.store).into_iter().filter_map(|a| {
            if let Action::Send(f) = a {
                Some(f)
            } else {
                None
            }
        }));
        // Deliver everything except the final Commit: the sender "died".
        let before = b.store.vv().clone();
        for f in frames {
            if matches!(f.body, Body::Commit(_)) {
                break;
            }
            let acts = sb.on_frame(f, &b.store);
            assert!(!acts.iter().any(|a| matches!(a, Action::Commit(_))));
        }
        assert_eq!(b.store.vv(), &before, "no Commit, no VV movement");
    }

    fn sb_start_frame(b: &Dev) -> Action {
        Session::new(Limits::default(), None)
            .start(&b.store)
            .remove(0)
    }

    #[test]
    fn a_device_behind_its_own_history_gets_a_rollback_notice() {
        let (mut g, mut b) = pair();
        setting(&mut b, 1);
        setting(&mut b, 2);
        exchange(&mut g, &mut b);
        // b is restored from before those writes (a rollback).
        let genesis = b.store.genesis();
        let mut restored = dev(2, Some(genesis));
        let (la, _lb) = exchange(&mut restored, &mut g);
        assert!(la
            .iter()
            .any(|a| matches!(a, Action::Direct(DirectMsg::RollbackNotice { held_seq: 2 }))));
    }
}
