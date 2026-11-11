//! The canonical item-body codec (PROTOCOL.md §2).
//!
//! An item body is JSON with exactly one valid byte encoding:
//!
//! * the envelope's eight fields appear in the fixed order
//!   `v, mesh, origin, seq, hlc, kind, key, payload`;
//! * object keys inside `payload` are sorted by their UTF-8 bytes;
//! * no whitespace; integers only (no fractions, exponents or `-0`);
//! * strings escape only `"`, `\`, and control characters — `\b \f \n \r \t`
//!   in short form, the rest as `\u00xx` with lowercase hex — and carry every
//!   other character as literal UTF-8.
//!
//! [`decode_body`] re-encodes what it parsed and refuses any input that is
//! not byte-identical to that re-encoding. Every accepted body therefore has
//! one encoding, so a body's hash identifies its content, and a relay that
//! re-serialized a body would be caught. Relays never need to: items are
//! stored and forwarded as the exact bytes received.

use super::dot::{DeviceId, MeshId};
use super::error::MeshError;
use super::hlc::Hlc;
use serde::Deserialize;
use serde_json::Value;

/// The only item format this version understands.
pub const FORMAT_VERSION: u64 = 1;
/// Largest item on the wire: body plus signature.
pub const MAX_ITEM_BYTES: usize = 64 * 1024;
/// Ed25519 signature length.
pub const SIGNATURE_LEN: usize = 64;
/// Largest body, leaving room for the signature inside [`MAX_ITEM_BYTES`].
pub const MAX_BODY_BYTES: usize = MAX_ITEM_BYTES - SIGNATURE_LEN;
/// Longest `kind` string.
pub const MAX_KIND_BYTES: usize = 64;
/// Longest `key` string.
pub const MAX_KEY_BYTES: usize = 1024;
/// Largest `seq`: 2^63 − 1, so every accepted seq fits SQLite's signed 64-bit
/// INTEGER and keeps its order there (ADR 0031 R16). An origin reaches it
/// only after 2^63 items, so honest devices never come near it.
pub const MAX_SEQ: u64 = i64::MAX as u64;
/// Deepest nesting of arrays/objects inside `payload` (the payload object
/// itself is depth 1).
pub const MAX_PAYLOAD_DEPTH: usize = 16;

/// A decoded item body. Construct it freely; [`encode_body`] validates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemBody {
    pub v: u64,
    pub mesh: MeshId,
    pub origin: DeviceId,
    pub seq: u64,
    pub hlc: Hlc,
    pub kind: String,
    pub key: String,
    pub payload: Value,
}

impl ItemBody {
    /// A v1 body.
    pub fn new(
        mesh: MeshId,
        origin: DeviceId,
        seq: u64,
        hlc: Hlc,
        kind: impl Into<String>,
        key: impl Into<String>,
        payload: Value,
    ) -> Self {
        Self {
            v: FORMAT_VERSION,
            mesh,
            origin,
            seq,
            hlc,
            kind: kind.into(),
            key: key.into(),
            payload,
        }
    }

    pub fn dot(&self) -> super::dot::Dot {
        super::dot::Dot::new(self.origin, self.seq)
    }
}

/// `kind` is 1-64 bytes of `[a-z0-9._-]`.
pub fn is_valid_kind(kind: &str) -> bool {
    !kind.is_empty()
        && kind.len() <= MAX_KIND_BYTES
        && kind
            .bytes()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

/// `key` is 1-1024 bytes with no control characters.
pub fn is_valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= MAX_KEY_BYTES && !key.chars().any(char::is_control)
}

fn validate_envelope(body: &ItemBody) -> Result<(), MeshError> {
    if body.v != FORMAT_VERSION {
        return Err(MeshError::UnsupportedFormat(body.v));
    }
    if body.seq == 0 {
        return Err(MeshError::Malformed("seq must be at least 1"));
    }
    if body.seq > MAX_SEQ {
        return Err(MeshError::Malformed("seq must be at most 2^63 - 1"));
    }
    if !is_valid_kind(&body.kind) {
        return Err(MeshError::Malformed(
            "kind must be 1-64 bytes of lowercase letters, digits, '.', '_' or '-'",
        ));
    }
    if !is_valid_key(&body.key) {
        return Err(MeshError::Malformed(
            "key must be 1-1024 bytes without control characters",
        ));
    }
    if !body.payload.is_object() {
        return Err(MeshError::Malformed("payload must be a JSON object"));
    }
    Ok(())
}

/// Encode `body` canonically. Fails if a field is out of range, the payload
/// is not an object, holds a non-integer number or nests too deeply, or the
/// result exceeds [`MAX_BODY_BYTES`].
pub fn encode_body(body: &ItemBody) -> Result<Vec<u8>, MeshError> {
    validate_envelope(body)?;
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"{\"v\":");
    write_u64(&mut out, body.v);
    out.extend_from_slice(b",\"mesh\":");
    write_string(&mut out, &body.mesh.to_hex());
    out.extend_from_slice(b",\"origin\":");
    write_string(&mut out, &body.origin.to_hex());
    out.extend_from_slice(b",\"seq\":");
    write_u64(&mut out, body.seq);
    out.extend_from_slice(b",\"hlc\":");
    write_u64(&mut out, body.hlc.raw());
    out.extend_from_slice(b",\"kind\":");
    write_string(&mut out, &body.kind);
    out.extend_from_slice(b",\"key\":");
    write_string(&mut out, &body.key);
    out.extend_from_slice(b",\"payload\":");
    write_value(&mut out, &body.payload, 1)?;
    out.push(b'}');
    if out.len() > MAX_BODY_BYTES {
        return Err(MeshError::ItemTooLarge {
            size: out.len() + SIGNATURE_LEN,
            max: MAX_ITEM_BYTES,
        });
    }
    Ok(out)
}

/// The envelope as it appears on the wire. `deny_unknown_fields` makes an
/// extra envelope field an error rather than something silently dropped.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEnvelope {
    v: u64,
    mesh: String,
    origin: String,
    seq: u64,
    hlc: u64,
    kind: String,
    key: String,
    payload: Value,
}

/// Decode and validate a body. Enforces the size limit, the envelope shape,
/// identifier formats and canonical form. Does **not** check the signature or
/// the mesh id; see [`super::item::SignedItem::verify`].
pub fn decode_body(bytes: &[u8]) -> Result<ItemBody, MeshError> {
    if bytes.len() > MAX_BODY_BYTES {
        return Err(MeshError::ItemTooLarge {
            size: bytes.len() + SIGNATURE_LEN,
            max: MAX_ITEM_BYTES,
        });
    }
    // Two steps so a newer format reports itself as such instead of as a
    // parse error: read `v` first, then the strict v1 envelope.
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| MeshError::Malformed("body is not valid JSON"))?;
    let version = value
        .get("v")
        .and_then(Value::as_u64)
        .ok_or(MeshError::Malformed("body has no integer format version"))?;
    if version != FORMAT_VERSION {
        return Err(MeshError::UnsupportedFormat(version));
    }
    let wire: WireEnvelope = serde_json::from_value(value)
        .map_err(|_| MeshError::Malformed("body does not match the v1 envelope"))?;
    let body = ItemBody {
        v: wire.v,
        mesh: MeshId::parse(&wire.mesh)?,
        origin: DeviceId::parse(&wire.origin)?,
        seq: wire.seq,
        hlc: Hlc::from_raw(wire.hlc),
        kind: wire.kind,
        key: wire.key,
        payload: wire.payload,
    };
    if encode_body(&body)? != bytes {
        return Err(MeshError::NonCanonical);
    }
    Ok(body)
}

fn write_u64(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(n.to_string().as_bytes());
}

fn write_string(out: &mut Vec<u8>, s: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0C}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                let b = c as u8;
                out.extend_from_slice(b"\\u00");
                out.push(HEX[usize::from(b >> 4)]);
                out.push(HEX[usize::from(b & 0x0f)]);
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn write_value(out: &mut Vec<u8>, v: &Value, depth: usize) -> Result<(), MeshError> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                write_u64(out, u);
            } else if let Some(i) = n.as_i64() {
                out.extend_from_slice(i.to_string().as_bytes());
            } else {
                return Err(MeshError::Malformed("payload numbers must be integers"));
            }
        }
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            check_depth(depth)?;
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(out, item, depth + 1)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            check_depth(depth)?;
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_unstable_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push(b'{');
            for (i, (k, val)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(out, k);
                out.push(b':');
                write_value(out, val, depth + 1)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn check_depth(depth: usize) -> Result<(), MeshError> {
    if depth > MAX_PAYLOAD_DEPTH {
        Err(MeshError::Malformed("payload nests too deeply"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::sim::rng::SplitMix64;
    use serde_json::{json, Map};

    fn mesh() -> MeshId {
        MeshId::from_bytes([0x11; 16])
    }
    fn origin() -> DeviceId {
        DeviceId::from_bytes([0x22; 16])
    }

    fn sample() -> ItemBody {
        ItemBody::new(
            mesh(),
            origin(),
            7,
            Hlc::new(1_700_000_000_000, 3),
            "project.meta",
            "0123456789abcdef0123456789abcdef",
            json!({"name": "Billing API", "archived": false, "merged_into": null}),
        )
    }

    #[test]
    fn exact_bytes_of_a_sample_body() {
        let bytes = encode_body(&sample()).unwrap();
        let hlc = Hlc::new(1_700_000_000_000, 3).raw();
        let expected = format!(
            "{{\"v\":1,\"mesh\":\"{}\",\"origin\":\"{}\",\"seq\":7,\"hlc\":{hlc},\
             \"kind\":\"project.meta\",\"key\":\"0123456789abcdef0123456789abcdef\",\
             \"payload\":{{\"archived\":false,\"merged_into\":null,\"name\":\"Billing API\"}}}}",
            "11".repeat(16),
            "22".repeat(16),
        );
        assert_eq!(String::from_utf8(bytes).unwrap(), expected);
    }

    #[test]
    fn round_trip() {
        let b = sample();
        let bytes = encode_body(&b).unwrap();
        assert_eq!(decode_body(&bytes).unwrap(), b);
    }

    #[test]
    fn string_escaping_is_canonical() {
        let mut b = sample();
        b.payload = json!({"s": "q\"b\\s/\u{08}\u{0C}\n\r\t\u{01}\u{1f}\u{7f}é€😀"});
        let bytes = encode_body(&b).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.contains(r#""s":"q\"b\\s/\b\f\n\r\t\u0001\u001f"#));
        assert!(
            text.contains("\u{7f}é€😀\""),
            "non-control characters stay literal"
        );
        assert_eq!(decode_body(&bytes).unwrap(), b);
    }

    #[test]
    fn non_canonical_encodings_are_refused() {
        let canonical = String::from_utf8(encode_body(&sample()).unwrap()).unwrap();
        let variants = [
            canonical.replace("\"seq\":7", "\"seq\": 7"),
            format!(" {canonical}"),
            canonical.replace("Billing API", "Billing\\u0020API"),
            canonical.replace(
                "\"archived\":false,\"merged_into\":null",
                "\"merged_into\":null,\"archived\":false",
            ),
            canonical.replace("\"v\":1,\"mesh\"", "\"mesh\""),
        ];
        for v in &variants {
            assert!(decode_body(v.as_bytes()).is_err(), "accepted: {v}");
        }
        // Reordered envelope fields (valid JSON, same content) are refused.
        let reordered = canonical
            .replacen("{\"v\":1,", "{", 1)
            .replacen("}}", "},\"v\":1}", 1);
        assert_eq!(
            decode_body(reordered.as_bytes()),
            Err(MeshError::NonCanonical)
        );
    }

    #[test]
    fn duplicate_payload_keys_are_refused() {
        let canonical = String::from_utf8(encode_body(&sample()).unwrap()).unwrap();
        let dup = canonical.replace(
            "\"archived\":false,",
            "\"archived\":true,\"archived\":false,",
        );
        assert!(decode_body(dup.as_bytes()).is_err());
    }

    #[test]
    fn floats_and_negative_zero_are_refused() {
        let mut b = sample();
        b.payload = json!({"x": 1.5});
        assert_eq!(
            encode_body(&b),
            Err(MeshError::Malformed("payload numbers must be integers"))
        );
        let canonical = String::from_utf8(encode_body(&sample()).unwrap()).unwrap();
        for bad in ["\"seq\":7.0", "\"seq\":7e0", "\"seq\":-0"] {
            let v = canonical.replace("\"seq\":7", bad);
            assert!(decode_body(v.as_bytes()).is_err(), "accepted {bad}");
        }
        let neg = canonical.replace("\"archived\":false", "\"archived\":-0");
        assert!(decode_body(neg.as_bytes()).is_err());
    }

    #[test]
    fn negative_integers_round_trip() {
        let mut b = sample();
        b.payload = json!({"a": -5, "b": i64::MIN, "c": u64::MAX});
        let bytes = encode_body(&b).unwrap();
        assert_eq!(decode_body(&bytes).unwrap(), b);
    }

    #[test]
    fn unknown_envelope_field_is_refused() {
        let canonical = String::from_utf8(encode_body(&sample()).unwrap()).unwrap();
        let extra = canonical.replacen(",\"payload\":", ",\"extra\":1,\"payload\":", 1);
        assert_eq!(
            decode_body(extra.as_bytes()),
            Err(MeshError::Malformed("body does not match the v1 envelope"))
        );
    }

    #[test]
    fn newer_format_reports_itself() {
        let canonical = String::from_utf8(encode_body(&sample()).unwrap()).unwrap();
        let v2 = canonical.replacen("{\"v\":1,", "{\"v\":2,", 1);
        assert_eq!(
            decode_body(v2.as_bytes()),
            Err(MeshError::UnsupportedFormat(2))
        );
        let mut b = sample();
        b.v = 2;
        assert_eq!(encode_body(&b), Err(MeshError::UnsupportedFormat(2)));
    }

    #[test]
    fn envelope_field_validation() {
        let mut b = sample();
        b.seq = 0;
        assert!(encode_body(&b).is_err());
        let mut b = sample();
        b.seq = MAX_SEQ;
        let at_max = encode_body(&b).unwrap();
        assert_eq!(decode_body(&at_max).unwrap().seq, MAX_SEQ);
        b.seq = MAX_SEQ + 1;
        assert!(encode_body(&b).is_err());
        let above = String::from_utf8(at_max)
            .unwrap()
            .replace(&MAX_SEQ.to_string(), &(MAX_SEQ + 1).to_string());
        assert!(decode_body(above.as_bytes()).is_err());
        let mut b = sample();
        b.kind = "Roster.Add".into();
        assert!(encode_body(&b).is_err());
        let mut b = sample();
        b.kind = "k".repeat(65);
        assert!(encode_body(&b).is_err());
        let mut b = sample();
        b.key = String::new();
        assert!(encode_body(&b).is_err());
        let mut b = sample();
        b.key = "a\nb".into();
        assert!(encode_body(&b).is_err());
        let mut b = sample();
        b.key = "k".repeat(1025);
        assert!(encode_body(&b).is_err());
        let mut b = sample();
        b.payload = json!([1, 2]);
        assert!(encode_body(&b).is_err());
        let canonical = String::from_utf8(encode_body(&sample()).unwrap()).unwrap();
        let bad_id = canonical.replace(&"22".repeat(16), &"2G".repeat(16));
        assert_eq!(decode_body(bad_id.as_bytes()), Err(MeshError::InvalidId));
        let upper = canonical.replace(&"11".repeat(16), &"AA".repeat(16));
        assert_eq!(decode_body(upper.as_bytes()), Err(MeshError::InvalidId));
    }

    #[test]
    fn depth_limit() {
        let mut v = json!(1);
        for _ in 0..MAX_PAYLOAD_DEPTH {
            v = json!([v]);
        }
        let mut b = sample();
        b.payload = json!({ "deep": v });
        assert_eq!(
            encode_body(&b),
            Err(MeshError::Malformed("payload nests too deeply"))
        );
        let mut ok = json!(1);
        for _ in 0..MAX_PAYLOAD_DEPTH - 1 {
            ok = json!([ok]);
        }
        b.payload = json!({ "deep": ok });
        assert!(encode_body(&b).is_ok());
    }

    #[test]
    fn oversize_is_refused_both_ways() {
        let mut b = sample();
        b.payload = json!({"blob": "x".repeat(MAX_BODY_BYTES)});
        assert!(matches!(
            encode_body(&b),
            Err(MeshError::ItemTooLarge {
                max: MAX_ITEM_BYTES,
                ..
            })
        ));
        let big = vec![b' '; MAX_BODY_BYTES + 1];
        assert!(matches!(
            decode_body(&big),
            Err(MeshError::ItemTooLarge { .. })
        ));
        // Exactly at the limit is fine.
        let base = encode_body(&sample()).unwrap().len();
        let mut b = sample();
        let pad = MAX_BODY_BYTES - base - "\"pad\":\"\",".len();
        let mut obj = b.payload.as_object().unwrap().clone();
        obj.insert("pad".into(), Value::String("p".repeat(pad)));
        b.payload = Value::Object(obj);
        let bytes = encode_body(&b).unwrap();
        assert_eq!(bytes.len(), MAX_BODY_BYTES);
        assert_eq!(decode_body(&bytes).unwrap(), b);
    }

    fn random_string(rng: &mut SplitMix64) -> String {
        const ALPHABET: &[char] = &[
            'a', 'b', 'z', 'A', '0', '9', '_', '/', ' ', '"', '\\', '\n', '\t', '\u{0}', '\u{1b}',
            '\u{7f}', 'é', '€', '😀', '{', ':', ',',
        ];
        (0..rng.below(12))
            .map(|_| *rng.choose(ALPHABET).unwrap())
            .collect()
    }

    /// A random JSON value, nested at most a few levels deep.
    fn random_value(rng: &mut SplitMix64, depth: usize) -> Value {
        match rng.below(if depth >= 3 { 4 } else { 6 }) {
            0 => Value::Null,
            1 => Value::Bool(rng.bool()),
            2 => {
                if rng.bool() {
                    json!(rng.next_u64())
                } else {
                    json!(-(rng.below(1 << 62) as i64))
                }
            }
            3 => Value::String(random_string(rng)),
            4 => Value::Array(
                (0..rng.below(4))
                    .map(|_| random_value(rng, depth + 1))
                    .collect(),
            ),
            _ => Value::Object(random_object(rng, depth + 1)),
        }
    }

    fn random_object(rng: &mut SplitMix64, depth: usize) -> Map<String, Value> {
        (0..rng.below(5))
            .map(|_| (random_string(rng), random_value(rng, depth)))
            .collect()
    }

    /// Rebuild an object with every map's keys inserted in reverse order.
    fn reinsert_reversed(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut entries: Vec<_> = m.iter().collect();
                entries.reverse();
                Value::Object(
                    entries
                        .into_iter()
                        .map(|(k, v)| (k.clone(), reinsert_reversed(v)))
                        .collect(),
                )
            }
            Value::Array(a) => Value::Array(a.iter().map(reinsert_reversed).collect()),
            other => other.clone(),
        }
    }

    #[test]
    fn encoding_is_deterministic_over_10k_random_bodies() {
        let seed = 0xC0DEC;
        let mut rng = SplitMix64::new(seed);
        for case in 0..10_000 {
            let mut kind = String::from("k");
            for _ in 0..rng.below(8) {
                kind.push(*rng.choose(&['a', 'z', '0', '.', '_', '-']).unwrap());
            }
            let key = format!("key/{}", rng.next_u64());
            let body = ItemBody::new(
                MeshId::from_bytes(rng.next_u64().to_le_bytes().repeat(2).try_into().unwrap()),
                DeviceId::from_bytes(rng.next_u64().to_be_bytes().repeat(2).try_into().unwrap()),
                rng.range_inclusive(1, MAX_SEQ),
                Hlc::from_raw(rng.next_u64()),
                kind,
                key,
                Value::Object(random_object(&mut rng, 1)),
            );
            let first = encode_body(&body).unwrap();
            let second = encode_body(&body).unwrap();
            assert_eq!(first, second, "MESH_SIM_SEED={seed} case {case}");
            let rebuilt = ItemBody {
                payload: reinsert_reversed(&body.payload),
                ..body.clone()
            };
            assert_eq!(
                encode_body(&rebuilt).unwrap(),
                first,
                "MESH_SIM_SEED={seed} case {case}: insertion order changed the bytes"
            );
            assert_eq!(
                decode_body(&first).unwrap(),
                body,
                "MESH_SIM_SEED={seed} case {case}: round trip"
            );
        }
    }
}
