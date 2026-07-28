//! Destination policy — the proxy's defence against becoming a local SSRF tool.
//!
//! Every CONNECT / absolute-form target passes through here TWICE: once on the
//! literal authority the client asked for (`check_authority`), and once on each
//! address DNS resolves it to (`classify_ip`). Because the proxy then dials the
//! *validated `SocketAddr`* — never re-resolving the name — there is no
//! window for DNS rebinding: the address we connect to is the address that
//! passed the check.
//!
//! The default policy denies loopback, RFC1918/private, link-local, CGNAT,
//! multicast, broadcast, unspecified, reserved/benchmarking/documentation
//! ranges, IPv4-mapped IPv6 wrappers of any of those, cloud-metadata names and
//! addresses, non-web ports, and malformed hostnames. Teams monitoring their
//! own internal APIs can add explicit `(host, port)` entries to an
//! [`AllowList`], which bypass the private-range denial for exactly those
//! destinations (and are surfaced with a warning elsewhere).
//!
//! Addresses are classified by VALUE, not by spelling: the IPv4 shorthand
//! forms `inet_aton` accepts (`127.1`, `0x7f.0.0.1`, `0177.0.0.1`,
//! `2130706433`) are canonicalised before classification, because the
//! resolver every SDK ends up in accepts them too. Treating them as ordinary
//! hostnames let loopback be described to the user as public (RA-011).
//!
//! Note: several range predicates (CGNAT `100.64/10`, reserved `240/4`,
//! benchmarking `198.18/15`, IPv6 unique-local/link-local) are implemented by
//! hand because the corresponding `std::net` predicates are unstable on the
//! pinned toolchain. They are covered by unit tests.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why a destination was denied. Machine-readable; the string form is safe to
/// show a user and carries no attacker-controlled data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    Loopback,
    Private,
    LinkLocal,
    Cgnat,
    Multicast,
    Broadcast,
    Unspecified,
    Reserved,
    Documentation,
    CloudMetadata,
    BadHostname,
    BadPort,
}

impl DenyReason {
    pub fn as_str(self) -> &'static str {
        match self {
            DenyReason::Loopback => "loopback address blocked",
            DenyReason::Private => "private/RFC1918 address blocked",
            DenyReason::LinkLocal => "link-local address blocked",
            DenyReason::Cgnat => "carrier-grade NAT address blocked",
            DenyReason::Multicast => "multicast address blocked",
            DenyReason::Broadcast => "broadcast address blocked",
            DenyReason::Unspecified => "unspecified address blocked",
            DenyReason::Reserved => "reserved address range blocked",
            DenyReason::Documentation => "documentation/test address blocked",
            DenyReason::CloudMetadata => "cloud metadata endpoint blocked",
            DenyReason::BadHostname => "invalid or unsupported hostname",
            DenyReason::BadPort => "port not allowed (only 80/443 unless allowlisted)",
        }
    }
}

/// The result of a policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny(DenyReason),
}

impl Verdict {
    pub fn is_allowed(self) -> bool {
        matches!(self, Verdict::Allow)
    }
}

/// Explicit per-project allowlist of internal `(host, port)` destinations that
/// bypass the private-range denial. Hostnames are compared case-insensitively.
#[derive(Debug, Clone, Default)]
pub struct AllowList {
    entries: HashSet<(String, u16)>,
}

impl AllowList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, host: &str, port: u16) {
        self.entries.insert((host.to_ascii_lowercase(), port));
    }

    pub fn from_pairs<I: IntoIterator<Item = (String, u16)>>(pairs: I) -> Self {
        let mut a = Self::new();
        for (h, p) in pairs {
            a.insert(&h, p);
        }
        a
    }

    pub fn contains(&self, host: &str, port: u16) -> bool {
        self.entries.contains(&(host.to_ascii_lowercase(), port))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Ports the proxy will connect to by default. Anything else must be
/// explicitly allowlisted.
pub const DEFAULT_ALLOWED_PORTS: &[u16] = &[80, 443];

/// Cloud-metadata hostnames that must never be reachable, independent of what
/// they resolve to.
const METADATA_HOSTS: &[&str] = &[
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
    "instance-data.ec2.internal",
];

/// Validate the literal authority the client asked to reach, before DNS.
///
/// - The port must be 80/443 or explicitly allowlisted for this host.
/// - A cloud-metadata hostname is denied outright.
/// - An IP literal is classified immediately (unless allowlisted).
/// - A DNS name is validated for syntax; its addresses are checked after
///   resolution via [`classify_ip`].
pub fn check_authority(host: &str, port: u16, allow: &AllowList) -> Verdict {
    // Normalize ONCE: trim, lowercase, and strip trailing FQDN dot(s). Every
    // downstream check uses this normalized form so the metadata-name, single-
    // label, `.local`, and allowlist tests cannot be desynchronized from
    // is_valid_hostname (which also strips the dot). Without this, a single
    // trailing dot flips an intended Deny to Allow — e.g. `metadata.google.
    // internal.` skips the metadata blocklist, and `intranet.` (contains a dot)
    // dodges the single-label guard.
    let host_l = host.trim().to_ascii_lowercase();
    let host_l = host_l.trim_end_matches('.').to_string();
    if host_l.is_empty() {
        return Verdict::Deny(DenyReason::BadHostname);
    }

    // Port policy first.
    if !DEFAULT_ALLOWED_PORTS.contains(&port) && !allow.contains(&host_l, port) {
        return Verdict::Deny(DenyReason::BadPort);
    }

    // Metadata names are always denied — even if (mis)allowlisted, deny to be
    // safe: the allowlist is for a team's own internal APIs, never metadata.
    if METADATA_HOSTS.contains(&host_l.as_str()) {
        return Verdict::Deny(DenyReason::CloudMetadata);
    }

    let allowlisted = allow.contains(&host_l, port);

    // IP literal? classify now (unwrapping IPv4-mapped IPv6 and brackets).
    match parse_ip_literal(&host_l) {
        Some(IpLiteral::Canonical(ip)) => {
            if allowlisted {
                return Verdict::Allow;
            }
            return classify_ip(ip);
        }
        Some(IpLiteral::Shorthand(v4)) => {
            if allowlisted {
                return Verdict::Allow;
            }
            let verdict = classify_v4(v4);
            if !verdict.is_allowed() {
                return verdict;
            }
            // A shorthand that canonicalises to a PUBLIC address deliberately
            // falls through to the hostname path below instead of returning
            // this Allow. Teaching the parser more spellings must only ever
            // TIGHTEN the policy: `134744072` is 8.8.8.8, and returning Allow
            // here would hand a bare integer the pass that the single-label
            // guard denies `localhost`. Restricted shorthands are denied
            // above; public-looking ones keep the verdict they already had.
        }
        None => {}
    }

    // Otherwise it's a DNS name — validate syntax; the resolved addresses are
    // checked separately. `.local` (mDNS) is treated as internal and denied
    // unless allowlisted.
    if !is_valid_hostname(&host_l) {
        return Verdict::Deny(DenyReason::BadHostname);
    }
    if (host_l.ends_with(".local") || !host_l.contains('.')) && !allowlisted {
        // single-label names and mDNS names are internal; require allowlisting.
        return Verdict::Deny(DenyReason::Private);
    }
    Verdict::Allow
}

/// Classify a resolved IP address. `allowlisted` skips the private-range denial
/// (the caller passes the allowlist decision made for the original host).
pub fn check_resolved(addr: IpAddr, allowlisted: bool) -> Verdict {
    if allowlisted {
        return Verdict::Allow;
    }
    classify_ip(addr)
}

/// The core address classifier. Denies every non-public range.
pub fn classify_ip(addr: IpAddr) -> Verdict {
    match addr {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => {
            // Unwrap IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible so a
            // wrapped private v4 cannot slip through the v6 path.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify_v4(v4);
            }
            classify_v6(v6)
        }
    }
}

fn classify_v4(ip: Ipv4Addr) -> Verdict {
    let o = ip.octets();
    if ip.is_unspecified() {
        return Verdict::Deny(DenyReason::Unspecified);
    }
    if ip.is_loopback() {
        return Verdict::Deny(DenyReason::Loopback);
    }
    if ip.is_broadcast() {
        return Verdict::Deny(DenyReason::Broadcast);
    }
    if ip.is_private() {
        return Verdict::Deny(DenyReason::Private);
    }
    if ip.is_link_local() {
        // 169.254/16 — also covers the 169.254.169.254 metadata address.
        return Verdict::Deny(DenyReason::LinkLocal);
    }
    if ip.is_multicast() {
        return Verdict::Deny(DenyReason::Multicast);
    }
    if ip.is_documentation() {
        // 192.0.2/24, 198.51.100/24, 203.0.113/24
        return Verdict::Deny(DenyReason::Documentation);
    }
    // 0.0.0.0/8 "this network"
    if o[0] == 0 {
        return Verdict::Deny(DenyReason::Unspecified);
    }
    // 100.64.0.0/10 carrier-grade NAT (also covers 100.100.100.200 Alibaba md)
    if o[0] == 100 && (64..=127).contains(&o[1]) {
        return Verdict::Deny(DenyReason::Cgnat);
    }
    // 192.0.0.0/24 IETF protocol assignments (incl. 192.0.0.170/.171 NAT64
    // discovery) — not a routable destination.
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return Verdict::Deny(DenyReason::Reserved);
    }
    // 198.18.0.0/15 benchmarking
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return Verdict::Deny(DenyReason::Reserved);
    }
    // 240.0.0.0/4 reserved (excludes 255.255.255.255 already handled)
    if o[0] >= 240 {
        return Verdict::Deny(DenyReason::Reserved);
    }
    Verdict::Allow
}

fn classify_v6(ip: Ipv6Addr) -> Verdict {
    let s = ip.segments();
    if ip.is_unspecified() {
        return Verdict::Deny(DenyReason::Unspecified);
    }
    if ip.is_loopback() {
        return Verdict::Deny(DenyReason::Loopback);
    }
    if ip.is_multicast() {
        return Verdict::Deny(DenyReason::Multicast);
    }
    // fc00::/7 unique local (covers fd00:ec2::254 AWS IPv6 metadata)
    if (s[0] & 0xfe00) == 0xfc00 {
        return Verdict::Deny(DenyReason::Private);
    }
    // fe80::/10 link-local
    if (s[0] & 0xffc0) == 0xfe80 {
        return Verdict::Deny(DenyReason::LinkLocal);
    }
    // 2001:db8::/32 documentation
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return Verdict::Deny(DenyReason::Documentation);
    }
    // ::/96 IPv4-compatible (deprecated) — treat embedded v4
    if s[..6].iter().all(|&x| x == 0) && !(s[6] == 0 && s[7] == 0) {
        return classify_v4(embedded_v4(s[6], s[7]));
    }
    // NAT64: the well-known prefix 64:ff9b::/96 and the RFC 8215 local-use
    // prefix 64:ff9b:1::/48 both live in the 64:ff9b::/32 allocation and embed an
    // IPv4 in the low 32 bits (for the common `::`-filled literal form). On a
    // host with a NAT64/CLAT translator this would otherwise be an SSRF path to
    // the embedded address (e.g. 64:ff9b::7f00:1 or 64:ff9b:1::7f00:1 ->
    // 127.0.0.1). Match the whole /32 and decode the low 32 bits; a non-embedded
    // low half classifies to 0.0.0.0/8 and is denied anyway (fail-safe).
    if s[0] == 0x0064 && s[1] == 0xff9b {
        return classify_v4(embedded_v4(s[6], s[7]));
    }
    // 6to4 2002::/16 embeds the IPv4 gateway in segments [1..3].
    if s[0] == 0x2002 {
        return classify_v4(embedded_v4(s[1], s[2]));
    }
    Verdict::Allow
}

/// Decode two IPv6 segments into the embedded IPv4 address they carry.
fn embedded_v4(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::new(
        (hi >> 8) as u8,
        (hi & 0xff) as u8,
        (lo >> 8) as u8,
        (lo & 0xff) as u8,
    )
}

/// How an authority string spelled an IP address.
enum IpLiteral {
    /// The canonical, unambiguous spelling: four-dotted-decimal IPv4, or
    /// IPv6 (optionally bracketed). What `IpAddr::from_str` accepts.
    Canonical(IpAddr),
    /// An IPv4 SHORTHAND — `127.1`, `0x7f.0.0.1`, `0177.0.0.1`,
    /// `2130706433`. `IpAddr::from_str` rejects all of these; `inet_aton`
    /// (and therefore `getaddrinfo`, and therefore every SDK) accepts them
    /// and reaches the address carried here.
    Shorthand(Ipv4Addr),
}

/// Parse an IP literal, accepting bracketed IPv6 (`[::1]`) and the IPv4
/// shorthand spellings the platform resolver also accepts.
///
/// The strict `IpAddr::from_str` parse alone meant `127.1`, `0x7f.0.0.1`,
/// `0177.0.0.1` and `2130706433` were not recognised as addresses at all:
/// they fell through to [`is_valid_hostname`], were accepted as ordinary DNS
/// names, and a committed `SUPABASE_URL=https://127.1` was therefore
/// DISCLOSED to the user as "a public internet address" (RA-011). No
/// credential ever reached loopback — the gateway resolves and re-checks
/// every address before dialing — but the consent surface told the user the
/// opposite of the truth about what they were approving.
///
/// The two cases are kept apart because widening this parser changes which
/// hosts [`check_authority`] denies BEFORE DNS, and that must only ever
/// tighten. See the `Shorthand` arm there.
fn parse_ip_literal(host: &str) -> Option<IpLiteral> {
    let trimmed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(IpLiteral::Canonical(ip));
    }
    parse_ipv4_shorthand(trimmed).map(IpLiteral::Shorthand)
}

/// Canonicalise the `inet_aton` IPv4 forms: 1..=4 parts, each decimal,
/// octal (`0…`) or hexadecimal (`0x…`), where the LAST part fills all the
/// octets the leading parts did not.
///
/// Returns `None` for anything `inet_aton` itself would reject (an empty or
/// non-numeric part, a leading part above 255, a trailing part too wide for
/// the octets it must fill, more than four parts), so ordinary hostnames
/// stay hostnames.
fn parse_ipv4_shorthand(host: &str) -> Option<Ipv4Addr> {
    let mut values: Vec<u32> = Vec::with_capacity(4);
    for part in host.split('.') {
        if values.len() == 4 {
            return None;
        }
        values.push(parse_inet_part(part)?);
    }
    let tail = values.pop()?;
    // Every leading part is exactly one octet…
    if values.iter().any(|&v| v > 0xff) {
        return None;
    }
    // …and the last part fills the rest, so `127.1` is 127.0.0.1 and
    // `2130706433` is the whole address.
    let filled = 4 - values.len();
    let max = if filled == 4 {
        u32::MAX
    } else {
        (1u32 << (8 * filled)) - 1
    };
    if tail > max {
        return None;
    }
    let mut addr = tail;
    for (i, v) in values.iter().enumerate() {
        addr |= v << (8 * (3 - i));
    }
    Some(Ipv4Addr::from(addr))
}

/// One `inet_aton` part: `0x`/`0X` prefixed hexadecimal, `0` prefixed octal,
/// otherwise decimal. Rejects an empty part and any digit outside the radix
/// (so `08.0.0.1` and `0x1g.0.0.1` are names, not addresses — exactly as
/// `inet_aton` treats them).
fn parse_inet_part(part: &str) -> Option<u32> {
    let (radix, digits) = match part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        Some(hex) => (16u32, hex),
        None if part.len() > 1 && part.starts_with('0') => (8, &part[1..]),
        None => (10, part),
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    u32::from_str_radix(digits, radix).ok()
}

/// RFC-1123-ish hostname validation: 1..=253 bytes, labels 1..=63 bytes of
/// `[A-Za-z0-9-]` not starting/ending with `-`, no empty labels.
fn is_valid_hostname(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host); // tolerate FQDN dot
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_addresses_are_allowed() {
        for a in ["1.1.1.1", "8.8.8.8", "140.82.121.4", "2606:4700:4700::1111"] {
            assert_eq!(classify_ip(ip(a)), Verdict::Allow, "{a}");
        }
    }

    #[test]
    fn loopback_and_private_denied() {
        assert_eq!(
            classify_ip(ip("127.0.0.1")),
            Verdict::Deny(DenyReason::Loopback)
        );
        assert_eq!(classify_ip(ip("::1")), Verdict::Deny(DenyReason::Loopback));
        assert_eq!(
            classify_ip(ip("10.0.0.5")),
            Verdict::Deny(DenyReason::Private)
        );
        assert_eq!(
            classify_ip(ip("172.16.0.1")),
            Verdict::Deny(DenyReason::Private)
        );
        assert_eq!(
            classify_ip(ip("192.168.1.1")),
            Verdict::Deny(DenyReason::Private)
        );
        assert_eq!(
            classify_ip(ip("fd00::1")),
            Verdict::Deny(DenyReason::Private)
        );
    }

    #[test]
    fn cloud_metadata_addresses_denied() {
        // 169.254.169.254 is link-local; fd00:ec2::254 is unique-local; both
        // land in a deny bucket regardless of the metadata name.
        assert!(!classify_ip(ip("169.254.169.254")).is_allowed());
        assert!(!classify_ip(ip("fd00:ec2::254")).is_allowed());
        assert_eq!(
            classify_ip(ip("100.100.100.200")),
            Verdict::Deny(DenyReason::Cgnat)
        );
    }

    #[test]
    fn special_ranges_denied() {
        assert_eq!(
            classify_ip(ip("169.254.1.1")),
            Verdict::Deny(DenyReason::LinkLocal)
        );
        assert_eq!(
            classify_ip(ip("100.64.0.1")),
            Verdict::Deny(DenyReason::Cgnat)
        );
        assert_eq!(
            classify_ip(ip("224.0.0.1")),
            Verdict::Deny(DenyReason::Multicast)
        );
        assert_eq!(
            classify_ip(ip("255.255.255.255")),
            Verdict::Deny(DenyReason::Broadcast)
        );
        assert_eq!(
            classify_ip(ip("0.0.0.0")),
            Verdict::Deny(DenyReason::Unspecified)
        );
        assert_eq!(
            classify_ip(ip("240.0.0.1")),
            Verdict::Deny(DenyReason::Reserved)
        );
        assert_eq!(
            classify_ip(ip("198.18.0.1")),
            Verdict::Deny(DenyReason::Reserved)
        );
        assert_eq!(
            classify_ip(ip("192.0.2.1")),
            Verdict::Deny(DenyReason::Documentation)
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_is_unwrapped_before_checking() {
        // ::ffff:127.0.0.1 must be caught as loopback, not allowed as v6.
        assert_eq!(
            classify_ip(ip("::ffff:127.0.0.1")),
            Verdict::Deny(DenyReason::Loopback)
        );
        assert_eq!(
            classify_ip(ip("::ffff:10.0.0.1")),
            Verdict::Deny(DenyReason::Private)
        );
    }

    #[test]
    fn authority_checks_port_and_metadata_and_literals() {
        let allow = AllowList::new();
        assert_eq!(
            check_authority("api.openai.com", 443, &allow),
            Verdict::Allow
        );
        assert_eq!(
            check_authority("api.openai.com", 80, &allow),
            Verdict::Allow
        );
        assert_eq!(
            check_authority("api.openai.com", 8080, &allow),
            Verdict::Deny(DenyReason::BadPort)
        );
        assert_eq!(
            check_authority("metadata.google.internal", 80, &allow),
            Verdict::Deny(DenyReason::CloudMetadata)
        );
        assert_eq!(
            check_authority("127.0.0.1", 443, &allow),
            Verdict::Deny(DenyReason::Loopback)
        );
        assert_eq!(
            check_authority("[::1]", 443, &allow),
            Verdict::Deny(DenyReason::Loopback)
        );
    }

    #[test]
    fn single_label_and_mdns_names_are_internal() {
        let allow = AllowList::new();
        assert_eq!(
            check_authority("localhost", 80, &allow),
            Verdict::Deny(DenyReason::Private)
        );
        assert_eq!(
            check_authority("printer.local", 80, &allow),
            Verdict::Deny(DenyReason::Private)
        );
    }

    #[test]
    fn trailing_dot_does_not_bypass_metadata_or_single_label_guards() {
        let allow = AllowList::new();
        // FQDN trailing dot must not skip the metadata blocklist.
        assert_eq!(
            check_authority("metadata.google.internal.", 80, &allow),
            Verdict::Deny(DenyReason::CloudMetadata)
        );
        assert_eq!(
            check_authority("metadata.google.internal..", 80, &allow),
            Verdict::Deny(DenyReason::CloudMetadata)
        );
        // FQDN trailing dot must not flip a single-label internal name to Allow.
        assert_eq!(
            check_authority("intranet.", 80, &allow),
            Verdict::Deny(DenyReason::Private)
        );
        assert_eq!(
            check_authority("printer.local.", 80, &allow),
            Verdict::Deny(DenyReason::Private)
        );
        // A normal FQDN with a trailing dot is still allowed.
        assert_eq!(
            check_authority("api.openai.com.", 443, &allow),
            Verdict::Allow
        );
    }

    #[test]
    fn ipv6_transition_prefixes_decode_embedded_ipv4() {
        // NAT64 64:ff9b::/96 embedding 127.0.0.1 must be denied as loopback.
        assert_eq!(
            classify_ip(ip("64:ff9b::7f00:1")),
            Verdict::Deny(DenyReason::Loopback)
        );
        // NAT64 embedding 10.0.0.5 (private).
        assert_eq!(
            classify_ip(ip("64:ff9b::a00:5")),
            Verdict::Deny(DenyReason::Private)
        );
        // 6to4 2002::/16 embedding 127.0.0.1 (2002:7f00:1::) -> loopback.
        assert_eq!(
            classify_ip(ip("2002:7f00:1::")),
            Verdict::Deny(DenyReason::Loopback)
        );
        // NAT64 embedding a genuinely public address stays allowed.
        assert_eq!(classify_ip(ip("64:ff9b::808:808")), Verdict::Allow);
        // RFC 8215 local-use NAT64 prefix 64:ff9b:1::/48 embedding 127.0.0.1.
        assert_eq!(
            classify_ip(ip("64:ff9b:1::7f00:1")),
            Verdict::Deny(DenyReason::Loopback)
        );
    }

    #[test]
    fn ietf_protocol_assignments_block_denied() {
        // 192.0.0.0/24 (incl NAT64 discovery 192.0.0.170).
        assert_eq!(
            classify_ip(ip("192.0.0.170")),
            Verdict::Deny(DenyReason::Reserved)
        );
        // 192.0.2.0/24 documentation is a different range, still denied.
        assert_eq!(
            classify_ip(ip("192.0.2.1")),
            Verdict::Deny(DenyReason::Documentation)
        );
        // A normal 192.x public-ish address outside these /24s is allowed.
        assert_eq!(classify_ip(ip("192.5.6.7")), Verdict::Allow);
    }

    #[test]
    fn allowlist_bypasses_private_denial_for_exact_pair() {
        let mut allow = AllowList::new();
        allow.insert("localhost", 3000);
        // allowlisted host+port on a non-standard port is allowed
        assert_eq!(check_authority("localhost", 3000, &allow), Verdict::Allow);
        // but a different port for the same host is not
        assert_eq!(
            check_authority("localhost", 3001, &allow),
            Verdict::Deny(DenyReason::BadPort)
        );
        // a resolved private IP is allowed only when the caller says allowlisted
        assert_eq!(check_resolved(ip("127.0.0.1"), true), Verdict::Allow);
        assert_eq!(
            check_resolved(ip("127.0.0.1"), false),
            Verdict::Deny(DenyReason::Loopback)
        );
        // metadata is never allowlistable
        allow.insert("metadata.google.internal", 80);
        assert_eq!(
            check_authority("metadata.google.internal", 80, &allow),
            Verdict::Deny(DenyReason::CloudMetadata)
        );
    }

    #[test]
    fn malformed_hostnames_denied() {
        let allow = AllowList::new();
        for bad in [
            "",
            " ",
            "-bad.com",
            "bad-.com",
            "a..b.com",
            "toolonglabel-toolonglabel-toolonglabel-toolonglabel-toolonglabel-x.com",
        ] {
            assert!(
                !check_authority(bad, 443, &allow).is_allowed(),
                "{bad:?} should be denied"
            );
        }
    }

    #[test]
    fn ipv4_shorthand_spellings_are_canonicalised_before_classification() {
        // `IpAddr::from_str` takes only the four-dotted-decimal form, so
        // `127.1`, `0x7f.0.0.1`, `0177.0.0.1` and `2130706433` fell through to
        // `is_valid_hostname`, were accepted as ordinary DNS names, and were
        // classified — and DISCLOSED to the user — as public internet
        // addresses (RA-011). Every one of them reaches 127.0.0.1 through
        // `inet_aton`, which is what `getaddrinfo` (and therefore every SDK)
        // uses.
        let allow = AllowList::new();
        for spelling in [
            "127.0.0.1",    // the ordinary dotted quad, for contrast
            "127.1",        // 2-part: last part fills three octets
            "127.0.1",      // 3-part: last part fills two octets
            "0x7f.0.0.1",   // hexadecimal first part
            "0177.0.0.1",   // octal first part
            "2130706433",   // bare 32-bit decimal
            "0x7f000001",   // bare 32-bit hexadecimal
            "017700000001", // bare 32-bit octal
        ] {
            assert_eq!(
                check_authority(spelling, 443, &allow),
                Verdict::Deny(DenyReason::Loopback),
                "{spelling} resolves to 127.0.0.1 and must be denied as loopback"
            );
        }
    }

    #[test]
    fn ipv4_shorthand_is_canonicalised_for_every_restricted_range() {
        // Not just loopback: the shorthand spellings hid the whole private
        // address space behind `is_valid_hostname`. The link-local case is
        // the cloud-metadata address in octal.
        let allow = AllowList::new();
        for (spelling, reason) in [
            ("10.1", DenyReason::Private),                  // 10.0.0.1
            ("192.168.1", DenyReason::Private),             // 192.168.0.1
            ("0xc0a80101", DenyReason::Private),            // 192.168.1.1
            ("0251.0376.0251.0376", DenyReason::LinkLocal), // 169.254.169.254
            ("0xa9fea9fe", DenyReason::LinkLocal),          // 169.254.169.254
            ("0.0", DenyReason::Unspecified),               // 0.0.0.0
        ] {
            assert_eq!(
                check_authority(spelling, 443, &allow),
                Verdict::Deny(reason),
                "{spelling} must be denied as {reason:?}"
            );
        }
    }

    #[test]
    fn widening_the_literal_parser_never_turns_a_deny_into_an_allow() {
        // The safety property for RA-011's fix. `parse_ip_literal` sits on the
        // LIVE proxy path (`check_authority`), so teaching it more spellings
        // changes which hosts are denied pre-DNS. It must only ever tighten.
        //
        // The direction that could loosen it: a shorthand that canonicalises
        // to a PUBLIC address. `134744072` is 8.8.8.8, and before the change
        // the single-label guard denied it as internal. Returning the
        // classifier's `Allow` for it would have handed a bare integer the
        // pass that `localhost` is refused, so a public-looking shorthand
        // falls through to the hostname path that judged it before.
        let allow = AllowList::new();
        for public_shorthand in [
            "134744072",  // 8.8.8.8 in decimal
            "0x8080808",  // 8.8.8.8 in hexadecimal
            "0xdeadbeef", // 222.173.190.239
        ] {
            assert_eq!(
                check_authority(public_shorthand, 443, &allow),
                Verdict::Deny(DenyReason::Private),
                "{public_shorthand} is a single label and must stay denied as internal"
            );
        }
        // And the ordinary spellings are untouched in both directions.
        assert_eq!(check_authority("8.8.8.8", 443, &allow), Verdict::Allow);
        assert_eq!(
            check_authority("api.openai.com", 443, &allow),
            Verdict::Allow
        );
        assert_eq!(
            check_authority("[2606:4700:4700::1111]", 443, &allow),
            Verdict::Allow,
            "a bracketed public IPv6 literal must still be allowed"
        );
        // A dotted shorthand for a public address keeps the verdict the
        // hostname path already gave it (`8.0.0.1` here, from octal `010`).
        assert_eq!(check_authority("010.0.0.1", 443, &allow), Verdict::Allow);
    }

    #[test]
    fn shorthand_that_is_not_an_address_is_still_a_hostname() {
        // The negative control for the shorthand parser: it must not swallow
        // ordinary names, over-long parts, or empty labels.
        let allow = AllowList::new();
        assert_eq!(check_authority("1.2.3.4.5", 443, &allow), Verdict::Allow);
        assert_eq!(check_authority("999.1", 443, &allow), Verdict::Allow);
        assert_eq!(check_authority("0x1g.0.0.1", 443, &allow), Verdict::Allow);
        assert_eq!(check_authority("08.0.0.1", 443, &allow), Verdict::Allow);
        assert_eq!(
            check_authority("127.0.0.1.example.com", 443, &allow),
            Verdict::Allow,
            "a real DNS name that merely starts with a dotted quad is not an address"
        );
        assert_eq!(
            check_authority("a..b.com", 443, &allow),
            Verdict::Deny(DenyReason::BadHostname)
        );
    }

    #[test]
    fn hostname_validation_basics() {
        assert!(is_valid_hostname("api.openai.com"));
        assert!(is_valid_hostname("a.b.c.d.e"));
        assert!(is_valid_hostname("example.com."));
        assert!(!is_valid_hostname("bad_underscore.com"));
        assert!(!is_valid_hostname("space in.com"));
    }
}
