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
    let host_l = host.trim().to_ascii_lowercase();
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
    if let Some(ip) = parse_ip_literal(&host_l) {
        if allowlisted {
            return Verdict::Allow;
        }
        return classify_ip(ip);
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
        let v4 = Ipv4Addr::new(
            (s[6] >> 8) as u8,
            (s[6] & 0xff) as u8,
            (s[7] >> 8) as u8,
            (s[7] & 0xff) as u8,
        );
        return classify_v4(v4);
    }
    Verdict::Allow
}

/// Parse an IP literal, accepting bracketed IPv6 (`[::1]`).
fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    let trimmed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    trimmed.parse::<IpAddr>().ok()
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
    fn hostname_validation_basics() {
        assert!(is_valid_hostname("api.openai.com"));
        assert!(is_valid_hostname("a.b.c.d.e"));
        assert!(is_valid_hostname("example.com."));
        assert!(!is_valid_hostname("bad_underscore.com"));
        assert!(!is_valid_hostname("space in.com"));
    }
}
