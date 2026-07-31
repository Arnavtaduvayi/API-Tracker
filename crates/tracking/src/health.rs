//! The ONE place that answers "is tracking working right now?".
//!
//! `ZFT-005` was the defect where a status surface read historical event
//! rows and reported success while the user's application was pointed at a
//! loopback port with nothing listening. It was closed on the dashboard,
//! then again on the desktop's track screen, and each close rebuilt the same
//! rule locally: probe the gateway, feed the answer into
//! [`state::refresh_with`], and gate the headline on
//! [`CurrentHealth::is_currently_working`].
//!
//! The fresh audit (`NEW-01`/`VER-02`) found the third copy of that rule
//! missing: `tethra track`'s verify loop gated its `✓ Tracking verified`
//! banner and its exit status on [`verify::check_traffic`], which switches
//! on the cached `tracking_setups.state` column after a
//! [`GatewayLiveness::Unknown`] refresh. That column records that traffic
//! was *ever* observed; it says nothing about whether anything is listening
//! now. A shell script gating on `tethra track` therefore got exit 0 while
//! every request the user's app made was failing.
//!
//! The rule is not restated here for a fourth time — it is *moved* here.
//! Every surface that makes a present-tense claim (the CLI's verify loop and
//! `track status`, the desktop's `tracking_status` and `tracking_list`
//! commands) resolves it through [`resolve`], and the derivation itself
//! stays where it always was, in [`state::refresh_with`]. Nothing in this
//! module decides health; it decides only what evidence the derivation is
//! given, which is exactly the part every caller was getting subtly
//! differently.
//!
//! ## What a present-tense success requires
//!
//! [`CurrentHealth::is_currently_working`] is true for exactly two variants,
//! and reaching either through [`resolve`] means all of the following held
//! at the moment of the read:
//!
//! | Condition | Where it is established |
//! | --- | --- |
//! | The gateway is reachable AND proves it is this vault's | [`probe_liveness`] → `control::verify_listener` → [`GatewayLiveness::Verified`] |
//! | Every configured route still exists and is forwardable | `ProviderFreshness::route_present`, else `ConfigurationChanged` |
//! | Every configured project link still exists | `ProviderFreshness::link_present`, else `ConfigurationChanged` |
//! | The configuration generation matches the observations counted | `state::refresh_with` admits only events at/after `applied_at` and this session |
//! | The current verification session is the one being reported | `VerificationHistory::verification_session`, minted on apply |
//! | A qualifying observation is fresh | `ProviderFreshness::fresh` → `working_now > 0` |
//! | No newer failure supersedes the observation | `failure_is_newer` → `NeedsAttention` |
//!
//! Attribution is deliberately NOT one of them: a gateway that forwards
//! without a matching key is still tracking, so [`attribution_is_paused`] is
//! reported beside health rather than folded into it (`SI-11`/`SI-12`).

use std::path::Path;

use api_tracker_core::Result;
use api_tracker_gateway::{control, store};
use rusqlite::Connection;

use crate::state::{self, GatewayLiveness, TrackingSetup, TrackingStatusReport};

/// Probe whether this vault's gateway is answering right now.
///
/// [`GatewayLiveness::Verified`] is returned only when a listener answers
/// the identity challenge — "something is bound to the port" is not enough,
/// because the port could belong to anything. Every other outcome, including
/// a listener that fails the challenge, is [`GatewayLiveness::Down`]: from
/// the user's application's point of view a socket that is not this gateway
/// and a socket that is not there are the same failure.
///
/// This never returns [`GatewayLiveness::Unknown`]. `Unknown` is the honest
/// answer only when a caller chose not to probe; a caller that called this
/// function did probe.
pub fn probe_liveness(conn: &Connection, data_dir: &Path) -> GatewayLiveness {
    let port = match store::load_config(conn) {
        Ok(config) => config.port.unwrap_or(0),
        Err(_) => 0,
    };
    liveness_at(data_dir, port)
}

/// [`probe_liveness`] for callers that already know the port (the install
/// and repair paths hold one that is not yet in the config row).
pub fn liveness_at(data_dir: &Path, port: u16) -> GatewayLiveness {
    if port == 0 {
        return GatewayLiveness::Down;
    }
    match control::verify_listener(data_dir, port) {
        control::ListenerIdentity::Verified { .. } => GatewayLiveness::Verified,
        _ => GatewayLiveness::Down,
    }
}

/// The authoritative present-tense answer for one setup: probe, then
/// re-derive.
///
/// Callers must not reconstruct this. A surface that reads
/// `setup.state` — or calls [`crate::verify::check_traffic`], which switches
/// on it — is reading a cache of what was once true, and the two are not
/// interchangeable: `TrafficObserved` survives the service being stopped,
/// the route being removed, and the link being deleted.
pub fn resolve(
    conn: &Connection,
    data_dir: &Path,
    setup: &mut TrackingSetup,
) -> Result<TrackingStatusReport> {
    let liveness = probe_liveness(conn, data_dir);
    state::refresh_with(conn, setup, liveness)
}

/// [`resolve`] with a liveness answer the caller already has.
///
/// The desktop's list view probes once for a whole list rather than once per
/// setup, because liveness is a property of the machine and not of the row.
pub fn resolve_with(
    conn: &Connection,
    setup: &mut TrackingSetup,
    liveness: GatewayLiveness,
) -> Result<TrackingStatusReport> {
    state::refresh_with(conn, setup, liveness)
}

/// Whether the gateway is forwarding but holds no usable matching key.
///
/// Attribution pausing does NOT make tracking unhealthy: traffic is still
/// forwarded and still recorded, only the credential attribution degrades
/// (`SI-11`/`SI-12`/`SI-13`). It is reported beside [`resolve`]'s answer so
/// a surface can say both things without either one contradicting the other.
pub fn attribution_is_paused(data_dir: &Path) -> bool {
    if !control::instance_is_live(data_dir) {
        return false;
    }
    let Ok(nonce) = control::read_nonce(data_dir) else {
        return false;
    };
    match control::send(
        data_dir,
        &control::Request::Status {
            nonce: nonce.to_string(),
        },
    ) {
        Ok(control::Response::Status(status)) => {
            !status.matching_key_present || status.matching_key_expired
        }
        _ => false,
    }
}
