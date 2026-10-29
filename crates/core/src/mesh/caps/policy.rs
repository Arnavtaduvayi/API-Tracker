//! The spend-cap policy as pure arithmetic: who gets how much, when to ask,
//! how much to give, what to burn after a lower (DESIGN §D15). Every
//! threshold is a named constant here; the reconciler only applies them.
//!
//! Amounts are micro-USD. `avail` is signed: a device that overshot (the
//! gateway's last in-flight request, Increment 08) can be below zero.

use super::period::DAY_MS;

/// A device asks a peer for rights when it holds less than this percentage
/// of its fair share.
pub const REQUEST_BELOW_PCT: u64 = 20;

/// A donor keeps at least this percentage of its fair share when it grants.
/// With [`REQUEST_BELOW_PCT`] it is the hysteresis that stops rights moving
/// back and forth: a device that has just been given rights is far from
/// both thresholds.
pub const DONOR_KEEP_PCT: u64 = 50;

/// From this UTC day of month `m`, the owner mints month `m + 1` and
/// pre-distributes it.
pub const ADVANCE_MINT_DAY: u8 = 20;

/// A device counts as active (it gets a share when the owner mints) if this
/// device exchanged with it, or saw it publish usage or cap figures, within
/// this window.
pub const ACTIVE_WINDOW_MS: u64 = 30 * DAY_MS;

/// At most one rights request to one peer for one cap in this window, and
/// at most one grant to one requester for one cap.
pub const REQUEST_INTERVAL_MS: u64 = 5 * 60_000;

/// How long a transfer may wait for the running gateway's acknowledgement
/// before it is reported as waiting; it is then carried to later rounds.
pub const ACK_WAIT_MS: u64 = 15_000;

/// A manual reclaim (`tethra mesh cap reclaim`) stays in force this long.
pub const RECLAIM_WINDOW_MS: u64 = 24 * 3_600_000;

/// Alert thresholds, as a percentage of the effective target.
pub const ALERT_THRESHOLDS: [u64; 2] = [80, 100];

fn pct(x: u64, p: u64) -> u128 {
    u128::from(x) * u128::from(p) / 100
}

fn pct_ceil(x: u64, p: u64) -> u128 {
    (u128::from(x) * u128::from(p)).div_ceil(100)
}

fn clamp_u64(x: i128) -> u64 {
    u64::try_from(x.max(0)).unwrap_or(u64::MAX)
}

/// The fair share of `target` among `active` devices (the owner keeps the
/// remainder of the division).
pub fn fair_share(target: u64, active: usize) -> u64 {
    target / (active.max(1) as u64)
}

/// How much a device holding `avail` should ask for, if anything: it asks
/// when below [`REQUEST_BELOW_PCT`] of `fair`, for enough to get back to
/// `fair`.
pub fn wants(avail: i128, fair: u64) -> Option<u64> {
    if fair == 0 || avail.max(0) as u128 >= pct(fair, REQUEST_BELOW_PCT).max(1) {
        return None;
    }
    Some(clamp_u64(i128::from(fair) - avail.max(0)))
}

/// What a donor holding `avail` can give: everything above
/// [`DONOR_KEEP_PCT`] of its fair share, not counting its own local
/// overrides (an override raised the cap for that device only).
pub fn donatable(avail: i128, fair: u64, overrides: u64) -> u64 {
    let keep = pct_ceil(fair, DONOR_KEEP_PCT) + u128::from(overrides);
    clamp_u64(avail - i128::try_from(keep).unwrap_or(i128::MAX))
}

/// A donor's grant for a request of `want`.
pub fn grant_amount(want: u64, avail: i128, fair: u64, overrides: u64) -> u64 {
    want.min(donatable(avail, fair, overrides))
}

/// Rights in existence beyond what the cap now allows: `supply` (minted
/// minus burned) above the larger of the effective target (target plus
/// overrides) and what has already been spent. Rights already spent cannot
/// be taken back, so a target below the spend leaves nothing to burn for.
pub fn pending_decrease(supply: i128, effective_target: u128, total_used: u128) -> u128 {
    let floor = effective_target.max(total_used);
    u128::try_from(supply.max(0))
        .unwrap_or(0)
        .saturating_sub(floor)
}

/// What a holder keeps unspent after a lower: what its fair share still
/// allows after its own spend, plus its own overrides.
pub fn keep_after_lower(fair: u64, used: u64, overrides: u64) -> u64 {
    fair.saturating_sub(used).saturating_add(overrides)
}

/// What a holder burns after a lower: what it holds above
/// [`keep_after_lower`], and never more than the pending decrease.
pub fn burn_after_lower(avail: i128, keep: u64, pending: u128) -> u64 {
    let above = clamp_u64(avail - i128::from(keep));
    u64::try_from(u128::from(above).min(pending)).unwrap_or(u64::MAX)
}

/// Whether the owner mints next month on this day of the month.
pub fn advance_due(day_of_month: u8) -> bool {
    day_of_month >= ADVANCE_MINT_DAY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fair_share_divides_and_never_by_zero() {
        assert_eq!(fair_share(100, 3), 33);
        assert_eq!(fair_share(100, 0), 100);
    }

    #[test]
    fn a_device_asks_only_below_twenty_percent_and_asks_back_to_its_share() {
        assert_eq!(wants(20, 100), None, "exactly 20% does not ask");
        assert_eq!(wants(19, 100), Some(81));
        assert_eq!(
            wants(-5, 100),
            Some(100),
            "a negative holding asks for a full share"
        );
        assert_eq!(wants(0, 0), None, "no target, no request");
        assert_eq!(wants(0, 3), Some(3), "tiny shares still ask when empty");
    }

    #[test]
    fn a_donor_keeps_half_its_share_and_its_overrides() {
        assert_eq!(donatable(100, 100, 0), 50);
        assert_eq!(donatable(50, 100, 0), 0);
        assert_eq!(donatable(130, 100, 30), 50);
        assert_eq!(donatable(-10, 100, 0), 0);
        assert_eq!(donatable(100, 99, 0), 50, "the kept half rounds up");
        assert_eq!(grant_amount(30, 100, 100, 0), 30);
        assert_eq!(grant_amount(80, 100, 100, 0), 50);
    }

    #[test]
    fn the_thresholds_do_not_ping_pong() {
        // A requester at 0 asks for a full share; a donor at a full share can
        // give half. Afterwards neither crosses a threshold.
        let fair = 1_000;
        let want = wants(0, fair).unwrap();
        let g = grant_amount(want, i128::from(fair), fair, 0);
        let (requester, donor) = (i128::from(g), i128::from(fair - g));
        assert!(wants(requester, fair).is_none());
        assert!(wants(donor, fair).is_none());
        assert_eq!(donatable(donor, fair, 0), 0);
    }

    #[test]
    fn a_pending_decrease_never_counts_spent_rights() {
        assert_eq!(pending_decrease(100, 40, 10), 60);
        assert_eq!(pending_decrease(100, 40, 70), 30);
        assert_eq!(pending_decrease(100, 40, 120), 0);
        assert_eq!(pending_decrease(30, 40, 10), 0);
        assert_eq!(pending_decrease(-5, 0, 0), 0);
    }

    #[test]
    fn a_lower_burns_above_the_new_share_and_no_more_than_pending() {
        let keep = keep_after_lower(20, 5, 0);
        assert_eq!(keep, 15);
        assert_eq!(burn_after_lower(45, keep, 100), 30);
        assert_eq!(burn_after_lower(45, keep, 10), 10);
        assert_eq!(burn_after_lower(10, keep, 100), 0);
        assert_eq!(
            keep_after_lower(20, 35, 7),
            7,
            "overspent: keeps only its overrides"
        );
    }

    #[test]
    fn advance_minting_starts_on_the_twentieth() {
        assert!(!advance_due(19));
        assert!(advance_due(20));
        assert!(advance_due(31));
    }
}
