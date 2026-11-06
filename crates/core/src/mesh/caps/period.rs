//! The spend-cap period: the UTC calendar month, with the same boundaries
//! as `crate::budget::period_start` (a test checks they agree). Written
//! separately on purpose: caps never call into budgets (SI-19).

use crate::mesh::kinds::{Day, Month};

pub const DAY_MS: u64 = 86_400_000;

/// The UTC month containing `ms` milliseconds after the Unix epoch.
pub fn month_of(ms: u64) -> Month {
    Day::from_unix_ms(ms).month()
}

/// The UTC day of the month (1-31) at `ms`.
pub fn day_of_month(ms: u64) -> u8 {
    Day::from_unix_ms(ms).date().day()
}

/// Midnight UTC on the first day of `m`, in milliseconds.
pub fn month_start_ms(m: Month) -> u64 {
    let start = m.first_day().date().midnight().assume_utc();
    u64::try_from(start.unix_timestamp()).unwrap_or(0) * 1_000
}

/// Whether `m` has ended at `now_ms` (its rights have expired).
pub fn has_ended(m: Month, now_ms: u64) -> bool {
    month_of(now_ms) > m
}

/// `ms` as RFC 3339 (local rows written by cap decisions use the store's
/// clock, so tests with an injected clock read consistent times).
pub fn rfc3339_of(ms: u64) -> String {
    let t = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    crate::clock::to_rfc3339(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn months_start_at_utc_midnight_on_the_first() {
        let m = Month::parse("2024-03").unwrap();
        let start = month_start_ms(m);
        assert_eq!(month_of(start), m);
        assert_eq!(month_of(start - 1), Month::parse("2024-02").unwrap());
        assert_eq!(day_of_month(start), 1);
        assert_eq!(day_of_month(start - 1), 29, "2024 is a leap year");
        assert!(has_ended(Month::parse("2024-02").unwrap(), start));
        assert!(!has_ended(m, start));
    }
}
