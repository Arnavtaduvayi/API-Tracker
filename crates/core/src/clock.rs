//! Small helpers for timestamps. All persisted timestamps are RFC 3339 UTC
//! strings; user-entered dates ("YYYY-MM-DD") are interpreted as UTC midnight.

use crate::error::{CoreError, Result};
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime};

pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

pub fn to_rfc3339(t: OffsetDateTime) -> String {
    t.format(&Rfc3339)
        .expect("RFC 3339 formatting of a valid timestamp cannot fail")
}

pub fn now_rfc3339() -> String {
    to_rfc3339(now())
}

pub fn parse_rfc3339(s: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339)
        .map_err(|_| CoreError::InvalidInput(format!("'{s}' is not an RFC 3339 timestamp")))
}

/// Parse either a full RFC 3339 timestamp or a plain `YYYY-MM-DD` date
/// (interpreted as UTC midnight). Used for user-entered dates such as
/// credential creation and expiration dates.
pub fn parse_user_date(s: &str) -> Result<OffsetDateTime> {
    if let Ok(t) = OffsetDateTime::parse(s, &Rfc3339) {
        return Ok(t);
    }
    let fmt = format_description!("[year]-[month]-[day]");
    Date::parse(s, &fmt)
        .map(|d| d.midnight().assume_utc())
        .map_err(|_| {
            CoreError::InvalidInput(format!(
                "'{s}' is not a date; use YYYY-MM-DD or an RFC 3339 timestamp"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_date_as_utc_midnight() {
        let t = parse_user_date("2027-01-31").unwrap();
        assert_eq!(to_rfc3339(t), "2027-01-31T00:00:00Z");
    }

    #[test]
    fn parses_rfc3339_roundtrip() {
        let t = parse_user_date("2027-01-31T12:30:00Z").unwrap();
        assert_eq!(to_rfc3339(t), "2027-01-31T12:30:00Z");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_user_date("not-a-date").is_err());
        assert!(parse_rfc3339("2027-01-31").is_err());
    }
}
