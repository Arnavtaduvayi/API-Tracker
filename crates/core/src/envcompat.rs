//! Preferred/legacy environment-variable resolution for the Tethra rename.
//!
//! The product was renamed from API Tracker to Tethra; every user-facing
//! environment variable gained a preferred `TETHRA_*` name while the legacy
//! `API_TRACKER_*` name keeps working. Resolution rules (documented in
//! `docs/rebrand/TETHRA_COMPATIBILITY_MATRIX.md`):
//!
//! - When only one of the pair is present, that one is used.
//! - When both are present, the `TETHRA_*` variable wins. Presence is
//!   authoritative even for an empty value, so each call site's existing
//!   "empty means none" semantics apply to the preferred variable and never
//!   silently fall through to a conflicting legacy value.
//! - The two directory overrides are never combined; a differing pair
//!   produces a stderr warning (see [`crate::vault::default_data_dir`]).
//!
//! Values are never logged or printed here — only variable *names* appear in
//! messages.

use std::ffi::OsString;

/// Preferred prefix for all Tethra environment variables.
pub const PREFERRED_PREFIX: &str = "TETHRA_";
/// Legacy prefix, preserved for backward compatibility.
pub const LEGACY_PREFIX: &str = "API_TRACKER_";

/// The preferred (`TETHRA_*`) name for a variable suffix like `"PASSWORD"`.
pub fn preferred_name(suffix: &str) -> String {
    format!("{PREFERRED_PREFIX}{suffix}")
}

/// The legacy (`API_TRACKER_*`) name for a variable suffix.
pub fn legacy_name(suffix: &str) -> String {
    format!("{LEGACY_PREFIX}{suffix}")
}

/// The name of the variable that resolution would read for `suffix`:
/// the preferred name if it is present in the environment (even empty),
/// otherwise the legacy name if that is present, otherwise `None`.
pub fn active_name(suffix: &str) -> Option<String> {
    let preferred = preferred_name(suffix);
    if std::env::var_os(&preferred).is_some() {
        return Some(preferred);
    }
    let legacy = legacy_name(suffix);
    if std::env::var_os(&legacy).is_some() {
        return Some(legacy);
    }
    None
}

/// Resolve the value for `suffix` (preferred wins; legacy is the fallback).
pub fn var_os(suffix: &str) -> Option<OsString> {
    active_name(suffix).and_then(std::env::var_os)
}

/// Whether either variable of the pair is present.
pub fn is_set(suffix: &str) -> bool {
    active_name(suffix).is_some()
}

/// Resolve the value as UTF-8. `None` when neither variable is present;
/// `Some(Err(name))` when the winning variable is set but not valid UTF-8,
/// carrying the winning variable's name for error messages.
pub fn var(suffix: &str) -> Option<std::result::Result<String, String>> {
    let name = active_name(suffix)?;
    match std::env::var(&name) {
        Ok(v) => Some(Ok(v)),
        Err(_) => Some(Err(name)),
    }
}

/// `"TETHRA_X (or legacy API_TRACKER_X)"` — for user-facing hints.
pub fn hint(suffix: &str) -> String {
    format!(
        "{} (or legacy {})",
        preferred_name(suffix),
        legacy_name(suffix)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Env-var tests share process state; run under `--test-threads=1`-safe
    // unique names instead of locking.
    #[test]
    fn preferred_wins_when_both_set() {
        std::env::set_var("TETHRA_ENVCOMPAT_T1", "new");
        std::env::set_var("API_TRACKER_ENVCOMPAT_T1", "old");
        assert_eq!(
            active_name("ENVCOMPAT_T1").as_deref(),
            Some("TETHRA_ENVCOMPAT_T1")
        );
        assert_eq!(var_os("ENVCOMPAT_T1"), Some("new".into()));
        std::env::remove_var("TETHRA_ENVCOMPAT_T1");
        std::env::remove_var("API_TRACKER_ENVCOMPAT_T1");
    }

    #[test]
    fn legacy_used_when_only_legacy_set() {
        std::env::set_var("API_TRACKER_ENVCOMPAT_T2", "old");
        assert_eq!(
            active_name("ENVCOMPAT_T2").as_deref(),
            Some("API_TRACKER_ENVCOMPAT_T2")
        );
        assert_eq!(var_os("ENVCOMPAT_T2"), Some("old".into()));
        std::env::remove_var("API_TRACKER_ENVCOMPAT_T2");
    }

    #[test]
    fn empty_preferred_is_still_authoritative() {
        std::env::set_var("TETHRA_ENVCOMPAT_T3", "");
        std::env::set_var("API_TRACKER_ENVCOMPAT_T3", "old");
        assert_eq!(var_os("ENVCOMPAT_T3"), Some("".into()));
        std::env::remove_var("TETHRA_ENVCOMPAT_T3");
        std::env::remove_var("API_TRACKER_ENVCOMPAT_T3");
    }

    #[test]
    fn absent_pair_resolves_to_none() {
        assert_eq!(active_name("ENVCOMPAT_T4"), None);
        assert!(var_os("ENVCOMPAT_T4").is_none());
        assert!(!is_set("ENVCOMPAT_T4"));
    }
}
