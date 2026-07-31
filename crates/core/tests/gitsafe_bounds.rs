//! Bounds tests for the non-executing Git reader (ADR 0023).
//!
//! `gitsafe`'s module documentation promises that it "never allocates
//! without limit" and that exceeding a bound "degrades the answer to
//! unknown and is reported to the caller". Two paths did not keep that
//! promise: version-4 index paths were rebuilt with no cap on the retained
//! bytes (RA-008), and the `**` evaluator explored an exponential search
//! space (RA-009).
//!
//! These are bound assertions, not benchmarks. Each one either observes the
//! declared limit being reported, or completes far inside a ceiling that the
//! unbounded implementation could not reach on any machine. Every timed test
//! is paired with an identical-shape case that must still SUCCEED, so a
//! blanket refusal cannot make them pass.

use std::time::{Duration, Instant};

use api_tracker_core::gitsafe::{
    load_ignore_rules, read_index, RepoLayout, ViewLimit, MAX_INDEX_PATH_BYTES,
};

/// A synthetic version-4 index whose every entry strips nothing off the
/// previous path and appends a single byte, so entry *n* reconstructs an
/// *n*-byte path and the file as a whole reconstructs `count * (count + 1) /
/// 2` bytes from `count * 65` bytes on disk.
///
/// This is the exact shape of RA-008: version 4 stores paths as "strip N,
/// append this suffix", and `MAX_INDEX_BYTES` bounds only the file.
fn amplifying_v4_index(count: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(count * 65 + 32);
    buf.extend_from_slice(b"DIRC");
    buf.extend_from_slice(&4u32.to_be_bytes());
    buf.extend_from_slice(&(count as u32).to_be_bytes());
    for _ in 0..count {
        buf.extend_from_slice(&[0u8; 40]); // stat data
        buf.extend_from_slice(&[0u8; 20]); // SHA-1 object id
        buf.extend_from_slice(&[0x00, 0x01]); // flags, extended bit clear
        buf.push(0x00); // varint: strip nothing off the previous path
        buf.push(b'a'); // one-byte suffix
        buf.push(0x00); // NUL terminator
    }
    buf.extend_from_slice(&[0u8; 20]); // trailing checksum
    buf
}

/// The retained path bytes for `count` entries of the shape above.
fn reconstructed_bytes(count: usize) -> usize {
    count * (count + 1) / 2
}

fn write_index(bytes: &[u8]) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("index"), bytes).unwrap();
    tmp
}

/// Under the cap the same generator must parse cleanly. Without this the
/// test above would pass just as well against a reader that refused every
/// version-4 index.
#[test]
fn a_version_4_index_under_the_path_budget_still_parses() {
    let count = 4_000;
    assert!(
        reconstructed_bytes(count) < MAX_INDEX_PATH_BYTES,
        "the negative control must sit under the cap"
    );
    let git_dir = write_index(&amplifying_v4_index(count));
    let paths = read_index(git_dir.path()).expect("an index under the cap is read normally");
    assert_eq!(paths.len(), count, "every entry must be reconstructed");
    assert!(paths.contains("a"));
    assert!(paths.contains(&"a".repeat(count)));
}

/// Over the cap the reader must report the bound instead of allocating.
#[test]
fn a_prefix_amplified_version_4_index_reports_the_path_budget() {
    // Just past 32 MiB of reconstructed path from ~520 KiB of file: the
    // auditor measured 764 MiB of live heap from 0.61 MiB of input, and
    // 11.9 GiB from 2.44 MiB, because nothing bounded this quantity.
    let count = 8_200;
    assert!(
        reconstructed_bytes(count) > MAX_INDEX_PATH_BYTES,
        "the fixture must actually cross the cap"
    );
    let bytes = amplifying_v4_index(count);
    let file_len = bytes.len();
    let git_dir = write_index(&bytes);

    let started = Instant::now();
    let result = read_index(git_dir.path());
    let elapsed = started.elapsed();

    assert_eq!(
        result,
        Err(ViewLimit::IndexPathBudget),
        "{file_len} bytes of index reconstruct {} bytes of path; that must degrade to a \
         reported limit, not an allocation",
        reconstructed_bytes(count)
    );
    // The parse stops at the cap, so the work is bounded by 32 MiB of
    // copying however large the amplification factor is.
    assert!(
        elapsed < Duration::from_secs(20),
        "bounded parsing took {elapsed:?}"
    );
    let limit = ViewLimit::IndexPathBudget.describe();
    assert!(
        limit.contains("unknown"),
        "the warning must say the answer is unknown, never that files are untracked: {limit}"
    );
}

/// Versions 2 and 3 store each path whole, so their retained bytes are
/// bounded by the file and the cap can never fire on them. Pinning that
/// keeps a future tightening of `MAX_INDEX_PATH_BYTES` from quietly turning
/// ordinary repositories into `Unknown`.
#[test]
fn the_path_budget_cannot_fire_on_an_uncompressed_index() {
    let count = 2_000;
    let mut buf = Vec::new();
    buf.extend_from_slice(b"DIRC");
    buf.extend_from_slice(&2u32.to_be_bytes());
    buf.extend_from_slice(&(count as u32).to_be_bytes());
    for i in 0..count {
        let start = buf.len();
        buf.extend_from_slice(&[0u8; 40]);
        buf.extend_from_slice(&[0u8; 20]);
        let name = format!("dir/file{i:06}.env");
        buf.extend_from_slice(&(name.len() as u16).to_be_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.push(0);
        while (buf.len() - start) % 8 != 0 {
            buf.push(0);
        }
    }
    buf.extend_from_slice(&[0u8; 20]);
    let git_dir = write_index(&buf);
    let paths = read_index(git_dir.path()).expect("a version-2 index is read normally");
    assert_eq!(paths.len(), count);
    assert!(paths.contains("dir/file000000.env"));
}

fn rules_for(pattern: &str) -> (tempfile::TempDir, api_tracker_core::gitsafe::IgnoreRules) {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
    std::fs::write(tmp.path().join(".gitignore"), pattern).unwrap();
    let layout = RepoLayout {
        work_tree: tmp.path().to_path_buf(),
        git_dir: tmp.path().join(".git"),
        common_dir: tmp.path().join(".git"),
    };
    let rules = load_ignore_rules(&layout, "");
    (tmp, rules)
}

/// Fourteen `**` segments against fourteen path components used to explore
/// C(28,14) — forty million — recursive calls per ancestor, and the ancestor
/// loop runs it fifteen times over. The auditor measured 2.5s at ten `**`
/// and 18.3s at twelve, roughly 7x per additional one, so this fixture could
/// not finish inside the ceiling below under the old evaluator (RA-009).
#[test]
fn a_pattern_full_of_double_stars_cannot_backtrack_catastrophically() {
    let stars = 14;
    let depth = 14;
    let (_tmp, rules) = rules_for(&format!("{}nomatch.env\n", "**/".repeat(stars)));
    let rel = format!("{}b.env", "a/".repeat(depth));

    let started = Instant::now();
    let ignored = rules.is_ignored(&rel, false);
    let elapsed = started.elapsed();

    assert!(
        !ignored,
        "the pattern's last component never matches, so nothing is ignored"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "matching {stars} '**' segments against {depth} components took {elapsed:?}; the \
         evaluator is backtracking exponentially again"
    );
}

/// The same fixture that must match — otherwise the timing test above would
/// pass against an evaluator that had simply stopped matching `**` at all.
#[test]
fn many_double_stars_still_match_what_they_should() {
    let stars = 14;
    let depth = 14;
    let (_tmp, rules) = rules_for(&format!("{}b.env\n", "**/".repeat(stars)));
    let rel = format!("{}b.env", "a/".repeat(depth));

    let started = Instant::now();
    let ignored = rules.is_ignored(&rel, false);
    let elapsed = started.elapsed();

    assert!(ignored, "'**' must still match zero or more components");
    assert!(
        elapsed < Duration::from_secs(5),
        "the matching case took {elapsed:?}"
    );
}

/// `**` semantics, pinned independently of the timing assertions.
#[test]
fn double_star_semantics_are_unchanged() {
    let cases: &[(&str, &str, bool)] = &[
        ("**/secret/*.env", "a/secret/x.env", true),
        ("**/secret/*.env", "a/b/c/secret/x.env", true),
        ("**/secret/*.env", "secret/x.env", true),
        ("**/secret/*.env", "a/secret/deep/x.env", false),
        ("a/**/x.env", "a/x.env", true),
        ("a/**/x.env", "a/b/c/x.env", true),
        ("a/**/x.env", "b/a/x.env", false),
        ("a/**", "a/b/c.env", true),
        ("a/**", "b/c.env", false),
        ("**/**/x.env", "a/b/x.env", true),
        ("**/**/x.env", "x.env", true),
    ];
    for (pattern, rel, expected) in cases {
        let (_tmp, rules) = rules_for(&format!("{pattern}\n"));
        assert_eq!(
            rules.is_ignored(rel, false),
            *expected,
            "pattern {pattern:?} against {rel:?}"
        );
    }
}

/// A `link` extension whose payload is exactly an object id.
///
/// Git's `write_link_extension` writes the shared index's object id and
/// then returns early when it is holding neither bitmap, so "object id and
/// nothing else" is a valid split index meaning "nothing deleted, nothing
/// replaced". Treating the missing bitmaps as a truncated extension would
/// degrade a perfectly readable repository to `Unknown`.
#[test]
fn a_link_extension_without_bitmaps_is_read_not_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let git_dir = tmp.path();
    let shared_oid = [0x11u8; 20];
    let mut shared_name = String::from("sharedindex.");
    for byte in shared_oid {
        shared_name.push_str(&format!("{byte:02x}"));
    }
    std::fs::write(
        git_dir.join(&shared_name),
        version_2_index(&["a.env", "sub/b.env"]),
    )
    .unwrap();

    // Main index: one name-less placeholder plus a `link` extension holding
    // only the object id.
    let mut main = version_2_index(&[""]);
    let trailer = main.split_off(main.len() - 20);
    let mut ext = Vec::new();
    ext.extend_from_slice(b"link");
    ext.extend_from_slice(&(shared_oid.len() as u32).to_be_bytes());
    ext.extend_from_slice(&shared_oid);
    main.extend_from_slice(&ext);
    main.extend_from_slice(&trailer);
    std::fs::write(git_dir.join("index"), &main).unwrap();

    let paths = read_index(git_dir).expect("a bitmap-less link extension is a valid split index");
    assert_eq!(
        paths,
        ["a.env".to_string(), "sub/b.env".to_string()]
            .into_iter()
            .collect()
    );

    // Negative control: the same extension truncated mid-bitmap must still
    // be refused rather than read as "nothing deleted".
    let mut broken = version_2_index(&[""]);
    let trailer = broken.split_off(broken.len() - 20);
    let mut ext = Vec::new();
    ext.extend_from_slice(b"link");
    ext.extend_from_slice(&((shared_oid.len() + 3) as u32).to_be_bytes());
    ext.extend_from_slice(&shared_oid);
    ext.extend_from_slice(&[0u8; 3]); // three bytes of a four-byte bit_size
    broken.extend_from_slice(&ext);
    broken.extend_from_slice(&trailer);
    std::fs::write(git_dir.join("index"), &broken).unwrap();
    assert!(
        read_index(git_dir).is_err(),
        "a truncated bitmap must degrade to a reported limit"
    );
}

/// A minimal version-2 `DIRC` file holding `names` in order. An empty name
/// is what a split-index placeholder looks like.
fn version_2_index(names: &[&str]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"DIRC");
    buf.extend_from_slice(&2u32.to_be_bytes());
    buf.extend_from_slice(&(names.len() as u32).to_be_bytes());
    for name in names {
        let start = buf.len();
        buf.extend_from_slice(&[0u8; 40]);
        buf.extend_from_slice(&[0u8; 20]);
        buf.extend_from_slice(&(name.len() as u16).to_be_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.push(0);
        while (buf.len() - start) % 8 != 0 {
            buf.push(0);
        }
    }
    buf.extend_from_slice(&[0u8; 20]);
    buf
}
