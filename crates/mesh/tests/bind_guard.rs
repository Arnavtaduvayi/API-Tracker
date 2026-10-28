//! MESH-SI-1, by source scan: `bind.rs` is the only file in `crates/mesh/src`
//! that binds a socket, and no file holds a wildcard address. Modelled on
//! `crates/gateway/tests/no_insecure_verifier.rs`.

use api_tracker_mesh::bind::bind_listener;
use std::fs;
use std::path::{Path, PathBuf};

fn src_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            src_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Strip `//` comments so prose that names an API does not trip the scan.
fn code_only(src: &str) -> String {
    src.lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn only_bind_rs_binds_and_no_file_names_a_wildcard_address() {
    let mut files = Vec::new();
    src_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    assert!(files.len() >= 8, "found {} source files", files.len());
    const BINDS: &[&str] = &[
        "TcpListener::bind",
        "UdpSocket::bind",
        "Socket::bind",
        ".bind(",
    ];
    const WILDCARDS: &[&str] = &["0.0.0.0", "INADDR_ANY", "\"::\"", "[::]:", "UNSPECIFIED"];
    for f in files {
        let code = code_only(&fs::read_to_string(&f).unwrap());
        let is_bind_rs = f.file_name().is_some_and(|n| n == "bind.rs");
        for pat in WILDCARDS {
            assert!(!code.contains(pat), "{pat} in {}", f.display());
        }
        if !is_bind_rs {
            for pat in BINDS {
                assert!(
                    !code.contains(pat),
                    "{pat} in {}: only bind.rs may bind (MESH-SI-1)",
                    f.display()
                );
            }
        }
    }
}

#[test]
fn unspecified_addresses_are_refused_without_the_flag() {
    for a in ["0.0.0.0:0", "[::]:0"] {
        let err = bind_listener(a.parse().unwrap(), false).unwrap_err();
        assert!(err.to_string().contains("--all-interfaces"));
    }
    let l = bind_listener("127.0.0.1:0".parse().unwrap(), false).unwrap();
    assert!(l.local_addr().unwrap().ip().is_loopback());
}
