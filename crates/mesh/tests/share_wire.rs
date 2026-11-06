//! MESH-SI-6 on the wire (Increment 11): a credential share crosses a real
//! Noise session through a TCP shim that records every byte in both
//! directions. The fake value never appears in those bytes in any encoding
//! (raw, hex, base64 at each alignment, JSON-escaped), and the share still
//! arrives and imports on the other side. 127.0.0.1 only; fake value only.

mod common;

use api_tracker_core::mesh::share::Recipients;
use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{AddCredential, ImportOptions, NewProject};
use api_tracker_mesh::replicate::replicate_once;
use base64::Engine;
use common::*;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

const CANARY: &str = "sk-test-FAKE-mesh-wire-canary-b71e4c9d03a6";

/// Forwards one connection from `listener` to `upstream`, appending every
/// byte seen in either direction to `log`.
fn shim(listener: TcpListener, upstream: String, log: Arc<Mutex<Vec<u8>>>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let (client, _) = listener.accept().unwrap();
        let server = TcpStream::connect(upstream).unwrap();
        let pump = |mut from: TcpStream, mut to: TcpStream, log: Arc<Mutex<Vec<u8>>>| {
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    match from.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            log.lock().unwrap().extend_from_slice(&buf[..n]);
                            if to.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = to.shutdown(Shutdown::Write);
            })
        };
        let up = pump(
            client.try_clone().unwrap(),
            server.try_clone().unwrap(),
            log.clone(),
        );
        let down = pump(server, client, log);
        let _ = up.join();
        let _ = down.join();
    })
}

fn leak_forms(secret: &str) -> Vec<Vec<u8>> {
    let mut out = vec![
        secret.as_bytes().to_vec(),
        hex::encode(secret).into_bytes(),
        serde_json::to_string(secret).unwrap().into_bytes(),
    ];
    for pad in ["", "x", "xx"] {
        let enc = base64::engine::general_purpose::STANDARD.encode(format!("{pad}{secret}"));
        out.push(enc.as_bytes()[4..enc.len() - 4].to_vec());
    }
    out
}

#[test]
fn a_shared_credential_never_crosses_the_wire_in_plaintext() {
    let (a, server, b) = pair_of();
    let (mut a, mut b) = (a, b);
    for d in [&mut a, &mut b] {
        d.vault
            .create_project(NewProject {
                name: "app".into(),
                ..Default::default()
            })
            .unwrap();
    }
    a.vault.mesh_project_share("app").unwrap();
    let cred = a
        .vault
        .add_credential(AddCredential {
            project: "app".into(),
            provider: "openai".into(),
            name: "OPENAI_API_KEY".into(),
            environment: Environment::Development,
            value: SecretString::from(CANARY),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap()
        .0;
    let receipt = a
        .vault
        .mesh_credential_share(&master(), &cred.id, Recipients::AllCurrent)
        .unwrap();
    assert_eq!(receipt.recipients.len(), 1);

    // B pulls the share from A's serving node through the shim.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let shim_addr = listener.local_addr().unwrap().to_string();
    let log = Arc::new(Mutex::new(Vec::new()));
    let t = shim(listener, server.addr_string(), log.clone());
    let nb = node(&b);
    let r = replicate_once(&nb, &shim_addr).unwrap();
    assert!(r.aborted.is_none(), "{r:?}");
    assert!(r.items_in >= 1, "{r:?}");
    drop(nb);
    t.join().unwrap();

    let wire = log.lock().unwrap().clone();
    assert!(
        wire.len() > 1_000,
        "the shim saw the session ({} bytes)",
        wire.len()
    );
    for form in leak_forms(CANARY) {
        assert!(
            !wire.windows(form.len()).any(|w| w == form.as_slice()),
            "the wire carried the value as {:?}",
            String::from_utf8_lossy(&form)
        );
    }

    // The share arrived intact and imports on B, re-encrypted there.
    let share = b.vault.mesh_shares_list().unwrap().incoming[0].share_id;
    let got = b
        .vault
        .mesh_credential_import(
            &master(),
            &share.to_hex(),
            "app",
            ImportOptions {
                replace: false,
                environment: Environment::Development,
            },
        )
        .unwrap();
    assert_eq!(
        b.vault
            .reveal_credential(&got.credential.id, &master())
            .unwrap()
            .expose(),
        CANARY
    );
    drop(server);
}
