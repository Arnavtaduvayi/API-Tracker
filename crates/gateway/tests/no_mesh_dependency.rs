//! The gateway links only `api-tracker-core`, never the mesh's network crate
//! (DESIGN §D4): it reads spend-cap state from core and nothing in its
//! process may open a mesh connection. Checked on the manifest and on the
//! resolved dependency graph in `Cargo.lock`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[test]
fn the_gateway_does_not_depend_on_api_tracker_mesh() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    assert!(!manifest.contains("api-tracker-mesh"));

    let lock = std::fs::read_to_string(root.join("../../Cargo.lock")).unwrap();
    // package name -> dependency names
    let mut graph: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for pkg in lock.split("[[package]]").skip(1) {
        let name = pkg
            .lines()
            .find_map(|l| l.strip_prefix("name = \""))
            .map(|n| n.trim_end_matches('"').to_owned())
            .unwrap();
        let deps: Vec<String> = pkg
            .split("dependencies = [")
            .nth(1)
            .map(|d| d.split(']').next().unwrap_or(""))
            .unwrap_or("")
            .lines()
            .filter_map(|l| l.trim().strip_prefix('"'))
            .map(|l| l.split([' ', '"']).next().unwrap_or("").to_owned())
            .collect();
        graph.entry(name).or_default().extend(deps);
    }
    assert!(
        graph.contains_key("api-tracker-mesh"),
        "the mesh crate is in the lockfile"
    );
    let mut seen = BTreeSet::new();
    let mut todo = vec!["api-tracker-gateway".to_owned()];
    while let Some(p) = todo.pop() {
        if !seen.insert(p.clone()) {
            continue;
        }
        todo.extend(graph.get(&p).cloned().unwrap_or_default());
    }
    assert!(seen.contains("api-tracker-core"));
    assert!(
        !seen.contains("api-tracker-mesh"),
        "api-tracker-gateway reaches api-tracker-mesh"
    );
}
