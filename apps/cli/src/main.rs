//! The preferred `tethra` entry point. The program itself lives in
//! `src/lib.rs`, shared byte-for-byte with the legacy `api-tracker` binary.

fn main() {
    api_tracker_cli::run_cli()
}
