//! The legacy `api-tracker` entry point, kept so existing scripts, git
//! hooks, and automation keep working after the Tethra rename.
//!
//! It runs the exact same program as `tethra` (`src/lib.rs`); the only
//! difference a user can observe is the name in `--help` / `--version`,
//! which is derived from argv[0] at run time so each entry point identifies
//! itself. See `docs/rebrand/TETHRA_MIGRATION_GUIDE.md`.

fn main() {
    api_tracker_cli::run_cli()
}
