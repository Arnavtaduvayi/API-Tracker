# API Tracker — Repository Instructions

## Read this first

API Tracker is an open-source, local-first desktop application for individual developers to organize, secure, monitor, and manage API credentials across their projects.

Before making architectural or implementation decisions, read:

* `PRODUCT_SPEC.md`
* `THREAT_MODEL.md`, once it exists
* Existing architecture decision records in `docs/decisions/`, once they exist

`PRODUCT_SPEC.md` is the source of truth for the product vision and intended features.

These instructions describe how work should be performed in this repository.

## Role and working behavior

Act as the lead engineer for this repository.

Use strong engineering judgment and work autonomously. Do not ask for approval on minor technical decisions.

Do not stop after:

* Writing a plan
* Creating scaffolding
* Defining interfaces
* Adding database tables
* Adding buttons that do not work
* Writing TODO comments
* Creating mocked screens without functioning behavior

For every requested milestone:

1. Inspect the current repository.
2. Understand the relevant existing implementation.
3. Make a concise implementation plan.
4. Implement the milestone.
5. Run the application.
6. Test the implementation.
7. Fix failures.
8. Update documentation.
9. Review the Git diff.
10. Commit working changes.
11. Push the current branch.

Ask the user only when genuinely blocked by something that cannot safely be assumed, such as:

* Missing repository permissions
* A destructive Git operation
* A licensing conflict
* A required code-signing certificate
* A real provider account needed for optional live verification
* A decision that fundamentally changes the product direction

Do not ask about ordinary library choices, naming decisions, file organization, or other normal engineering decisions.

## Product priorities

Prioritize in this order:

1. Security
2. Correctness
3. Usability
4. Reliability
5. Maintainability
6. Performance
7. Visual appearance

Do not spend substantial time on branding, animations, visual polish, or a custom design system.

The interface should be plain, accessible, understandable, and functional.

## Local-first requirements

API Tracker must function without:

* An API Tracker account
* An API Tracker cloud service
* A hosted API Tracker backend
* Internet access, except when communicating directly with selected API providers or official documentation websites

Sensitive user information must remain on the user’s computer, including:

* API credential values
* Project information
* Credential metadata
* Repository scan results
* Usage records
* Alerts
* Audit records
* Provider connection details

Do not add:

* Analytics
* Telemetry
* Advertising
* User tracking
* Cloud synchronization
* Hosted crash reporting
* Requests to an API Tracker-owned server

Provider requests and documentation checks must be made directly from the user’s device.

## Security requirements

Treat API Tracker as security-sensitive software.

Never:

* Store API credentials in plaintext
* Log credential values
* Print full credentials in CLI output
* Include real credentials in tests or fixtures
* Include credential values in errors or crash reports
* Commit `.env` files
* Commit local vault databases
* Commit encrypted backups
* Build custom cryptographic algorithms
* Claim that local software has no security risks
* Silently weaken security to simplify implementation

Always:

* Encrypt sensitive values at rest
* Use authenticated encryption
* Use a mature, reviewed cryptography library
* Use a memory-hard password key derivation function
* Use cryptographically secure randomness
* Redact secret values by default
* Require reauthentication before revealing, copying, exporting, or changing secrets
* Require explicit confirmation before destructive actions
* Use unmistakably fake test credentials
* Add tests preventing credentials from appearing in logs and errors
* Document security assumptions and limitations
* Minimize how long decrypted values remain in memory

Local-first reduces centralized exposure but does not eliminate risks from malware, unlocked devices, memory inspection, clipboard monitoring, malicious dependencies, or compromised operating systems.

Document these limitations honestly.

## Architecture guidance

Prefer the architecture described in `PRODUCT_SPEC.md`, including:

* Tauri for the desktop application
* Rust for security-sensitive core functionality
* React and TypeScript for a minimal desktop interface
* SQLite for local structured storage
* Versioned database migrations
* A Rust CLI named `api-tracker`
* Shared Rust crates between the desktop app and CLI

The desktop app and CLI must share the same:

* Vault implementation
* Database
* Encryption logic
* Project model
* Credential model
* Provider connectors
* Repository scanner
* Status engine
* Usage calculations
* Alert rules

Do not duplicate important business logic in TypeScript.

Do not introduce:

* Microservices
* Hosted infrastructure
* A mandatory remote proxy
* A hosted database
* Unnecessary network dependencies

Create architecture decision records for important choices in:

```text
docs/decisions/
```

Each decision record should explain:

* The decision
* Why it was made
* Alternatives considered
* Security implications
* Future limitations

## Provider integrations

Do not invent or assume provider capabilities.

For every provider capability, distinguish between:

* Supported and implemented
* Supported but not yet implemented
* Unsupported by the provider
* Requires manual action
* Requires an administrative credential
* Available only at account level
* Available only at provider-project level
* Available at exact credential level

Never present account-level usage as exact per-key usage.

Never claim that a permission, credential, or provider setting changed unless the provider confirms the result.

Use official APIs and official documentation.

Do not automate undocumented private APIs.

Automated tests must use mocks and fixtures. Normal tests must not require real provider credentials.

## Repository and Git scanning

All source-code and Git scanning must happen locally.

Never send source code, commits, diffs, or findings to an external service.

Secret findings must:

* Redact the detected value
* Show the affected file
* Show the line number when available
* Explain why it was detected
* Include a confidence level
* Minimize false positives

Never automatically:

* Rewrite Git history
* Revoke a credential
* Delete a user file
* Modify source code without confirmation
* Push a remediation commit without confirmation

## Coding standards

Use the repository’s configured formatting, linting, and type-checking tools.

Prefer:

* Small modules with clear responsibilities
* Typed errors
* Explicit interfaces
* Testable external-service adapters
* Minimal dependencies
* Locked dependency versions
* Clear migration paths
* Backward-compatible data formats when practical

Avoid:

* Giant files
* Duplicated business logic
* Silent error handling
* Unexplained suppression of warnings
* Placeholder implementations represented as complete features
* Unnecessary dependencies in security-sensitive code

Do not leave avoidable compiler, linter, or type-checking warnings.

## Testing requirements

Every meaningful feature must include appropriate tests.

Prioritize tests for:

* Encryption and decryption
* Incorrect passwords
* Ciphertext corruption
* Project locking
* Auto-locking
* Secret redaction
* Duplicate credential detection
* Database migrations
* Backup and restore
* Provider capability handling
* Repository secret scanning
* Git hook behavior
* Usage and cost calculations
* Expiration classification
* Permission handling
* Error paths
* Prevention of secret leakage through logs and errors

Tests must not:

* Use real credentials
* Make destructive provider calls
* Depend on the developer’s personal vault
* Modify unrelated local repositories

## Definition of done

A feature is not complete because:

* A UI control exists
* A database table exists
* An interface exists
* Mock information appears
* A command prints “not implemented”
* A TODO has been added

A feature is complete only when:

* Its intended workflow works end to end
* Relevant tests exist and pass
* Errors are handled
* Sensitive information is protected
* Documentation reflects the actual implementation
* The desktop and CLI remain compatible
* The application builds successfully

Before considering a milestone complete:

1. Format changed files.
2. Run linting.
3. Run type checking.
4. Run relevant unit tests.
5. Run integration tests.
6. Build affected applications.
7. Run the main workflow manually where practical.
8. Review `git diff`.
9. Verify no secrets or generated local files are staged.
10. Update documentation.
11. Commit only working code.
12. Push the current branch.

## Git workflow

Repository:

```text
https://github.com/Arnavtaduvayi/API-Tracker
```

Before changing files:

1. Run `git status`.
2. Check the current branch.
3. Run `git remote -v`.
4. Review existing files.
5. Preserve existing user work.

Use descriptive conventional commits, such as:

```text
chore: initialize desktop workspace
feat: add encrypted local vault
feat: add project credential management
feat: add repository secret scanner
test: cover vault backup restoration
docs: document provider connector architecture
```

After each meaningful, working checkpoint:

1. Run relevant checks.
2. Review the diff.
3. Confirm no secrets, vaults, databases, backups, `.env` files, or build artifacts are staged.
4. Commit.
5. Push the current branch.

Do not:

* Force-push
* Rewrite shared history
* Delete existing user work
* Commit broken checkpoints
* Change the user’s Git author identity
* Include Claude as a co-author
* Add “Generated by Claude”
* Add a Claude session URL to commits or pull requests

The initial repository foundation may be committed directly to `main` because the repository began empty. Use feature branches for substantial later milestones unless the user explicitly requests otherwise.

## Documentation

Keep these files accurate as the project evolves:

* `README.md`
* `PRODUCT_SPEC.md`
* `SECURITY.md`
* `THREAT_MODEL.md`
* `CONTRIBUTING.md`
* Architecture decision records
* Provider capability documentation
* Build and release instructions

Documentation must describe what the application currently does, not just what is planned.

## Session completion report

At the end of every major coding session, report:

1. What was implemented
2. What works end to end
3. What is partially implemented
4. What remains
5. Tests, linting, type checking, and builds run
6. Important architecture decisions
7. Security decisions
8. Commits created
9. Branch pushed
10. Repository status
11. Any action required from the user
12. Recommended next milestone

