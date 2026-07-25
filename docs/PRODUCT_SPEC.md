You are Claude Code working as the lead engineer for an open-source, local-first desktop application currently called **Tethra**.

Your job in this session is to inspect the repository, design the architecture, and implement as much of the first shippable product as possible. Do not stop after creating a plan or scaffolding. Build the product, run it, test it, document it, and commit working milestones.

Repository:

https://github.com/Arnavtaduvayi/API-Tracker

## 1. Product vision

Build a **local-first workspace for individual developers to organize, secure, monitor, and manage API keys across all their software projects**.

The mental model is:

* A project is like a folder in Google Docs or Notion.
* Each API credential is like a document inside that project.
* The developer can see all credentials associated with a project.
* The developer can inspect status, expiration, usage, permissions, documentation, and security warnings.
* All sensitive information remains on the developer’s computer.
* The product must not require a hosted backend or a Tethra account.
* Any requests to API providers or documentation websites must be sent directly from the user’s device.
* No API keys, usage records, project information, or telemetry should be sent to a Tethra server.
* Telemetry must be disabled by default. Do not add third-party analytics.

This product is intended to become a serious open-source developer tool, not a hackathon prototype.

The initial user is a single developer with API keys spread across:

* `.env` files
* Local repositories
* Shell environment variables
* Notes
* Provider dashboards
* Deployment platforms
* Multiple side projects

The application should help that developer answer:

* Which API keys do I have?
* Which project uses each key?
* Is the same credential reused across multiple projects?
* Is a key active, invalid, stale, expired, exposed, or suspicious?
* When does it expire?
* What permissions does it have?
* How much is it being used?
* How much is it costing me?
* Has its provider documentation changed?
* Did I accidentally commit a secret?
* Can I safely change or revoke it?

## 2. Important security correction

Local-first does not mean security no longer matters.

Treat this as security-sensitive software. A local database containing API credentials is a valuable target.

The application must:

* Never store credentials in plaintext.
* Never write plaintext credentials to logs.
* Never include real credentials in tests, fixtures, screenshots, examples, documentation, Git history, error messages, or crash reports.
* Redact credentials everywhere except during an explicit, authenticated reveal action.
* Avoid retaining plaintext credentials in memory longer than necessary.
* Auto-lock after inactivity.
* Require reauthentication before revealing, exporting, copying, or changing sensitive values.
* Clear copied secrets from the clipboard after a configurable interval where the operating system permits it.
* Use authenticated encryption.
* Use a memory-hard password derivation function.
* Use secure random number generation.
* Use constant-time comparisons where appropriate.
* Maintain a written threat model.
* Clearly document security limitations, including risks from local malware, compromised operating systems, screenshots, debuggers, and processes running as the user.

Do not claim that the product makes keys perfectly safe.

## 3. Product scope for this session

Implement the foundational product and architecture for the features below.

Prioritize a reliable, complete core over half-building many integrations.

### Required core features

1. Create and manage projects.
2. Add and manage API credentials inside each project.
3. Encrypt all credential values locally.
4. Password-lock selected projects.
5. Track credential status, timing, and expiration.
6. Detect reuse of the same credential across projects.
7. Provide a CLI that uses the same local vault and core logic as the desktop app.
8. Scan registered Git repositories for accidentally committed credentials.
9. Install local Git pre-commit protection.
10. Maintain a local provider/API information library.
11. Check selected official provider documentation pages for changes.
12. Define a provider connector architecture for metadata, usage, permissions, and management actions.
13. Implement useful provider integrations where officially supported.
14. Track usage snapshots and estimate costs where sufficient data exists.
15. Track permissions and allow changes where the provider officially supports programmatic permission changes.
16. Track request activity where provider data or local instrumentation makes it possible.
17. Generate local alerts for expiration, exposure, reuse, unusual activity, budget changes, and documentation changes.
18. Package the application as an installable desktop app.
19. Add tests, documentation, automated checks, and a secure release process foundation.

## 4. Non-goals for this version

Do not build these yet unless all required work is complete:

* Team collaboration
* Shared cloud vaults
* User accounts
* Organization management
* Enterprise SSO
* A hosted Tethra backend
* Mobile applications
* Complex UI design
* A mandatory API proxy
* Full production-grade support for hundreds of providers
* AI-generated security decisions
* Automatic destructive remediation without confirmation
* Perfect attribution when a provider does not expose sufficient data

Do not fabricate capabilities that providers do not offer.

If a provider cannot expose usage per key, show the most precise supported level, such as account or project usage. Clearly label it.

If a provider cannot programmatically change permissions, display the permissions that can be discovered and provide a manual action or official dashboard link.

## 5. Recommended technical architecture

First inspect the existing repository. Preserve useful existing work if any exists. If the repository is empty, initialize it cleanly.

Use an architecture appropriate for a cross-platform local desktop application.

Preferred architecture:

* **Tauri** for the desktop shell.
* **Rust** for the security-sensitive core, local vault, scanning, provider adapters, scheduler, and CLI.
* A minimal **TypeScript/React** interface for usability.
* **SQLite** for local structured storage.
* A migration framework for all schema changes.
* Authenticated encryption using a well-reviewed modern cryptographic library.
* Argon2id or another appropriate memory-hard KDF for master-password derivation.
* OS keychain integration as an optional convenience, not the only recovery mechanism.
* Shared Rust crates so the desktop app and CLI use the exact same vault, data model, provider connectors, scanning engine, and business rules.

Suggested workspace structure:

```text
/
├── apps/
│   ├── desktop/
│   └── cli/
├── crates/
│   ├── core/
│   ├── vault/
│   ├── database/
│   ├── providers/
│   ├── scanner/
│   ├── usage/
│   ├── alerts/
│   └── docs-watcher/
├── provider-manifests/
├── migrations/
├── tests/
├── docs/
├── scripts/
├── .github/
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── THREAT_MODEL.md
└── LICENSE
```

You may adjust this structure if another arrangement is materially better. Explain significant deviations in an architecture decision record.

Select current stable dependencies after checking their official documentation. Pin or lock dependencies appropriately.

Avoid unnecessary dependencies, especially in the security-sensitive core.

## 6. Local storage and encryption design

Implement a vault architecture that supports both an overall application lock and additional project locks.

A suitable design is:

1. On first launch, generate a random vault root key.
2. Ask the user to create a master password.
3. Derive a key-encryption key from the master password using Argon2id with appropriate parameters and a random salt.
4. Use that key to wrap the vault root key.
5. Generate a separate random data-encryption key for each project.
6. Encrypt each project key with the vault root key.
7. For a password-locked project, add an additional wrapping layer derived from that project’s password.
8. Encrypt each secret independently with its project key using authenticated encryption.
9. Bind ciphertext to contextual associated data such as project ID, credential ID, field name, and schema version.
10. Never use the raw password directly as an encryption key.
11. Never store passwords.
12. Store salts, nonces, encrypted data keys, ciphertext, algorithm identifiers, and version information needed for future migration.
13. Support cryptographic versioning so algorithms and KDF parameters can be upgraded later.
14. Use best-effort memory zeroization for secret buffers.
15. Auto-lock after a configurable inactivity period.
16. Lock immediately when the operating system session locks, if supported.
17. Make backups encrypted.
18. Never silently overwrite an existing vault.

Add tests covering:

* Correct unlock
* Incorrect password
* Corrupted ciphertext
* Modified associated data
* Project-level password locking
* Key rotation
* Database migration
* Backup and restore
* Secret redaction
* Auto-lock behavior

## 7. Core data model

Implement at least the following entities.

### Project

Fields should include:

* ID
* Name
* Description
* Local repository paths
* Environment classifications
* Creation time
* Last updated time
* Archived status
* Password-locked status
* Auto-lock settings
* Default budget
* Notes

### Credential

Fields should include:

* ID
* Project ID
* Provider ID
* Friendly name
* Encrypted secret value
* Masked display value
* Tenant-local fingerprint
* Credential type
* Environment
* Provider-side credential ID, if available
* Provider account or project ID, if available
* Creation date
* User-entered expiration date
* Provider-reported expiration date
* Last validated time
* Last successful usage time
* Last rotated time
* Current status
* Current status reason
* Permissions or scopes
* Known local locations
* Documentation links
* Monthly budget
* Notes

### Provider

Fields should include:

* Stable provider ID
* Name
* Official website
* Official documentation URLs
* Authentication style
* Known environment-variable names
* Secret-detection patterns
* Key-prefix patterns
* Credential creation URL
* Credential management URL
* Usage capabilities
* Permission capabilities
* Rotation capabilities
* Revocation capabilities
* Pricing capabilities
* Documentation-watch configuration
* Connector version

### Usage snapshot

Fields should include:

* Credential ID, where attribution is possible
* Provider account or project ID
* Measurement period
* Request count
* Input tokens
* Output tokens
* Total tokens
* Credits
* Provider-reported cost
* Locally estimated cost
* Currency
* Source
* Attribution precision
* Collection time

### Documentation snapshot

Fields should include:

* Provider
* URL
* ETag
* Last-Modified value
* Content hash
* Last checked time
* Last changed time
* User-visible summary or change marker
* Fetch status

### Alert

Fields should include:

* Type
* Severity
* Project
* Credential
* Description
* Evidence
* Created time
* Acknowledged time
* Resolved time
* Recommended action

### Audit event

Maintain a local audit history for sensitive actions:

* Credential created
* Credential viewed
* Credential copied
* Credential changed
* Permission changed
* Credential deleted
* Credential exported
* Project unlocked
* Scan completed
* Leak detected
* Provider synchronized

Do not put credential values in audit events.

## 8. Credential status model

Implement explainable classifications.

At minimum support:

* `unknown`
* `active`
* `invalid`
* `expired`
* `expiring_soon`
* `unused`
* `stale`
* `shared_across_projects`
* `possibly_exposed`
* `over_budget`
* `suspicious_activity`
* `permission_review_needed`
* `provider_sync_failed`
* `manually_disabled`
* `revoked`

A credential can have one primary status and multiple findings.

Do not assign statuses without evidence. Every status must include:

* Reason
* Evidence source
* Observation time
* Confidence level
* Recommended action

Suggested defaults:

* Expiring soon: configurable, default 14 days.
* Unused: configurable, default 30 days.
* Stale: configurable, default 90 days since confirmed use or validation.
* Over budget: current period exceeds configured threshold.
* Suspicious activity: detected by an explicit rule and supported by available data.

## 9. Project workflow

The minimum desktop workflow should be:

### First launch

1. Create or open a local vault.
2. Set master password.
3. Display recovery and backup guidance.
4. Create the first project.
5. Optionally register a local Git repository.
6. Add or discover credentials.
7. Show the credential list and current findings.

### Project creation

Allow the user to:

* Name the project.
* Add a description.
* Select one or more repository directories.
* Set development, test, staging, or production classifications.
* Optionally password-lock the project.
* Configure expiration and budget defaults.
* Enable repository scanning.

### Credential creation

Allow the user to:

* Choose a provider from the local provider library.
* Name the credential.
* Paste or securely capture the key.
* Assign an environment.
* Enter known creation or expiration dates.
* Add documentation and notes.
* Validate the credential where a safe provider-supported method exists.
* Detect whether it is already stored in another project.
* Choose between referencing the existing credential or intentionally creating a duplicate record.

When a duplicate credential is detected, show:

* Other projects using it.
* Risks of sharing one key.
* The advantage of creating separate provider credentials.
* An option to reference the existing stored credential rather than storing another encrypted copy.
* A recommendation to create a distinct credential for production or unrelated projects.

Use a keyed local fingerprint, such as an HMAC derived from a vault-specific secret, to detect duplicate values. Do not use a simple unsalted public hash.

## 10. Minimal desktop interface

Do not spend time on visual polish, animations, branding, or a custom design system.

Build a plain, accessible, functional interface with these screens:

1. Vault create/unlock screen
2. Projects list
3. Create/edit project
4. Project details
5. Credential list
6. Add/edit credential
7. Credential details
8. Provider catalog
9. Repository scan results
10. Alerts
11. Usage summary
12. Settings
13. Backup and restore

Credential detail should clearly show:

* Provider
* Masked value
* Project
* Environment
* Status
* Expiration
* Last validation
* Last usage
* Estimated cost
* Permissions
* Known locations
* Reuse warnings
* Documentation status
* Recent alerts
* Sensitive action controls

Use confirmation dialogs for destructive actions.

Require reauthentication before:

* Revealing a credential
* Copying it
* Exporting it
* Changing its value
* Deleting it
* Changing provider permissions
* Revoking it

## 11. CLI requirements

Create a CLI named `api-tracker`.

The CLI must use the same core crates and local database as the desktop application.

Support commands similar to:

```bash
api-tracker init
api-tracker unlock
api-tracker lock
api-tracker doctor

api-tracker project create
api-tracker project list
api-tracker project show <project>
api-tracker project lock <project>
api-tracker project unlock <project>
api-tracker project archive <project>

api-tracker key add --project <project>
api-tracker key list --project <project>
api-tracker key show <credential>
api-tracker key validate <credential>
api-tracker key status <credential>
api-tracker key reveal <credential>
api-tracker key remove <credential>

api-tracker provider list
api-tracker provider show <provider>
api-tracker provider docs <provider>
api-tracker provider check-docs <provider>
api-tracker provider sync <provider>

api-tracker usage sync
api-tracker usage report
api-tracker alerts list

api-tracker scan <path>
api-tracker scan --history <path>
api-tracker hooks install <path>
api-tracker hooks remove <path>
```

Add a secure process-injection command if the core architecture allows it safely:

```bash
api-tracker run --project <project> -- <command>
```

This command should:

* Unlock the necessary project.
* Inject selected credentials into the child process environment.
* Avoid writing a `.env` file.
* Avoid printing values.
* Remove access when the child process exits.
* Support explicit credential-to-environment-variable mappings.
* Never expose unrelated project credentials.

If this cannot be implemented safely in the first session, design the interface, add tests around the intended contract, and document the remaining work. Do not create a fake command.

CLI output must redact secret values by default.

## 12. Provider/API library

Create a local provider catalog backed by version-controlled provider manifests.

Initial providers should include at least:

* OpenAI
* Anthropic
* GitHub
* Stripe
* Supabase

Each provider manifest should include:

* Provider name
* Description
* Official documentation links
* Credential-management link
* Known environment-variable names
* Known token prefixes or safe detection patterns
* General authentication guidance
* Whether keys expire
* Whether usage can be queried
* Whether usage can be attributed per key
* Whether permissions can be queried
* Whether permissions can be changed
* Whether keys can be created, rotated, disabled, or revoked programmatically
* Current connector implementation status

Use a capability matrix. For example:

```text
ProviderCapability
- validateCredential
- listCredentials
- fetchCredentialMetadata
- fetchUsage
- fetchPermissions
- changePermissions
- createCredential
- disableCredential
- revokeCredential
- rotateCredential
- fetchPricing
- watchDocumentation
```

Every provider adapter must explicitly declare supported and unsupported capabilities.

Never infer support merely because a provider has an API.

Provider-specific network calls must happen directly from the local machine.

Store administrative provider credentials in the encrypted vault like any other secret.

## 13. Documentation change notifications

Implement a local documentation watcher.

The user should be able to watch selected official documentation pages for each provider.

Use efficient checks where supported:

* ETag
* Last-Modified
* Conditional requests
* Content hashes

Requirements:

* Respect robots directives, provider terms, and rate limits.
* Do not circumvent authentication, bot protection, or access controls.
* Do not repeatedly download entire sites.
* Watch only explicit official URLs from provider manifests or URLs selected by the user.
* Store the minimum needed information.
* Do not redistribute full documentation content.
* Notify the user when the page’s tracked content changes.
* Show the old and new check times.
* Link to the official page.
* Clearly state that a page change does not necessarily mean a breaking API change.
* Allow watch frequency configuration.
* Default to a conservative interval.
* Handle offline mode and failed checks gracefully.

For the MVP, a reliable content-change notification is sufficient. Do not build an elaborate semantic-diff AI system.

## 14. Repository and commit scanning

The phrase “scan every commit” should be implemented through several local mechanisms:

### On-demand repository scan

Scan approved local repositories for likely credentials.

Support:

* Working tree
* Staged files
* Recent commits
* Full Git history when explicitly requested
* Common text configuration formats
* `.env` files
* JSON, YAML, TOML, XML, source code, scripts, logs, and documentation

### Pre-commit hook

Install a local pre-commit hook that scans staged changes before a commit succeeds.

Requirements:

* Fast enough for normal development.
* Scan only staged changes by default.
* Block likely high-confidence secrets.
* Show filename and line number.
* Never print the full credential.
* Support “ignore once” and permanent suppression with an explicit reason.
* Store suppressions locally.
* Detect known provider key patterns.
* Include generic high-entropy detection as a secondary signal.
* Minimize false positives.
* Do not send code or findings anywhere.

### Background monitoring

For registered projects, allow the desktop app to detect new local commits and schedule a local scan.

Do not implement aggressive filesystem polling that wastes battery. Prefer filesystem notifications or periodic lightweight checks.

### Secret matching

When a detected secret matches a credential already in the vault:

* Identify the affected credential.
* Identify every project referencing it.
* Mark it as possibly exposed.
* Recommend rotation.
* Do not automatically revoke it.

When the secret is unknown:

* Show a redacted preview.
* Suggest the likely provider.
* Offer to add it to the vault.
* Recommend removing it from the repository.

### Git-history safety

Do not automatically rewrite Git history.

Explain that deleting a secret from the latest file does not remove it from existing history.

Provide safe instructions or an explicitly confirmed workflow for history cleanup.

## 15. Usage and cost tracking

Important limitation: an API key itself usually does not contain usage metadata. Usage must come from provider administration APIs, billing APIs, project-level APIs, or local request instrumentation.

Implement a provider usage layer that records the precision of every measurement.

Possible attribution levels:

* Exact credential
* Provider project
* Provider account
* Local process
* Local application project
* Unknown

Never display account-level cost as exact per-key cost.

Support both:

* Provider-reported cost
* Locally estimated cost

Estimated cost should:

* Use a versioned pricing record.
* Record the pricing source and retrieval date.
* Clearly say “estimated.”
* Account for input and output token prices separately when relevant.
* Avoid silently using stale prices.
* Allow manual price overrides.
* Handle models and pricing units that do not use tokens.
* Support requests, credits, compute units, and flat charges where relevant.

For initial adapters, implement the deepest officially available usage sync possible. Where real provider access is unavailable during development, use mocks and fixture responses.

Do not require real production credentials to run tests.

## 16. Request tracking and suspicious-activity alerts

Request tracking depends on available provider data.

Implement a normalized activity model that can accept:

* Provider usage snapshots
* Provider audit events
* Local process-injection events
* Future local proxy events
* Future SDK instrumentation

Start with explainable local rules such as:

* Request volume exceeds the recent baseline.
* Cost increases significantly compared with previous periods.
* An unused credential suddenly becomes active.
* Validation begins failing repeatedly.
* A credential is used across unrelated projects.
* Usage continues after the credential was marked disabled.
* Activity appears in an unexpected provider project.
* A production credential is configured in a development project.
* A credential exceeds its budget.
* A credential appears in Git history.

Every alert must show:

* The exact rule
* Supporting measurements
* Time window
* Confidence
* Recommended next action

Do not label behavior malicious without evidence.

Do not automatically revoke or rotate credentials in this version.

Implement a local scheduler for periodic provider syncs, document checks, expiration checks, and repository scans.

Use native desktop notifications where available.

## 17. Permissions tracking and changes

Create a normalized permission representation while preserving provider-specific raw scopes.

For each credential, show:

* Raw provider scopes
* Human-readable interpretation
* Read versus write capabilities
* Administrative capabilities
* Production-sensitive permissions
* Last synchronized time
* Source of the permission information

Where the provider supports permission changes:

1. Show the proposed change.
2. Explain the effect.
3. Require reauthentication.
4. Require explicit confirmation.
5. Make the provider request directly from the local device.
6. Refresh and verify the resulting permissions.
7. Record a local audit event.
8. Handle partial failures.

Where the provider does not support changes:

* Mark the operation unsupported.
* Show official manual instructions or open the official management page.
* Never pretend the change succeeded.

Do not attempt to reverse-engineer or automate unsupported private provider APIs.

## 18. Duplicate credential and reuse intelligence

Detect the same credential across multiple projects using a local keyed fingerprint.

Classify reuse as:

* Same project, multiple environments
* Same provider credential across related projects
* Same production credential in development
* Same credential across unrelated projects
* Intentional shared credential
* Unknown

Show useful recommendations:

* Create a separate credential per project.
* Create separate development and production credentials.
* Keep one encrypted source of truth and reference it from multiple projects.
* Set separate budgets where the provider supports project-level attribution.
* Rotate the credential if an old project no longer needs it.

Do not automatically duplicate secret values.

Prefer references to one vault entry when the developer intentionally shares a credential.

## 19. Backups, export, and recovery

Implement:

* Encrypted local backup
* Explicit backup creation
* Backup verification
* Restore into a new vault or existing vault with conflict handling
* Versioned backup format
* Recovery documentation
* Export of non-secret metadata
* Separate, strongly confirmed encrypted secret export

Never export plaintext by default.

Do not implement insecure “forgot password” recovery that bypasses encryption.

Clearly explain that losing both the password and recovery material may make the vault unrecoverable.

## 20. Testing requirements

Add meaningful automated tests.

At minimum:

### Unit tests

* Encryption and decryption
* Wrong password
* Corruption detection
* Redaction
* Fingerprinting
* Duplicate detection
* Status classification
* Cost estimation
* Provider capability handling
* Documentation hashing
* Alert rules
* Secret-pattern detection

### Integration tests

* SQLite migrations
* Project creation
* Credential lifecycle
* Project locking
* Backup and restore
* CLI and desktop core compatibility
* Git staged-file scanning
* Hook installation
* Provider adapter mocks
* Failed provider synchronization
* Permission-change confirmation flow

### End-to-end tests

Cover the central path:

1. Create vault.
2. Create project.
3. Add credential.
4. Lock and unlock project.
5. Detect duplicate credential.
6. Register repository.
7. Detect a fake test-pattern secret.
8. Generate a finding.
9. View status in CLI and desktop app.
10. Create and restore an encrypted backup.

Use obvious fake credentials designed only for testing.

Add regression tests ensuring that secrets never appear in logs or serialized errors.

## 21. Logging and error handling

Use structured local logs.

Requirements:

* Redact all known credentials.
* Redact authorization headers.
* Redact query parameters likely to contain secrets.
* Avoid request-body logging by default.
* Keep logs local.
* Make log retention configurable.
* Support a diagnostic bundle that excludes secrets.
* Display actionable error messages.
* Distinguish offline errors, authentication errors, permission errors, rate limits, unsupported capabilities, and provider outages.

Implement a top-level error boundary in the desktop app and consistent typed errors in Rust.

## 22. Packaging and release readiness

Set up development and packaging for:

* macOS
* Windows
* Linux

It is acceptable to prioritize macOS for the first manually tested build, but the architecture and automated build configuration must remain cross-platform.

Create:

* Local development instructions
* Build instructions
* Packaging scripts
* GitHub Actions for formatting, linting, tests, and builds
* Dependency update configuration
* Security policy
* Contribution guide
* Issue templates
* Pull request template
* Changelog
* Architecture overview
* Threat model
* Provider connector guide
* Release checklist

Do not claim production code signing unless certificates are actually configured.

Document the later need for:

* Apple Developer ID signing and notarization
* Windows code-signing certificate
* Linux packaging verification
* Release artifact checksums
* Reproducible-build improvements

## 23. Open-source expectations

If the repository has no license, use Apache-2.0 as the default for now and clearly mention this assumption in the final report.

Write documentation that makes it possible for another developer to:

* Build the application.
* Run the desktop app.
* Use the CLI.
* Create a provider connector.
* Add secret-detection patterns.
* Run tests.
* Report a vulnerability safely.

Avoid branding work. Use “Tethra” as the working name throughout the codebase.

## 24. Git and GitHub workflow

Before changing files:

1. Inspect the repository.
2. Run `git status`.
3. Check existing branches and remotes.
4. Verify that the origin points to:
   `https://github.com/Arnavtaduvayi/API-Tracker`
5. Preserve existing work.
6. Determine whether the repository is empty, private, or unavailable.
7. Verify GitHub authentication with the existing user configuration.
8. Do not request or store a GitHub token in source files.

Create a working branch such as:

```text
feat/local-first-mvp
```

Use small, descriptive conventional commits.

Examples:

```text
chore: initialize local-first desktop workspace
feat: add encrypted project vault
feat: add credential status classification
feat: add repository secret scanner
feat: add provider manifest system
test: cover encrypted backup restoration
docs: add threat model and connector guide
```

After each meaningful milestone:

1. Run formatting.
2. Run linting.
3. Run relevant tests.
4. Build affected packages.
5. Review `git diff`.
6. Verify no credentials or generated vault files are staged.
7. Commit only if checks pass.
8. Push the working branch to GitHub.

Do not:

* Force-push.
* Rewrite shared history.
* Commit directly over unrelated user work.
* Commit broken checkpoints.
* Commit `.env` files.
* Commit local vault databases.
* Commit test credentials that resemble live credentials.
* Include Claude as a co-author.
* Add “Generated by Claude” to commits or pull requests.
* Add a Claude session URL to commits or pull requests.
* Change the user’s Git author identity.

Add or update the project-level Claude Code settings to disable commit attribution, pull-request attribution, and session-link attribution:

```json
{
  "attribution": {
    "commit": "",
    "pr": "",
    "sessionUrl": false
  }
}
```

Verify generated commit messages manually before pushing.

## 25. Implementation milestones

Work through these milestones in order.

### Milestone 0: Repository assessment

* Inspect all existing code.
* Identify current architecture and incomplete work.
* Run existing tests.
* Write a concise implementation plan.
* Create the feature branch.
* Do not stop after the plan.

### Milestone 1: Foundation

* Initialize workspace.
* Set up Tauri desktop app.
* Set up shared Rust core.
* Set up CLI.
* Add SQLite and migrations.
* Add formatting, linting, tests, and CI.
* Add baseline documentation.

### Milestone 2: Secure local vault

* Master-password setup.
* Root-key wrapping.
* Per-project encryption keys.
* Project-level password locks.
* Auto-lock.
* Credential encryption.
* Redaction.
* Backup and restore.
* Security tests.

### Milestone 3: Project and credential workflows

* Create/edit/archive projects.
* Add/edit/remove credentials.
* Provider selection.
* Status and expiration tracking.
* Duplicate detection.
* Minimal desktop screens.
* CLI parity.

### Milestone 4: Provider catalog and connectors

* Provider manifest schema.
* Initial provider records.
* Connector capability interface.
* Mock adapters.
* At least one real provider validation or metadata integration where officially supported.
* Clear unsupported states.

### Milestone 5: Git scanning

* Pattern engine.
* Entropy heuristics.
* Repository scan.
* Staged-diff scan.
* Pre-commit hook.
* Local findings.
* Redacted output.
* Tests.

### Milestone 6: Usage and alerts

* Usage snapshots.
* Cost-estimation engine.
* Versioned pricing records.
* Local scheduler.
* Expiration alerts.
* Budget alerts.
* Reuse alerts.
* Suspicious-activity rules.
* Desktop notifications.

### Milestone 7: Documentation watcher

* Official URL registry.
* ETag and Last-Modified handling.
* Content hashing.
* Change alerts.
* Offline and failure behavior.
* Rate limiting.

### Milestone 8: Permission management foundation

* Normalized scope model.
* Provider raw scopes.
* Capability checks.
* Confirmation workflow.
* At least one supported read-only permission sync if possible.
* Manual fallback for unsupported providers.

### Milestone 9: Shipping preparation

* Full test suite.
* Security review.
* Dependency audit.
* Cross-platform build checks.
* README walkthrough.
* Threat model.
* Contribution documentation.
* Release checklist.
* Demo using fake credentials.
* Final push.

If the session cannot complete every milestone, fully complete the earliest milestones rather than leaving all features partially implemented.

The minimum acceptable outcome is a working, tested application where a developer can:

1. Create an encrypted vault.
2. Create a project.
3. Add an encrypted API credential.
4. Password-lock the project.
5. Track expiration and status.
6. detect reuse across projects.
7. interact through both desktop app and CLI.
8. scan a repository and staged changes.
9. browse the provider catalog.
10. receive at least basic local alerts.
11. create and restore an encrypted backup.

## 26. Acceptance criteria

The product is not complete merely because the code compiles.

Before declaring a milestone complete:

* Desktop app starts successfully.
* CLI starts successfully.
* Both use the same vault.
* Tests pass.
* Formatting and linting pass.
* Sensitive values are encrypted at rest.
* Sensitive values are redacted from logs and errors.
* A project can be password-locked and unlocked.
* A duplicate credential can be detected across projects.
* A fake credential in a staged file can block a test commit.
* Unsupported provider capabilities are honestly labeled.
* Backup and restore work.
* The README reproduces setup from a clean machine.
* No real secrets are present in the repository.
* The working branch is pushed.

## 27. Decision-making behavior

Use your engineering judgment.

Do not pause for minor implementation choices. Make reasonable, secure assumptions and record them in:

```text
docs/decisions/
```

Ask for user input only when blocked by something that cannot be safely assumed, such as:

* Missing repository access
* A destructive Git operation
* A required signing certificate
* A real provider credential needed for live verification
* A license conflict with existing repository files

Do not weaken security to save time.

Do not invent provider API behavior.

Do not silently skip failed tests.

Do not declare features finished if they are only represented by empty interfaces or TODO comments.

When a feature cannot be completed, leave:

* A clean interface
* Tests for completed behavior
* A documented limitation
* A specific follow-up issue
* No misleading UI

## 28. Final session report

At the end of the session, provide:

1. What was implemented
2. What is fully working
3. What is partially implemented
4. What remains
5. Architecture decisions
6. Security decisions
7. Tests run and their results
8. Desktop and CLI run instructions
9. Current provider-support matrix
10. Git commits created
11. Branch pushed
12. Repository status
13. Exact blockers requiring user action
14. Recommended next session prompt

Begin by inspecting the repository and current environment. Then implement the product. Do not stop after writing a plan.
