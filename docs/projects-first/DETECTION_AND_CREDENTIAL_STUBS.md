# Detection and unfinished credential records

## What detection reads

The existing bounded, non-executing scanner, unchanged. Its limits are
test-pinned, not merely documented: depth 6, 2 000 candidate files, 20 000
directories, 256 KiB per file checked from the directory entry *before* the file
is opened, 64 MiB total, 20 seconds. Symlinks are refused. The filesystem root,
every spelling of the home directory, and `/Users` are refused outright. Git
access goes through a sealed `--git-dir` and never spawns a subprocess on this
path.

## Where a detected record comes from

Two sources, neither of which carries a value:

* `Evidence::SecretEnvVarName { var, file }` — a credential-shaped variable the
  scan saw in a file, attributed to a provider Tethra recognises. Its own
  documentation states the value never leaves the parse.
* `ProjectDetection::unrecognized` — a credential-shaped variable that matched no
  provider. It carries the variable name, the file, and a name hint derived from
  the variable name alone.

`ProviderDetection::credential_candidates` is **not** a source. It holds the
names of credentials the project *already holds* (the vault-side S4 signal), and
a non-empty list is what marks a detection `already_have_credential`. Reading it
as "variables found in the project" was a mistake caught by a test, and the
comment in `derive_detections` says so.

## No value can be stored

`detected_credentials` has no column capable of holding a secret. This is
structural: the guarantee does not depend on a predicate a later edit could
loosen, and a caller that somehow held a value could not persist it through this
table.

`crates/tracking/tests/projects_first.rs::no_secret_value_reaches_a_detected_credential_row`
writes a canary as the value of two variables in a fixture, runs the real
detection and persistence path, then dumps **every column of every row** and
greps for the canary — and separately checks the serialized preview DTO. Not "the
predicate rejects this shape"; a sweep.

## Fields

```text
env_var                 ANTHROPIC_API_KEY        the NAME
suggested_provider      anthropic                presentation only
suggested_name          anthropic-api-key        derived from the name
suggested_environment   NULL                     unknown, never guessed
source_kind             manifest | env_file | dependency
source_file             .env                     FOLDER-RELATIVE, never absolute
status                  pending | completed | ignored | external | merged
resolved_credential_id  NULL until completed/merged
```

`suggested_environment` stays `NULL` and renders as `unknown`. An environment is
not derivable from a variable name, and guessing would put a wrong answer in
front of the user as though Tethra knew it.

`source_file` is relative so a row does not record where on disk the user keeps
their work.

## What the user can do

Confirm or change the provider, rename, choose the environment, ignore, mark as
intentionally external, or merge with an existing credential. To supply the
value, add the credential to the project through the normal credential form.

There is no import-from-`.env` action. Adding one would mean this layer reading a
value, and the whole design is that it cannot.

The status CHECK keeps an unrecognized value out of the table, and two
combinations are refused rather than silently accepted:

* `completed` or `merged` without the credential it resolved to;
* `ignored` or `external` *with* one — both mean "there is no Tethra record for
  this", so storing one would contradict the sentence the user is shown.

## Re-detection

Keyed `(project_id, env_var, source_file)`. Re-running detection refreshes
`last_detected_at` and, for a still-pending row, its suggestions — so a better
provider guess reaches the user. A row the user set to `ignored`, `external`,
`completed` or `merged` keeps that status: a rescan never resurrects a decision.

The same variable in a different file is a different finding, because it may
belong to a different environment.

## Approximately thirty integrations

Every detection reaches the surface; none is silently dropped. Pinned by
`about_thirty_detections_all_appear`, which asserts all 30 are listed and all 30
are counted as needing attention.

## Repository content is not authorization

Unchanged from ADR 0024. Only `Configurability::Automatic` providers at
confidence `>= Likely` are configured. A destination read from project files
appears as a pending approval and is excluded from the plan;
`a_repository_discovered_destination_is_not_pre_approved` asserts that such a
folder produces no plan, an empty digest, and no approval row.
