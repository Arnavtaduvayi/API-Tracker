# Project Templates and Stack Detection

## Templates

Nine version-controlled templates (`templates/*.toml`, embedded and
validated at build time) seed a project with the right structure for a
stack: suggested providers, environment classifications, conventional
environment-variable names with secret/not-secret labeling,
credential-separation, permission, and rotation guidance, documentation
links, and suggested deployment destinations.

```bash
tethra template list
tethra template show fullstack-saas
tethra template apply openai-app --project my-app --write-example ~/code/my-app
```

The legacy `api-tracker` command remains available as a compatibility
alias for the same program; see `docs/rebrand/TETHRA_MIGRATION_GUIDE.md`.

Hard guarantees:

- **Templates never contain credential values** — a test proves no
  template text matches any secret-detection pattern.
- `--write-example` writes a names-only `.env.example` and refuses to
  overwrite an existing one.
- Applying a template never creates credentials. It prints the exact
  `key add` / `mapping set` commands, each of which prompts for its secret
  — values never enter through templates.

Templates: `openai-app`, `anthropic-app`, `supabase-web`, `stripe-app`,
`github-automation`, `nextjs-app`, `node-backend`, `python-backend`,
`fullstack-saas`.

## Stack detection

```bash
tethra template detect --repo ~/code/my-app     # or --project my-app
tethra template confirm openai-app --repo ~/code/my-app
tethra template dismiss node-backend --repo ~/code/my-app
```

Detection is **deterministic rules plus a locally stored confirm/dismiss
history — not machine learning** — and every surface describes it that
way. It reads a bounded set of static files: `package.json`,
`requirements.txt`, `pyproject.toml`, lockfiles, framework configuration
(`next.config.*`, `vercel.json`), workflow files, Dockerfiles, and the
variable NAMES in `.env` files (values are parsed into redacting wrappers
and never appear in results). Files over 256 KiB are skipped. Nothing is
executed; nothing leaves the machine.

Every suggestion shows its evidence lines and a confidence level, and
nothing is applied without your explicit confirmation. Decisions are
remembered per repository: a confirmed suggestion is trusted at high
confidence on later runs, a dismissed one is hidden (visible with
`--all`, always listed with its stored decision).

## The learned data — and deleting it

The complete "learning" store is one local table of
(repository, template, decision, time) rows. Inspect and delete it any
time:

```bash
tethra template prefs                       # list every stored decision
tethra template prefs --reset-repo <dir>    # forget one repository
tethra template prefs --clear-all           # delete ALL learned stack data
```

The desktop Templates screen offers the same catalog, guidance, apply,
detection-with-evidence, and learned-decision management.
