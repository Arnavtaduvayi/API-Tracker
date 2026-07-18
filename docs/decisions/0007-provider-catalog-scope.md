# ADR 0007: Provider catalog is informational-only in this milestone

Status: accepted (2026-07-17)

## Decision

This milestone ships a small, static, in-code provider list (OpenAI,
Anthropic, GitHub, Stripe, Supabase, AWS, Google Cloud, plus "other"):
stable id, display name, official documentation URL, official key-management
URL, and common environment-variable names. It exists so users can tag
credentials with a provider and jump to official pages. Arbitrary custom
provider names are accepted and stored normalized.

It deliberately makes **no capability claims** — no validation, usage,
permissions, rotation, or revocation support is declared or implied — and
triggers **no network requests**. The CLI/UI say so explicitly.

## Why

The product spec's provider connector architecture (manifests, capability
matrix, adapters, mocked and real integrations) is its own milestone. The
honest middle ground for this milestone is informational metadata clearly
labeled as such; the dishonest alternative — a capability matrix full of
"supported" flags with no implementation behind them — is exactly what the
spec forbids.

## Future path

The connector milestone will replace this constant list with versioned
provider manifests plus a `ProviderCapability` matrix, where every declared
capability is either implemented or explicitly `unsupported`/`not yet
implemented`. Credential records already store a free-form provider id, so
the migration is additive.
