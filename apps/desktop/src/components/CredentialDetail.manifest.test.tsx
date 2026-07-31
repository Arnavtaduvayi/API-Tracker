// A failed manifest read must not become a capability claim (NEW-38).
// `.catch(() => setManifest(null))` made "the manifest did not load" and
// "this provider does not implement it" the same state, and the screen then
// told the user OpenAI has no API key creation — on the surface whose whole
// purpose is capability honesty.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import type { Credential, ProviderManifest } from "../types";

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      credentialGet: vi.fn(),
      credentialPermissions: vi.fn().mockResolvedValue(null),
      providerGet: vi.fn(),
      credentialActivitySources: vi.fn().mockResolvedValue({
        last_gateway_observed: null,
        last_proxy_observed: null,
        last_provider_reported: null,
        last_marked_used: null,
        last_validated: null,
        most_recent: null,
      }),
    },
  };
});

import { api } from "../api";
import { CredentialDetail } from "./CredentialDetail";

const mockApi = api as unknown as {
  credentialGet: ReturnType<typeof vi.fn>;
  providerGet: ReturnType<typeof vi.fn>;
};

function credential(): Credential {
  return {
    id: "cred-1",
    project_id: "proj-1",
    project_name: "web",
    provider: "openai",
    name: "openai-main",
    environment: "production",
    credential_type: "api_key",
    masked_value: "sk-…01",
    is_reference: false,
    linked_credential_id: null,
    linked_target: null,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    key_created_at: null,
    expires_at: null,
    expires_at_invalid: false,
    provider_expires_at: null,
    provider_expires_at_invalid: false,
    last_validated_at: null,
    last_used_at: null,
    docs_url: "",
    notes: "",
    manually_disabled: false,
    revoked: false,
    marked_invalid: false,
    possibly_exposed: false,
    exposure_note: "",
    status: { primary: "active", findings: [] },
  };
}

/** A manifest that genuinely declares both operations unimplemented. */
function manifestWithout(): ProviderManifest {
  return {
    id: "openai",
    name: "OpenAI",
    description: "",
    website: "",
    api_docs_url: "",
    auth_docs_url: "",
    manage_url: "https://platform.openai.com/api-keys",
    env_vars: [],
    credential_types: [],
    expiration: "none",
    changelog_url: "",
    pricing_url: "",
    permissions_docs_url: "",
    login_url: "",
    billing_url: "",
    watch_docs: [],
    detection: [],
    gateway: null,
    capabilities: {
      create_credential: { support: "unsupported", detail: "", requires: "" },
      revoke_credential: { support: "unsupported", detail: "", requires: "" },
    } as unknown as ProviderManifest["capabilities"],
  };
}

async function renderDetail() {
  mockApi.credentialGet.mockResolvedValue(credential());
  render(<CredentialDetail id="cred-1" onBack={vi.fn()} onEdit={vi.fn()} />);
  await screen.findByText("web/openai-main");
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("CredentialDetail provider capabilities (NEW-38)", () => {
  it("does not turn a failed manifest read into 'this provider cannot do it'", async () => {
    mockApi.providerGet.mockRejectedValue({
      code: "ipc",
      message: "the backend did not answer",
    });
    await renderDetail();

    expect(
      await screen.findByText(
        /capability manifest could not be read: the backend did not answer/,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Whether openai supports API key creation is unknown/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Whether openai supports API revocation is unknown/),
    ).toBeInTheDocument();

    // The negative controls: the fabricated capability claims.
    expect(document.body.textContent).not.toMatch(/This provider has no API key creation/);
    expect(document.body.textContent).not.toMatch(/This provider has no API revocation/);
  });

  it("still states a genuinely unsupported capability as unsupported", async () => {
    mockApi.providerGet.mockResolvedValue(manifestWithout());
    await renderDetail();

    expect(
      await screen.findByText(/This provider has no API key creation/),
    ).toBeInTheDocument();
    expect(screen.getByText(/This provider has no API revocation/)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/capability manifest could not be read/);
  });
});
