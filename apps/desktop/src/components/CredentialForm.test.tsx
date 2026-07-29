// A failed provider list is not "there are no providers" (NEW-41). The
// swallowed catch emptied the dropdown, which made every real provider look
// unknown and pushed the user into the free-text "Custom…" branch — storing
// a credential under a provider name no manifest backs.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import type { ProviderManifest } from "../types";

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      providersList: vi.fn(),
      credentialGet: vi.fn(),
      credentialAdd: vi.fn(),
      credentialCheckReuse: vi.fn(),
    },
  };
});

import { api } from "../api";
import { CredentialForm } from "./CredentialForm";

const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>;

function manifest(id: string, name: string): ProviderManifest {
  return {
    id,
    name,
    description: "",
    website: "",
    api_docs_url: "",
    auth_docs_url: "",
    manage_url: "",
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
    capabilities: {} as ProviderManifest["capabilities"],
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("CredentialForm provider list (NEW-41)", () => {
  it("says the provider list failed instead of showing an empty one", async () => {
    mockApi.providersList.mockRejectedValue({
      code: "ipc",
      message: "the backend did not answer",
    });
    render(<CredentialForm project="p1" onDone={vi.fn()} />);
    expect(
      await screen.findByText(/provider list could not be loaded: the backend did not answer/),
    ).toBeInTheDocument();
    expect(screen.getByText(/The choices below are incomplete/)).toBeInTheDocument();
    expect(
      screen.getByText(/not a sign that the provider you want is unsupported/),
    ).toBeInTheDocument();
  });

  it("says nothing when the list loaded", async () => {
    mockApi.providersList.mockResolvedValue([manifest("openai", "OpenAI")]);
    render(<CredentialForm project="p1" onDone={vi.fn()} />);
    expect(await screen.findByRole("option", { name: "OpenAI" })).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/provider list could not be loaded/);
  });
});
