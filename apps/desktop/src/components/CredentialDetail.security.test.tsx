import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Credential } from "../types";

// Mock the whole api module: the component's security behavior is what it
// asks the backend to do and how it renders secrets — not the real IPC.
vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      credentialGet: vi.fn(),
      credentialPermissions: vi.fn().mockResolvedValue(null),
      providerGet: vi.fn().mockRejectedValue(new Error("no manifest")),
      credentialReveal: vi.fn(),
      credentialCopy: vi.fn(),
      credentialDelete: vi.fn(),
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
  credentialReveal: ReturnType<typeof vi.fn>;
  credentialCopy: ReturnType<typeof vi.fn>;
  credentialDelete: ReturnType<typeof vi.fn>;
};

function credential(overrides: Partial<Credential> = {}): Credential {
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
    ...overrides,
  };
}

async function renderDetail(cred: Credential) {
  mockApi.credentialGet.mockResolvedValue(cred);
  render(<CredentialDetail id={cred.id} onBack={vi.fn()} onEdit={vi.fn()} />);
  await screen.findByText(`${cred.project_name}/${cred.name}`);
}

beforeEach(() => {
  mockApi.credentialGet.mockReset();
  mockApi.credentialReveal.mockReset();
  mockApi.credentialCopy.mockReset();
  mockApi.credentialDelete.mockReset();
});

describe("CredentialDetail — secret reveal and clearing", () => {
  it("reveals the plaintext after reauth, then clears it on hide", async () => {
    const user = userEvent.setup();
    mockApi.credentialReveal.mockResolvedValue("FAKE-REVEALED-SECRET");
    await renderDetail(credential());

    await user.click(screen.getByRole("button", { name: "Reveal value" }));
    await user.type(screen.getByLabelText(/master password/i), "master-pw");
    await user.click(screen.getByRole("button", { name: "Confirm" }));

    expect(mockApi.credentialReveal).toHaveBeenCalledWith("cred-1", "master-pw");
    expect(await screen.findByText("FAKE-REVEALED-SECRET")).toBeInTheDocument();

    // Hiding removes the plaintext from the DOM.
    await user.click(screen.getByRole("button", { name: "hide" }));
    await waitFor(() =>
      expect(screen.queryByText("FAKE-REVEALED-SECRET")).not.toBeInTheDocument(),
    );
  });

  it("does not reveal when reauth fails (secret never rendered)", async () => {
    const user = userEvent.setup();
    mockApi.credentialReveal.mockRejectedValue({
      code: "wrong_password",
      message: "wrong password",
    });
    await renderDetail(credential());

    await user.click(screen.getByRole("button", { name: "Reveal value" }));
    await user.type(screen.getByLabelText(/master password/i), "bad-pw");
    await user.click(screen.getByRole("button", { name: "Confirm" }));

    expect(await screen.findByText("wrong password")).toBeInTheDocument();
    expect(screen.queryByText("FAKE-REVEALED-SECRET")).not.toBeInTheDocument();
  });
});

describe("CredentialDetail — copy state", () => {
  it("shows the clipboard-clear delay reported by the backend", async () => {
    const user = userEvent.setup();
    mockApi.credentialCopy.mockResolvedValue(15);
    await renderDetail(credential());

    await user.click(screen.getByRole("button", { name: "Copy value" }));
    await user.type(screen.getByLabelText(/master password/i), "master-pw");
    await user.click(screen.getByRole("button", { name: "Confirm" }));

    expect(mockApi.credentialCopy).toHaveBeenCalledWith("cred-1", "master-pw");
    expect(
      await screen.findByText(/clipboard will be cleared in about 15 seconds/i),
    ).toBeInTheDocument();
  });
});

describe("CredentialDetail — destructive delete confirmation", () => {
  it("requires reauth and passes the password to the backend delete", async () => {
    const user = userEvent.setup();
    const onBack = vi.fn();
    mockApi.credentialDelete.mockResolvedValue(undefined);
    mockApi.credentialGet.mockResolvedValue(credential());
    render(<CredentialDetail id="cred-1" onBack={onBack} onEdit={vi.fn()} />);
    await screen.findByText("web/openai-main");

    await user.click(screen.getByRole("button", { name: "Delete…" }));
    // The reauth dialog IS the confirmation for delete.
    await user.type(screen.getByLabelText(/master password/i), "master-pw");
    await user.click(screen.getByRole("button", { name: "Delete permanently" }));

    expect(mockApi.credentialDelete).toHaveBeenCalledWith("cred-1", "master-pw");
    await waitFor(() => expect(onBack).toHaveBeenCalledWith("proj-1"));
  });
});

describe("CredentialDetail — unsafe docs_url rejection (IPC-05)", () => {
  it("renders a javascript: docs_url as inert text, never an anchor", async () => {
    await renderDetail(credential({ docs_url: "javascript:alert(document.cookie)" }));
    expect(screen.getByText(/not a safe link/i)).toBeInTheDocument();
    // No anchor element carries the dangerous href.
    const anchors = document.querySelectorAll("a[href]");
    anchors.forEach((a) => expect(a.getAttribute("href")).not.toContain("javascript:"));
  });

  it("renders an https docs_url as a real anchor", async () => {
    await renderDetail(credential({ docs_url: "https://platform.openai.com/docs" }));
    const link = screen.getByRole("link", { name: "https://platform.openai.com/docs" });
    expect(link).toHaveAttribute("href", "https://platform.openai.com/docs");
    expect(link).toHaveAttribute("rel", "noreferrer");
  });
});
