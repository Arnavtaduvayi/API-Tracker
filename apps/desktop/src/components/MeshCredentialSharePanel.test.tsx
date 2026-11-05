// "Shared with my devices" on a credential's page (Tethra Mesh, Increment 11;
// ADR 0033): sharing needs an explicit choice of devices and the master
// password (re-verified in core); nothing is shared on render; revoke asks
// first and says it does not revoke at the provider; no value is rendered.
// Fake values only.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Credential } from "../types";
import {
  CRED_ID,
  DESKTOP_ID,
  LOCAL_ID,
  NOT_IN_MESH,
  SHARE_ID,
  inMesh,
  projectRow,
  shareRow,
  sharesList,
} from "./MeshTestFixtures";

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      meshStatus: vi.fn(),
      meshProjectsList: vi.fn(),
      meshSharesList: vi.fn(),
      meshCredentialShare: vi.fn(),
      meshCredentialReseal: vi.fn(),
      meshShareRevoke: vi.fn(),
      meshCredentialRevoke: vi.fn(),
    },
  };
});

import { api } from "../api";
import { MeshCredentialSharePanel } from "./MeshCredentialSharePanel";

const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>;
const PW = "fake-master-pw-0001";
const CANARY = "sk-test-FAKE-ui-canary-0001";

const credential = {
  id: CRED_ID,
  project_id: LOCAL_ID,
  project_name: "fake-local",
  provider: "openai",
  name: "FAKE_API_KEY",
  masked_value: "sk-t…01",
  is_reference: false,
} as unknown as Credential;

function outgoing(over = {}) {
  return shareRow({
    sharer: "11".repeat(16),
    sharer_name: "test-laptop",
    recipient: DESKTOP_ID,
    recipient_name: "test-desktop",
    local_credential_id: CRED_ID,
    current_value_version: 1,
    ...over,
  });
}

beforeEach(() => {
  mockApi.meshStatus.mockResolvedValue(inMesh());
  mockApi.meshProjectsList.mockResolvedValue([projectRow({ bound_local_project: LOCAL_ID })]);
  mockApi.meshSharesList.mockResolvedValue(sharesList());
  mockApi.meshCredentialShare.mockResolvedValue({
    credential_ref: "c7".repeat(16),
    credential_id: CRED_ID,
    credential_name: "FAKE_API_KEY",
    provider: "openai",
    value_version: 1,
    mesh_project_id: "aa".repeat(16),
    all_current: true,
    recipients: [{ device_id: DESKTOP_ID, device_name: "test-desktop", share_id: SHARE_ID }],
  });
});

describe("MeshCredentialSharePanel", () => {
  it("shows nothing outside a mesh", async () => {
    mockApi.meshStatus.mockResolvedValue(NOT_IN_MESH);
    const { container } = render(<MeshCredentialSharePanel credential={credential} />);
    await waitFor(() => expect(mockApi.meshStatus).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
    expect(mockApi.meshSharesList).not.toHaveBeenCalled();
  });

  it("asks to share the project first when it is not bound", async () => {
    mockApi.meshProjectsList.mockResolvedValue([projectRow()]);
    render(<MeshCredentialSharePanel credential={credential} />);
    expect(await screen.findByText(/first share its project/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Share with my devices…" })).toBeNull();
  });

  it("shares with all devices only after the device choice and the master password", async () => {
    const user = userEvent.setup();
    render(<MeshCredentialSharePanel credential={credential} />);
    await user.click(await screen.findByRole("button", { name: "Share with my devices…" }));
    expect(
      screen.getByText(/does not revoke the credential at its provider/),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(mockApi.meshCredentialShare).not.toHaveBeenCalled();
    expect(
      screen.getByText(/all your devices \(test-desktop \(22222222\)\)/),
    ).toBeInTheDocument();
    await user.type(screen.getByLabelText("Master password"), PW);
    await user.click(screen.getByRole("button", { name: "Share" }));
    await waitFor(() =>
      expect(mockApi.meshCredentialShare).toHaveBeenCalledWith(PW, CRED_ID, null),
    );
    expect(
      await screen.findByText(/Shared FAKE_API_KEY with test-desktop/),
    ).toBeInTheDocument();
    // The list was re-read after the action (collecting old shares first).
    expect(mockApi.meshSharesList).toHaveBeenLastCalledWith(true);
  });

  it("shares with exactly the devices ticked", async () => {
    const user = userEvent.setup();
    render(<MeshCredentialSharePanel credential={credential} />);
    await user.click(await screen.findByRole("button", { name: "Share with my devices…" }));
    await user.click(screen.getByLabelText("Only these devices:"));
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
    await user.click(screen.getByLabelText("test-desktop (22222222)"));
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.type(screen.getByLabelText("Master password"), PW);
    await user.click(screen.getByRole("button", { name: "Share" }));
    await waitFor(() =>
      expect(mockApi.meshCredentialShare).toHaveBeenCalledWith(PW, CRED_ID, [DESKTOP_ID]),
    );
  });

  it("never shows the typed password in a failure", async () => {
    const user = userEvent.setup();
    mockApi.meshCredentialShare.mockRejectedValue({
      code: "wrong_password",
      message: `bad password ${PW}`,
    });
    render(<MeshCredentialSharePanel credential={credential} />);
    await user.click(await screen.findByRole("button", { name: "Share with my devices…" }));
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.type(screen.getByLabelText("Master password"), PW);
    await user.click(screen.getByRole("button", { name: "Share" }));
    expect(await screen.findByText(/bad password \[hidden\]/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(PW);
  });

  it("lists where it is shared; revoke asks first, says what it does not do, and links rotation", async () => {
    const user = userEvent.setup();
    const onOpenRotation = vi.fn();
    // A misbehaving backend field is never rendered.
    mockApi.meshSharesList.mockResolvedValue(
      sharesList({ outgoing: [{ ...outgoing(), value: CANARY } as never] }),
    );
    mockApi.meshShareRevoke.mockResolvedValue([
      {
        share_id: SHARE_ID,
        credential_ref: "c7".repeat(16),
        credential_name: "FAKE_API_KEY",
        recipient: DESKTOP_ID,
        recipient_name: "test-desktop",
      },
    ]);
    render(
      <MeshCredentialSharePanel credential={credential} onOpenRotation={onOpenRotation} />,
    );
    expect(await screen.findByText("5e5e5e5e")).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(CANARY);
    await user.click(
      screen.getByRole("button", { name: "Revoke the share to test-desktop (22222222)" }),
    );
    expect(mockApi.meshShareRevoke).not.toHaveBeenCalled();
    expect(
      screen.getAllByText(/does not revoke the credential at its provider/).length,
    ).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(mockApi.meshShareRevoke).toHaveBeenCalledWith(SHARE_ID));
    expect(await screen.findByText(/Revoked 1 share\(s\)/)).toBeInTheDocument();
    // Cutting a device off is revoke first, then rotate: a reseal after a
    // rotation would otherwise seal the new value to that device too (MD-4).
    const notices = screen.getAllByText(
      /To cut a device off, revoke its share first, then rotate/,
    );
    expect(notices.length).toBeGreaterThan(0);
    for (const n of notices) {
      expect(n).toHaveTextContent(/a reseal never offers a device whose share you revoked/);
      expect(n).not.toHaveTextContent(/To cut a device off, rotate the credential\./);
    }
    await user.click(screen.getByRole("button", { name: "Open Rotation" }));
    expect(onOpenRotation).toHaveBeenCalled();
  });

  it("offers a reseal and performs it only with the master password", async () => {
    const user = userEvent.setup();
    mockApi.meshSharesList.mockResolvedValue(
      sharesList({
        outgoing: [outgoing({ current_value_version: 2 })],
        reseal_offers: [
          {
            credential_ref: "c7".repeat(16),
            credential_id: CRED_ID,
            credential_name: "FAKE_API_KEY",
            project_name: "fake-local",
            current_value_version: 2,
            new_devices: [],
            stale_devices: [DESKTOP_ID],
          },
        ],
      }),
    );
    mockApi.meshCredentialReseal.mockResolvedValue({
      credential_ref: "c7".repeat(16),
      credential_id: CRED_ID,
      credential_name: "FAKE_API_KEY",
      provider: "openai",
      value_version: 2,
      mesh_project_id: "aa".repeat(16),
      all_current: false,
      recipients: [{ device_id: DESKTOP_ID, device_name: "test-desktop", share_id: SHARE_ID }],
    });
    render(<MeshCredentialSharePanel credential={credential} />);
    expect(await screen.findByText(/older value \(now v2\)/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Reseal…" }));
    expect(mockApi.meshCredentialReseal).not.toHaveBeenCalled();
    await user.type(screen.getByLabelText("Master password"), PW);
    await user.click(screen.getByRole("button", { name: "Reseal" }));
    await waitFor(() => expect(mockApi.meshCredentialReseal).toHaveBeenCalledWith(PW, CRED_ID));
  });

  it("says when another device's share replaced this one at a device", async () => {
    mockApi.meshSharesList.mockResolvedValue(
      sharesList({ outgoing: [outgoing({ superseded_by: "33".repeat(16) })] }),
    );
    render(<MeshCredentialSharePanel credential={credential} />);
    expect(await screen.findByText(/replaced at the device by/)).toBeInTheDocument();
  });
});
