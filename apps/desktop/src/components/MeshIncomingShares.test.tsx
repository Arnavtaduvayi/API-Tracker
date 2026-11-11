// "Credentials shared with this device" (Tethra Mesh, Increment 11; ADR
// 0033): nothing imports on render or on the Devices poll; an import needs a
// chosen local project and the master password (re-verified in core); the
// result shows the masked value only. Fake values only.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { LOCAL_ID, SHARE_ID, localProject, shareRow, sharesList } from "./MeshTestFixtures";

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      meshSharesList: vi.fn(),
      meshCredentialImport: vi.fn(),
      projectList: vi.fn(),
    },
  };
});

import { api } from "../api";
import { MeshIncomingShares } from "./MeshIncomingShares";

const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>;
const PW = "fake-master-pw-0002";

function rows() {
  return [
    shareRow(),
    shareRow({
      share_id: "6f".repeat(16),
      credential_name: "FAKE_IMPORTED",
      imported: {
        credential_id: "c-1",
        credential_name: "FAKE_IMPORTED",
        project_id: LOCAL_ID,
        project_name: "fake-local",
        imported_at: "2026-11-03T00:00:00Z",
      },
    }),
    shareRow({ share_id: "7a".repeat(16), credential_name: "FAKE_REVOKED", revoked: true }),
  ];
}

beforeEach(() => {
  mockApi.meshSharesList.mockResolvedValue(sharesList({ incoming: rows() }));
  mockApi.projectList.mockResolvedValue([localProject()]);
  mockApi.meshCredentialImport.mockResolvedValue({
    credential: {
      id: "c-2",
      project_id: LOCAL_ID,
      project_name: "fake-local",
      name: "FAKE_API_KEY",
      provider: "openai",
      masked_value: "sk-t…99",
    },
    share_id: SHARE_ID,
    sharer: "22".repeat(16),
    sharer_name: "test-desktop",
    replaced: false,
    reuse_warnings: [],
  });
});

describe("MeshIncomingShares", () => {
  it("lists shares with their state; only an available one can be imported", async () => {
    render(<MeshIncomingShares refreshKey={0} />);
    const row = (await screen.findByText("FAKE_API_KEY")).closest("tr") as HTMLElement;
    expect(within(row).getByText("available")).toBeInTheDocument();
    expect(within(row).getByText("test-desktop (22222222)")).toBeInTheDocument();
    const imported = screen.getByText("FAKE_IMPORTED").closest("tr") as HTMLElement;
    expect(
      within(imported).getByText("imported as fake-local/FAKE_IMPORTED"),
    ).toBeInTheDocument();
    expect(within(imported).queryByRole("button")).toBeNull();
    const revoked = screen.getByText("FAKE_REVOKED").closest("tr") as HTMLElement;
    expect(within(revoked).getByText("revoked")).toBeInTheDocument();
    expect(within(revoked).queryByRole("button")).toBeNull();
  });

  it("never imports on render or on a refresh; only opening collects old shares", async () => {
    const { rerender } = render(<MeshIncomingShares refreshKey={0} />);
    await screen.findByText("FAKE_API_KEY");
    rerender(<MeshIncomingShares refreshKey={1} />);
    await waitFor(() => expect(mockApi.meshSharesList).toHaveBeenCalledTimes(2));
    expect(mockApi.meshSharesList).toHaveBeenNthCalledWith(1, true);
    expect(mockApi.meshSharesList).toHaveBeenNthCalledWith(2, false);
    expect(mockApi.meshCredentialImport).not.toHaveBeenCalled();
    expect(mockApi.projectList).not.toHaveBeenCalled();
  });

  it("imports into the chosen project only after the master password, showing the masked value", async () => {
    const user = userEvent.setup();
    const onChanged = vi.fn();
    render(<MeshIncomingShares refreshKey={0} onChanged={onChanged} />);
    await user.click(
      await screen.findByRole("button", {
        name: "Import FAKE_API_KEY from test-desktop (22222222)",
      }),
    );
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
    await user.selectOptions(await screen.findByLabelText("Project on this device"), LOCAL_ID);
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(mockApi.meshCredentialImport).not.toHaveBeenCalled();
    await user.type(screen.getByLabelText("Master password"), PW);
    await user.click(screen.getByRole("button", { name: "Import" }));
    await waitFor(() =>
      expect(mockApi.meshCredentialImport).toHaveBeenCalledWith(
        PW,
        SHARE_ID,
        LOCAL_ID,
        false,
        "development",
      ),
    );
    expect(
      await screen.findByText("Imported fake-local/FAKE_API_KEY (sk-t…99)."),
    ).toBeInTheDocument();
    expect(onChanged).toHaveBeenCalled();
  });

  it("passes replace when asked, and scrubs the password from a failure", async () => {
    const user = userEvent.setup();
    mockApi.meshCredentialImport.mockRejectedValue({
      code: "mesh_share_binding_mismatch",
      message: `mismatch ${PW}`,
    });
    render(<MeshIncomingShares refreshKey={0} />);
    await user.click(
      await screen.findByRole("button", {
        name: "Import FAKE_API_KEY from test-desktop (22222222)",
      }),
    );
    await user.selectOptions(await screen.findByLabelText("Project on this device"), LOCAL_ID);
    await user.click(screen.getByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.type(screen.getByLabelText("Master password"), PW);
    await user.click(screen.getByRole("button", { name: "Import" }));
    await waitFor(() =>
      expect(mockApi.meshCredentialImport).toHaveBeenCalledWith(
        PW,
        SHARE_ID,
        LOCAL_ID,
        true,
        "development",
      ),
    );
    expect(await screen.findByText(/mismatch \[hidden\]/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(PW);
  });

  it("lists a share from a removed device without an import", async () => {
    mockApi.meshSharesList.mockResolvedValue(
      sharesList({
        incoming: [shareRow({ credential_name: "FAKE_GONE", sharer_active: false })],
      }),
    );
    render(<MeshIncomingShares refreshKey={0} />);
    const row = (await screen.findByText("FAKE_GONE")).closest("tr") as HTMLElement;
    expect(
      within(row).getByText("from a removed device (cannot be imported)"),
    ).toBeInTheDocument();
    expect(within(row).queryByRole("button")).toBeNull();
  });
});
