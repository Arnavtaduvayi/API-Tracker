// Outside a mesh (Tethra Mesh, Increment 09): create or join. The invite is a
// bearer secret: after a failed join it stays only in its own input (so a
// typo can be fixed) and never in any error text; after a successful join it
// is cleared. All values are obviously fake.

import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("@tauri-apps/plugin-opener", () => ({
  openUrl: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      meshInit: vi.fn(),
      meshJoin: vi.fn(),
    },
  };
});

import { openUrl } from "@tauri-apps/plugin-opener";
import { api } from "../api";
import { MeshSetup } from "./MeshSetup";
import { MESH_GUIDE_URL } from "./MeshCommon";

const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>;

const INVITE = "tethra-mesh-invite:v1:FAKEFAKEFAKE@127.0.0.1:7700";
const SELF_ID = "11".repeat(16);

function inviteField(): HTMLInputElement {
  return screen.getByLabelText("Invite") as HTMLInputElement;
}

function joinForm() {
  return screen.getByRole("form", { name: "Join a mesh" });
}

async function fillJoin(user: ReturnType<typeof userEvent.setup>) {
  await user.type(inviteField(), INVITE);
  const names = screen.getAllByLabelText(/^Device name/);
  // The second "Device name" field belongs to Join a mesh.
  await user.type(names[1], "test-desktop");
}

describe("MeshSetup", () => {
  it("opens the user guide with the opener plugin", async () => {
    const user = userEvent.setup();
    render(<MeshSetup onDone={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Read the mesh user guide" }));
    expect(openUrl).toHaveBeenCalledWith(MESH_GUIDE_URL);
    expect(MESH_GUIDE_URL).toMatch(/^https:\/\/github\.com\/Arnavtaduvayi\/API-Tracker\//);
  });

  it("creates a mesh with the device name", async () => {
    const user = userEvent.setup();
    const onDone = vi.fn();
    mockApi.meshInit.mockResolvedValue({
      mesh_id: "ab".repeat(16),
      device_id: SELF_ID,
      device_name: "test-laptop",
      created_at: new Date().toISOString(),
    });
    render(<MeshSetup onDone={onDone} />);
    await user.type(screen.getAllByLabelText(/^Device name/)[0], " test-laptop ");
    await user.click(screen.getByRole("button", { name: "Create mesh" }));
    await waitFor(() => expect(mockApi.meshInit).toHaveBeenCalledWith("test-laptop"));
    expect(onDone).toHaveBeenCalledWith({
      notice: "Created a mesh. This device is test-laptop (11111111).",
    });
  });

  it("joins, clears the invite, and warns when the inviter is not verified", async () => {
    const user = userEvent.setup();
    const onDone = vi.fn();
    mockApi.meshJoin.mockResolvedValue({
      mesh_id: "ab".repeat(16),
      device_id: SELF_ID,
      device_name: "test-desktop",
      items_in: 12,
      first_exchange_completed: true,
      inviter_verified: false,
    });
    render(<MeshSetup onDone={onDone} />);
    await fillJoin(user);
    await user.click(screen.getByRole("button", { name: "Join mesh" }));

    await waitFor(() => expect(mockApi.meshJoin).toHaveBeenCalledWith(INVITE, "test-desktop"));
    expect(onDone).toHaveBeenCalledTimes(1);
    const outcome = onDone.mock.calls[0][0];
    expect(outcome.notice).toMatch(/Joined the mesh as test-desktop/);
    expect(outcome.warning).toMatch(/does not match its roster entry/);
    expect(JSON.stringify(outcome)).not.toContain("FAKEFAKEFAKE");
    expect(inviteField().value).toBe("");
  });

  it("does not warn about the inviter when the first exchange ended early", async () => {
    const user = userEvent.setup();
    const onDone = vi.fn();
    mockApi.meshJoin.mockResolvedValue({
      mesh_id: "ab".repeat(16),
      device_id: SELF_ID,
      device_name: "test-desktop",
      items_in: 3,
      first_exchange_completed: false,
      inviter_verified: false,
    });
    render(<MeshSetup onDone={onDone} />);
    await fillJoin(user);
    await user.click(screen.getByRole("button", { name: "Join mesh" }));
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(onDone.mock.calls[0][0].warning).toBeUndefined();
    expect(onDone.mock.calls[0][0].notice).toMatch(/ended early/);
  });

  it("on failure shows only the backend message and keeps the invite in its input", async () => {
    const user = userEvent.setup();
    const onDone = vi.fn();
    mockApi.meshJoin.mockRejectedValue({
      code: "mesh_invalid_invite",
      message: "the invite is not valid (checksum)",
    });
    render(<MeshSetup onDone={onDone} />);
    await fillJoin(user);
    await user.click(screen.getByRole("button", { name: "Join mesh" }));

    expect(await screen.findByText("the invite is not valid (checksum)")).toBeInTheDocument();
    expect(onDone).not.toHaveBeenCalled();
    // Kept for a retry, but only as the input's own value: never as text.
    expect(inviteField().value).toBe(INVITE);
    expect(document.body.textContent).not.toContain("FAKEFAKEFAKE");
    expect(joinForm()).toBeInTheDocument();
    expect(inviteField()).toHaveAttribute("autocomplete", "off");
    expect(inviteField()).toHaveAttribute("spellcheck", "false");
  });

  it("blanks an invite even if an error message were to echo it", async () => {
    const user = userEvent.setup();
    mockApi.meshJoin.mockRejectedValue({
      code: "mesh_network",
      message: `could not reach ${INVITE}`,
    });
    render(<MeshSetup onDone={vi.fn()} />);
    await fillJoin(user);
    await user.click(screen.getByRole("button", { name: "Join mesh" }));
    expect(await screen.findByText(/could not reach \[invite hidden\]/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("FAKEFAKEFAKE");
  });

  it("never shows a raw non-API rejection", async () => {
    const user = userEvent.setup();
    mockApi.meshJoin.mockRejectedValue(`raw failure ${INVITE}`);
    render(<MeshSetup onDone={vi.fn()} />);
    await fillJoin(user);
    await user.click(screen.getByRole("button", { name: "Join mesh" }));
    expect(await screen.findByText("The request failed. Try again.")).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("FAKEFAKEFAKE");
    expect(document.body.textContent).not.toContain("raw failure");
  });
});
