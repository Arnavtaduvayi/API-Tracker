// Devices view (Tethra Mesh, Increment 09): what renders inside and outside a
// mesh, and the security-relevant flows. The pairing invite is shown once and
// is gone from the DOM after its dialog closes; removing a device and leaving
// the mesh each need a confirmation AND then the master password, in that
// order; errors show the backend's redacted message and never echo the
// invite or the password. All values here are obviously fake.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type {
  MeshDevice,
  MeshInvite,
  MeshNodeState,
  MeshStatus,
  MeshStatusDetail,
} from "../types";

vi.mock("@tauri-apps/plugin-opener", () => ({
  openUrl: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      meshStatus: vi.fn(),
      meshInit: vi.fn(),
      meshInviteCreate: vi.fn(),
      meshJoin: vi.fn(),
      meshDevices: vi.fn(),
      meshDeviceRename: vi.fn(),
      meshDeviceRemove: vi.fn(),
      meshLeave: vi.fn(),
      meshPeersList: vi.fn(),
      meshPeerAdd: vi.fn(),
      meshPeerRemove: vi.fn(),
      meshReplicateNow: vi.fn(),
      meshDoctor: vi.fn(),
      meshNodeGetSettings: vi.fn(),
      meshNodeSetSettings: vi.fn(),
      // Increment 10: "Available from your devices".
      meshProjectsList: vi.fn(),
      meshSharesList: vi.fn(),
      meshProjectBind: vi.fn(),
      projectList: vi.fn(),
      projectCreate: vi.fn(),
    },
  };
});

import { api } from "../api";
import { DevicesView } from "./DevicesView";
import { MeshPairDialog } from "./MeshPairDialog";

const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>;

const INVITE = "tethra-mesh-invite:v1:FAKEFAKEFAKE@127.0.0.1:7700";
const PASSWORD = "test-master-password";
const SELF_ID = "11".repeat(16);
const DESKTOP_ID = "22".repeat(16);

function node(over: Partial<MeshNodeState> = {}): MeshNodeState {
  return {
    running: null,
    stopping: false,
    last_error: null,
    last_stop: null,
    external: null,
    ...over,
  };
}

const NOT_IN_MESH: MeshStatus = { initialized: false, node: node() };

function inMesh(over: Partial<MeshStatusDetail> = {}): MeshStatus {
  return {
    initialized: true,
    mesh_id: "ab".repeat(16),
    mesh_id_short: "abababab",
    genesis_device: SELF_ID,
    device_id: SELF_ID,
    device_name: "test-laptop",
    state: "active",
    next_seq: 5,
    marker: "ok",
    marker_problem: null,
    self_forked: false,
    roster_size: 2,
    devices: [],
    vv: {},
    items_by_kind: {},
    rejected_items: 0,
    clock_skew: {},
    fork_evidence: 0,
    forked_devices: 0,
    regressions: 0,
    repairs_changed: 0,
    rollback_hold: null,
    ...over,
    node: node(),
  };
}

function device(over: Partial<MeshDevice> = {}): MeshDevice {
  return {
    device_id: DESKTOP_ID,
    short_id: DESKTOP_ID.slice(0, 8),
    name: "test-desktop",
    is_self: false,
    added_by: SELF_ID,
    member: true,
    active: true,
    removed: false,
    cutoff_seq: null,
    fork_seq: null,
    last_exchange: null,
    stale: false,
    lag: null,
    ...over,
  };
}

function self(): MeshDevice {
  return device({
    device_id: SELF_ID,
    short_id: SELF_ID.slice(0, 8),
    name: "test-laptop",
    is_self: true,
    added_by: null,
  });
}

function invite(over: Partial<MeshInvite> = {}): MeshInvite {
  return {
    invite: INVITE,
    expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
    ttl_minutes: 10,
    addresses: ["127.0.0.1:7700"],
    ...over,
  };
}

function passwordField(): HTMLInputElement {
  return screen.getByLabelText(/master password/i) as HTMLInputElement;
}

/** Nothing on screen (text, attributes, input values aside) holds a secret. */
function expectNoSecretsInDom() {
  expect(document.body.textContent).not.toContain("FAKEFAKEFAKE");
  expect(document.body.textContent).not.toContain(PASSWORD);
}

beforeEach(() => {
  mockApi.meshStatus.mockResolvedValue(inMesh());
  mockApi.meshDevices.mockResolvedValue([self(), device()]);
  mockApi.meshPeersList.mockResolvedValue([]);
  mockApi.meshDoctor.mockResolvedValue({ worst: "ok", initialized: true, findings: [] });
  mockApi.meshNodeGetSettings.mockResolvedValue({
    run_while_open: false,
    listen: ["127.0.0.1:7700"],
    all_interfaces: false,
    discover: false,
  });
  mockApi.meshProjectsList.mockResolvedValue([]);
  mockApi.meshSharesList.mockResolvedValue({ incoming: [], outgoing: [], reseal_offers: [] });
});

describe("DevicesView rendering", () => {
  it("offers Create mesh and Join a mesh outside a mesh, and no in-mesh panels", async () => {
    mockApi.meshStatus.mockResolvedValue(NOT_IN_MESH);
    render(<DevicesView />);
    expect(
      await screen.findByRole("heading", { name: "This device is not in a mesh" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create mesh" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Join mesh" })).toBeInTheDocument();
    expect(screen.getByText(/Credential values do not replicate/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Leave mesh" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Pair a device" })).not.toBeInTheDocument();
    expect(mockApi.meshDevices).not.toHaveBeenCalled();
  });

  it("shows this device, devices, peers, health and Leave inside a mesh", async () => {
    render(<DevicesView />);
    expect(await screen.findByRole("heading", { name: "This device" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Devices", level: 2 })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Peers" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Health" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Leave mesh" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Pair a device" })).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "This device is not in a mesh" }),
    ).not.toBeInTheDocument();
    // The short id, never a full key or id dump.
    expect(screen.getAllByText("11111111").length).toBeGreaterThan(0);
  });

  it("shows the backend's message when the status cannot be read", async () => {
    mockApi.meshStatus.mockRejectedValue({ code: "mesh_storage", message: "mesh store busy" });
    render(<DevicesView />);
    expect(await screen.findByText(/mesh store busy/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("[object Object]");
  });
});

describe("Devices list badges", () => {
  it("marks this device, stale, removed, forked and not-admitted devices", async () => {
    mockApi.meshDevices.mockResolvedValue([
      self(),
      device({
        device_id: "33".repeat(16),
        short_id: "33333333",
        name: "stale-box",
        stale: true,
      }),
      device({
        device_id: "44".repeat(16),
        short_id: "44444444",
        name: "gone-box",
        active: false,
        removed: true,
        cutoff_seq: 9,
      }),
      device({
        device_id: "55".repeat(16),
        short_id: "55555555",
        name: "fork-box",
        fork_seq: 3,
      }),
      device({
        device_id: "66".repeat(16),
        short_id: "66666666",
        name: "new-box",
        active: false,
      }),
      device({ device_id: "77".repeat(16), short_id: "77777777", name: null }),
    ]);
    render(<DevicesView />);
    // This device's name also appears under "This device"; take its table row.
    const row = async (name: string): Promise<HTMLElement> => {
      let found: HTMLElement | null = null;
      await waitFor(() => {
        found =
          screen
            .getAllByText(name)
            .map((e) => e.closest("tr"))
            .find((r): r is HTMLTableRowElement => r !== null) ?? null;
        expect(found).not.toBeNull();
      });
      return found as unknown as HTMLElement;
    };

    const me = await row("test-laptop");
    expect(within(me).getByText("this device")).toBeInTheDocument();
    expect(within(me).queryByRole("button", { name: /Remove/ })).not.toBeInTheDocument();

    const stale = await row("stale-box");
    expect(within(stale).getByText("stale")).toBeInTheDocument();
    expect(within(stale).getByText("never")).toBeInTheDocument();
    expect(within(stale).queryByText("removed")).not.toBeInTheDocument();

    const gone = await row("gone-box");
    expect(within(gone).getByText("removed")).toBeInTheDocument();
    expect(within(gone).queryByText("not admitted")).not.toBeInTheDocument();
    // A removed device cannot be removed again.
    expect(within(gone).queryByRole("button", { name: /Remove/ })).not.toBeInTheDocument();

    const fork = await row("fork-box");
    expect(within(fork).getByText("forked")).toBeInTheDocument();

    const fresh = await row("new-box");
    expect(within(fresh).getByText("not admitted")).toBeInTheDocument();

    expect(await screen.findByText("unnamed")).toBeInTheDocument();
  });

  it("shows the lag from the last exchange only when there is one", async () => {
    mockApi.meshDevices.mockResolvedValue([
      self(),
      device({
        last_exchange: new Date(Date.now() - 5 * 60_000).toISOString(),
        lag: {
          at: new Date().toISOString(),
          completed: true,
          at_hello: {},
          peer_behind: 4,
          peer_ahead: 2,
          peer_behind_now: 3,
          digest_mismatches: 0,
        },
      }),
    ]);
    render(<DevicesView />);
    const row = (await screen.findByText("test-desktop")).closest("tr") as HTMLElement;
    expect(
      within(row).getByText(/lacks 3 item\(s\) from this device; had 2 new/),
    ).toBeInTheDocument();
    expect(within(row).getByText("5 minutes ago")).toBeInTheDocument();
  });
});

describe("Pair a device", () => {
  it("reauth, then the invite is shown once, and closing drops it from the DOM", async () => {
    const user = userEvent.setup();
    mockApi.meshInviteCreate.mockResolvedValue(invite());
    render(<DevicesView />);

    await user.click(await screen.findByRole("button", { name: "Pair a device" }));
    expect(
      screen.getByRole("heading", { name: "Create a pairing invite" }),
    ).toBeInTheDocument();
    expect(screen.queryByText(INVITE)).not.toBeInTheDocument();
    await user.type(passwordField(), PASSWORD);
    await user.click(screen.getByRole("button", { name: "Create invite" }));

    expect(mockApi.meshInviteCreate).toHaveBeenCalledWith(PASSWORD, null);
    expect(await screen.findByText(INVITE)).toBeInTheDocument();
    expect(screen.getAllByText(INVITE)).toHaveLength(1);
    expect(
      screen.getByText(/Treat this invite like a password for the next 10 minutes/),
    ).toBeInTheDocument();
    expect(screen.getByText(/Expires in \d+:\d\d/)).toBeInTheDocument();
    // The reauth dialog is gone, and the password went nowhere visible.
    expect(screen.queryByLabelText(/master password/i)).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain(PASSWORD);

    await user.click(screen.getByRole("button", { name: "Close" }));
    expect(screen.queryByText(INVITE)).not.toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain("FAKEFAKEFAKE");
    expectNoSecretsInDom();
  });

  it("shows why when the node is not running, and no invite", async () => {
    const user = userEvent.setup();
    mockApi.meshInviteCreate.mockRejectedValue({
      code: "mesh_node_not_running",
      message:
        "pairing needs this device's mesh node running; turn on Run mesh while Tethra is open",
    });
    render(<DevicesView />);

    await user.click(await screen.findByRole("button", { name: "Pair a device" }));
    await user.type(passwordField(), PASSWORD);
    await user.click(screen.getByRole("button", { name: "Create invite" }));

    expect(
      await screen.findByText(/pairing needs this device's mesh node running/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Treat this invite like a password/)).not.toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain("tethra-mesh-invite");
    expectNoSecretsInDom();
  });

  it("never shows the typed password even if a message were to echo it", async () => {
    const user = userEvent.setup();
    mockApi.meshInviteCreate.mockRejectedValue({
      code: "wrong_password",
      message: `wrong password: ${PASSWORD}`,
    });
    render(<DevicesView />);
    await user.click(await screen.findByRole("button", { name: "Pair a device" }));
    await user.type(passwordField(), PASSWORD);
    await user.click(screen.getByRole("button", { name: "Create invite" }));
    expect(await screen.findByText(/wrong password: \[hidden\]/)).toBeInTheDocument();
    expectNoSecretsInDom();
  });
});

describe("MeshPairDialog", () => {
  it("hides an expired invite and says so", () => {
    render(
      <MeshPairDialog
        invite={invite({ expires_at: new Date(Date.now() - 1000).toISOString() })}
        onClose={vi.fn()}
      />,
    );
    expect(screen.getByText(/This invite expired/)).toBeInTheDocument();
    expect(screen.queryByText(INVITE)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Copy invite" })).not.toBeInTheDocument();
  });

  it("copies the invite, and says to select it when the clipboard fails", async () => {
    const user = userEvent.setup();
    const write = vi.spyOn(navigator.clipboard, "writeText");
    render(<MeshPairDialog invite={invite()} onClose={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Copy invite" }));
    expect(write).toHaveBeenCalledWith(INVITE);
    expect(await screen.findByText(/Copied\./)).toBeInTheDocument();

    write.mockRejectedValueOnce(new Error("denied"));
    await user.click(screen.getByRole("button", { name: "Copy invite" }));
    expect(await screen.findByText(/Select the invite above and copy it/)).toBeInTheDocument();
  });

  it("names the addresses and warns when only this computer can reach them", () => {
    render(<MeshPairDialog invite={invite()} onClose={vi.fn()} />);
    expect(screen.getByText("127.0.0.1:7700")).toBeInTheDocument();
    expect(screen.getByText(/These are loopback addresses/)).toBeInTheDocument();
  });
});

describe("Remove a device", () => {
  it("needs a confirmation and then the master password, in that order", async () => {
    const user = userEvent.setup();
    mockApi.meshDeviceRemove.mockResolvedValue({ removed: DESKTOP_ID, access_key_epoch: 2 });
    render(<DevicesView />);

    const removeButton = await screen.findByRole("button", {
      name: "Remove test-desktop (22222222)",
    });

    // Cancelling the confirmation never reaches the API or the password step.
    await user.click(removeButton);
    expect(screen.getByText(/It cannot rejoin under the same identity/)).toBeInTheDocument();
    expect(screen.queryByLabelText(/master password/i)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByText(/It cannot rejoin/)).not.toBeInTheDocument();
    expect(mockApi.meshDeviceRemove).not.toHaveBeenCalled();

    // Confirm, then the password, then the call.
    await user.click(removeButton);
    await user.click(screen.getByRole("button", { name: "Remove" }));
    expect(mockApi.meshDeviceRemove).not.toHaveBeenCalled();
    await user.type(passwordField(), PASSWORD);
    await user.click(screen.getByRole("button", { name: "Remove device" }));

    await waitFor(() =>
      expect(mockApi.meshDeviceRemove).toHaveBeenCalledWith(PASSWORD, DESKTOP_ID),
    );
    expect(mockApi.meshDeviceRemove).toHaveBeenCalledTimes(1);
    expect(await screen.findByText(/Removed test-desktop \(22222222\)/)).toBeInTheDocument();
    expect(screen.queryByLabelText(/master password/i)).not.toBeInTheDocument();
    expectNoSecretsInDom();
  });

  it("cancelling the password step does not remove", async () => {
    const user = userEvent.setup();
    render(<DevicesView />);
    await user.click(
      await screen.findByRole("button", { name: "Remove test-desktop (22222222)" }),
    );
    await user.click(screen.getByRole("button", { name: "Remove" }));
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(mockApi.meshDeviceRemove).not.toHaveBeenCalled();
  });

  it("keeps the dialog open with the backend message on a wrong password", async () => {
    const user = userEvent.setup();
    mockApi.meshDeviceRemove.mockRejectedValue({
      code: "wrong_password",
      message: "wrong password",
    });
    render(<DevicesView />);
    await user.click(
      await screen.findByRole("button", { name: "Remove test-desktop (22222222)" }),
    );
    await user.click(screen.getByRole("button", { name: "Remove" }));
    await user.type(passwordField(), PASSWORD);
    await user.click(screen.getByRole("button", { name: "Remove device" }));
    expect(await screen.findByText("wrong password")).toBeInTheDocument();
    expect(passwordField()).toBeInTheDocument();
    expectNoSecretsInDom();
  });
});

describe("Leave the mesh", () => {
  it("needs a confirmation and then the master password, then returns to setup", async () => {
    const user = userEvent.setup();
    mockApi.meshLeave.mockResolvedValue({
      delivered: true,
      wipe: { identity: SELF_ID, rows_deleted: 12, marker: "removed" },
    });
    render(<DevicesView />);

    const leaveButton = await screen.findByRole("button", { name: "Leave mesh" });
    await user.click(leaveButton);
    expect(screen.getByText(/to rejoin, pair again with a new invite/)).toBeInTheDocument();
    expect(screen.queryByLabelText(/master password/i)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(mockApi.meshLeave).not.toHaveBeenCalled();

    await user.click(leaveButton);
    // The confirm dialog's own "Leave mesh" button (the page's is the first).
    const confirmButtons = screen.getAllByRole("button", { name: "Leave mesh" });
    await user.click(confirmButtons[confirmButtons.length - 1]);
    expect(mockApi.meshLeave).not.toHaveBeenCalled();

    mockApi.meshStatus.mockResolvedValue(NOT_IN_MESH);
    await user.type(passwordField(), PASSWORD);
    const reauthButtons = screen.getAllByRole("button", { name: "Leave mesh" });
    await user.click(reauthButtons[reauthButtons.length - 1]);

    await waitFor(() => expect(mockApi.meshLeave).toHaveBeenCalledWith(PASSWORD));
    expect(
      await screen.findByText(/another device received this device's departure/),
    ).toBeInTheDocument();
    expect(
      await screen.findByRole("heading", { name: "This device is not in a mesh" }),
    ).toBeInTheDocument();
    expectNoSecretsInDom();
  });

  it("says so when no device received the departure", async () => {
    const user = userEvent.setup();
    mockApi.meshLeave.mockResolvedValue({
      delivered: false,
      wipe: { identity: SELF_ID, rows_deleted: 12, marker: "removed" },
    });
    render(<DevicesView />);
    await user.click(await screen.findByRole("button", { name: "Leave mesh" }));
    let buttons = screen.getAllByRole("button", { name: "Leave mesh" });
    await user.click(buttons[buttons.length - 1]);
    await user.type(passwordField(), PASSWORD);
    buttons = screen.getAllByRole("button", { name: "Leave mesh" });
    await user.click(buttons[buttons.length - 1]);
    expect(await screen.findByText(/No other device was reachable/)).toBeInTheDocument();
  });
});

describe("Available from your devices (Increment 10)", () => {
  it("lists shared projects not bound here, inside a mesh only, and binds nothing", async () => {
    mockApi.meshProjectsList.mockResolvedValue([
      {
        mesh_project_id: "aa".repeat(16),
        name: "fake-shared",
        archived: false,
        merged_into: null,
        root: "aa".repeat(16),
        bound_local_project: null,
        bound_local_project_name: null,
        publishing_devices: [DESKTOP_ID],
      },
    ]);
    render(<DevicesView />);
    expect(
      await screen.findByRole("heading", { name: "Available from your devices" }),
    ).toBeInTheDocument();
    const row = (await screen.findByText("fake-shared")).closest("tr") as HTMLElement;
    // The publishing device, by its short id (this roster has no names).
    expect(within(row).getByText("22222222", { exact: false })).toBeInTheDocument();
    expect(
      within(row).getByRole("button", { name: "Bind fake-shared (aaaaaaaa) to a project" }),
    ).toBeInTheDocument();
    expect(mockApi.meshProjectBind).not.toHaveBeenCalled();
    expect(mockApi.projectList).not.toHaveBeenCalled();
  });

  it("is not shown, and not read, outside a mesh", async () => {
    mockApi.meshStatus.mockResolvedValue(NOT_IN_MESH);
    render(<DevicesView />);
    await screen.findByRole("heading", { name: "This device is not in a mesh" });
    expect(
      screen.queryByRole("heading", { name: "Available from your devices" }),
    ).not.toBeInTheDocument();
    expect(mockApi.meshProjectsList).not.toHaveBeenCalled();
  });
});

describe("Credentials shared with this device (Increment 11)", () => {
  it("is shown inside a mesh, collects old shares on opening, and imports nothing", async () => {
    render(<DevicesView />);
    expect(
      await screen.findByRole("heading", { name: "Credentials shared with this device" }),
    ).toBeInTheDocument();
    await waitFor(() => expect(mockApi.meshSharesList).toHaveBeenCalledWith(true));
  });

  it("is not shown, and not read, outside a mesh", async () => {
    mockApi.meshStatus.mockResolvedValue(NOT_IN_MESH);
    render(<DevicesView />);
    await screen.findByRole("heading", { name: "This device is not in a mesh" });
    expect(
      screen.queryByRole("heading", { name: "Credentials shared with this device" }),
    ).not.toBeInTheDocument();
    expect(mockApi.meshSharesList).not.toHaveBeenCalled();
  });
});
