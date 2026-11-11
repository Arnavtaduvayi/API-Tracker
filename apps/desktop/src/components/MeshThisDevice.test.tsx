// This device and its node (Tethra Mesh, Increment 09). Settings that open
// the node's listener to the network (all interfaces, mDNS, a non-loopback
// address) show a LAN-exposure warning, and saving them goes through the
// master password when core answers `mesh_reauth_required`. Node and identity
// states render honestly. All values are obviously fake.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type {
  MeshNodeSettings,
  MeshNodeState,
  MeshNodeStatus,
  MeshStatus,
  MeshStatusDetail,
} from "../types";

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      meshDeviceRename: vi.fn(),
      meshNodeGetSettings: vi.fn(),
      meshNodeSetSettings: vi.fn(),
    },
  };
});

import { api } from "../api";
import { MeshThisDevice } from "./MeshThisDevice";

const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>;

const PASSWORD = "test-master-password";
const SELF_ID = "11".repeat(16);
const LAN_WARNING = /Other machines on your network can reach this device's mesh listener/;

type InMesh = MeshStatus & { initialized: true };

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

function nodeStatus(over: Partial<MeshNodeStatus> = {}): MeshNodeStatus {
  return {
    pid: 4242,
    device_id: SELF_ID,
    started_at: new Date().toISOString(),
    listen: ["127.0.0.1:7700"],
    advertised: ["127.0.0.1:7700"],
    interval_ms: 30_000,
    discovery: false,
    rounds: 7,
    last_round_at: null,
    active_sessions: 0,
    hooks: [],
    last_hook_error: null,
    last_publish_error: null,
    stopping: false,
    ...over,
  };
}

function status(over: Partial<MeshStatusDetail> = {}, n: MeshNodeState = node()): InMesh {
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
    node: n,
  };
}

function settings(over: Partial<MeshNodeSettings> = {}): MeshNodeSettings {
  return {
    run_while_open: false,
    listen: ["127.0.0.1:7700"],
    all_interfaces: false,
    discover: false,
    ...over,
  };
}

beforeEach(() => {
  mockApi.meshNodeGetSettings.mockResolvedValue(settings());
});

describe("LAN-exposure settings", () => {
  it("warns whenever all interfaces, discovery or a non-loopback address is on", async () => {
    const user = userEvent.setup();
    render(<MeshThisDevice status={status()} onChanged={vi.fn()} />);
    const allIfaces = await screen.findByRole("checkbox", {
      name: "Allow all interfaces (0.0.0.0 / [::])",
    });
    expect(screen.queryByText(LAN_WARNING)).not.toBeInTheDocument();

    await user.click(allIfaces);
    expect(screen.getByText(LAN_WARNING)).toBeInTheDocument();
    await user.click(allIfaces);
    expect(screen.queryByText(LAN_WARNING)).not.toBeInTheDocument();

    const discover = screen.getByRole("checkbox", {
      name: "Find devices on this network (mDNS)",
    });
    await user.click(discover);
    expect(screen.getByText(LAN_WARNING)).toBeInTheDocument();
    await user.click(discover);
    expect(screen.queryByText(LAN_WARNING)).not.toBeInTheDocument();

    const listen = screen.getByLabelText("Listen address 1");
    await user.clear(listen);
    // "[[" types a literal "[" (user-event key descriptors).
    await user.type(listen, "[[::1]:7700");
    expect(screen.queryByText(LAN_WARNING)).not.toBeInTheDocument();
    await user.clear(listen);
    await user.type(listen, "100.64.1.2:7700");
    expect(screen.getByText(LAN_WARNING)).toBeInTheDocument();
    expect(screen.getByText(LAN_WARNING).closest("[role=alert]")).not.toBeNull();
  });

  it("asks for the master password when core requires it, then retries with it", async () => {
    const user = userEvent.setup();
    const onChanged = vi.fn();
    const wide = settings({ run_while_open: true, discover: true });
    mockApi.meshNodeSetSettings
      .mockRejectedValueOnce({
        code: "mesh_reauth_required",
        message: "this change opens the node to the network; it needs the master password",
      })
      .mockResolvedValueOnce({ settings: wide, outcome: "started", start_error: null });
    render(<MeshThisDevice status={status()} onChanged={onChanged} />);

    await user.click(
      await screen.findByRole("checkbox", { name: "Run mesh while Tethra is open" }),
    );
    await user.click(
      screen.getByRole("checkbox", { name: "Find devices on this network (mDNS)" }),
    );
    await user.click(screen.getByRole("button", { name: "Save node settings" }));

    expect(mockApi.meshNodeSetSettings).toHaveBeenNthCalledWith(1, wide, null);
    expect(
      await screen.findByRole("heading", { name: "Allow network access" }),
    ).toBeInTheDocument();
    expect(onChanged).not.toHaveBeenCalled();

    await user.type(screen.getByLabelText(/master password/i), PASSWORD);
    await user.click(screen.getByRole("button", { name: "Save settings" }));

    await waitFor(() =>
      expect(mockApi.meshNodeSetSettings).toHaveBeenNthCalledWith(2, wide, PASSWORD),
    );
    expect(await screen.findByText(/The mesh node started/)).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Allow network access" }),
    ).not.toBeInTheDocument();
    expect(onChanged).toHaveBeenCalled();
    expect(document.body.textContent).not.toContain(PASSWORD);
  });

  it("saves loopback-only changes without a password and drops empty rows", async () => {
    const user = userEvent.setup();
    const saved = settings({ listen: ["127.0.0.1:7700", "127.0.0.1:0"] });
    mockApi.meshNodeSetSettings.mockResolvedValue({
      settings: saved,
      outcome: "off",
      start_error: null,
    });
    render(<MeshThisDevice status={status()} onChanged={vi.fn()} />);

    await user.click(await screen.findByRole("button", { name: "Add listen address" }));
    await user.type(screen.getByLabelText("Listen address 2"), " 127.0.0.1:0 ");
    await user.click(screen.getByRole("button", { name: "Add listen address" }));
    await user.click(screen.getByRole("button", { name: "Save node settings" }));

    await waitFor(() => expect(mockApi.meshNodeSetSettings).toHaveBeenCalledTimes(1));
    expect(mockApi.meshNodeSetSettings).toHaveBeenCalledWith(saved, null);
    expect(await screen.findByText(/The mesh node is off/)).toBeInTheDocument();
    expect(screen.queryByLabelText(/master password/i)).not.toBeInTheDocument();
  });

  it("shows why the node did not start, and other errors by their message", async () => {
    const user = userEvent.setup();
    mockApi.meshNodeSetSettings
      .mockResolvedValueOnce({
        settings: settings({ run_while_open: true }),
        outcome: null,
        start_error: "another Tethra Mesh node is already running for this data directory",
      })
      .mockRejectedValueOnce({
        code: "mesh_invalid_node_settings",
        message:
          "invalid mesh node settings: a listen address must be IP:PORT, such as 127.0.0.1:7420",
      });
    render(<MeshThisDevice status={status()} onChanged={vi.fn()} />);

    await user.click(
      await screen.findByRole("checkbox", { name: "Run mesh while Tethra is open" }),
    );
    await user.click(screen.getByRole("button", { name: "Save node settings" }));
    expect(
      await screen.findByText(/The node did not start: another Tethra Mesh node/),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Save node settings" }));
    expect(await screen.findByText(/a listen address must be IP:PORT/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("[object Object]");
  });
});

describe("node and identity state", () => {
  it("shows a running node's addresses and rounds", async () => {
    render(
      <MeshThisDevice
        status={status({}, node({ running: nodeStatus({ listen: ["127.0.0.1:41000"] }) }))}
        onChanged={vi.fn()}
      />,
    );
    expect(screen.getByText("running")).toBeInTheDocument();
    expect(screen.getByText("127.0.0.1:41000")).toBeInTheDocument();
    expect(screen.getByText(/Rounds: 7/)).toBeInTheDocument();
    await screen.findByRole("button", { name: "Save node settings" });
  });

  it("shows a node another process runs, and a stopped node with its last error", async () => {
    const { unmount } = render(
      <MeshThisDevice
        status={status({}, node({ external: nodeStatus({ pid: 777 }) }))}
        onChanged={vi.fn()}
      />,
    );
    expect(screen.getByText("running in another process")).toBeInTheDocument();
    expect(screen.getByText(/pid 777/)).toBeInTheDocument();
    await screen.findByRole("button", { name: "Save node settings" });
    unmount();

    render(
      <MeshThisDevice
        status={status(
          {},
          node({
            last_error: "the listen address 127.0.0.1:7700 is in use",
            last_stop: {
              reason: "locked",
              description: "the vault locked",
              keys_dropped: true,
              at: new Date().toISOString(),
            },
          }),
        )}
        onChanged={vi.fn()}
      />,
    );
    expect(screen.getByText("stopped")).toBeInTheDocument();
    expect(
      screen.getByText(/The node could not start: the listen address/),
    ).toBeInTheDocument();
    expect(screen.getByText(/the vault locked/)).toBeInTheDocument();
    await screen.findByRole("button", { name: "Save node settings" });
  });

  it("says plainly when the identity is not trusted, forked or on a rollback hold", async () => {
    render(
      <MeshThisDevice
        status={status({
          marker: "mismatch",
          marker_problem: "the identity marker belongs to another installation",
          self_forked: true,
          rollback_hold: 41,
        })}
        onChanged={vi.fn()}
      />,
    );
    expect(
      screen.getByText(/the identity marker belongs to another installation/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Another installation has used this device's identity/),
    ).toBeInTheDocument();
    expect(screen.getByText(/up to number 41/)).toBeInTheDocument();
    await screen.findByRole("button", { name: "Save node settings" });
  });

  it("renames this device", async () => {
    const user = userEvent.setup();
    const onChanged = vi.fn();
    mockApi.meshDeviceRename.mockResolvedValue(undefined);
    render(<MeshThisDevice status={status()} onChanged={onChanged} />);
    await user.click(screen.getByRole("button", { name: "Rename" }));
    const input = screen.getByLabelText(/^New name for this device/);
    await user.clear(input);
    await user.type(input, "test-workstation");
    await user.click(screen.getByRole("button", { name: "Save name" }));
    await waitFor(() =>
      expect(mockApi.meshDeviceRename).toHaveBeenCalledWith("test-workstation"),
    );
    expect(await screen.findByText(/Renamed\./)).toBeInTheDocument();
    expect(onChanged).toHaveBeenCalled();
  });
});
