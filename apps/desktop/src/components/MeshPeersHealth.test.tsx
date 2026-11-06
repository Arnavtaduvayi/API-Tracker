// Peers and Health panels (Tethra Mesh, Increment 09): add and remove peer
// addresses, the doctor findings, and Replicate now with its results and its
// errors shown by message. All values are obviously fake.

import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { MeshPeer } from "../types";

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      meshPeersList: vi.fn(),
      meshPeerAdd: vi.fn(),
      meshPeerRemove: vi.fn(),
      meshDoctor: vi.fn(),
      meshReplicateNow: vi.fn(),
    },
  };
});

import { api } from "../api";
import { MeshPeers } from "./MeshPeers";
import { MeshHealth } from "./MeshHealth";

const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>;

function peer(over: Partial<MeshPeer> = {}): MeshPeer {
  return {
    addr: "127.0.0.1:7701",
    device_id: "22".repeat(16),
    source: "manual",
    last_attempt_at: null,
    last_success_at: null,
    failures: 0,
    unreachable_since: null,
    last_error: null,
    device_name: "test-desktop",
    backoff_until: null,
    ...over,
  };
}

describe("MeshPeers", () => {
  it("lists addresses with their source, failures and backoff", async () => {
    mockApi.meshPeersList.mockResolvedValue([
      peer(),
      peer({
        addr: "100.64.1.2:7700",
        source: "gossip",
        device_id: null,
        device_name: null,
        failures: 3,
        unreachable_since: new Date(Date.now() - 10 * 60_000).toISOString(),
        backoff_until: new Date(Date.now() + 60_000).toISOString(),
        last_error: "connection refused",
      }),
    ]);
    render(<MeshPeers refreshKey={0} onChanged={vi.fn()} />);
    const row = (await screen.findByText("100.64.1.2:7700")).closest("tr") as HTMLElement;
    expect(within(row).getByText("gossip")).toBeInTheDocument();
    expect(within(row).getByText("3")).toBeInTheDocument();
    expect(within(row).getByText("not yet known")).toBeInTheDocument();
    expect(within(row).getByText(/Unreachable since/)).toBeInTheDocument();
    expect(within(row).getByText(/Retrying after/)).toBeInTheDocument();
    expect(within(row).getByText(/connection refused/)).toBeInTheDocument();
    const known = screen.getByText("127.0.0.1:7701").closest("tr") as HTMLElement;
    expect(within(known).getByText(/test-desktop/)).toBeInTheDocument();
    expect(within(known).getByText("manual")).toBeInTheDocument();
  });

  it("adds a trimmed address and removes one", async () => {
    const user = userEvent.setup();
    const onChanged = vi.fn();
    mockApi.meshPeersList.mockResolvedValue([peer()]);
    mockApi.meshPeerAdd.mockResolvedValue({ addr: "100.64.1.2:7700", added: true });
    mockApi.meshPeerRemove.mockResolvedValue({ removed: true, source: "manual" });
    render(<MeshPeers refreshKey={0} onChanged={onChanged} />);

    await user.type(
      await screen.findByLabelText("Add a peer address (HOST:PORT)"),
      " 100.64.1.2:7700 ",
    );
    await user.click(screen.getByRole("button", { name: "Add peer" }));
    await waitFor(() => expect(mockApi.meshPeerAdd).toHaveBeenCalledWith("100.64.1.2:7700"));
    expect(await screen.findByText(/Added 100\.64\.1\.2:7700/)).toBeInTheDocument();
    expect(onChanged).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole("button", { name: "Remove peer 127.0.0.1:7701" }));
    await waitFor(() => expect(mockApi.meshPeerRemove).toHaveBeenCalledWith("127.0.0.1:7701"));
    expect(await screen.findByText("Removed 127.0.0.1:7701.")).toBeInTheDocument();
    expect(onChanged).toHaveBeenCalledTimes(2);
  });

  it("shows an invalid address by the backend's message", async () => {
    const user = userEvent.setup();
    mockApi.meshPeersList.mockResolvedValue([]);
    mockApi.meshPeerAdd.mockRejectedValue({
      code: "mesh_invalid_peer_address",
      message: "a peer address must be HOST:PORT",
    });
    render(<MeshPeers refreshKey={0} onChanged={vi.fn()} />);
    await user.type(await screen.findByLabelText("Add a peer address (HOST:PORT)"), "nope");
    await user.click(screen.getByRole("button", { name: "Add peer" }));
    expect(await screen.findByText("a peer address must be HOST:PORT")).toBeInTheDocument();
  });

  it("reloads when the refresh key changes", async () => {
    mockApi.meshPeersList.mockResolvedValue([]);
    const { rerender } = render(<MeshPeers refreshKey={0} onChanged={vi.fn()} />);
    await screen.findByText("No peer addresses yet.");
    rerender(<MeshPeers refreshKey={1} onChanged={vi.fn()} />);
    await waitFor(() => expect(mockApi.meshPeersList).toHaveBeenCalledTimes(2));
  });
});

describe("MeshHealth", () => {
  it("shows the doctor's findings, with a fix for those that are not ok", async () => {
    mockApi.meshDoctor.mockResolvedValue({
      worst: "warning",
      initialized: true,
      findings: [
        { check: "keys", severity: "ok", summary: "the keys decrypt and match" },
        {
          check: "peers",
          severity: "warning",
          summary: "no peer address is known",
          fix: "add one with Add peer",
        },
      ],
    });
    render(<MeshHealth onChanged={vi.fn()} />);
    expect(await screen.findByText(/no peer address is known/)).toBeInTheDocument();
    expect(screen.getByText("Fix: add one with Add peer")).toBeInTheDocument();
    expect(screen.getByText("1 check(s) passed")).toBeInTheDocument();
    expect(screen.getAllByText("warning").length).toBeGreaterThan(0);
  });

  it("replicates now and lists the exchanges and notes", async () => {
    const user = userEvent.setup();
    const onChanged = vi.fn();
    mockApi.meshDoctor.mockResolvedValue({ worst: "ok", initialized: true, findings: [] });
    mockApi.meshReplicateNow.mockResolvedValue({
      via: "one_shot",
      exchanges: [
        {
          addr: "127.0.0.1:7701",
          device: "22222222",
          items_in: 4,
          items_out: 1,
          duration_ms: 12,
          error: null,
        },
        {
          addr: "100.64.1.2:7700",
          device: null,
          items_in: 0,
          items_out: 0,
          duration_ms: 3000,
          error: "connection refused",
        },
      ],
      repairs_changed: 0,
      notes: ["usage was not published: the vault is busy"],
    });
    render(<MeshHealth onChanged={onChanged} />);
    await user.click(await screen.findByRole("button", { name: "Replicate now" }));

    await waitFor(() => expect(mockApi.meshReplicateNow).toHaveBeenCalledWith(null));
    expect(await screen.findByText(/one exchange per known address/)).toBeInTheDocument();
    const ok = screen.getByText("127.0.0.1:7701").closest("tr") as HTMLElement;
    expect(within(ok).getByText("4")).toBeInTheDocument();
    expect(within(ok).getByText("ok")).toBeInTheDocument();
    const failed = screen.getByText("100.64.1.2:7700").closest("tr") as HTMLElement;
    expect(within(failed).getByText("connection refused")).toBeInTheDocument();
    expect(screen.getByText("usage was not published: the vault is busy")).toBeInTheDocument();
    expect(onChanged).toHaveBeenCalled();
  });

  it("shows a replicate error by its message", async () => {
    const user = userEvent.setup();
    mockApi.meshDoctor.mockResolvedValue({ worst: "ok", initialized: true, findings: [] });
    mockApi.meshReplicateNow.mockRejectedValue({
      code: "mesh_no_peers",
      message: "no peer address is known yet; add one under Peers",
    });
    render(<MeshHealth onChanged={vi.fn()} />);
    await user.click(await screen.findByRole("button", { name: "Replicate now" }));
    expect(
      await screen.findByText("no peer address is known yet; add one under Peers"),
    ).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("[object Object]");
  });
});
