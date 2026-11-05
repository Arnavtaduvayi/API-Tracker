// Spend-cap panel (Tethra Mesh, Increment 10; ADR 0032). Create; raise on
// the owner, and the local-override confirmation on a non-owner; lower with
// confirmation; the reauthenticated "Enforce on this device" switch with its
// explanation (403 not 429, the qualified overshoot, a self-limit); the
// enforcement warnings; frozen caps. Dollar amounts go to core as typed
// text. Fake values only.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { MeshGateStatus } from "../types";
import {
  CAP_ID,
  CAP_NOTES,
  DESKTOP_ID,
  MESH_A,
  MESH_B,
  capDevice,
  capMonth,
  capReport,
  capRow,
  projectRow,
} from "./MeshTestFixtures";

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      meshCapsList: vi.fn(),
      meshCapCreate: vi.fn(),
      meshCapRaise: vi.fn(),
      meshCapLower: vi.fn(),
      meshCapReclaim: vi.fn(),
      meshCapEnforce: vi.fn(),
      meshCapRights: vi.fn(),
    },
  };
});

import { api } from "../api";
import { CapsPanel } from "./CapsPanel";

const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>;
const PASSWORD = "test-master-password";
const PROJECTS = [projectRow({ bound_local_project: "local-1" })];

function gate(over: Partial<MeshGateStatus> = {}): MeshGateStatus {
  return {
    at_ms: Date.now(),
    generation: 3,
    inactive_reason: null,
    failing_open: false,
    caps: [],
    ...over,
  };
}

function nonOwnerCap() {
  return capRow({
    owner_device: DESKTOP_ID,
    owner_name: "test-desktop",
    owned_here: false,
    months: [
      capMonth({
        devices: [
          capDevice({ is_owner: false, minted: 0, sent: 0, received: 20_000_000 }),
          capDevice({
            device_id: DESKTOP_ID,
            device_name: "test-desktop",
            is_self: false,
            is_owner: true,
            stale: true,
            as_of: new Date(Date.now() - 2 * 86_400_000).toISOString(),
          }),
        ],
      }),
    ],
  });
}

function renderPanel() {
  return render(<CapsPanel meshProjectId={MESH_A} projects={PROJECTS} />);
}

beforeEach(() => {
  mockApi.meshCapsList.mockResolvedValue(capReport());
});

describe("CapsPanel create", () => {
  it("offers to create a cap when the project has none, sending the typed text", async () => {
    const user = userEvent.setup();
    mockApi.meshCapCreate.mockResolvedValue({
      cap_id: CAP_ID,
      mesh_project_id: MESH_A,
      month: "2026-11",
      monthly_micros: 50_000_000,
      distributed_micros: 25_000_000,
    });
    renderPanel();
    expect(await screen.findByText("This project has no spend cap.")).toBeInTheDocument();
    expect(mockApi.meshCapsList).toHaveBeenCalledWith(true);

    await user.type(screen.getByLabelText("Monthly spend cap (USD)"), "50");
    mockApi.meshCapsList.mockResolvedValue(capReport({ caps: [capRow()] }));
    await user.click(screen.getByRole("button", { name: "Create a spend cap" }));

    await waitFor(() => expect(mockApi.meshCapCreate).toHaveBeenCalledWith(MESH_A, "50"));
    expect(await screen.findByText(/Created a \$50\.00 monthly spend cap/)).toBeInTheDocument();
    expect(
      await screen.findByRole("region", { name: /spend cap c0c0c0c0/ }),
    ).toBeInTheDocument();
    // Reconciled again after the action.
    expect(mockApi.meshCapsList).toHaveBeenLastCalledWith(true);
    expect(
      screen.queryByRole("button", { name: "Create a spend cap" }),
    ).not.toBeInTheDocument();
  });

  it("creates the cap on the root of a merged project and shows its caps", async () => {
    const user = userEvent.setup();
    mockApi.meshCapCreate.mockResolvedValue({
      cap_id: CAP_ID,
      mesh_project_id: MESH_A,
      month: "2026-11",
      monthly_micros: 10_000_000,
      distributed_micros: 0,
    });
    render(
      <CapsPanel
        meshProjectId={MESH_B}
        projects={[
          projectRow(),
          projectRow({ mesh_project_id: MESH_B, merged_into: MESH_A, root: MESH_A }),
        ]}
      />,
    );
    await user.type(await screen.findByLabelText("Monthly spend cap (USD)"), "10");
    await user.click(screen.getByRole("button", { name: "Create a spend cap" }));
    await waitFor(() => expect(mockApi.meshCapCreate).toHaveBeenCalledWith(MESH_A, "10"));
  });

  it("shows core's refusal message", async () => {
    const user = userEvent.setup();
    mockApi.meshCapCreate.mockRejectedValue({
      code: "invalid_input",
      message: "a spend cap must be more than $0",
    });
    renderPanel();
    await user.type(await screen.findByLabelText("Monthly spend cap (USD)"), "0");
    await user.click(screen.getByRole("button", { name: "Create a spend cap" }));
    expect(await screen.findByText("a spend cap must be more than $0")).toBeInTheDocument();
  });
});

describe("CapsPanel figures", () => {
  it("shows target, effective target, used, this device's available, pending decrease and notes", async () => {
    mockApi.meshCapsList.mockResolvedValue(
      capReport({
        caps: [
          capRow({
            months: [
              capMonth({
                overrides: 5_000_000,
                effective_target: 55_000_000,
                pending_decrease: 3_000_000,
                devices: [
                  capDevice(),
                  capDevice({
                    device_id: DESKTOP_ID,
                    device_name: "test-desktop",
                    is_self: false,
                    is_owner: false,
                    minted: 5_000_000,
                    is_override: true,
                    removed: true,
                    avail: -500_000,
                  }),
                ],
              }),
            ],
          }),
        ],
      }),
    );
    renderPanel();
    await screen.findByText("Effective target");
    expect(screen.getByText("$55.00")).toBeInTheDocument();
    expect(screen.getByText(/the target plus \$5\.00 of local overrides/)).toBeInTheDocument();
    expect(screen.getByText(/\$12\.00 \(24%\)/)).toBeInTheDocument();
    expect(
      screen.getByText(/estimated, gateway-observed, across 2 device\(s\); 1 stale/),
    ).toBeInTheDocument();
    expect(screen.getByText("$3.00 until devices burn rights")).toBeInTheDocument();
    expect(screen.getByText(CAP_NOTES[0])).toBeInTheDocument();

    const table = screen.getByRole("table", { name: "Rights per device, 2026-11" });
    const desk = within(table).getByText("test-desktop").closest("tr") as HTMLElement;
    expect(within(desk).getByText("override")).toBeInTheDocument();
    expect(within(desk).getByText("removed")).toBeInTheDocument();
    expect(within(desk).getByText("-$0.50")).toBeInTheDocument();
    const me = within(table).getByText("test-laptop").closest("tr") as HTMLElement;
    expect(within(me).getByText("owner")).toBeInTheDocument();
    expect(within(me).getByText("this device")).toBeInTheDocument();
  });

  it("says nothing is bound here when this device has no available figure", async () => {
    mockApi.meshCapsList.mockResolvedValue(
      capReport({ caps: [capRow({ months: [capMonth({ local_avail: null })] })] }),
    );
    renderPanel();
    expect(await screen.findByText("nothing bound here")).toBeInTheDocument();
  });

  it("explains a frozen cap and offers no raise, lower or reclaim", async () => {
    mockApi.meshCapsList.mockResolvedValue(capReport({ caps: [capRow({ frozen: true })] }));
    renderPanel();
    expect(
      await screen.findByText(/Frozen: the device that owns this cap was removed/),
    ).toBeInTheDocument();
    expect(screen.getByText("frozen")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Raise" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Lower" })).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Reclaim unspent rights" }),
    ).not.toBeInTheDocument();
    // A new cap replaces a frozen one.
    expect(screen.getByRole("button", { name: "Create a spend cap" })).toBeInTheDocument();
  });
});

describe("CapsPanel raise and lower", () => {
  it("raises directly on the owner", async () => {
    const user = userEvent.setup();
    mockApi.meshCapsList.mockResolvedValue(capReport({ caps: [capRow()] }));
    mockApi.meshCapRaise.mockResolvedValue({
      cap_id: CAP_ID,
      owner: true,
      is_override: false,
      months: ["2026-11"],
      amount_micros: 10_000_000,
      burned_micros: 0,
      distributed_micros: 5_000_000,
    });
    renderPanel();
    await user.type(await screen.findByLabelText("Raise by (USD)"), "10");
    await user.click(screen.getByRole("button", { name: "Raise" }));
    await waitFor(() => expect(mockApi.meshCapRaise).toHaveBeenCalledWith(CAP_ID, "10"));
    // No override confirmation on the owner.
    expect(
      screen.queryByRole("heading", { name: "Add a local override?" }),
    ).not.toBeInTheDocument();
    expect(
      await screen.findByText(/Raised the cap by \$10\.00 for 2026-11/),
    ).toBeInTheDocument();
  });

  it("asks before a non-owner's raise, explaining the local override", async () => {
    const user = userEvent.setup();
    mockApi.meshCapsList.mockResolvedValue(capReport({ caps: [nonOwnerCap()] }));
    mockApi.meshCapRaise.mockResolvedValue({
      cap_id: CAP_ID,
      owner: false,
      is_override: true,
      months: ["2026-11"],
      amount_micros: 10_000_000,
      burned_micros: 0,
      distributed_micros: 0,
    });
    renderPanel();
    await user.type(await screen.findByLabelText("Raise by (USD)"), "10");
    await user.click(screen.getByRole("button", { name: "Raise" }));

    const dialog = screen.getByRole("heading", { name: "Add a local override?" })
      .parentElement as HTMLElement;
    expect(dialog).toHaveTextContent(/test-desktop \(22222222\) does/);
    expect(dialog).toHaveTextContent(/adds \$10 of rights to this device only/);
    expect(dialog).toHaveTextContent(/until the end of this month/);
    expect(dialog).toHaveTextContent(/labelled as an override/);
    expect(dialog).toHaveTextContent(/does not change the cap's target for your other devices/);
    expect(mockApi.meshCapRaise).not.toHaveBeenCalled();

    // Cancel: nothing happens.
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(mockApi.meshCapRaise).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Raise" }));
    await user.click(screen.getByRole("button", { name: "Add local override" }));
    await waitFor(() => expect(mockApi.meshCapRaise).toHaveBeenCalledWith(CAP_ID, "10"));
    expect(
      await screen.findByText(/Added \$10\.00 to this device only, as a local override/),
    ).toBeInTheDocument();
    // Owner-only actions are not offered on a non-owner.
    expect(
      screen.queryByRole("button", { name: "Reclaim unspent rights" }),
    ).not.toBeInTheDocument();
  });

  it("asks before lowering, explaining the burn and spend already made", async () => {
    const user = userEvent.setup();
    mockApi.meshCapsList.mockResolvedValue(capReport({ caps: [capRow()] }));
    mockApi.meshCapLower.mockResolvedValue({
      cap_id: CAP_ID,
      owner: true,
      is_override: false,
      months: ["2026-11"],
      amount_micros: 30_000_000,
      burned_micros: 2_000_000,
      distributed_micros: 0,
    });
    renderPanel();
    await user.type(await screen.findByLabelText("Lower to (USD a month)"), "30");
    await user.click(screen.getByRole("button", { name: "Lower" }));

    const dialog = screen.getByRole("heading", {
      name: "Lower this spend cap to $30 a month?",
    }).parentElement as HTMLElement;
    expect(dialog).toHaveTextContent(/gives up the rights it holds above its new share/);
    expect(dialog).toHaveTextContent(/lowering below what is already spent caps every device/);
    expect(mockApi.meshCapLower).not.toHaveBeenCalled();

    await user.click(within(dialog).getByRole("button", { name: "Lower the cap" }));
    await waitFor(() => expect(mockApi.meshCapLower).toHaveBeenCalledWith(CAP_ID, "30"));
    expect(await screen.findByText(/Lowered the cap to \$30\.00 a month/)).toBeInTheDocument();
  });

  it("reclaims on the owner after a confirmation", async () => {
    const user = userEvent.setup();
    mockApi.meshCapsList.mockResolvedValue(capReport({ caps: [capRow()] }));
    mockApi.meshCapReclaim.mockResolvedValue({ cap_id: CAP_ID, devices: [DESKTOP_ID] });
    renderPanel();
    await user.click(await screen.findByRole("button", { name: "Reclaim unspent rights" }));
    expect(mockApi.meshCapReclaim).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Reclaim rights" }));
    await waitFor(() => expect(mockApi.meshCapReclaim).toHaveBeenCalledWith(CAP_ID, null));
    expect(
      await screen.findByText(/Asked 22222222 to hand their unspent rights/),
    ).toBeInTheDocument();
  });
});

describe("CapsPanel enforcement", () => {
  it("needs the master password, explains the 403 behaviour, then switches it on", async () => {
    const user = userEvent.setup();
    mockApi.meshCapsList.mockResolvedValue(
      capReport({ caps: [capRow()], gate: gate(), gate_fresh: true }),
    );
    mockApi.meshCapEnforce.mockResolvedValue({ caps: [CAP_ID], on: true });
    renderPanel();

    const toggle = await screen.findByRole("checkbox", { name: "Enforce on this device" });
    expect(toggle).not.toBeChecked();
    await user.click(toggle);

    const dialog = screen.getByRole("heading", {
      name: "Enforce this spend cap on this device",
    }).parentElement as HTMLElement;
    expect(dialog).toHaveTextContent(/HTTP 403 \(not 429, so SDKs do not retry them\)/);
    // The overshoot is qualified, never "at most one request" (MD-1).
    expect(dialog).not.toHaveTextContent(/at most one request/);
    expect(dialog).toHaveTextContent(
      /while no request cost is known \(after a gateway restart or at the start of a month\)/,
    );
    expect(dialog).toHaveTextContent(/typical \(95th-percentile\) cost/);
    expect(dialog).toHaveTextContent(/can together go over by more than one request/);
    expect(dialog).toHaveTextContent(/a gateway restart can forget spend it has not saved yet/);
    expect(dialog).toHaveTextContent(/never charged against the cap/);
    expect(dialog).toHaveTextContent(/self-limit on traffic through Tethra's gateway/);
    expect(dialog).toHaveTextContent(/not a security boundary/);
    expect(dialog).toHaveTextContent(/no other device can change it/);
    // Nothing changes until the password is given.
    expect(mockApi.meshCapEnforce).not.toHaveBeenCalled();
    expect(toggle).not.toBeChecked();

    mockApi.meshCapsList.mockResolvedValue(
      capReport({
        caps: [capRow({ enforced_here: true })],
        gate: gate(),
        gate_fresh: true,
      }),
    );
    await user.type(screen.getByLabelText(/master password/i), PASSWORD);
    await user.click(screen.getByRole("button", { name: "Enforce" }));

    await waitFor(() =>
      expect(mockApi.meshCapEnforce).toHaveBeenCalledWith(PASSWORD, CAP_ID, true),
    );
    expect(await screen.findByText(/now enforces this cap/)).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByRole("checkbox", { name: "Enforce on this device" })).toBeChecked(),
    );
    expect(screen.queryByLabelText(/master password/i)).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain(PASSWORD);
  });

  it("asks for the password to switch it off too, and cancelling changes nothing", async () => {
    const user = userEvent.setup();
    mockApi.meshCapsList.mockResolvedValue(
      capReport({ caps: [capRow({ enforced_here: true })], gate: gate(), gate_fresh: true }),
    );
    renderPanel();
    const toggle = await screen.findByRole("checkbox", { name: "Enforce on this device" });
    expect(toggle).toBeChecked();
    await user.click(toggle);
    expect(
      screen.getByRole("heading", { name: "Stop enforcing this spend cap on this device" }),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(mockApi.meshCapEnforce).not.toHaveBeenCalled();
    expect(screen.getByRole("checkbox", { name: "Enforce on this device" })).toBeChecked();
  });

  it("keeps the dialog open on a wrong password and never echoes it", async () => {
    const user = userEvent.setup();
    mockApi.meshCapsList.mockResolvedValue(capReport({ caps: [capRow()] }));
    mockApi.meshCapEnforce.mockRejectedValue({
      code: "wrong_password",
      message: `wrong password: ${PASSWORD}`,
    });
    renderPanel();
    await user.click(await screen.findByRole("checkbox", { name: "Enforce on this device" }));
    await user.type(screen.getByLabelText(/master password/i), PASSWORD);
    await user.click(screen.getByRole("button", { name: "Enforce" }));
    expect(await screen.findByText("wrong password: [hidden]")).toBeInTheDocument();
    expect(screen.getByLabelText(/master password/i)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(PASSWORD);
  });

  it("warns when the gateway reports enforcement inactive", async () => {
    mockApi.meshCapsList.mockResolvedValue(
      capReport({
        caps: [capRow()],
        gate: gate({ inactive_reason: "no spend cap is enforced on this device" }),
        gate_fresh: true,
      }),
    );
    renderPanel();
    const warning = await screen.findByText(
      /Enforcement inactive: no spend cap is enforced on this device\./,
    );
    expect(warning).toHaveClass("warnbox");
    expect(warning).not.toHaveTextContent(/not holding/);
  });

  it("uses stronger wording when the gate is failing open", async () => {
    mockApi.meshCapsList.mockResolvedValue(
      capReport({
        caps: [capRow({ enforced_here: true })],
        gate: gate({
          inactive_reason: "the spend-cap tables could not be read",
          failing_open: true,
        }),
        gate_fresh: true,
      }),
    );
    renderPanel();
    const warning = await screen.findByText(
      /Enforcement inactive: the spend-cap tables could not be read\./,
    );
    expect(warning).toHaveClass("error");
    expect(warning).toHaveTextContent(/forwarding every request/);
    expect(warning).toHaveTextContent(/not holding/);
  });

  it("says nothing is enforced when a cap is enforced here but the gateway is not running", async () => {
    mockApi.meshCapsList.mockResolvedValue(
      capReport({
        caps: [capRow({ enforced_here: true })],
        gate: gate({ at_ms: Date.now() - 3_600_000 }),
        gate_fresh: false,
      }),
    );
    renderPanel();
    expect(
      await screen.findByText(/does not seem to be running on this device/),
    ).toHaveTextContent(/nothing is being enforced right now/);
  });

  it("shows what the gateway still admits for an enforced cap", async () => {
    mockApi.meshCapsList.mockResolvedValue(
      capReport({
        caps: [capRow({ enforced_here: true })],
        gate: gate({
          caps: [
            {
              cap_id: CAP_ID,
              month: "2026-11",
              enforced: true,
              avail_micros: 1_500_000,
              near_exhaustion: true,
              accounting_incomplete: false,
              unpriced_requests: 2,
              unmetered_requests: 1,
              refused_requests: 4,
            },
          ],
        }),
        gate_fresh: true,
      }),
    );
    renderPanel();
    const line = await screen.findByText(/gateway still admits \$1\.50/);
    expect(line).toHaveTextContent(/one request through at a time/);
    expect(line).toHaveTextContent(/Refused: 4; unpriced: 2; without usage: 1\./);
  });
});
