// Gateway panel behavior: no silent install (consent card + honest
// CLI-absence), truthful status rendering, and the locked-strip fallback.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { GatewayDoctor } from "../types";

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      gatewayDoctor: vi.fn(),
      gatewayLocateCli: vi.fn(),
      gatewayInstall: vi.fn(),
      gatewayRouteList: vi.fn().mockResolvedValue({ routes: [], skipped: [] }),
      gatewayMatchWhileLockedGet: vi.fn().mockResolvedValue(false),
      gatewayMatchWhileLockedSet: vi.fn().mockResolvedValue(undefined),
      gatewayUnlink: vi.fn(),
      providersList: vi.fn().mockResolvedValue([]),
      projectList: vi.fn().mockResolvedValue([]),
    },
  };
});

import { api } from "../api";
import { GatewayView } from "./GatewayView";

const mockApi = api as unknown as {
  gatewayDoctor: ReturnType<typeof vi.fn>;
  gatewayMatchWhileLockedGet: ReturnType<typeof vi.fn>;
  gatewayMatchWhileLockedSet: ReturnType<typeof vi.fn>;
  gatewayLocateCli: ReturnType<typeof vi.fn>;
  gatewayInstall: ReturnType<typeof vi.fn>;
  gatewayUnlink: ReturnType<typeof vi.fn>;
};

function absent(): GatewayDoctor {
  return {
    overall: "info",
    findings: [
      {
        id: "not_installed",
        severity: "info",
        title: "gateway not installed",
        detail: "no service is installed",
        repair: "tethra gateway install",
      },
    ],
    service: {
      platform: "macos-launch-agent",
      installed: false,
      definition_path: "/home/u/Library/LaunchAgents/dev.api-tracker.gateway.plist",
      definition: null,
      matches_data_dir: false,
      binary_exists: false,
      binary_version: null,
      registered: false,
      running: false,
      pid: null,
      os_will_run: { state: "no" },
      owned_artifacts: [],
      notes: [],
    },
    gateway: null,
    listener: null,
    configured_port: null,
    enabled: false,
    links: [],
    cli_version: "0.1.0",
  };
}

function running(): GatewayDoctor {
  const d = absent();
  d.service.installed = true;
  d.service.matches_data_dir = true;
  d.service.os_will_run = { state: "yes" };
  d.gateway = {
    version: "0.1.0",
    port: 49723,
    uptime_secs: 12,
    routes: 1,
    routes_unavailable: 0,
    connections_in_flight: 0,
    queue_depth: 0,
    dropped_events: 0,
    written_events: 3,
    persist_failures: 0,
    routes_degraded: false,
    recording_degraded: false,
    recording_paused: false,
    matching_key_present: false,
    last_observation_at: null,
    last_error: null,
    routes_disabled: 0,
    routes_skipped: [],
    pid: 4242,
    matching_key_deadline_secs: null,
    matching_key_expired: false,
  };
  d.listener = { verdict: "verified", version: "0.1.0" };
  return d;
}

function linked(): GatewayDoctor {
  const d = running();
  d.links = [
    {
      project_id: "app",
      route_prefix: "openai",
      env_path: "/Users/dev/app/.env",
      env_file_exists: true,
      env_points_at_gateway: true,
      issues: [],
    },
  ];
  return d;
}

beforeEach(() => {
  mockApi.gatewayDoctor.mockReset();
  mockApi.gatewayLocateCli.mockReset();
  mockApi.gatewayInstall.mockReset();
  mockApi.gatewayUnlink.mockReset();
});

describe("GatewayView consent and honesty", () => {
  it("shows the consent card (never a silent install) when nothing is installed", async () => {
    mockApi.gatewayDoctor.mockResolvedValue(absent());
    render(<GatewayView />);
    expect(
      await screen.findByText(/Tethra can run a local background gateway at 127\.0\.0\.1/),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Enable Local Gateway" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Not now" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Learn more" })).toBeInTheDocument();
    expect(mockApi.gatewayInstall).not.toHaveBeenCalled();
  });

  it("reports a missing CLI honestly instead of installing anything", async () => {
    mockApi.gatewayDoctor.mockResolvedValue(absent());
    mockApi.gatewayLocateCli.mockResolvedValue(null);
    render(<GatewayView />);
    await userEvent.click(await screen.findByRole("button", { name: "Enable Local Gateway" }));
    expect(await screen.findByText(/no runnable .*tethra.* CLI was found/)).toBeInTheDocument();
    expect(mockApi.gatewayInstall).not.toHaveBeenCalled();
  });

  it("renders truthful status for a running gateway, including attribution-off", async () => {
    mockApi.gatewayDoctor.mockResolvedValue(running());
    render(<GatewayView />);
    expect(await screen.findByText(/running v0\.1\.0 \(pid 4242\)/)).toBeInTheDocument();
    expect(screen.getByText(/identity verified/)).toBeInTheDocument();
    expect(screen.getByText(/unavailable_no_key/)).toBeInTheDocument();
    expect(
      screen.getByText(/absence of recorded traffic is not evidence of absence of traffic/),
    ).toBeInTheDocument();
  });

  it("states the drop-on-lock promise the implementation actually keeps", async () => {
    mockApi.gatewayDoctor.mockResolvedValue(running());
    render(<GatewayView />);
    await userEvent.click(await screen.findByRole("button", { name: "Enable attribution…" }));
    const body = await screen.findByText(/dropped on stop, revoke, or lock/);
    expect(body).toBeInTheDocument();
    // The consent copy must name the bound, not just the default.
    expect(body.textContent).toMatch(/keep-while-locked defaults OFF/);
    expect(body.textContent).toMatch(/at most your auto-lock duration \(8 h cap\)/);
  });

  it("shows the keep-while-locked countdown rather than a bare 'on'", async () => {
    const d = running();
    d.gateway!.matching_key_present = true;
    d.gateway!.matching_key_deadline_secs = 25 * 60;
    mockApi.gatewayDoctor.mockResolvedValue(d);
    render(<GatewayView />);
    expect(
      await screen.findByText(/key drops in 25 min unless you unlock/),
    ).toBeInTheDocument();
  });

  it("distinguishes an expired keep-while-locked window from a key never pushed", async () => {
    const d = running();
    d.gateway!.matching_key_present = false;
    d.gateway!.matching_key_expired = true;
    mockApi.gatewayDoctor.mockResolvedValue(d);
    render(<GatewayView />);
    expect(
      await screen.findByText(/keep-while-locked window expired; push the key again/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/until a key is pushed/)).not.toBeInTheDocument();
  });

  it("requires reauthentication to turn keep-while-locked on", async () => {
    mockApi.gatewayMatchWhileLockedGet.mockResolvedValue(false);
    mockApi.gatewayDoctor.mockResolvedValue(running());
    render(<GatewayView />);
    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Keep matching while the vault is locked/ }),
    );
    expect(
      await screen.findByText(/locking the vault immediately drops the gateway's matching key/),
    ).toBeInTheDocument();
    // Nothing is written until the password is supplied and confirmed.
    expect(mockApi.gatewayMatchWhileLockedSet).not.toHaveBeenCalled();
  });
});

describe("GatewayView unlink reporting (RA-013)", () => {
  /** Open Projects and confirm the unlink of the one linked project. */
  async function unlink() {
    mockApi.gatewayDoctor.mockResolvedValue(linked());
    render(<GatewayView />);
    await userEvent.click(await screen.findByRole("button", { name: "Projects" }));
    await userEvent.click(await screen.findByRole("button", { name: "Unlink" }));
    await userEvent.click(await screen.findByRole("button", { name: "Unlink and restore" }));
  }

  it("never says 'restored' for a variable whose prior value was never recorded", async () => {
    // The exact report `gateway_unlink` now returns for a withheld prior:
    // the restore did NOT happen, the row was kept, and the .env is still
    // pointing at the gateway. The audited screen answered this with
    // "Unlinked app (restored)." — a word that was simply false (RA-013).
    mockApi.gatewayUnlink.mockResolvedValue({
      route_prefix: "openai",
      project_id: "app",
      complete: false,
      outcomes: [
        {
          outcome: "prior_not_recorded",
          path: "/Users/dev/app/.env",
          key: "OPENAI_BASE_URL",
        },
        { outcome: "restored", path: "/Users/dev/app/.env", key: "NO_PROXY" },
      ],
    });
    await unlink();

    // The negative control: the word the old screen printed unconditionally.
    expect(screen.queryByText(/Unlinked app \(restored\)/)).not.toBeInTheDocument();
    // What is actually true, naming the file and the variable.
    const said = await screen.findByText(/NOT restored/);
    expect(said.textContent).toMatch(/\/Users\/dev\/app\/\.env \(OPENAI_BASE_URL\)/);
    expect(said.textContent).toMatch(/its gateway line is STILL in your file/);
    expect(screen.getByText(/1 of 2 item\(s\) could not be restored/)).toBeInTheDocument();
    expect(screen.getByText(/app is still linked to openai/)).toBeInTheDocument();
    // The variable that DID come back is still reported as such.
    expect(
      screen.getByText(/\/Users\/dev\/app\/\.env \(NO_PROXY\): the value you had before/),
    ).toBeInTheDocument();
  });

  it("distinguishes a value left as the user edited it from one restored", async () => {
    mockApi.gatewayUnlink.mockResolvedValue({
      route_prefix: "openai",
      project_id: "app",
      complete: true,
      outcomes: [
        {
          outcome: "left_user_edit",
          path: "/Users/dev/app/.env",
          key: "OPENAI_BASE_URL",
        },
      ],
    });
    await unlink();

    expect(
      await screen.findByRole("heading", { name: "Unlinked app from openai" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/left exactly as YOU changed it after linking/),
    ).toBeInTheDocument();
    // A completed unlink is still not a blanket claim that values came back.
    expect(
      screen.queryByText(/the value you had before linking is back/),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/NOT restored/)).not.toBeInTheDocument();
  });

  it("names the file and the error when a restore fails outright", async () => {
    mockApi.gatewayUnlink.mockResolvedValue({
      route_prefix: "openai",
      project_id: "app",
      complete: false,
      outcomes: [
        {
          outcome: "failed",
          path: "/Users/dev/app/.env",
          key: "",
          error: "the file is now a symlink; refusing to replace it",
        },
      ],
    });
    await unlink();

    const line = await screen.findByText(/NOT restored/);
    expect(line.textContent).toMatch(/\/Users\/dev\/app\/\.env/);
    expect(line.textContent).toMatch(/the file is now a symlink; refusing to replace it/);
  });

  it("shows an outcome it does not recognise rather than dropping it", async () => {
    // A variant a future gateway build adds must not vanish from a report
    // the user reads to decide whether their .env is back.
    mockApi.gatewayUnlink.mockResolvedValue({
      route_prefix: "openai",
      project_id: "app",
      complete: false,
      outcomes: [{ outcome: "some_future_variant", path: "/Users/dev/app/.env", key: "X" }],
    });
    await unlink();

    expect(
      await screen.findByText(/\/Users\/dev\/app\/\.env \(X\): some_future_variant/),
    ).toBeInTheDocument();
  });

  it("says nothing was restored when the link had no restore record", async () => {
    // `gateway_unlink` removes a link row with no `prior_env_json` and
    // returns complete: true with NO outcomes. Nothing was restored, so the
    // screen must not let "complete" be read as "your .env is back".
    mockApi.gatewayUnlink.mockResolvedValue({
      route_prefix: "openai",
      project_id: "app",
      complete: true,
      outcomes: [],
    });
    await unlink();

    expect(
      await screen.findByText(/Nothing was recorded for this link, so nothing was restored/),
    ).toBeInTheDocument();
  });
});
