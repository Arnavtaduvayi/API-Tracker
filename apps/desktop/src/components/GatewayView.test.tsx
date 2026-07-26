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
      providersList: vi.fn().mockResolvedValue([]),
      projectList: vi.fn().mockResolvedValue([]),
    },
  };
});

import { api } from "../api";
import { GatewayView } from "./GatewayView";

const mockApi = api as unknown as {
  gatewayDoctor: ReturnType<typeof vi.fn>;
  gatewayLocateCli: ReturnType<typeof vi.fn>;
  gatewayInstall: ReturnType<typeof vi.fn>;
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
  };
  d.listener = { verdict: "verified", version: "0.1.0" };
  return d;
}

beforeEach(() => {
  mockApi.gatewayDoctor.mockReset();
  mockApi.gatewayLocateCli.mockReset();
  mockApi.gatewayInstall.mockReset();
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
    expect(screen.getByText(/unavailable_vault_locked/)).toBeInTheDocument();
    expect(
      screen.getByText(/absence of recorded traffic is not evidence of absence of traffic/),
    ).toBeInTheDocument();
  });
});
