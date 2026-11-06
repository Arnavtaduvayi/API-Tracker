// The Devices nav entry (Tethra Mesh, Increment 09): it renders the Devices
// view, and no `screen_view` analytics event is tracked for it, even with
// analytics consent granted (MESH-SI-14: no analytics for mesh features).

import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { VaultStatus } from "../types";

vi.mock("@tauri-apps/plugin-opener", () => ({
  openUrl: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../analytics", async () => {
  const actual = await vi.importActual<typeof import("../analytics")>("../analytics");
  return {
    ...actual,
    getAnalyticsConsent: () => "granted",
    initializeAnalytics: vi.fn().mockResolvedValue("granted"),
    subscribeToAnalyticsConsent: () => () => {},
    trackAnalytics: vi.fn(),
  };
});

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    setVaultLockedHandler: () => {},
    api: {
      vaultStatus: vi.fn(),
      settingsGet: vi.fn().mockResolvedValue({ monitor_interval_minutes: 0 }),
      projectList: vi.fn().mockResolvedValue([]),
      credentialList: vi.fn().mockResolvedValue([]),
      vaultLock: vi.fn().mockResolvedValue(undefined),
      monitorRunFull: vi.fn().mockResolvedValue({}),
      gatewayDoctor: vi.fn().mockRejectedValue({ code: "unavailable", message: "n/a" }),
      gatewayActivity: vi.fn().mockRejectedValue({ code: "unavailable", message: "n/a" }),
      trackingList: vi.fn().mockResolvedValue([]),
      trackingForegroundActive: vi.fn().mockResolvedValue(false),
      meshStatus: vi.fn(),
    },
  };
});

import { api } from "../api";
import { trackAnalytics } from "../analytics";
import App from "../App";

const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>;
const track = trackAnalytics as unknown as ReturnType<typeof vi.fn>;

function status(): VaultStatus {
  return { exists: true, unlocked: true, data_dir: "/data" };
}

function screenViews(): unknown[] {
  return track.mock.calls
    .map((c) => c[0] as { name: string })
    .filter((e) => e.name === "screen_view");
}

beforeEach(() => {
  mockApi.vaultStatus.mockResolvedValue(status());
  mockApi.meshStatus.mockResolvedValue({
    initialized: false,
    node: { running: null, stopping: false, last_error: null, last_stop: null, external: null },
  });
});

describe("Devices navigation", () => {
  it("renders the Devices view and tracks no screen_view for it", async () => {
    render(<App />);
    const nav = await screen.findByRole("button", { name: "Devices" });
    // Positive control: other screens are tracked with consent granted. With no
    // projects the app redirects to Welcome on its own; wait for that to land
    // so it cannot be mistaken for a Devices screen_view below.
    await waitFor(() =>
      expect(track).toHaveBeenCalledWith({ name: "screen_view", screen_name: "welcome" }),
    );

    track.mockClear();
    fireEvent.click(nav);
    expect(
      await screen.findByRole("heading", { level: 1, name: "Devices" }),
    ).toBeInTheDocument();
    expect(
      await screen.findByRole("heading", { name: "This device is not in a mesh" }),
    ).toBeInTheDocument();
    expect(mockApi.meshStatus).toHaveBeenCalled();
    expect(nav).toHaveAttribute("aria-current", "page");
    expect(screenViews()).toEqual([]);
    // Nothing mesh-related reaches analytics at all.
    expect(JSON.stringify(track.mock.calls)).not.toMatch(/mesh|device/i);

    // Leaving Devices tracks the next screen again.
    fireEvent.click(screen.getByRole("button", { name: "Settings" }));
    await screen.findByRole("heading", { name: "Settings" });
    await waitFor(() =>
      expect(track).toHaveBeenCalledWith({ name: "screen_view", screen_name: "settings" }),
    );
  });
});
