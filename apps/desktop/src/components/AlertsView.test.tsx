// A failed load is not an empty result (NEW-41). The alerts list started as
// `[]`, so a read that never returned rendered "No alerts." — the most
// reassuring sentence available — beside the error that says nothing is
// known.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import type { Alert } from "../types";

vi.mock("@tauri-apps/plugin-notification", () => ({
  isPermissionGranted: vi.fn().mockResolvedValue(false),
  requestPermission: vi.fn().mockResolvedValue("denied"),
  sendNotification: vi.fn(),
}));

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      alertsList: vi.fn(),
      monitorStatus: vi.fn(),
      monitorRunFull: vi.fn(),
      alertAcknowledge: vi.fn(),
      alertResolve: vi.fn(),
    },
  };
});

import { api } from "../api";
import { AlertsView } from "./AlertsView";

const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>;

function alert(): Alert {
  return {
    id: "a1",
    credential_id: "cred-1",
    project_id: "p1",
    kind: "expiring_soon",
    severity: "high",
    title: "openai-main expires in 3 days",
    detail: "the key expires on 2026-08-01",
    evidence: "expires_at = 2026-08-01",
    recommended_action: "rotate the key",
    created_at: "2026-07-29T00:00:00Z",
    acknowledged_at: null,
    resolved_at: null,
  } as unknown as Alert;
}

beforeEach(() => {
  vi.clearAllMocks();
  mockApi.monitorStatus.mockResolvedValue({
    last_run_at: null,
    last_success_at: null,
    last_failure_at: null,
    last_error: null,
    last_detail: null,
  });
});

describe("AlertsView load failures (NEW-41)", () => {
  it("does not render 'No alerts' when the list could not be read", async () => {
    mockApi.alertsList.mockRejectedValue({ code: "db_error", message: "database is locked" });
    render(<AlertsView />);
    expect(await screen.findByText(/database is locked/)).toBeInTheDocument();
    expect(screen.getByText(/An unread list is not an empty one/)).toBeInTheDocument();
    // The negative control: the sentence the audited screen printed.
    expect(document.body.textContent).not.toMatch(/No alerts\./);
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("still says 'No alerts' when the read succeeded and there are none", async () => {
    mockApi.alertsList.mockResolvedValue([]);
    render(<AlertsView />);
    expect(await screen.findByText(/No alerts\./)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/An unread list is not an empty one/);
  });

  it("keeps the alerts that loaded when only the run history failed", async () => {
    mockApi.alertsList.mockResolvedValue([alert()]);
    mockApi.monitorStatus.mockRejectedValue({
      code: "db_error",
      message: "status unavailable",
    });
    render(<AlertsView />);
    expect(await screen.findByText("openai-main expires in 3 days")).toBeInTheDocument();
    expect(screen.getByText(/status unavailable/)).toBeInTheDocument();
  });
});
