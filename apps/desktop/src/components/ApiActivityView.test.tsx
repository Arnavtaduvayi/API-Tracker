import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      observeOverview: vi.fn().mockResolvedValue([]),
      observeSessions: vi.fn().mockResolvedValue([]),
      observeCertStatus: vi.fn().mockResolvedValue({ present: false, system_trust: "absent" }),
      observeSettingsGet: vi.fn().mockResolvedValue({
        default_mode: "off",
        event_retention_days: 7,
        aggregate_retention_days: 90,
      }),
      observeDiagnostics: vi.fn().mockResolvedValue([]),
    },
  };
});

import { api } from "../api";
import { ApiActivityView } from "./ApiActivityView";

const mockApi = api as unknown as { observeOverview: ReturnType<typeof vi.fn> };

beforeEach(() => {
  mockApi.observeOverview.mockReset();
  mockApi.observeOverview.mockResolvedValue([]);
});

describe("ApiActivityView", () => {
  it("states the metadata-only guarantee and empty state", async () => {
    render(<ApiActivityView />);
    // The privacy guarantee is stated up front.
    expect(screen.getByText(/Metadata only/i, { selector: "p" })).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByText(/No API traffic observed yet/i)).toBeInTheDocument(),
    );
  });

  it("the Privacy tab enumerates what is never stored", async () => {
    render(<ApiActivityView />);
    await userEvent.click(screen.getByRole("button", { name: "Privacy" }));
    expect(
      screen.getByText(/Request and response bodies are never retained/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/Query strings are discarded/i)).toBeInTheDocument();
    expect(screen.getByText(/nothing is uploaded to Tethra/i)).toBeInTheDocument();
  });
});

describe("ApiActivityView load failure (NEW-41)", () => {
  it("does not report a failed overview read as 'no traffic observed'", async () => {
    mockApi.observeOverview.mockRejectedValue({
      code: "db_error",
      message: "database is locked",
    });
    render(<ApiActivityView />);
    expect(
      await screen.findByText(/overview could not be read: database is locked/),
    ).toBeInTheDocument();
    expect(screen.getByText(/do not read it as none/)).toBeInTheDocument();
    // The negative control: the empty state the audited screen fell back to.
    expect(document.body.textContent).not.toMatch(/No API traffic observed yet/);
  });
});
