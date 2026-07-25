import { describe, expect, it, vi } from "vitest";
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

import { ApiActivityView } from "./ApiActivityView";

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
