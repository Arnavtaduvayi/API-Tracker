// Cross-device usage card (Tethra Mesh, Increment 10; MESH-SI-11, SI-19).
// Each device's row carries core's freshness (current, as of, stale,
// removed); a device without figures is "No data from", never zeros; the
// total is shown only with core's label; the notes are shown; unpriced and
// not-extracted counts are visible; and the card never shows provider
// figures. It publishes first on open and on Refresh only. Fake values only.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  DESKTOP_ID,
  MESH_A,
  MESH_B,
  NOT_IN_MESH,
  OLD_ID,
  SERVER_ID,
  USAGE_NOTES,
  deviceUsage,
  inMesh,
  projectUsage,
  totals,
  usageReport,
} from "./MeshTestFixtures";

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      meshStatus: vi.fn(),
      meshUsageReport: vi.fn(),
    },
  };
});

import { api } from "../api";
import { MeshUsageCard } from "./MeshUsageCard";

const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>;

const LABEL = "estimated, gateway-observed, across 3 device(s); 1 stale; 1 with no data";

function richReport() {
  return usageReport({
    projects: [
      projectUsage({
        devices: [
          deviceUsage({
            totals: totals({
              requests: 120,
              priced_requests: 100,
              unpriced_requests: 7,
              unextracted_requests: 13,
              input_tokens: 45_000,
              output_tokens: 9_000,
              estimated_cost_micros: 1_250_000,
            }),
          }),
          deviceUsage({
            device_id: DESKTOP_ID,
            device_name: "test-desktop",
            is_self: false,
            as_of: new Date(Date.now() - 30 * 3_600_000).toISOString(),
            stale: true,
            totals: totals({ requests: 4, priced_requests: 4, estimated_cost_micros: 40_000 }),
          }),
          deviceUsage({
            device_id: OLD_ID,
            device_name: "old-box",
            is_self: false,
            as_of: null,
            removed: true,
            totals: totals({ requests: 2, priced_requests: 0, unpriced_requests: 0 }),
            split_unknown_requests: 2,
            split_known_since: "2026-11-03",
          }),
        ],
        no_data_from: [[SERVER_ID, "test-server"]],
        total: totals({
          requests: 126,
          priced_requests: 104,
          unpriced_requests: 7,
          unextracted_requests: 13,
          input_tokens: 45_000,
          output_tokens: 9_000,
          estimated_cost_micros: 1_290_000,
        }),
        total_label: LABEL,
      }),
    ],
  });
}

function rowOf(name: string): HTMLElement {
  return screen.getByText(name).closest("tr") as HTMLElement;
}

beforeEach(() => {
  mockApi.meshStatus.mockResolvedValue(inMesh());
  mockApi.meshUsageReport.mockResolvedValue(richReport());
});

describe("MeshUsageCard figures and labels", () => {
  it("labels every device row with core's freshness and badges", async () => {
    render(<MeshUsageCard meshProjectId={MESH_A} />);
    await screen.findByText("test-desktop");

    const me = rowOf("test-laptop");
    expect(within(me).getByText("this device")).toBeInTheDocument();
    expect(within(me).getByText("current")).toBeInTheDocument();
    expect(within(me).queryByText("stale")).not.toBeInTheDocument();

    const desk = rowOf("test-desktop");
    expect(within(desk).getByText("stale")).toBeInTheDocument();
    expect(within(desk).getByText("1 day ago")).toBeInTheDocument();
    expect(within(desk).queryByText("removed")).not.toBeInTheDocument();

    const old = rowOf("old-box");
    expect(within(old).getByText("removed")).toBeInTheDocument();
    expect(within(old).getByText("never exchanged")).toBeInTheDocument();
  });

  it("lists a device without figures as 'No data from', unknown, not as zeros", async () => {
    render(<MeshUsageCard meshProjectId={MESH_A} />);
    const none = await screen.findByText(/No data from test-server \(33333333\)/);
    expect(none).toHaveTextContent(/unknown, not zero/);
    const row = none.closest("tr") as HTMLElement;
    expect(row.textContent).not.toMatch(/\$0\.00/);
    expect(within(row).queryByText("0")).not.toBeInTheDocument();
  });

  it("shows the unpriced, not-extracted and split-unknown counts beside the estimate", async () => {
    render(<MeshUsageCard meshProjectId={MESH_A} />);
    await screen.findByText("test-laptop");
    expect(screen.getByRole("columnheader", { name: "Unpriced" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Not extracted" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Split unknown" })).toBeInTheDocument();
    const me = rowOf("test-laptop");
    expect(within(me).getByText("7")).toBeInTheDocument();
    expect(within(me).getByText("13")).toBeInTheDocument();
    expect(within(me).getByText("$1.25 est.")).toBeInTheDocument();
    expect(within(rowOf("old-box")).getAllByText("2").length).toBeGreaterThan(0);
    expect(
      screen.getByText(
        /old-box \(44444444\): the priced\/unpriced split is known from 2026-11-03/,
      ),
    ).toBeInTheDocument();
  });

  it("labels the total with core's total_label and shows the notes", async () => {
    render(<MeshUsageCard meshProjectId={MESH_A} />);
    const total = await screen.findByRole("rowheader", { name: `Total — ${LABEL}` });
    const row = total.closest("tr") as HTMLElement;
    expect(within(row).getByText("126")).toBeInTheDocument();
    expect(within(row).getByText("$1.29 est.")).toBeInTheDocument();
    for (const note of USAGE_NOTES) expect(screen.getByText(note)).toBeInTheDocument();
  });

  it("has no total row when no device has figures", async () => {
    mockApi.meshUsageReport.mockResolvedValue(
      usageReport({
        projects: [
          projectUsage({
            no_data_from: [[DESKTOP_ID, "test-desktop"]],
            total_label:
              "estimated, gateway-observed, across 0 device(s); 0 stale; 1 with no data",
          }),
        ],
      }),
    );
    render(<MeshUsageCard meshProjectId={MESH_A} />);
    expect(await screen.findByText(/No data from test-desktop/)).toBeInTheDocument();
    expect(screen.queryByRole("rowheader", { name: /^Total/ })).not.toBeInTheDocument();
    expect(screen.getByText(/so there is no total/)).toBeInTheDocument();
  });

  it("never shows provider-reported figures", async () => {
    render(<MeshUsageCard meshProjectId={MESH_A} />);
    const card = await screen.findByTestId("mesh-usage-card");
    await within(card).findByText("test-laptop");
    expect(
      within(card).getByRole("heading", {
        name: "Usage across your devices (estimated, gateway-observed)",
      }),
    ).toBeInTheDocument();
    for (const header of within(card).getAllByRole("columnheader")) {
      expect(header.textContent).not.toMatch(/reported|bill|budget/i);
    }
    // Outside core's own note (which says it is never summed with it), the
    // card names no reported cost and no "(provider-reported)" figure.
    const notes = within(card).getByText(USAGE_NOTES[0]);
    const text = (card.textContent ?? "").replace(notes.textContent ?? "", "");
    expect(text).not.toMatch(/reported cost|provider-reported/i);
    expect(within(card).queryByText(/^Reported/)).not.toBeInTheDocument();
  });

  it("shows why this device's usage was not published first", async () => {
    mockApi.meshUsageReport.mockResolvedValue({
      ...richReport(),
      publish_error: "the mesh store is busy",
    });
    render(<MeshUsageCard meshProjectId={MESH_A} />);
    expect(
      await screen.findByText(/could not be published first \(the mesh store is busy\)/),
    ).toBeInTheDocument();
  });
});

describe("MeshUsageCard loading", () => {
  it("publishes first on open and on Refresh only, for the one project", async () => {
    const user = userEvent.setup();
    render(<MeshUsageCard meshProjectId={MESH_A} />);
    await screen.findByText("test-laptop");
    expect(mockApi.meshUsageReport).toHaveBeenCalledTimes(1);
    expect(mockApi.meshUsageReport).toHaveBeenCalledWith(
      { project: MESH_A, month: null, day: null },
      true,
    );
    // The project page's mode does not re-read the mesh status.
    expect(mockApi.meshStatus).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(mockApi.meshUsageReport).toHaveBeenCalledTimes(2));
    expect(mockApi.meshUsageReport).toHaveBeenLastCalledWith(
      { project: MESH_A, month: null, day: null },
      true,
    );
  });

  it("all-projects mode titles each project and renders nothing outside a mesh", async () => {
    mockApi.meshUsageReport.mockResolvedValue(
      usageReport({
        projects: [
          projectUsage({ name: "fake-one" }),
          projectUsage({ mesh_project_id: MESH_B, name: "fake-two", archived: true }),
        ],
      }),
    );
    const { unmount } = render(<MeshUsageCard />);
    expect(await screen.findByRole("heading", { name: /fake-one/ })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /fake-two/ })).toHaveTextContent("archived");
    expect(mockApi.meshUsageReport).toHaveBeenCalledWith(
      { project: null, month: null, day: null },
      true,
    );
    unmount();

    vi.clearAllMocks();
    mockApi.meshStatus.mockResolvedValue(NOT_IN_MESH);
    render(<MeshUsageCard />);
    await waitFor(() => expect(mockApi.meshStatus).toHaveBeenCalled());
    expect(screen.queryByTestId("mesh-usage-card")).not.toBeInTheDocument();
    expect(mockApi.meshUsageReport).not.toHaveBeenCalled();
  });

  it("shows the backend's message when the report cannot be read", async () => {
    mockApi.meshUsageReport.mockRejectedValue({ code: "mesh_storage", message: "store busy" });
    render(<MeshUsageCard meshProjectId={MESH_A} />);
    expect(await screen.findByText(/store busy/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("[object Object]");
  });
});
