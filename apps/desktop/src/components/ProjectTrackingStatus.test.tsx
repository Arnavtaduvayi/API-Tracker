// The tracking-status contract, from the frontend side (AUD-05).
//
// Every fixture here is bytes Rust wrote: `statusFixtures.ts` imports a file
// generated and verified by `crates/tracking/tests/status_contract.rs`. The
// audited defect was invisible to a full frontend suite precisely because the
// suite's fixtures were hand-written — `status: null` in every case, against a
// declared type belonging to a different command — so the page's
// `overview.status.health.currently_working` was never evaluated against a real
// payload. These tests evaluate it against nothing else.

import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { ProjectOverview } from "../types";
import { DECLARED_STATE_TAGS, everyFixture, fixture } from "../test/statusFixtures";
import { ProjectTracking } from "./ProjectTracking";

vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));
vi.mock("../api", () => ({
  api: {
    projectFolderPreview: vi.fn(),
    projectFolderLink: vi.fn(),
    projectRescan: vi.fn(),
    projectSetTrackingEnabled: vi.fn(),
    projectUnlinkFolder: vi.fn(),
    projectResolveDetection: vi.fn(),
    projectUpdateDetection: vi.fn(),
  },
  isApiError: (e: unknown) => typeof e === "object" && e !== null && "message" in e,
}));

const noop = () => {};

function renderWith(overview: ProjectOverview) {
  return render(
    <ProjectTracking
      projectIdent="p1"
      overview={overview}
      reloading={false}
      onChanged={noop}
      onOpenAdvanced={noop}
    />,
  );
}

/** The rendered value of the "Tracking" row. */
function trackingLabel(): string {
  return screen.getByTestId("tracking-state").textContent ?? "";
}

// ---------------------------------------------------------------------------
// The shape
// ---------------------------------------------------------------------------

describe("the serialized ProjectOverview contract", () => {
  it("carries a projected `tracking` object for every state, never null", () => {
    for (const [name, o] of everyFixture()) {
      expect(o.tracking, `${name}: no tracking projection`).toBeTruthy();
      expect(typeof o.tracking.state, `${name}: state`).toBe("string");
      expect(typeof o.tracking.label, `${name}: label`).toBe("string");
      expect(o.tracking.label.length, `${name}: empty label`).toBeGreaterThan(0);
      expect(typeof o.tracking.is_working, `${name}: is_working`).toBe("boolean");
      expect(typeof o.tracking.sentence, `${name}: sentence`).toBe("string");
      expect(o.tracking.sentence.length, `${name}: empty sentence`).toBeGreaterThan(0);
      expect(typeof o.tracking.configuration_behind).toBe("boolean");
      expect(typeof o.tracking.folder_available).toBe("boolean");
      expect(["not_enabled", "active", "paused"]).toContain(o.tracking.attribution);
      // Nullable, but always PRESENT, so a surface never has to distinguish
      // "absent" from "null".
      expect(o.tracking).toHaveProperty("action");
      expect(o.tracking).toHaveProperty("last_observed_at");
      expect(o.tracking).toHaveProperty("first_verified_at");
      expect(o).toHaveProperty("folder_available");
    }
  });

  it("emits only state tokens the TypeScript union declares", () => {
    const seen = new Set<string>();
    for (const [name, o] of everyFixture()) {
      expect(DECLARED_STATE_TAGS, `${name}: undeclared state ${o.tracking.state}`).toContain(
        o.tracking.state,
      );
      seen.add(o.tracking.state);
    }
    // The other direction: a token declared here that Rust never produces is a
    // dead branch a surface might still be styling for.
    const unreachable = DECLARED_STATE_TAGS.filter((t) => !seen.has(t));
    expect(unreachable, "declared states with no fixture").toEqual([]);
  });

  it("`status` is a TrackingStatusReport and has no `health` key", () => {
    const o = fixture("tracking_on");
    expect(o.status).toBeTruthy();
    expect(o.status!.current.kind).toBe("verified_and_active");
    expect(o.status!.state).toBe("traffic_observed");
    expect(Array.isArray(o.status!.freshness)).toBe(true);
    // The exact path the audited build read. It does not exist and never did.
    const loose = o.status as unknown as Record<string, unknown>;
    expect(loose.health).toBeUndefined();
    expect(loose.setup_id).toBeUndefined();
    expect(loose.watch).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// What the page renders
// ---------------------------------------------------------------------------

describe("ProjectTracking against real payloads", () => {
  it("renders 'Tracking is on' for a verified and active setup", () => {
    // This is the audit's reproduction. On the audited head it rendered
    // "needs attention", for this payload and for every other one.
    renderWith(fixture("tracking_on"));
    expect(trackingLabel()).toBe("Tracking is on");
    // A healthy project is not told to do anything.
    expect(screen.queryByTestId("tracking-detail")).toBeNull();
  });

  it("does not read `status.health` — removing `status` entirely changes nothing", () => {
    // The negative control the audit asked for. If the component still consulted
    // `status.health.currently_working`, deleting `status` would flip the label
    // to the fallback state; the projected DTO makes that impossible.
    const healthy = fixture("tracking_on");
    const withoutStatus: ProjectOverview = { ...healthy, status: null };
    const { unmount } = renderWith(withoutStatus);
    expect(trackingLabel()).toBe("Tracking is on");
    unmount();

    // And the converse: a `status` carrying the OLD, impossible shape cannot
    // resurrect the fallback either, because nothing reads it.
    const withImpossibleStatus = {
      ...healthy,
      status: { health: { currently_working: false } },
    } as unknown as ProjectOverview;
    renderWith(withImpossibleStatus);
    expect(trackingLabel()).toBe("Tracking is on");
  });

  it("renders the label from every fixture, and never a bare token", () => {
    const expected: Record<string, string> = {
      tracking_on: "Tracking is on",
      partially_tracked: "Partially tracked",
      waiting_for_first_request: "Waiting for first request",
      restart_required: "Restart required",
      gateway_unavailable: "Gateway unavailable",
      gateway_unavailable_after_verification: "Gateway unavailable",
      route_unavailable: "Route unavailable",
      project_link_unavailable: "Project link unavailable",
      configuration_changed: "Configuration changed",
      attribution_paused: "Tracking is on",
      health_attribution_paused: "Attribution paused",
      needs_attention: "Tracking needs attention",
      setup_incomplete: "Setup did not finish",
      idle: "No recent requests",
      unsupported: "Nothing to track",
      folder_missing: "Folder missing",
      tracking_off: "Tracking is off",
      awaiting_setup: "Waiting for setup",
    };
    for (const [name, want] of Object.entries(expected)) {
      const { unmount } = renderWith(fixture(name as never));
      expect(trackingLabel(), `${name}`).toBe(want);
      // A user must never see the machine token itself.
      expect(trackingLabel()).not.toMatch(/^[a-z_]+$/);
      unmount();
    }
  });

  it("a project with no folder shows the call to action, not a status row", () => {
    renderWith(fixture("not_linked"));
    expect(screen.getByTestId("select-folder-cta")).toBeTruthy();
    expect(screen.queryByTestId("tracking-state")).toBeNull();
  });

  it("a state the user must act on names the action beside the sentence", () => {
    for (const name of [
      "gateway_unavailable",
      "route_unavailable",
      "project_link_unavailable",
      "needs_attention",
      "setup_incomplete",
      "restart_required",
    ] as const) {
      const o = fixture(name);
      const { unmount } = renderWith(o);
      const detail = screen.getByTestId("tracking-detail").textContent ?? "";
      expect(detail, `${name}: sentence`).toContain(o.tracking.sentence);
      expect(o.tracking.action, `${name}: action`).toBeTruthy();
      expect(detail, `${name}: action`).toContain(o.tracking.action!);
      unmount();
    }
  });

  it("an idle project is not asked to fix anything", () => {
    const o = fixture("idle");
    expect(o.tracking.action).toBeNull();
    renderWith(o);
    expect(trackingLabel()).toBe("No recent requests");
    expect(screen.getByTestId("tracking-detail").textContent).toContain("verified previously");
  });
});

// ---------------------------------------------------------------------------
// Historical traffic, attribution, folder
// ---------------------------------------------------------------------------

describe("what must never be conflated", () => {
  it("historical traffic does not produce a present-tense success", () => {
    const o = fixture("gateway_unavailable_after_verification");
    // The payload carries observations AND a first-verified timestamp.
    expect(o.tracking.last_observed_at).toBeTruthy();
    expect(o.tracking.first_verified_at).toBeTruthy();
    expect(o.tracking.is_working).toBe(false);
    renderWith(o);
    expect(trackingLabel()).toBe("Gateway unavailable");
  });

  it("attribution paused is shown beside tracking, not as a tracking failure", () => {
    const o = fixture("attribution_paused");
    expect(o.tracking.attribution).toBe("paused");
    expect(o.tracking.is_working).toBe(true);
    renderWith(o);
    // Universal tracking still reads as on...
    expect(trackingLabel()).toBe("Tracking is on");
    // ...and the degradation is its own, separate sentence.
    const note = screen.getByTestId("attribution-paused").textContent ?? "";
    expect(note).toContain("still being recorded");
    expect(note).toContain("attribution is paused");
  });

  it("the attribution-paused health variant still says tracking is active", () => {
    // `CurrentHealth::AttributionPaused` is not `is_currently_working`, which is
    // the shared resolver's own definition and not a second one. What must not
    // happen is the state reading as a total tracking failure — so its sentence
    // says otherwise, in the resolver's own words.
    const o = fixture("health_attribution_paused");
    expect(o.tracking.is_working).toBe(false);
    renderWith(o);
    expect(trackingLabel()).toBe("Attribution paused");
    expect(screen.getByTestId("tracking-detail").textContent).toContain("tracking active");
  });

  it("a project that never enabled attribution is not warned about it", () => {
    const o = fixture("tracking_on");
    expect(o.tracking.attribution).toBe("not_enabled");
    renderWith(o);
    expect(screen.queryByTestId("attribution-paused")).toBeNull();
  });

  it("a missing folder is reported as missing, not as edited files", () => {
    const o = fixture("folder_missing");
    expect(o.folder_available).toBe(false);
    renderWith(o);
    expect(trackingLabel()).toBe("Folder missing");
    const box = screen.getByTestId("folder-missing").textContent ?? "";
    expect(box).toContain("cannot find");
    expect(box).toContain("/work/app");
    expect(box).toContain("recorded activity is kept");
    // The wrong sentence, and the action that fails for it, are both absent.
    expect(screen.queryByTestId("scan-stale")).toBeNull();
    expect(screen.getByText("Rescan project")).toHaveProperty("disabled", true);
  });

  it("a present folder whose files changed still offers a rescan", () => {
    const o: ProjectOverview = { ...fixture("tracking_on"), scan_stale: true };
    renderWith(o);
    expect(screen.getByTestId("scan-stale").textContent).toContain(
      "changed since the last scan",
    );
    expect(screen.getByText("Rescan project")).toHaveProperty("disabled", false);
  });
});
