import { describe, expect, it } from "vitest";
import {
  driftSeverity,
  emptyToNull,
  severityRank,
  statusLabel,
  statusSeverity,
  toDateInput,
  topSeverity,
} from "./utils";

describe("toDateInput", () => {
  it("extracts the date part from RFC 3339", () => {
    expect(toDateInput("2027-01-31T00:00:00Z")).toBe("2027-01-31");
  });
  it("handles missing values", () => {
    expect(toDateInput(null)).toBe("");
    expect(toDateInput(undefined)).toBe("");
  });
});

describe("statusLabel", () => {
  it("humanizes snake_case statuses", () => {
    expect(statusLabel("expiring_soon")).toBe("expiring soon");
    expect(statusLabel("shared_across_projects")).toBe("shared across projects");
  });
});

describe("statusSeverity", () => {
  it("classifies severities", () => {
    expect(statusSeverity("active")).toBe("ok");
    expect(statusSeverity("stale")).toBe("warn");
    expect(statusSeverity("possibly_exposed")).toBe("bad");
    expect(statusSeverity("revoked")).toBe("bad");
  });
});

describe("emptyToNull", () => {
  it("maps blank strings to null", () => {
    expect(emptyToNull("")).toBeNull();
    expect(emptyToNull("   ")).toBeNull();
    expect(emptyToNull("2030-01-01")).toBe("2030-01-01");
  });
});

describe("severityRank", () => {
  it("mirrors core's ordering and treats unknown severities as info", () => {
    expect(severityRank("critical")).toBeGreaterThan(severityRank("high"));
    expect(severityRank("high")).toBeGreaterThan(severityRank("medium"));
    expect(severityRank("medium")).toBeGreaterThan(severityRank("low"));
    expect(severityRank("low")).toBeGreaterThan(severityRank("info"));
    expect(severityRank("nonsense")).toBe(severityRank("info"));
  });
});

describe("topSeverity", () => {
  it("picks the highest severity", () => {
    expect(topSeverity(["low", "critical", "medium"])).toBe("critical");
    expect(topSeverity(["medium", "high"])).toBe("high");
    expect(topSeverity([])).toBeNull();
  });
});

describe("driftSeverity", () => {
  it("mirrors the core severity ordering", () => {
    expect(driftSeverity("unmapped_secret")).toBe("high");
    expect(driftSeverity("production_value_in_dev_file")).toBe("high");
    expect(driftSeverity("value_differs_from_vault")).toBe("medium");
    expect(driftSeverity("same_value_in_multiple_files")).toBe("medium");
    expect(driftSeverity("missing_expected_variable")).toBe("low");
    expect(driftSeverity("mapping_not_in_files")).toBe("info");
  });
});
