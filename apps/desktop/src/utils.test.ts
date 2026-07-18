import { describe, expect, it } from "vitest";
import { emptyToNull, statusLabel, statusSeverity, toDateInput } from "./utils";

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
