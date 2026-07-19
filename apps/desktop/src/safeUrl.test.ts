import { describe, expect, it } from "vitest";
import { safeExternalUrl } from "./utils";

// IPC-05: a user/vault-supplied docs_url must never render as a clickable
// href unless it is an explicitly-safe external scheme.
describe("safeExternalUrl", () => {
  it("allows http, https, and mailto", () => {
    expect(safeExternalUrl("https://platform.openai.com/docs")).toBe(
      "https://platform.openai.com/docs",
    );
    expect(safeExternalUrl("http://example.com")).toBe("http://example.com");
    expect(safeExternalUrl("mailto:support@example.com")).toBe("mailto:support@example.com");
  });

  it("rejects javascript, data, file, and vbscript schemes", () => {
    expect(safeExternalUrl("javascript:alert(document.cookie)")).toBeNull();
    expect(safeExternalUrl("JavaScript:alert(1)")).toBeNull();
    expect(safeExternalUrl("  javascript:alert(1)  ")).toBeNull();
    expect(safeExternalUrl("data:text/html,<script>alert(1)</script>")).toBeNull();
    expect(safeExternalUrl("file:///etc/passwd")).toBeNull();
    expect(safeExternalUrl("vbscript:msgbox(1)")).toBeNull();
  });

  it("rejects relative, empty, and malformed values", () => {
    expect(safeExternalUrl("/docs")).toBeNull();
    expect(safeExternalUrl("not a url")).toBeNull();
    expect(safeExternalUrl("")).toBeNull();
    expect(safeExternalUrl("   ")).toBeNull();
    expect(safeExternalUrl(null)).toBeNull();
    expect(safeExternalUrl(undefined)).toBeNull();
  });
});
