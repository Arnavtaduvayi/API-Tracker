// Vitest setup: jest-dom matchers and per-test cleanup. Tests mock the Tauri
// IPC bridge (`@tauri-apps/api/core`) individually.
import "@testing-library/jest-dom/vitest";
import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

// jsdom ships no ResizeObserver, which the decorative react-three-fiber
// canvas measures itself with. Stub it so component trees containing the
// visual chrome still render; the 3D scene itself is not under test.
// jsdom has no matchMedia either; the sidebar uses it to auto-collapse.
// Reports "does not match", i.e. the expanded desktop layout.
if (typeof window !== "undefined" && typeof window.matchMedia !== "function") {
  window.matchMedia = ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
}

if (!("ResizeObserver" in globalThis)) {
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver;
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});
