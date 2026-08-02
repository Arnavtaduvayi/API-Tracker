// Vitest setup: jest-dom matchers and per-test cleanup. Tests mock the Tauri
// IPC bridge (`@tauri-apps/api/core`) individually.
import "@testing-library/jest-dom/vitest";
import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

// jsdom has no matchMedia; the sidebar and ambient renderer use it for
// responsive layout and reduced-motion preferences.
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

// The ambient renderer treats a missing WebGL context as its supported static
// fallback. jsdom's default implementation emits a noisy not-implemented
// exception before returning null, so model the browser fallback directly.
Object.defineProperty(HTMLCanvasElement.prototype, "getContext", {
  configurable: true,
  value: vi.fn(() => null),
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});
