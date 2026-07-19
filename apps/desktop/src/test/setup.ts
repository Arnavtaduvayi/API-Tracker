// Vitest setup: jest-dom matchers and per-test cleanup. Tests mock the Tauri
// IPC bridge (`@tauri-apps/api/core`) individually.
import "@testing-library/jest-dom/vitest";
import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});
