import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Security workflow tests render React components in jsdom and assert on
// user-visible behavior and the backend `invoke` payloads (never on visual
// implementation details). The pure-function tests (utils, safe-url) run in
// the same environment.
export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
  },
});
