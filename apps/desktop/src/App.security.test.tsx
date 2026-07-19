import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { act } from "react";
import type { VaultStatus } from "./types";

// Capture the vault-locked handler App registers so we can fire it the way
// api.call does when the backend reports the vault has locked.
let lockedHandler: (() => void) | null = null;

vi.mock("./api", async () => {
  const actual = await vi.importActual<typeof import("./api")>("./api");
  return {
    ...actual,
    setVaultLockedHandler: (h: () => void) => {
      lockedHandler = h;
    },
    api: {
      vaultStatus: vi.fn(),
      settingsGet: vi.fn().mockResolvedValue({ monitor_interval_minutes: 0 }),
      projectList: vi.fn().mockResolvedValue([]),
      vaultLock: vi.fn().mockResolvedValue(undefined),
      monitorRunFull: vi.fn().mockResolvedValue({}),
    },
  };
});

import { api } from "./api";
import App from "./App";

const mockApi = api as unknown as { vaultStatus: ReturnType<typeof vi.fn> };

function status(unlocked: boolean): VaultStatus {
  return { exists: true, unlocked, data_dir: "/data" };
}

beforeEach(() => {
  mockApi.vaultStatus.mockReset();
  lockedHandler = null;
});

describe("App locked-vault gating (secret UI is not reachable while locked)", () => {
  it("renders the unlock screen when the backend reports the vault locked", async () => {
    mockApi.vaultStatus.mockResolvedValue(status(false));
    render(<App />);
    expect(await screen.findByRole("heading", { name: /unlock vault/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Destinations" })).not.toBeInTheDocument();
  });

  it("drops the authenticated UI when a backend call reports vault_locked", async () => {
    mockApi.vaultStatus.mockResolvedValue(status(true));
    render(<App />);
    // Authenticated nav is present while unlocked.
    await screen.findByRole("button", { name: "Destinations" });
    expect(lockedHandler).not.toBeNull();

    // Fire the vault-locked handler (what api.call does on a vault_locked
    // error from ANY command). The authenticated tree — including any open
    // reauth/confirm dialog and its in-memory password state — unmounts and
    // the unlock screen replaces it. No UI sequencing keeps a secret view up.
    act(() => lockedHandler!());
    await waitFor(() =>
      expect(screen.getByRole("heading", { name: /unlock vault/i })).toBeInTheDocument(),
    );
    expect(screen.queryByRole("button", { name: "Destinations" })).not.toBeInTheDocument();
  });
});
