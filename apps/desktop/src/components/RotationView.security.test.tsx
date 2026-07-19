import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { RotationView as RotationData } from "../types";

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      credentialList: vi.fn().mockResolvedValue([]),
      rotationSchedules: vi.fn().mockResolvedValue([]),
      rotationsList: vi.fn(),
      rotationGet: vi.fn(),
      rotationEvents: vi.fn().mockResolvedValue([]),
      rotationRollback: vi.fn(),
    },
  };
});

import { api } from "../api";
import { RotationView } from "./RotationView";

const mockApi = api as unknown as {
  rotationsList: ReturnType<typeof vi.fn>;
  rotationGet: ReturnType<typeof vi.fn>;
  rotationRollback: ReturnType<typeof vi.fn>;
};

// A rollback-capable rotation: old_version present, not yet revoked.
function rollbackable(): RotationData {
  return {
    id: "rot-abcdef01",
    credential_id: "cred-1",
    provider: "openai",
    state: "grace_period",
    mode: "manual_create",
    note: "",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    approved_at: "2026-01-01T00:00:00Z",
    old_version: 1,
    new_version: 2,
    sync_plan_id: null,
    grace_minutes: 60,
    grace_ends_at: null,
    old_provider_key_id: null,
    new_provider_key_id: null,
    provider_project_id: null,
    new_value_validated: true,
    old_disabled_at: null,
    old_revoked_at: null,
    last_error: "",
    manual_instructions: "",
    credential_name: "openai-main",
    project_name: "web",
    waiting_on: null,
  };
}

beforeEach(() => {
  mockApi.rotationsList.mockReset();
  mockApi.rotationGet.mockReset();
  mockApi.rotationRollback.mockReset();
});

describe("RotationView — destructive rollback confirmation", () => {
  it("requires a confirm step AND reauth before rolling back", async () => {
    const user = userEvent.setup();
    const rot = rollbackable();
    mockApi.rotationsList.mockResolvedValue([rot]);
    mockApi.rotationGet.mockResolvedValue(rot);
    mockApi.rotationRollback.mockResolvedValue({ ...rot, state: "rolled_back" });

    render(<RotationView />);
    // Open the rotation detail.
    await user.click(await screen.findByRole("button", { name: "rot-abcd" }));
    await screen.findByRole("button", { name: "Roll back…" });

    // Stage 1: the destructive confirmation (not yet a password prompt).
    await user.click(screen.getByRole("button", { name: "Roll back…" }));
    await user.click(await screen.findByRole("button", { name: "Continue to password" }));

    // Stage 2: reauthentication — rollback only happens after the password.
    expect(mockApi.rotationRollback).not.toHaveBeenCalled();
    await user.type(await screen.findByLabelText(/master password/i), "master-pw");
    await user.click(screen.getByRole("button", { name: "Roll back" }));

    await waitFor(() =>
      expect(mockApi.rotationRollback).toHaveBeenCalledWith("rot-abcdef01", "master-pw", false),
    );
  });
});
