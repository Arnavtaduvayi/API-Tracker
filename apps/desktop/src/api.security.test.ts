import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock the Tauri IPC bridge so we can assert the exact command + payload each
// security-sensitive api method sends to the backend, and exercise the
// vault-locked propagation path.
const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

import {
  api,
  isApiError,
  setVaultLockedHandler,
  subscribeToProductAnalytics,
  type ProductAnalyticsSignal,
} from "./api";

beforeEach(() => {
  invoke.mockReset();
});

describe("secret-bearing command payloads", () => {
  it("credential_reveal sends selector+password and returns the plaintext", async () => {
    invoke.mockResolvedValueOnce("FAKE-PLAINTEXT-VALUE");
    const value = await api.credentialReveal("web/openai", "master-pw");
    expect(invoke).toHaveBeenCalledWith("credential_reveal", {
      selector: "web/openai",
      password: "master-pw",
    });
    expect(value).toBe("FAKE-PLAINTEXT-VALUE");
  });

  it("credential_delete carries the reauth password to the backend", async () => {
    invoke.mockResolvedValueOnce(undefined);
    await api.credentialDelete("web/openai", "master-pw");
    expect(invoke).toHaveBeenCalledWith("credential_delete", {
      selector: "web/openai",
      password: "master-pw",
    });
  });

  it("credential_replace_value carries password + new value", async () => {
    invoke.mockResolvedValueOnce([]);
    await api.credentialReplaceValue("web/openai", "master-pw", "NEW-SECRET");
    expect(invoke).toHaveBeenCalledWith("credential_replace_value", {
      selector: "web/openai",
      password: "master-pw",
      value: "NEW-SECRET",
    });
  });

  it("env_example_write and env_export carry the reauth password", async () => {
    invoke.mockResolvedValue("/repo/.env.example");
    await api.envExampleWrite("app", "/repo/.env.example", "X=1\n", "master-pw");
    expect(invoke).toHaveBeenLastCalledWith("env_example_write", {
      project: "app",
      examplePath: "/repo/.env.example",
      content: "X=1\n",
      password: "master-pw",
    });
    invoke.mockResolvedValue({});
    await api.envExport({
      project: "app",
      path: "/repo/.env",
      vars: null,
      password: "master-pw",
      overwrite: false,
      ttlMinutes: null,
    });
    const lastCall = invoke.mock.calls[invoke.mock.calls.length - 1] as [
      string,
      Record<string, unknown>,
    ];
    const [cmd, payload] = lastCall;
    expect(cmd).toBe("env_export");
    expect(payload.password).toBe("master-pw");
  });

  it("rotation_rollback carries the reauth password", async () => {
    invoke.mockResolvedValueOnce({});
    await api.rotationRollback("rot-1", "master-pw", true);
    expect(invoke).toHaveBeenCalledWith("rotation_rollback", {
      id: "rot-1",
      password: "master-pw",
      revokeNew: true,
    });
  });
});

describe("backend authorization errors are surfaced honestly", () => {
  it("rethrows a WrongPassword ApiError unchanged (no silent success)", async () => {
    invoke.mockRejectedValueOnce({ code: "wrong_password", message: "wrong password" });
    await expect(api.credentialReveal("web/openai", "bad")).rejects.toMatchObject({
      code: "wrong_password",
    });
  });

  it("normalizes a non-ApiError rejection into an ApiError", async () => {
    invoke.mockRejectedValueOnce("boom");
    const err = await api.credentialDelete("x", "y").catch((e) => e);
    expect(isApiError(err)).toBe(true);
    expect(err.code).toBe("unknown");
  });
});

describe("vault-locked propagation", () => {
  it("fires the registered handler when the backend reports vault_locked", async () => {
    const onLocked = vi.fn();
    setVaultLockedHandler(onLocked);
    invoke.mockRejectedValueOnce({ code: "vault_locked", message: "locked" });
    await expect(api.credentialReveal("web/openai", "pw")).rejects.toMatchObject({
      code: "vault_locked",
    });
    expect(onLocked).toHaveBeenCalledTimes(1);
    setVaultLockedHandler(() => {});
  });
});

describe("privacy-bounded product analytics signals", () => {
  it("emits only a fixed project lifecycle event after a successful create", async () => {
    const signals: ProductAnalyticsSignal[] = [];
    const unsubscribe = subscribeToProductAnalytics((signal) => signals.push(signal));
    invoke.mockResolvedValueOnce({ id: "private-project-id" });

    await api.projectCreate({
      name: "Private project name",
      description: "Private description",
      notes: "Private notes",
      environments: ["production"],
      repoPaths: ["/private/repository/path"],
    });
    unsubscribe();

    expect(signals).toEqual([{ event: { name: "project_created" }, inventoryChanged: true }]);
    expect(JSON.stringify(signals)).not.toContain("Private");
    expect(JSON.stringify(signals)).not.toContain("repository");
  });

  it("classifies credential tracking without forwarding credential metadata", async () => {
    const signals: ProductAnalyticsSignal[] = [];
    const unsubscribe = subscribeToProductAnalytics((signal) => signals.push(signal));
    invoke.mockResolvedValueOnce({ id: "private-credential-id" });

    await api.credentialAdd({
      project: "private-project",
      provider: "private-provider",
      name: "private-key-name",
      environment: "production",
      value: "SECRET-VALUE",
      keyCreatedAt: null,
      expiresAt: null,
      docsUrl: "https://private.example/docs",
      notes: "private notes",
    });
    unsubscribe();

    expect(signals).toEqual([
      {
        event: { name: "credential_tracked", tracking_method: "stored_secret" },
        inventoryChanged: true,
      },
    ]);
    expect(JSON.stringify(signals)).toBe(
      '[{"event":{"name":"credential_tracked","tracking_method":"stored_secret"},"inventoryChanged":true}]',
    );
  });

  it("does not emit a lifecycle signal when the backend action fails", async () => {
    const signals: ProductAnalyticsSignal[] = [];
    const unsubscribe = subscribeToProductAnalytics((signal) => signals.push(signal));
    invoke.mockRejectedValueOnce({ code: "invalid", message: "rejected" });

    await expect(
      api.projectCreate({
        name: "not-created",
        description: "",
        notes: "",
        environments: [],
        repoPaths: [],
      }),
    ).rejects.toMatchObject({ code: "invalid" });
    unsubscribe();

    expect(signals).toEqual([]);
  });
});
