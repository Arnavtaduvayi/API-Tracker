// MESH-SI-14: the mesh emits no analytics. Two guards:
//
// 1. Behaviour (MD-5). "Devices → Available from your devices → Bind to… → a
//    new project" creates a local project. With consent granted, the App's
//    product-analytics listener mounted, and only the Tauri `invoke` bridge
//    mocked (the real `api` module), that path must reach no analytics event:
//    no `project_created`, no `inventory_snapshot`. A positive control shows
//    the same listener does track the ordinary project form's create.
// 2. Source (MD-9). No mesh component imports the analytics module or calls
//    `trackAnalytics`/`gtag`, and no `mesh_*` command maps to a product
//    analytics signal in `api.ts`.
//
// Fake values only.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import apiSource from "../api.ts?raw";
import { DESKTOP_ID, MESH_A, inMesh, localProject, projectRow } from "./MeshTestFixtures";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

vi.mock("@tauri-apps/plugin-opener", () => ({
  openUrl: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../analytics", async () => {
  const actual = await vi.importActual<typeof import("../analytics")>("../analytics");
  return {
    ...actual,
    getAnalyticsConsent: () => "granted",
    initializeAnalytics: vi.fn().mockResolvedValue("granted"),
    subscribeToAnalyticsConsent: () => () => {},
    trackAnalytics: vi.fn(),
  };
});

import { api } from "../api";
import { trackAnalytics } from "../analytics";
import App from "../App";
import { MeshAvailableProjects } from "./MeshAvailableProjects";

const track = trackAnalytics as unknown as ReturnType<typeof vi.fn>;
const status = inMesh();
const DEVICES = status.initialized ? status.devices : [];
const NEW_PROJECT = localProject({ id: "local-new", name: "fake-new" });

/** A tiny backend: what the unlocked App and the bind dialog ask for. */
function backend(command: string): unknown {
  switch (command) {
    case "vault_status":
      return { exists: true, unlocked: true, data_dir: "/data" };
    case "settings_get":
      return { monitor_interval_minutes: 0 };
    case "project_list":
    case "credential_list":
    case "tracking_list":
      return [];
    case "monitor_run_full":
      return {};
    case "tracking_foreground_active":
      return false;
    case "mesh_status":
      return status;
    case "mesh_projects_list":
      return [projectRow({ name: "fake-shared", publishing_devices: [DESKTOP_ID] })];
    case "project_create":
      return NEW_PROJECT;
    case "mesh_project_bind":
      return MESH_A;
    default:
      throw { code: "unavailable", message: "n/a" };
  }
}

function eventNames(): string[] {
  return track.mock.calls.map((c) => (c[0] as { name: string }).name);
}

beforeEach(() => {
  invoke.mockImplementation(async (command: string) => backend(command));
});

describe("MESH-SI-14: binding to a new project from Devices", () => {
  it("creates the project without any analytics event, with consent granted", async () => {
    const user = userEvent.setup();
    render(<App />);
    // The App is up, consented, and its product-analytics listener mounted:
    // the first screen is tracked.
    await waitFor(() =>
      expect(track).toHaveBeenCalledWith({ name: "screen_view", screen_name: "welcome" }),
    );
    await waitFor(() => expect(eventNames()).toContain("inventory_snapshot"));
    track.mockClear();

    render(<MeshAvailableProjects refreshKey={0} devices={DEVICES} />);
    await user.click(
      await screen.findByRole("button", { name: "Bind fake-shared (aaaaaaaa) to a project" }),
    );
    // No local project here yet, so the dialog offers a new one.
    await user.click(await screen.findByRole("radio", { name: "Create a new project" }));
    const name = screen.getByLabelText("New project name");
    await user.clear(name);
    await user.type(name, "fake-new");
    await user.click(screen.getByRole("button", { name: "Bind" }));

    expect(
      await screen.findByText(/Created fake-new and bound fake-shared to it/),
    ).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith(
      "project_create",
      expect.objectContaining({ name: "fake-new" }),
    );
    expect(invoke).toHaveBeenCalledWith("mesh_project_bind", {
      meshProjectId: MESH_A,
      localProjectId: "local-new",
    });
    // Let any listener-triggered inventory read settle before looking.
    await new Promise((r) => setTimeout(r, 20));
    expect(eventNames()).not.toContain("project_created");
    expect(eventNames()).not.toContain("inventory_snapshot");
    expect(track).not.toHaveBeenCalled();

    // Positive control: the ordinary project form's create is still tracked
    // by the same listener, so the silence above is the mesh path's doing.
    await api.projectCreate({
      name: "fake-form",
      description: "",
      notes: "",
      environments: [],
      repoPaths: [],
    });
    expect(track).toHaveBeenCalledWith({ name: "project_created" });
  });
});

// Every mesh component's source, test files excluded.
const MESH_SOURCES = Object.entries(
  import.meta.glob<string>(
    ["./Mesh*.tsx", "./Mesh*.ts", "./CapsPanel.tsx", "./DevicesView.tsx"],
    {
      query: "?raw",
      import: "default",
      eager: true,
    },
  ),
).filter(([path]) => !/\.test\.tsx?$/.test(path) && !path.endsWith("MeshTestFixtures.ts"));

describe("MESH-SI-14: no analytics in mesh sources", () => {
  it("reads the mesh components it guards", () => {
    const names = MESH_SOURCES.map(([path]) => path);
    expect(names).toEqual(
      expect.arrayContaining([
        "./CapsPanel.tsx",
        "./DevicesView.tsx",
        "./MeshAvailableProjects.tsx",
        "./MeshCredentialSharePanel.tsx",
        "./MeshProjectPanel.tsx",
      ]),
    );
    expect(MESH_SOURCES.length).toBeGreaterThanOrEqual(15);
  });

  it("no mesh component imports the analytics module or sends an event", () => {
    for (const [path, src] of MESH_SOURCES) {
      expect(src, path).not.toMatch(/from\s+["'][./]*analytics["']/);
      expect(src, path).not.toMatch(/\btrackAnalytics\b|\bgtag\b|subscribeToProductAnalytics/);
    }
  });

  it("no mesh command maps to a product analytics signal", () => {
    expect(signalledCommands()).toContain("project_create");
    expect([...signalledCommands()].filter((c) => c.startsWith("mesh_"))).toEqual([]);
  });

  it("no mesh component calls an api method that sends a product analytics signal", () => {
    const methods = signallingMethods();
    // Sensitivity: the ordinary create signals; the mesh variant does not.
    expect(methods).toContain("projectCreate");
    expect(methods).toContain("credentialAdd");
    expect(methods).not.toContain("projectCreateForMesh");
    for (const [path, src] of MESH_SOURCES) {
      for (const m of methods) {
        expect(src, `${path} calls api.${m}`).not.toMatch(new RegExp(`\\bapi\\.${m}\\(`));
      }
    }
  });
});

/** The commands `productAnalyticsSignal` in api.ts maps to an event. */
function signalledCommands(): Set<string> {
  const start = apiSource.indexOf("function productAnalyticsSignal(");
  const end = apiSource.indexOf("function publishProductAnalytics(");
  expect(start).toBeGreaterThan(-1);
  expect(end).toBeGreaterThan(start);
  const mapping = apiSource.slice(start, end);
  return new Set([...mapping.matchAll(/case\s+"(\w+)":/g)].map((m) => m[1]));
}

/** `api` methods whose call sends one of those commands with the signal on. */
function signallingMethods(): string[] {
  const commands = signalledCommands();
  const body = apiSource.slice(apiSource.indexOf("export const api = {"));
  const out: string[] = [];
  for (const m of body.matchAll(
    /(\w+):\s*\([^)]*\)[^=]*=>\s*call<[^>]*>\(\s*"(\w+)"([^)]*)\)/g,
  )) {
    const [, method, command, rest] = m;
    if (commands.has(command) && !/productAnalytics:\s*false/.test(rest)) out.push(method);
  }
  return out;
}
