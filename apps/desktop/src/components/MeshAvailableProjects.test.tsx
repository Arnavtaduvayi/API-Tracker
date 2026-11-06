// "Available from your devices" (Tethra Mesh, Increment 10; MESH-SI-13):
// shared projects not bound here, each bound only by an explicit "Bind to…"
// to an existing local project or a new one. Rendering and the Devices poll
// never bind; local projects are read only when the dialog opens. Fake
// values only.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  DESKTOP_ID,
  LOCAL_ID,
  MESH_A,
  MESH_B,
  MESH_C,
  inMesh,
  localProject,
  projectRow,
} from "./MeshTestFixtures";

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      meshProjectsList: vi.fn(),
      meshProjectBind: vi.fn(),
      meshProjectShare: vi.fn(),
      projectList: vi.fn(),
      projectCreateForMesh: vi.fn(),
    },
  };
});

import { api } from "../api";
import { MeshAvailableProjects } from "./MeshAvailableProjects";

const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>;
const status = inMesh();
const DEVICES = status.initialized ? status.devices : [];

function rows() {
  return [
    projectRow({ name: "fake-shared", publishing_devices: [DESKTOP_ID] }),
    // Bound here already: not available.
    projectRow({
      mesh_project_id: MESH_B,
      name: "fake-bound",
      bound_local_project: "local-other",
      bound_local_project_name: "fake-other",
    }),
    // Archived or merged: not available.
    projectRow({ mesh_project_id: MESH_C, name: "fake-archived", archived: true }),
    projectRow({
      mesh_project_id: "ce".repeat(16),
      name: "fake-merged",
      merged_into: MESH_A,
      root: MESH_A,
    }),
  ];
}

function renderList(refreshKey = 0) {
  return render(<MeshAvailableProjects refreshKey={refreshKey} devices={DEVICES} />);
}

beforeEach(() => {
  mockApi.meshProjectsList.mockResolvedValue(rows());
  mockApi.projectList.mockResolvedValue([
    localProject(),
    localProject({ id: "local-other", name: "fake-other" }),
  ]);
});

describe("MeshAvailableProjects", () => {
  it("lists only shared projects not bound here, not archived and not merged", async () => {
    renderList();
    const row = (await screen.findByText("fake-shared")).closest("tr") as HTMLElement;
    expect(within(row).getByText("aaaaaaaa")).toBeInTheDocument();
    expect(within(row).getByText("test-desktop (22222222)")).toBeInTheDocument();
    expect(screen.queryByText("fake-bound")).not.toBeInTheDocument();
    expect(screen.queryByText("fake-archived")).not.toBeInTheDocument();
    expect(screen.queryByText("fake-merged")).not.toBeInTheDocument();
  });

  it("never binds on render or on a refresh, and reads local projects only for the dialog", async () => {
    const { rerender } = renderList(0);
    await screen.findByText("fake-shared");
    rerender(<MeshAvailableProjects refreshKey={1} devices={DEVICES} />);
    await waitFor(() => expect(mockApi.meshProjectsList).toHaveBeenCalledTimes(2));
    expect(mockApi.meshProjectBind).not.toHaveBeenCalled();
    expect(mockApi.meshProjectShare).not.toHaveBeenCalled();
    expect(mockApi.projectCreateForMesh).not.toHaveBeenCalled();
    expect(mockApi.projectList).not.toHaveBeenCalled();
  });

  it("says so when nothing is available", async () => {
    mockApi.meshProjectsList.mockResolvedValue([]);
    renderList();
    expect(await screen.findByText(/None right now/)).toBeInTheDocument();
  });

  it("binds to an existing local project only on the explicit click", async () => {
    const user = userEvent.setup();
    mockApi.meshProjectBind.mockResolvedValue(MESH_A);
    renderList();
    await user.click(
      await screen.findByRole("button", { name: "Bind fake-shared (aaaaaaaa) to a project" }),
    );
    expect(
      screen.getByRole("heading", { name: "Bind fake-shared to a project on this device" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/never individual requests/)).toBeInTheDocument();

    const select = await screen.findByLabelText("Project");
    // A local project already bound to another shared project is not offered.
    const taken = within(select).getByRole("option", {
      name: "fake-other (already bound to fake-bound)",
    }) as HTMLOptionElement;
    expect(taken.disabled).toBe(true);
    expect(screen.getByRole("button", { name: "Bind" })).toBeDisabled();
    expect(mockApi.meshProjectBind).not.toHaveBeenCalled();

    mockApi.meshProjectsList.mockResolvedValue([
      projectRow({ name: "fake-shared", bound_local_project: LOCAL_ID }),
    ]);
    await user.selectOptions(select, LOCAL_ID);
    await user.click(screen.getByRole("button", { name: "Bind" }));
    await waitFor(() => expect(mockApi.meshProjectBind).toHaveBeenCalledWith(MESH_A, LOCAL_ID));
    expect(mockApi.meshProjectBind).toHaveBeenCalledTimes(1);
    expect(await screen.findByText(/Bound fake-shared to fake-local\./)).toBeInTheDocument();
    expect(await screen.findByText(/None right now/)).toBeInTheDocument();
  });

  it("creates a new project by name, then binds it", async () => {
    const user = userEvent.setup();
    mockApi.projectCreateForMesh.mockResolvedValue(
      localProject({ id: "local-new", name: "fake-new" }),
    );
    mockApi.meshProjectBind.mockResolvedValue(MESH_A);
    renderList();
    await user.click(
      await screen.findByRole("button", { name: "Bind fake-shared (aaaaaaaa) to a project" }),
    );
    await user.click(screen.getByRole("radio", { name: "Create a new project" }));
    const name = screen.getByLabelText("New project name");
    // Pre-filled with the shared project's name, but nothing happens yet.
    expect(name).toHaveValue("fake-shared");
    expect(mockApi.projectCreateForMesh).not.toHaveBeenCalled();
    await user.clear(name);
    await user.type(name, "fake-new");
    await user.click(screen.getByRole("button", { name: "Bind" }));

    await waitFor(() =>
      expect(mockApi.projectCreateForMesh).toHaveBeenCalledWith({
        name: "fake-new",
        description: "",
        notes: "",
        environments: [],
        repoPaths: [],
      }),
    );
    await waitFor(() =>
      expect(mockApi.meshProjectBind).toHaveBeenCalledWith(MESH_A, "local-new"),
    );
    expect(
      await screen.findByText(/Created fake-new and bound fake-shared to it/),
    ).toBeInTheDocument();
  });

  it("says the project was created when only the bind failed", async () => {
    const user = userEvent.setup();
    mockApi.projectCreateForMesh.mockResolvedValue(
      localProject({ id: "local-new", name: "fake-new" }),
    );
    mockApi.meshProjectBind.mockRejectedValue({
      code: "invalid_input",
      message: "that mesh project is archived",
    });
    renderList();
    await user.click(
      await screen.findByRole("button", { name: "Bind fake-shared (aaaaaaaa) to a project" }),
    );
    await user.click(screen.getByRole("radio", { name: "Create a new project" }));
    await user.click(screen.getByRole("button", { name: "Bind" }));
    expect(
      await screen.findByText(
        /Created the project fake-new, but binding it failed: that mesh project is archived/,
      ),
    ).toBeInTheDocument();
  });

  it("cancelling the dialog binds nothing", async () => {
    const user = userEvent.setup();
    renderList();
    await user.click(
      await screen.findByRole("button", { name: "Bind fake-shared (aaaaaaaa) to a project" }),
    );
    await user.selectOptions(await screen.findByLabelText("Project"), LOCAL_ID);
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("heading", { name: /Bind fake-shared/ })).toBeNull();
    expect(mockApi.meshProjectBind).not.toHaveBeenCalled();
  });
});
