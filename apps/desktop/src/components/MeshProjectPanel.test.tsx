// The "Devices" panel on a project's page (Tethra Mesh, Increment 10;
// MESH-SI-13). Rendering never shares or binds; Share is one explicit click
// with the sentence on what replicates; Unbind, archive and merge ask first;
// a merge refused because both projects have spend caps shows core's
// message. Fake values only.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  DESKTOP_ID,
  LOCAL_ID,
  MESH_A,
  MESH_B,
  MESH_C,
  NOT_IN_MESH,
  SELF_ID,
  capReport,
  inMesh,
  projectRow,
  usageReport,
} from "./MeshTestFixtures";

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      meshStatus: vi.fn(),
      meshProjectsList: vi.fn(),
      meshProjectShare: vi.fn(),
      meshProjectBind: vi.fn(),
      meshProjectUnbind: vi.fn(),
      meshProjectRename: vi.fn(),
      meshProjectArchive: vi.fn(),
      meshProjectMerge: vi.fn(),
      meshUsageReport: vi.fn(),
      meshCapsList: vi.fn(),
      meshCapCreate: vi.fn(),
      meshCapEnforce: vi.fn(),
    },
  };
});

import { api } from "../api";
import { MeshProjectPanel } from "./MeshProjectPanel";

const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>;

function shared() {
  return projectRow({
    bound_local_project: LOCAL_ID,
    bound_local_project_name: "fake-local",
    publishing_devices: [SELF_ID, DESKTOP_ID],
  });
}

function renderPanel() {
  return render(<MeshProjectPanel projectId={LOCAL_ID} projectName="fake-local" />);
}

/** Every call that changes mesh state. */
const WRITES = [
  "meshProjectShare",
  "meshProjectBind",
  "meshProjectUnbind",
  "meshProjectRename",
  "meshProjectArchive",
  "meshProjectMerge",
  "meshCapCreate",
  "meshCapEnforce",
];

function expectNoWrites() {
  for (const w of WRITES) expect(mockApi[w]).not.toHaveBeenCalled();
}

beforeEach(() => {
  mockApi.meshStatus.mockResolvedValue(inMesh());
  mockApi.meshProjectsList.mockResolvedValue([]);
  mockApi.meshUsageReport.mockResolvedValue(usageReport());
  mockApi.meshCapsList.mockResolvedValue(capReport());
});

describe("MeshProjectPanel not shared", () => {
  it("says so outside a mesh and reads nothing else", async () => {
    mockApi.meshStatus.mockResolvedValue(NOT_IN_MESH);
    renderPanel();
    expect(await screen.findByText(/This device is not in a mesh/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Share with my devices" })).toBeNull();
    expect(mockApi.meshProjectsList).not.toHaveBeenCalled();
    expect(mockApi.meshUsageReport).not.toHaveBeenCalled();
    expectNoWrites();
  });

  it("never shares or binds on render, even when a shared project has the same name", async () => {
    // A shared project named like this local one, bound nowhere here: it is
    // not this project's, and nothing binds it by name.
    mockApi.meshProjectsList.mockResolvedValue([projectRow({ name: "fake-local" })]);
    renderPanel();
    expect(
      await screen.findByRole("button", { name: "Share with my devices" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/This project is not shared/)).toBeInTheDocument();
    await waitFor(() => expect(mockApi.meshProjectsList).toHaveBeenCalled());
    expectNoWrites();
    expect(mockApi.meshUsageReport).not.toHaveBeenCalled();
    expect(mockApi.meshCapsList).not.toHaveBeenCalled();
  });

  it("explains what replicates, then shares on the explicit click", async () => {
    const user = userEvent.setup();
    mockApi.meshProjectShare.mockResolvedValue({ mesh_project_id: MESH_A, name: "fake-local" });
    renderPanel();
    const button = await screen.findByRole("button", { name: "Share with my devices" });
    const why = screen.getByText(/daily usage counters/);
    expect(why).toHaveTextContent(/requests, tokens, estimated cost/);
    expect(why).toHaveTextContent(
      /never individual requests, request content, routes or credentials/,
    );
    // Every member lists it by name and sees its usage after the next
    // exchange; binding decides only what that device counts (MD-7).
    expect(why).not.toHaveTextContent(/Your other devices see it only after/);
    expect(why).toHaveTextContent(/name and its daily usage counters/);
    expect(why).toHaveTextContent(
      /After their next exchange, every device in the mesh lists the project by name and can see its usage/,
    );
    expect(why).toHaveTextContent(/counts its own traffic for it only after you bind it there/);

    mockApi.meshProjectsList.mockResolvedValue([shared()]);
    await user.click(button);
    await waitFor(() => expect(mockApi.meshProjectShare).toHaveBeenCalledWith(LOCAL_ID));
    expect(mockApi.meshProjectShare).toHaveBeenCalledTimes(1);
    expect(await screen.findByText(/Shared as fake-local \(aaaaaaaa\)/)).toBeInTheDocument();
    // Now shared: the usage card and the spend-cap panel appear.
    expect(await screen.findByTestId("mesh-usage-card")).toBeInTheDocument();
    expect(await screen.findByTestId("mesh-caps-panel")).toBeInTheDocument();
    expect(mockApi.meshProjectBind).not.toHaveBeenCalled();
  });
});

describe("MeshProjectPanel shared", () => {
  it("names the shared project and the devices publishing for it", async () => {
    mockApi.meshProjectsList.mockResolvedValue([shared()]);
    renderPanel();
    const panel = await screen.findByTestId("mesh-project-panel");
    await within(panel).findByText("aaaaaaaa");
    expect(panel).toHaveTextContent(/Shared as fake-app/);
    expect(panel).toHaveTextContent(
      /2 device\(s\) published usage for it: test-laptop \(11111111\) — this device, test-desktop \(22222222\)/,
    );
    expect(screen.queryByRole("button", { name: "Share with my devices" })).toBeNull();
    // The cards for this mesh project, read with publish/reconcile on open.
    await waitFor(() =>
      expect(mockApi.meshUsageReport).toHaveBeenCalledWith(
        { project: MESH_A, month: null, day: null },
        true,
      ),
    );
    expect(mockApi.meshCapsList).toHaveBeenCalledWith(true);
    expectNoWrites();
  });

  it("unbinds only after a confirmation", async () => {
    const user = userEvent.setup();
    mockApi.meshProjectsList.mockResolvedValue([shared()]);
    mockApi.meshProjectUnbind.mockResolvedValue(true);
    renderPanel();
    await user.click(await screen.findByRole("button", { name: "Unbind" }));
    const dialog = screen.getByRole("heading", { name: "Unbind fake-local?" })
      .parentElement as HTMLElement;
    expect(dialog).toHaveTextContent(/stops publishing new usage/);
    expect(dialog).toHaveTextContent(/What it already published stays/);
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(mockApi.meshProjectUnbind).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Unbind" }));
    mockApi.meshProjectsList.mockResolvedValue([projectRow()]);
    const confirm = screen.getByRole("heading", { name: "Unbind fake-local?" })
      .parentElement as HTMLElement;
    await user.click(within(confirm).getByRole("button", { name: "Unbind" }));
    await waitFor(() => expect(mockApi.meshProjectUnbind).toHaveBeenCalledWith(LOCAL_ID));
    expect(await screen.findByText(/Unbound\./)).toBeInTheDocument();
    expect(
      await screen.findByRole("button", { name: "Share with my devices" }),
    ).toBeInTheDocument();
  });

  it("renames and archives the shared project after asking", async () => {
    const user = userEvent.setup();
    mockApi.meshProjectsList.mockResolvedValue([shared()]);
    mockApi.meshProjectRename.mockResolvedValue(MESH_A);
    mockApi.meshProjectArchive.mockResolvedValue(MESH_A);
    renderPanel();
    await user.click(await screen.findByText("Manage the shared project"));

    await user.click(screen.getByRole("button", { name: "Rename" }));
    const rename = screen.getByRole("heading", { name: /Rename the shared project/ })
      .parentElement as HTMLElement;
    expect(mockApi.meshProjectRename).not.toHaveBeenCalled();
    await user.type(within(rename).getByRole("textbox"), "fake-renamed");
    await user.click(within(rename).getByRole("button", { name: "Rename" }));
    await waitFor(() =>
      expect(mockApi.meshProjectRename).toHaveBeenCalledWith(MESH_A, "fake-renamed"),
    );

    await user.click(screen.getByRole("button", { name: "Archive shared project" }));
    expect(screen.getByText(/no way to unarchive it/)).toBeInTheDocument();
    expect(mockApi.meshProjectArchive).not.toHaveBeenCalled();
    const dialog = screen.getByRole("heading", { name: /Archive the shared project/ })
      .parentElement as HTMLElement;
    await user.click(within(dialog).getByRole("button", { name: "Archive shared project" }));
    await waitFor(() => expect(mockApi.meshProjectArchive).toHaveBeenCalledWith(MESH_A));
  });
});

describe("MeshProjectPanel merge", () => {
  function withOthers() {
    return [
      shared(),
      projectRow({ mesh_project_id: MESH_B, name: "fake-dup" }),
      projectRow({ mesh_project_id: MESH_C, name: "fake-old", archived: true }),
    ];
  }

  it("needs a confirmation and shows core's refusal when both projects have caps", async () => {
    const user = userEvent.setup();
    mockApi.meshProjectsList.mockResolvedValue(withOthers());
    mockApi.meshProjectMerge.mockRejectedValue({
      code: "invalid_input",
      message:
        "both projects have spend caps; lower one cap to 0 and archive that project first",
    });
    renderPanel();
    await user.click(await screen.findByText("Manage the shared project"));
    const select = screen.getByLabelText(/Merge with another shared project/);
    // Archived projects are not offered.
    expect(within(select).queryByText(/fake-old/)).toBeNull();
    await user.selectOptions(select, MESH_B);
    await user.click(screen.getByRole("button", { name: "Merge…" }));

    const dialog = screen.getByRole("heading", { name: "Merge fake-app and fake-dup?" })
      .parentElement as HTMLElement;
    expect(dialog).toHaveTextContent(/the same real project/);
    expect(dialog).toHaveTextContent(/smaller id stays as the root/);
    expect(dialog).toHaveTextContent(/refuses the merge when both projects have spend caps/);
    expect(mockApi.meshProjectMerge).not.toHaveBeenCalled();

    await user.click(within(dialog).getByRole("button", { name: "Merge" }));
    await waitFor(() => expect(mockApi.meshProjectMerge).toHaveBeenCalledWith(MESH_A, MESH_B));
    expect(
      await screen.findByText(
        "both projects have spend caps; lower one cap to 0 and archive that project first",
      ),
    ).toBeInTheDocument();
  });

  it("cancelling the confirmation does not merge; a merge reports the root", async () => {
    const user = userEvent.setup();
    mockApi.meshProjectsList.mockResolvedValue(withOthers());
    mockApi.meshProjectMerge.mockResolvedValue({ root: MESH_A, merged: MESH_B });
    renderPanel();
    await user.click(await screen.findByText("Manage the shared project"));
    await user.selectOptions(
      screen.getByLabelText(/Merge with another shared project/),
      MESH_B,
    );
    await user.click(screen.getByRole("button", { name: "Merge…" }));
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(mockApi.meshProjectMerge).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Merge…" }));
    await user.click(screen.getByRole("button", { name: "Merge" }));
    expect(
      await screen.findByText(
        /Merged: fake-dup \(bbbbbbbb\) now folds into fake-app \(aaaaaaaa\)/,
      ),
    ).toBeInTheDocument();
  });
});
