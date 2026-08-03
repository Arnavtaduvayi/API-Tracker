// First-run onboarding.
//
// The guards here are the ones that make this screen safe to put in front of
// someone on their first launch:
//
// * scope is stated BEFORE the folder picker opens (ZFT-009);
// * the backend's disclosure is rendered verbatim and is visible without a
//   click, not summarised into a friendlier sentence;
// * the digest the user was shown is the digest sent to `project_folder_link`;
// * one folder pick is the whole flow — no separate create-project step.

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

vi.mock("../api", () => ({
  api: {
    projectList: vi.fn(),
    projectCreate: vi.fn(),
    projectFolderPreview: vi.fn(),
    projectFolderLink: vi.fn(),
  },
  isApiError: (e: unknown) =>
    typeof e === "object" && e !== null && "code" in e && "message" in e,
}));

import { Welcome, folderName, projectNameFor, uniqueProjectName } from "./Welcome";
import { open } from "@tauri-apps/plugin-dialog";
import { api } from "../api";

const mocked = api as unknown as Record<string, ReturnType<typeof vi.fn>>;
const pick = open as unknown as ReturnType<typeof vi.fn>;

const DISCLOSURE = [
  "Tethra will rewrite OPENAI_BASE_URL in .env to point at the local gateway.",
  "A backup of every file it changes is kept so the change can be undone.",
];

function preview(over: Record<string, unknown> = {}) {
  return {
    project_id: "p1",
    folder: "/Users/dev/my-app",
    detection: {
      providers: [
        {
          provider_id: "openai",
          display_name: "OpenAI",
          bucket: "tracked_automatically",
        },
      ],
      coverage: { total: 1 },
    },
    summary: { attribution_requested: false },
    digest: "digest-abc",
    disclosure: DISCLOSURE,
    pending_origin_approvals: [],
    detected_credentials: [],
    already_configured: false,
    scan_fingerprint: "fp",
    ...over,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mocked.projectList.mockResolvedValue([]);
  mocked.projectCreate.mockResolvedValue({ id: "p1", name: "My app", repo_paths: [] });
  mocked.projectFolderPreview.mockResolvedValue(preview());
  mocked.projectFolderLink.mockResolvedValue({ report: { failed_step: null } });
  pick.mockResolvedValue("/Users/dev/my-app");
});

describe("Welcome", () => {
  it("states what will be read before opening the picker (ZFT-009)", () => {
    render(<Welcome onOpenProject={() => {}} onSkip={() => {}} />);
    expect(screen.getByText(/reads the dependency and environment files/)).toBeInTheDocument();
    expect(screen.getByText(/never their values/)).toBeInTheDocument();
    expect(screen.getByText(/Nothing is uploaded/)).toBeInTheDocument();
    // And it is on screen before anything has been chosen.
    expect(pick).not.toHaveBeenCalled();
  });

  it("creates the project and scans it from one folder pick", async () => {
    render(<Welcome onOpenProject={() => {}} onSkip={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Choose a project folder" }));

    await waitFor(() => expect(mocked.projectFolderPreview).toHaveBeenCalled());
    // The project was named after the folder, with the folder bound to it.
    expect(mocked.projectCreate).toHaveBeenCalledWith(
      expect.objectContaining({ name: "My app", repoPaths: ["/Users/dev/my-app"] }),
    );
    expect(await screen.findByText("Here is what is in my-app")).toBeInTheDocument();
    expect(screen.getByText("OpenAI")).toBeInTheDocument();
  });

  it("shows the backend disclosure verbatim, without needing a click", async () => {
    render(<Welcome onOpenProject={() => {}} onSkip={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Choose a project folder" }));

    const details = await screen.findByTestId("welcome-disclosure");
    expect(details).toHaveAttribute("open");
    for (const line of DISCLOSURE) {
      expect(screen.getByText(line)).toBeInTheDocument();
    }
  });

  it("sends the digest the user was shown", async () => {
    const onOpenProject = vi.fn();
    render(<Welcome onOpenProject={onOpenProject} onSkip={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Choose a project folder" }));
    await userEvent.click(await screen.findByRole("button", { name: "Start tracking" }));

    await waitFor(() =>
      expect(mocked.projectFolderLink).toHaveBeenCalledWith(
        "p1",
        "/Users/dev/my-app",
        "digest-abc",
        null,
      ),
    );
    expect(onOpenProject).toHaveBeenCalledWith("p1");
  });

  it("re-previews when the folder changed under the confirmation", async () => {
    mocked.projectFolderLink.mockRejectedValue({
      code: "digest_mismatch",
      message: "the folder changed",
    });
    mocked.projectFolderPreview
      .mockResolvedValueOnce(preview())
      .mockResolvedValueOnce(preview({ digest: "digest-new" }));

    render(<Welcome onOpenProject={() => {}} onSkip={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Choose a project folder" }));
    await userEvent.click(await screen.findByRole("button", { name: "Start tracking" }));

    expect(await screen.findByText(/the folder changed/)).toBeInTheDocument();
    // Still on the review screen, now showing the re-read state.
    expect(mocked.projectFolderPreview).toHaveBeenCalledTimes(2);
    expect(screen.getByRole("button", { name: "Start tracking" })).toBeInTheDocument();
  });

  it("reuses a project already bound to the chosen folder", async () => {
    mocked.projectList.mockResolvedValue([
      { id: "existing", name: "My app", repo_paths: ["/Users/dev/my-app"] },
    ]);
    render(<Welcome onOpenProject={() => {}} onSkip={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Choose a project folder" }));

    await waitFor(() => expect(mocked.projectFolderPreview).toHaveBeenCalled());
    expect(mocked.projectCreate).not.toHaveBeenCalled();
    expect(mocked.projectFolderPreview).toHaveBeenCalledWith("existing", "/Users/dev/my-app");
  });

  it("cannot be confirmed when there is nothing to configure", async () => {
    mocked.projectFolderPreview.mockResolvedValue(preview({ summary: null }));
    render(<Welcome onOpenProject={() => {}} onSkip={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Choose a project folder" }));

    expect(await screen.findByTestId("welcome-nothing-to-configure")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Start tracking" })).not.toBeInTheDocument();
  });

  it("names destinations that came from the project's own files", async () => {
    mocked.projectFolderPreview.mockResolvedValue(
      preview({
        pending_origin_approvals: [{ provider_id: "openai", origin: "https://proxy.internal" }],
      }),
    );
    render(<Welcome onOpenProject={() => {}} onSkip={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Choose a project folder" }));

    expect(await screen.findByTestId("welcome-pending-origins")).toBeInTheDocument();
    expect(
      screen.getByText(/will not route traffic to a destination it read/),
    ).toBeInTheDocument();
    expect(screen.getByText("https://proxy.internal (openai)")).toBeInTheDocument();
  });

  it("surfaces a scan failure instead of a blank screen", async () => {
    mocked.projectFolderPreview.mockRejectedValue({ code: "io", message: "folder unreadable" });
    render(<Welcome onOpenProject={() => {}} onSkip={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Choose a project folder" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("folder unreadable");
    // Back to a state the user can act from.
    expect(screen.getByRole("button", { name: "Choose a project folder" })).toBeEnabled();
  });

  it("does nothing when the picker is cancelled", async () => {
    pick.mockResolvedValue(null);
    render(<Welcome onOpenProject={() => {}} onSkip={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Choose a project folder" }));

    await waitFor(() => expect(pick).toHaveBeenCalled());
    expect(mocked.projectCreate).not.toHaveBeenCalled();
    expect(mocked.projectFolderPreview).not.toHaveBeenCalled();
  });
});

describe("Welcome naming helpers", () => {
  it("takes the project name from the folder", () => {
    expect(folderName("/Users/dev/my-app")).toBe("my-app");
    expect(folderName("C:\\code\\my-app")).toBe("my-app");
    expect(projectNameFor("/Users/dev/my_api-server")).toBe("My api server");
  });

  it("avoids colliding with a name already in the vault", () => {
    expect(uniqueProjectName("My app", [])).toBe("My app");
    expect(uniqueProjectName("My app", ["my app"])).toBe("My app 2");
    expect(uniqueProjectName("My app", ["My app", "My app 2"])).toBe("My app 3");
  });
});
