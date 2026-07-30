// Folder selection inside the project page (ADR 0029).
//
// What these tests hold in place: scope is stated BEFORE the picker opens, the
// disclosure shown is the backend's own, a confirmation is required before
// anything is configured, and no credential VALUE appears anywhere on the way
// through.

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { FolderLinkPreview, ProjectOverview } from "../types";
import { ProjectTracking } from "./ProjectTracking";

vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn(),
}));

vi.mock("../api", () => ({
  api: {
    projectFolderPreview: vi.fn(),
    projectFolderLink: vi.fn(),
    projectRescan: vi.fn(),
    projectSetTrackingEnabled: vi.fn(),
    projectUnlinkFolder: vi.fn(),
    projectResolveDetection: vi.fn(),
    projectUpdateDetection: vi.fn(),
  },
  isApiError: (e: unknown) => typeof e === "object" && e !== null && "message" in e,
}));

import { open } from "@tauri-apps/plugin-dialog";
import { api } from "../api";

const mocked = api as unknown as Record<string, ReturnType<typeof vi.fn>>;
const pick = open as unknown as ReturnType<typeof vi.fn>;

/** A value that must never reach the screen. */
const CANARY = "sk-live-CANARY-MUST-NEVER-RENDER-0001";

function preview(over: Partial<FolderLinkPreview> = {}): FolderLinkPreview {
  return {
    project_id: "p1",
    folder: "/work/app",
    detection: {
      folder: "/work/app",
      providers: [],
      env_files: [],
      unrecognized: [],
      coverage: null,
      scanned_files: 4,
      accounting: null,
    } as unknown as FolderLinkPreview["detection"],
    summary: {
      attribution_requested: false,
      files_to_edit: [".env"],
      routes_to_create: 2,
      service_change: true,
      restart_expected: true,
      port: 8787,
      warnings: [],
    },
    digest: "digest-abc",
    disclosure: [
      "Tethra will observe API traffic from /work/app and record request metadata locally. Request and response bodies are never stored.",
      "These files in your project will be edited so requests go through Tethra: .env. The previous values are recorded encrypted so this can be undone.",
      "Nothing is sent to Tethra. You can unlink this folder and undo these changes at any time.",
    ],
    pending_origin_approvals: [],
    detected_credentials: [
      {
        env_var: "OPENAI_API_KEY",
        suggested_provider: "openai",
        suggested_name: "openai-api-key",
        source_file: ".env",
        source_kind: "manifest",
        already_have_credential: false,
      },
    ],
    already_configured: false,
    scan_fingerprint: "fp-1",
    ...over,
  };
}

function overview(over: Partial<ProjectOverview> = {}): ProjectOverview {
  return {
    project_id: "p1",
    link: null,
    status: null,
    scan_stale: false,
    configuration_behind: false,
    detected_credentials: [],
    credentials_needing_details: 0,
    attribution_paused: false,
    ...over,
  };
}

function linked(over: Partial<ProjectOverview> = {}): ProjectOverview {
  return overview({
    link: {
      project_id: "p1",
      folder_path: "/work/app",
      tracking_enabled: true,
      linked_at: "2026-07-29T10:00:00Z",
      last_scan_at: "2026-07-29T10:00:00Z",
      scan_fingerprint: "fp-1",
      applied_generation: 1,
      last_activity_refresh_at: null,
      row_version: 2,
    },
    ...over,
  });
}

const noop = () => {};

describe("ProjectTracking", () => {
  beforeEach(() => {
    for (const fn of Object.values(mocked)) fn.mockReset();
    pick.mockReset();
  });

  it("offers folder selection and states the scope BEFORE the picker", () => {
    render(
      <ProjectTracking
        projectIdent="p1"
        overview={overview()}
        reloading={false}
        onChanged={noop}
        onOpenAdvanced={noop}
      />,
    );
    const cta = screen.getByTestId("select-folder-cta");
    // The scope sentence and the button are in the same block, scope first.
    expect(cta.textContent).toContain("reads variable");
    expect(cta.textContent).toContain("never runs");
    expect(cta.textContent).toContain("never looks outside the folder");
    expect(cta.textContent).toContain("Nothing is uploaded");
    const buttonIndex = cta.textContent!.indexOf("Select project folder");
    const scopeIndex = cta.textContent!.indexOf("reads variable");
    expect(scopeIndex).toBeLessThan(buttonIndex);
  });

  it("selecting a folder previews and shows the backend's own disclosure", async () => {
    pick.mockResolvedValue("/work/app");
    mocked.projectFolderPreview.mockResolvedValue(preview());
    render(
      <ProjectTracking
        projectIdent="p1"
        overview={overview()}
        reloading={false}
        onChanged={noop}
        onOpenAdvanced={noop}
      />,
    );
    fireEvent.click(screen.getByText("Select project folder"));
    const box = await screen.findByTestId("link-disclosure");
    expect(box.textContent).toContain("bodies are never stored");
    expect(box.textContent).toContain(".env");
    expect(box.textContent).toContain("undone");
    // Nothing has been applied yet.
    expect(mocked.projectFolderLink).not.toHaveBeenCalled();
  });

  it("requires a confirmation before anything is configured", async () => {
    pick.mockResolvedValue("/work/app");
    mocked.projectFolderPreview.mockResolvedValue(preview());
    mocked.projectFolderLink.mockResolvedValue({
      link: linked().link,
      report: {
        failed_step: null,
        failed_detail: null,
        install_blocked: false,
        attribution_enabled: false,
        setup_id: "s1",
        steps: [],
      },
      detected_credentials: [],
    });
    const onChanged = vi.fn();
    render(
      <ProjectTracking
        projectIdent="p1"
        overview={overview()}
        reloading={false}
        onChanged={onChanged}
        onOpenAdvanced={noop}
      />,
    );
    fireEvent.click(screen.getByText("Select project folder"));
    await screen.findByTestId("link-disclosure");
    fireEvent.click(screen.getByText("Start tracking this folder"));

    await waitFor(() =>
      // The digest the user was shown is what gets echoed back.
      expect(mocked.projectFolderLink).toHaveBeenCalledWith(
        "p1",
        "/work/app",
        "digest-abc",
        null,
      ),
    );
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
  });

  it("cancelling the picker configures nothing", async () => {
    pick.mockResolvedValue(null);
    render(
      <ProjectTracking
        projectIdent="p1"
        overview={overview()}
        reloading={false}
        onChanged={noop}
        onOpenAdvanced={noop}
      />,
    );
    fireEvent.click(screen.getByText("Select project folder"));
    await waitFor(() => expect(pick).toHaveBeenCalled());
    expect(mocked.projectFolderPreview).not.toHaveBeenCalled();
    expect(screen.queryByTestId("link-disclosure")).toBeNull();
  });

  it("a refused digest surfaces the reason and re-previews", async () => {
    pick.mockResolvedValue("/work/app");
    mocked.projectFolderPreview
      .mockResolvedValueOnce(preview())
      .mockResolvedValueOnce(preview({ digest: "digest-new" }));
    mocked.projectFolderLink.mockRejectedValue({
      code: "invalid_input",
      message:
        "this project's folder or configuration changed since it was reviewed. Look at the new summary and confirm again.",
    });
    render(
      <ProjectTracking
        projectIdent="p1"
        overview={overview()}
        reloading={false}
        onChanged={noop}
        onOpenAdvanced={noop}
      />,
    );
    fireEvent.click(screen.getByText("Select project folder"));
    await screen.findByTestId("link-disclosure");
    fireEvent.click(screen.getByText("Start tracking this folder"));

    await waitFor(() => expect(screen.getByText(/changed since it was reviewed/)).toBeTruthy());
    // A fresh preview replaced the stale one, so the user confirms what is true now.
    await waitFor(() => expect(mocked.projectFolderPreview).toHaveBeenCalledTimes(2));
  });

  it("a folder with nothing configurable explains the pending approval instead of failing", async () => {
    pick.mockResolvedValue("/work/app");
    mocked.projectFolderPreview.mockResolvedValue(
      preview({
        summary: null,
        digest: "",
        disclosure: [
          "Tethra found API integrations in this folder, but none of them is one it can configure on its own.",
          "Configuring one of these is an advanced action: open Tracking setup (advanced), where approving a destination and configuring it happen together.",
        ],
        pending_origin_approvals: [
          { provider_id: "supabase", origin: "https://x.example.com" },
        ],
      }),
    );
    render(
      <ProjectTracking
        projectIdent="p1"
        overview={overview()}
        reloading={false}
        onChanged={noop}
        onOpenAdvanced={noop}
      />,
    );
    fireEvent.click(screen.getByText("Select project folder"));
    // The copy must NOT promise that re-selecting the folder will pick up an
    // approved destination: `prepare_link` builds from `Selections::defaults`,
    // which never includes a repository-discovered one, so that loop cannot
    // terminate.
    const nothing = (await screen.findByTestId("nothing-to-configure")).textContent!;
    expect(nothing).toContain("Selecting it again will not change that");
    expect(nothing).toContain("Tracking setup (advanced)");
    expect(screen.getByTestId("pending-origins").textContent).toContain(
      "https://x.example.com",
    );
    // There is no way to confirm a preview that has no plan.
    expect(screen.queryByText("Start tracking this folder")).toBeNull();
  });

  it("a repository-discovered destination is presented as needing approval, not applied", async () => {
    pick.mockResolvedValue("/work/app");
    mocked.projectFolderPreview.mockResolvedValue(
      preview({
        pending_origin_approvals: [
          { provider_id: "supabase", origin: "https://attacker.example.com" },
        ],
      }),
    );
    render(
      <ProjectTracking
        projectIdent="p1"
        overview={overview()}
        reloading={false}
        onChanged={noop}
        onOpenAdvanced={noop}
      />,
    );
    fireEvent.click(screen.getByText("Select project folder"));
    const pending = await screen.findByTestId("pending-origins");
    expect(pending.textContent).toContain("came from this project");
    expect(pending.textContent).toContain("will not route traffic");
    expect(pending.textContent).toContain("stay left out however many times");
    expect(pending.textContent).toContain("https://attacker.example.com");
  });

  it("never renders a credential value, only its variable name", async () => {
    pick.mockResolvedValue("/work/app");
    mocked.projectFolderPreview.mockResolvedValue(preview());
    render(
      <ProjectTracking
        projectIdent="p1"
        overview={overview()}
        reloading={false}
        onChanged={noop}
        onOpenAdvanced={noop}
      />,
    );
    fireEvent.click(screen.getByText("Select project folder"));
    const box = await screen.findByTestId("link-disclosure");
    fireEvent.click(screen.getByText(/credential record\(s\) will be created/));
    expect(box.textContent).toContain("OPENAI_API_KEY");
    expect(box.textContent).toContain("value not read, not saved");
    expect(document.body.textContent).not.toContain(CANARY);
  });

  it("shows the linked folder, and that credentials needing details do not block tracking", () => {
    render(
      <ProjectTracking
        projectIdent="p1"
        overview={linked({
          credentials_needing_details: 2,
          detected_credentials: [
            {
              id: "d1",
              project_id: "p1",
              env_var: "ANTHROPIC_API_KEY",
              suggested_provider: "anthropic",
              suggested_name: "anthropic-api-key",
              suggested_environment: null,
              source_kind: "env_file",
              source_file: ".env",
              status: "pending",
              resolved_credential_id: null,
              first_detected_at: "2026-07-29T10:00:00Z",
              last_detected_at: "2026-07-29T10:00:00Z",
              row_version: 0,
            },
          ],
        })}
        reloading={false}
        onChanged={noop}
        onOpenAdvanced={noop}
      />,
    );
    expect(screen.getByText("/work/app")).toBeTruthy();
    expect(screen.getByTestId("credential-summary").textContent).toContain(
      "Tracking is already running",
    );
    const table = screen.getByTestId("detected-credentials");
    expect(table.textContent).toContain("ANTHROPIC_API_KEY");
    expect(table.textContent).toContain("Not saved in Tethra");
    expect(table.textContent).toContain("Pending exact key");
    // The environment is unknown, and is not guessed.
    expect(table.textContent).toContain("unknown");
  });

  it("a detection can be ignored or marked managed elsewhere", async () => {
    mocked.projectResolveDetection.mockResolvedValue({});
    render(
      <ProjectTracking
        projectIdent="p1"
        overview={linked({
          credentials_needing_details: 1,
          detected_credentials: [
            {
              id: "d1",
              project_id: "p1",
              env_var: "GROQ_API_KEY",
              suggested_provider: "groq",
              suggested_name: "groq-api-key",
              suggested_environment: null,
              source_kind: "env_file",
              source_file: ".env",
              status: "pending",
              resolved_credential_id: null,
              first_detected_at: "2026-07-29T10:00:00Z",
              last_detected_at: "2026-07-29T10:00:00Z",
              row_version: 0,
            },
          ],
        })}
        reloading={false}
        onChanged={noop}
        onOpenAdvanced={noop}
      />,
    );
    fireEvent.click(screen.getByText("Ignore"));
    await waitFor(() =>
      expect(mocked.projectResolveDetection).toHaveBeenCalledWith("d1", "ignored", null),
    );

    fireEvent.click(screen.getByText("Managed elsewhere"));
    await waitFor(() =>
      expect(mocked.projectResolveDetection).toHaveBeenCalledWith("d1", "external", null),
    );
  });

  it("offers a rescan when the project's manifests changed, and says it changes no files", () => {
    render(
      <ProjectTracking
        projectIdent="p1"
        overview={linked({ scan_stale: true })}
        reloading={false}
        onChanged={noop}
        onOpenAdvanced={noop}
      />,
    );
    const stale = screen.getByTestId("scan-stale");
    expect(stale.textContent).toContain("changed since the last scan");
    expect(stale.textContent).toContain("does not change your files");
  });

  it("rescanning calls the rescan command, not a re-link", async () => {
    mocked.projectRescan.mockResolvedValue([]);
    render(
      <ProjectTracking
        projectIdent="p1"
        overview={linked({ scan_stale: true })}
        reloading={false}
        onChanged={noop}
        onOpenAdvanced={noop}
      />,
    );
    fireEvent.click(screen.getByText("Rescan project"));
    await waitFor(() => expect(mocked.projectRescan).toHaveBeenCalledWith("p1"));
    expect(mocked.projectFolderLink).not.toHaveBeenCalled();
  });

  it("disabling tracking says the folder and history are kept", async () => {
    mocked.projectSetTrackingEnabled.mockResolvedValue(undefined);
    render(
      <ProjectTracking
        projectIdent="p1"
        overview={linked()}
        reloading={false}
        onChanged={noop}
        onOpenAdvanced={noop}
      />,
    );
    fireEvent.click(screen.getByText("Disable tracking"));
    await waitFor(() =>
      expect(mocked.projectSetTrackingEnabled).toHaveBeenCalledWith("p1", false),
    );
    await waitFor(() => expect(screen.getByText(/recorded activity is kept/)).toBeTruthy());
  });

  it("unlinking requires confirmation and spells out every consequence", async () => {
    mocked.projectUnlinkFolder.mockResolvedValue(true);
    render(
      <ProjectTracking
        projectIdent="p1"
        overview={linked()}
        reloading={false}
        onChanged={noop}
        onOpenAdvanced={noop}
      />,
    );
    fireEvent.click(screen.getByText("Unlink folder"));
    const dialog = screen.getByRole("dialog");
    expect(dialog.textContent).toContain("credentials and its recorded activity are kept");
    expect(dialog.textContent).toContain("files on disk are not touched");
    expect(dialog.textContent).toContain("stays until you undo it");
    // Nothing happened just from opening the dialog.
    expect(mocked.projectUnlinkFolder).not.toHaveBeenCalled();

    fireEvent.click(dialog.querySelector("button.danger")!);
    await waitFor(() => expect(mocked.projectUnlinkFolder).toHaveBeenCalledWith("p1"));
  });

  it("asks for the master password only when attribution is planned, and says why", async () => {
    pick.mockResolvedValue("/work/app");
    mocked.projectFolderPreview.mockResolvedValue(
      preview({
        summary: {
          attribution_requested: true,
          files_to_edit: [".env"],
          routes_to_create: 1,
          service_change: true,
          restart_expected: false,
          port: 8787,
          warnings: [],
        },
      }),
    );
    render(
      <ProjectTracking
        projectIdent="p1"
        overview={overview()}
        reloading={false}
        onChanged={noop}
        onOpenAdvanced={noop}
      />,
    );
    fireEvent.click(screen.getByText("Select project folder"));
    const box = await screen.findByTestId("link-disclosure");
    // The oracle disclosure must be present wherever a matching key is minted.
    expect(box.textContent).toContain("test guesses against your credentials");
    expect(box.textContent).toContain("Tracking works without this");
    expect(screen.getByLabelText(/Master password/)).toBeTruthy();
  });

  it("reports a partial apply honestly instead of claiming success", async () => {
    pick.mockResolvedValue("/work/app");
    mocked.projectFolderPreview.mockResolvedValue(preview());
    mocked.projectFolderLink.mockResolvedValue({
      link: linked().link,
      // The shape the BACKEND actually emits: `failed_step` computed in Rust.
      // The previous fixture invented a flat `outcome: "failed"` that the raw
      // report never produces, which made this test pass against a UI that
      // could not detect a failure at all.
      report: {
        failed_step: "Apply project links",
        failed_detail: "permission denied",
        install_blocked: false,
        attribution_enabled: false,
        setup_id: "s1",
        steps: [
          { title: "Register routes", outcome: "done", detail: "" },
          { title: "Apply project links", outcome: "failed", detail: "permission denied" },
        ],
      },
      detected_credentials: [],
    });
    render(
      <ProjectTracking
        projectIdent="p1"
        overview={overview()}
        reloading={false}
        onChanged={noop}
        onOpenAdvanced={noop}
      />,
    );
    fireEvent.click(screen.getByText("Select project folder"));
    await screen.findByTestId("link-disclosure");
    fireEvent.click(screen.getByText("Start tracking this folder"));
    await waitFor(() =>
      expect(screen.getByText(/stopped at "Apply project links"/)).toBeTruthy(),
    );
    expect(screen.getByText(/steps that completed are still in place/)).toBeTruthy();
  });
});
