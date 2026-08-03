// The card-based list screens.
//
// The rules these guard:
//
// * a card grid renders from its own list command — a failed activity or
//   credential-count read removes figures from the cards, never the cards from
//   the screen;
// * "no traffic" is not styled as a fault;
// * the provider library shows every shipped manifest, not a hard-coded subset;
// * no provider mark claims to be a logo Tethra does not actually bundle.

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../api", () => ({
  api: {
    projectList: vi.fn(),
    projectActivity: vi.fn(),
    gatewayActivityByProject: vi.fn(),
    providersList: vi.fn(),
    credentialList: vi.fn(),
  },
  isApiError: (e: unknown) =>
    typeof e === "object" && e !== null && "code" in e && "message" in e,
}));

import { ProjectList } from "./ProjectList";
import { ProviderCatalog } from "./ProviderCatalog";
import { Sparkline } from "./Sparkline";
import { ProviderMark, providerColor } from "./visuals/ProviderMarks";
import { api } from "../api";

const mocked = api as unknown as Record<string, ReturnType<typeof vi.fn>>;

function project(over: Record<string, unknown> = {}) {
  return {
    id: "p1",
    name: "my-app",
    description: "The main service",
    notes: "",
    environments: ["development", "production"],
    repo_paths: [],
    archived: false,
    password_locked: false,
    unlocked: true,
    created_at: "2026-07-01T00:00:00Z",
    updated_at: "2026-07-01T00:00:00Z",
    credential_count: 3,
    ...over,
  };
}

function manifest(over: Record<string, unknown> = {}) {
  return {
    id: "openai",
    name: "OpenAI",
    description: "",
    env_vars: ["OPENAI_API_KEY"],
    detection: [{ name: "k", regex: "sk-", confidence: "high" }],
    expiration: null,
    ...over,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mocked.projectList.mockResolvedValue([project()]);
  mocked.gatewayActivityByProject.mockResolvedValue([]);
  mocked.projectActivity.mockResolvedValue({ granularity: "day", series: [] });
  mocked.providersList.mockResolvedValue([manifest()]);
  mocked.credentialList.mockResolvedValue([]);
});

describe("ProjectList cards", () => {
  it("renders a card per project with its credential count", async () => {
    render(<ProjectList onOpen={() => {}} onNew={() => {}} />);
    const cards = await screen.findByTestId("project-cards");
    expect(within(cards).getByText("my-app")).toBeInTheDocument();
    expect(within(cards).getByText("3")).toBeInTheDocument();
    expect(within(cards).getByText(/credentials/)).toBeInTheDocument();
  });

  it("carries observed volume when activity is readable", async () => {
    mocked.gatewayActivityByProject.mockResolvedValue([
      {
        project_id: "p1",
        project_name: "my-app",
        total_requests: 1234,
        success_count: 1230,
        error_count: 4,
        transport_error_count: 0,
        first_event_at: "2026-08-01T00:00:00Z",
        last_event_at: "2026-08-02T00:00:00Z",
      },
    ]);
    render(<ProjectList onOpen={() => {}} onNew={() => {}} />);
    const cards = await screen.findByTestId("project-cards");
    await waitFor(() => expect(within(cards).getByText("1,234")).toBeInTheDocument());
    expect(within(cards).getByText("4")).toBeInTheDocument();
  });

  it("still lists projects when activity cannot be read", async () => {
    mocked.gatewayActivityByProject.mockRejectedValue({ code: "db", message: "locked" });
    render(<ProjectList onOpen={() => {}} onNew={() => {}} />);
    const cards = await screen.findByTestId("project-cards");
    expect(within(cards).getByText("my-app")).toBeInTheDocument();
    expect(within(cards).getByText("No traffic observed in this window")).toBeInTheDocument();
  });

  it("does not mark a quiet project as a fault", async () => {
    render(<ProjectList onOpen={() => {}} onNew={() => {}} />);
    const cards = await screen.findByTestId("project-cards");
    // A project nobody ran is not broken; only errors and a locked vault
    // colour the dot.
    expect(cards.querySelector(".dot.bad")).toBeNull();
    expect(cards.querySelector(".dot.warn")).toBeNull();
  });

  it("marks a password-locked project as needing attention", async () => {
    mocked.projectList.mockResolvedValue([project({ password_locked: true, unlocked: false })]);
    render(<ProjectList onOpen={() => {}} onNew={() => {}} />);
    const cards = await screen.findByTestId("project-cards");
    expect(within(cards).getByText("Password-locked")).toBeInTheDocument();
    expect(cards.querySelector(".dot.warn")).not.toBeNull();
  });

  it("offers the next action from the empty state", async () => {
    mocked.projectList.mockResolvedValue([]);
    const onNew = vi.fn();
    render(<ProjectList onOpen={() => {}} onNew={onNew} />);
    expect(await screen.findByText("No projects yet")).toBeInTheDocument();
    await userEvent.click(screen.getAllByRole("button", { name: "New project" })[1]);
    expect(onNew).toHaveBeenCalled();
  });

  it("opens the project it was clicked on", async () => {
    const onOpen = vi.fn();
    render(<ProjectList onOpen={onOpen} onNew={() => {}} />);
    const cards = await screen.findByTestId("project-cards");
    await userEvent.click(within(cards).getByText("my-app"));
    expect(onOpen).toHaveBeenCalledWith("p1");
  });
});

describe("ProviderCatalog cards", () => {
  it("renders every manifest the backend returns", async () => {
    mocked.providersList.mockResolvedValue([
      manifest(),
      manifest({ id: "anthropic", name: "Anthropic", env_vars: ["ANTHROPIC_API_KEY"] }),
      manifest({ id: "stripe", name: "Stripe", env_vars: ["STRIPE_SECRET_KEY"] }),
    ]);
    render(<ProviderCatalog onOpen={() => {}} />);
    const cards = await screen.findByTestId("provider-cards");
    expect(within(cards).getByText("OpenAI")).toBeInTheDocument();
    expect(within(cards).getByText("Anthropic")).toBeInTheDocument();
    expect(within(cards).getByText("Stripe")).toBeInTheDocument();
    expect(screen.getByText("3 of 3 providers")).toBeInTheDocument();
  });

  it("says how many credentials the user already holds", async () => {
    mocked.credentialList.mockResolvedValue([
      { provider: "openai" },
      { provider: "openai" },
      { provider: "stripe" },
    ]);
    render(<ProviderCatalog onOpen={() => {}} />);
    const cards = await screen.findByTestId("provider-cards");
    await waitFor(() =>
      expect(within(cards).getByText("2 credentials in your vault")).toBeInTheDocument(),
    );
  });

  it("still lists providers when the credential count cannot be read", async () => {
    mocked.credentialList.mockRejectedValue({ code: "vault_locked", message: "locked" });
    render(<ProviderCatalog onOpen={() => {}} />);
    const cards = await screen.findByTestId("provider-cards");
    expect(within(cards).getByText("OpenAI")).toBeInTheDocument();
    expect(within(cards).getByText("No credentials stored yet")).toBeInTheDocument();
  });

  it("keeps the capability caveat rather than implying full support", async () => {
    render(<ProviderCatalog onOpen={() => {}} />);
    expect(
      await screen.findByText(/implemented where each provider supports them/),
    ).toBeInTheDocument();
    // A provider with no documented expiry must say so, not stay silent.
    expect(
      screen.getByText(/No documented expiry — Tethra cannot warn on age alone/),
    ).toBeInTheDocument();
  });

  it("filters by name and by environment variable", async () => {
    mocked.providersList.mockResolvedValue([
      manifest(),
      manifest({ id: "stripe", name: "Stripe", env_vars: ["STRIPE_SECRET_KEY"] }),
    ]);
    render(<ProviderCatalog onOpen={() => {}} />);
    await screen.findByTestId("provider-cards");

    await userEvent.type(screen.getByLabelText("Search providers"), "STRIPE_SECRET");
    await waitFor(() => expect(screen.queryByText("OpenAI")).not.toBeInTheDocument());
    expect(screen.getByText("Stripe")).toBeInTheDocument();
    expect(screen.getByText("1 of 2 providers")).toBeInTheDocument();
  });
});

describe("ProviderMark", () => {
  it("falls back to a monogram for a provider with no bundled logo", () => {
    render(<ProviderMark id="openai" name="OpenAI" />);
    // No official path is bundled yet, so the mark must be the honest
    // monogram rather than an approximated logo.
    expect(screen.getByText("O")).toBeInTheDocument();
  });

  it("is hidden from assistive technology, because the name is beside it", () => {
    const { container } = render(<ProviderMark id="stripe" name="Stripe" />);
    expect(container.querySelector(".entity-mark")).toHaveAttribute("aria-hidden", "true");
  });

  it("gives an unknown provider a neutral colour instead of failing", () => {
    expect(providerColor("openai")).toBe("#10a37f");
    expect(providerColor("a-provider-that-does-not-exist")).toBe("#8e8e93");
    render(<ProviderMark id="a-provider-that-does-not-exist" name="Weird Co" />);
    expect(screen.getByText("W")).toBeInTheDocument();
  });
});

describe("Sparkline", () => {
  it("draws nothing when there is no shape to draw", () => {
    const { container } = render(<Sparkline values={[]} label="x" />);
    expect(container.querySelector("svg")).toBeNull();
    // A flat run of zeroes is "no traffic", and a flat baseline reads as
    // "no data" — the card says which, so the shape is omitted.
    const flat = render(<Sparkline values={[0, 0, 0]} label="x" />);
    expect(flat.container.querySelector("svg")).toBeNull();
  });

  it("states the range and total in its accessible name", () => {
    render(<Sparkline values={[1, 5, 2]} label="my-app request volume" />);
    expect(
      screen.getByRole("img", {
        name: "my-app request volume: 8 requests across 3 periods, peaking at 5",
      }),
    ).toBeInTheDocument();
  });
});
