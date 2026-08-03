// Projects as cards.
//
// This was a five-column table of names and counts, which is a fine way to
// render a database and a poor way to answer the question a user actually
// arrives with: which of my projects are busy, and is anything wrong. The card
// carries the project's request volume, its error state, and a shape for the
// window — every table column is still here, just arranged so the answer is
// visible rather than reconstructible.
//
// Activity is decoration on top of the list, never a precondition for it: the
// projects render as soon as `project_list` returns, and a failed activity
// read leaves the cards without figures rather than leaving the screen empty.

import { useCallback, useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type { Project, ProjectActivity } from "../types";
import { relativeTime } from "../useLiveRefresh";
import { Sparkline } from "./Sparkline";

/** Locally observed volume for one project, if it could be read. */
interface Volume {
  requests: number;
  errors: number;
  lastEventAt: string | null;
  series: number[];
}

function errText(e: unknown): string {
  return isApiError(e) ? e.message : String(e);
}

function sinceIso(days: number): string {
  return new Date(Date.now() - days * 86_400_000).toISOString();
}

export function ProjectList(props: { onOpen: (ident: string) => void; onNew: () => void }) {
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [showArchived, setShowArchived] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [volumes, setVolumes] = useState<Map<string, Volume>>(new Map());

  useEffect(() => {
    api
      .projectList(showArchived)
      .then(setProjects)
      .catch((e) => setError(errText(e)));
  }, [showArchived]);

  const loadVolumes = useCallback(async () => {
    try {
      const rows: ProjectActivity[] = await api.gatewayActivityByProject(sinceIso(7));
      const next = new Map<string, Volume>();
      await Promise.all(
        rows.map(async (r) => {
          // The counts come from the summary; the shape needs the per-project
          // series, and a project whose series fails still keeps its counts.
          let series: number[] = [];
          try {
            const snapshot = await api.projectActivity(r.project_id, "7d", {}, 1);
            series = snapshot.series.map((p) => p.requests);
          } catch {
            series = [];
          }
          next.set(r.project_id, {
            requests: r.total_requests,
            errors: r.error_count + r.transport_error_count,
            lastEventAt: r.last_event_at,
            series,
          });
        }),
      );
      setVolumes(next);
    } catch {
      // Activity is additive. Without it the cards simply carry no figures.
      setVolumes(new Map());
    }
  }, []);

  useEffect(() => {
    void loadVolumes();
  }, [loadVolumes]);

  return (
    <section className="stack">
      <div className="screen-heading">
        <div>
          <p className="screen-kicker">Local vault</p>
          <h1>Projects</h1>
        </div>
        <button className="primary" onClick={props.onNew}>
          New project
        </button>
      </div>

      <div className="dashboard-toolbar">
        <label className="switch-control">
          <input
            type="checkbox"
            checked={showArchived}
            onChange={(e) => setShowArchived(e.target.checked)}
          />
          <span aria-hidden="true" />
          <b>Archived</b>
        </label>
        <span className="dashboard-signal">Observed over the last 7 days</span>
      </div>

      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}

      {projects && projects.length === 0 && (
        <div className="empty-state">
          <h2>No projects yet</h2>
          <p>
            A project is one codebase and the API credentials it uses. Point Tethra at a folder
            and it creates the project, finds the APIs, and starts showing their traffic.
          </p>
          <button className="primary" onClick={props.onNew}>
            New project
          </button>
        </div>
      )}

      {projects && projects.length > 0 && (
        <div className="entity-grid" data-testid="project-cards">
          {projects.map((p) => (
            <ProjectCard
              key={p.id}
              project={p}
              volume={volumes.get(p.id) ?? null}
              onOpen={() => props.onOpen(p.id)}
            />
          ))}
        </div>
      )}
    </section>
  );
}

function ProjectCard(props: { project: Project; volume: Volume | null; onOpen: () => void }) {
  const { project, volume } = props;
  const tone = stateTone(project, volume);

  return (
    <button className="entity-card" onClick={props.onOpen}>
      <div className="entity-head">
        <span className={`dot ${tone}`} aria-hidden="true" />
        <div style={{ minWidth: 0 }}>
          <p className="entity-title">{project.name}</p>
          <p className="entity-sub">{stateSentence(project)}</p>
        </div>
      </div>

      {volume && <Sparkline values={volume.series} label={`${project.name} request volume`} />}

      <p className="entity-meta">
        <span>
          <b>{project.credential_count}</b> credential
          {project.credential_count === 1 ? "" : "s"}
        </span>
        {volume ? (
          <>
            <span>
              <b>{volume.requests.toLocaleString()}</b> requests
            </span>
            <span>
              <b>{volume.errors}</b> errors
            </span>
          </>
        ) : (
          <span>No traffic observed in this window</span>
        )}
      </p>

      <p className="entity-foot">
        {project.environments.length > 0 ? project.environments.join(" · ") : "No environments"}
        {volume?.lastEventAt ? ` · last request ${relativeTime(volume.lastEventAt)}` : ""}
      </p>
    </button>
  );
}

/**
 * The card's status dot.
 *
 * Errors dominate, then lock state. "No traffic" is deliberately NOT a fault —
 * a project nobody ran today is not broken, and colouring it as a problem is
 * how a dashboard trains people to ignore it. The dot always sits beside a
 * phrase, so colour never carries the meaning on its own.
 */
function stateTone(project: Project, volume: Volume | null): "ok" | "warn" | "bad" | "" {
  if (project.archived) return "";
  if (volume && volume.errors > 0) {
    return volume.errors > volume.requests / 10 ? "bad" : "warn";
  }
  if (project.password_locked && !project.unlocked) return "warn";
  if (volume && volume.requests > 0) return "ok";
  return "";
}

/** Never prints a bare flag; every state is a phrase. */
function stateSentence(project: Project): string {
  if (project.archived) return "Archived";
  if (project.password_locked) {
    return project.unlocked ? "Password set — unlocked" : "Password-locked";
  }
  return project.description || "No description";
}
