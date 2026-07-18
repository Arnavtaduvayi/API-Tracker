import { useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type { Project } from "../types";

export function ProjectList(props: { onOpen: (ident: string) => void; onNew: () => void }) {
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [showArchived, setShowArchived] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .projectList(showArchived)
      .then(setProjects)
      .catch((e) => setError(isApiError(e) ? e.message : String(e)));
  }, [showArchived]);

  return (
    <div>
      <h1>Projects</h1>
      <p>
        <button onClick={props.onNew}>New project</button>{" "}
        <label>
          <input
            type="checkbox"
            checked={showArchived}
            onChange={(e) => setShowArchived(e.target.checked)}
          />{" "}
          show archived
        </label>
      </p>
      {error && <p className="error">{error}</p>}
      {projects && projects.length === 0 && (
        <p>No projects yet. A project is a folder for the API credentials of one codebase.</p>
      )}
      {projects && projects.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Environments</th>
              <th>Credentials</th>
              <th>State</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            {projects.map((p) => (
              <tr key={p.id}>
                <td>
                  <button className="link" onClick={() => props.onOpen(p.id)}>
                    {p.name}
                  </button>
                </td>
                <td>{p.environments.join(", ") || "—"}</td>
                <td>{p.credential_count}</td>
                <td>
                  {p.archived
                    ? "archived"
                    : p.password_locked
                      ? p.unlocked
                        ? "password set (unlocked)"
                        : "password-locked"
                      : "—"}
                </td>
                <td>{p.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
