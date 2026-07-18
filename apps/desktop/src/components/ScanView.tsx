// Repository scanning: pick a path, choose a mode, view redacted findings
// (with vault matches), install/remove the pre-commit hook, and suppress
// false positives with a reason.

import { useState } from "react";
import { api, isApiError } from "../api";
import type { Finding, HookStatus } from "../types";
import { PromptDialog } from "./ConfirmDialog";

export function ScanView() {
  const [path, setPath] = useState("");
  const [mode, setMode] = useState<"working" | "staged" | "history">("staged");
  const [markExposed, setMarkExposed] = useState(true);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [hook, setHook] = useState<HookStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [suppressing, setSuppressing] = useState<Finding | null>(null);

  const run = async (action: () => Promise<void>) => {
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await action();
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const scan = () =>
    run(async () => {
      if (!path.trim()) {
        setError("Enter a repository or directory path.");
        return;
      }
      const result = await api.scanPath(path.trim(), mode, markExposed);
      setFindings(result);
      const matched = result.filter((f) => f.vault_match).length;
      if (matched > 0) {
        setNotice(
          `${matched} finding(s) match a stored credential. Matched credentials were marked possibly exposed — removing a secret from a file does not remove it from Git history; rotate it.`,
        );
      }
    });

  const refreshHook = () =>
    run(async () => {
      setHook(await api.hookStatus(path.trim()));
    });

  const confirmSuppress = (reason: string) => {
    const f = suppressing;
    setSuppressing(null);
    if (!f) return;
    void run(async () => {
      if (!reason.trim()) {
        setError("A reason is required to suppress.");
        return;
      }
      await api.suppressionAdd(f.suppression_key, f.file, reason);
      setNotice("Suppressed. Re-run the scan to confirm it is hidden.");
    });
  };

  return (
    <div>
      <h1>Repository scan</h1>
      <p className="muted">
        Scanning happens entirely on this machine. No source code or findings ever leave your
        computer.
      </p>
      <div className="stack" style={{ maxWidth: "44rem" }}>
        <label className="field">
          Repository or directory path
          <input
            className="mono"
            placeholder="/path/to/repo"
            value={path}
            onChange={(e) => setPath(e.target.value)}
          />
        </label>
        <label className="field">
          Mode
          <select value={mode} onChange={(e) => setMode(e.target.value as typeof mode)}>
            <option value="staged">Staged changes (Git)</option>
            <option value="working">Working tree</option>
            <option value="history">Recent history (Git)</option>
          </select>
        </label>
        <label>
          <input
            type="checkbox"
            checked={markExposed}
            onChange={(e) => setMarkExposed(e.target.checked)}
          />{" "}
          mark matched vault credentials as possibly exposed
        </label>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button onClick={() => void scan()} disabled={busy}>
            {busy ? "Scanning…" : "Scan"}
          </button>
          <button onClick={() => void refreshHook()} disabled={busy}>
            Check hook status
          </button>
        </div>
      </div>

      {hook && (
        <div style={{ marginTop: "1rem" }}>
          <h2>Pre-commit hook</h2>
          <p>
            State: <strong>{hook.state}</strong> ({hook.hook_path})
          </p>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button
              onClick={() =>
                void run(async () => setHook(await api.hookInstall(path.trim(), false)))
              }
            >
              Install
            </button>
            <button
              onClick={() =>
                void run(async () => setHook(await api.hookInstall(path.trim(), true)))
              }
            >
              Install (force / chain)
            </button>
            <button
              onClick={() => void run(async () => setHook(await api.hookRemove(path.trim())))}
            >
              Remove
            </button>
          </div>
        </div>
      )}

      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}

      {findings && (
        <div style={{ marginTop: "1rem" }}>
          <h2>Findings ({findings.length})</h2>
          {findings.length === 0 ? (
            <p>No secrets found.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Confidence</th>
                  <th>Location</th>
                  <th>Provider</th>
                  <th>Value</th>
                  <th>In vault</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.suppression_key}>
                    <td>
                      <span className={`badge ${f.confidence === "high" ? "bad" : "warn"}`}>
                        {f.confidence}
                      </span>
                    </td>
                    <td className="mono">
                      {f.file}:{f.line}
                    </td>
                    <td>{f.provider ?? "unknown"}</td>
                    <td className="mono">{f.redacted}</td>
                    <td>
                      {f.vault_match
                        ? `${f.vault_match.project_name}/${f.vault_match.credential_name}`
                        : "—"}
                    </td>
                    <td>
                      <button className="link" onClick={() => setSuppressing(f)}>
                        suppress
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {suppressing && (
        <PromptDialog
          title="Suppress this finding"
          body={`${suppressing.file}:${suppressing.line} — a reason is required and stored locally.`}
          placeholder="why this is not a real secret"
          confirmLabel="Suppress"
          onConfirm={confirmSuppress}
          onCancel={() => setSuppressing(null)}
        />
      )}
    </div>
  );
}
