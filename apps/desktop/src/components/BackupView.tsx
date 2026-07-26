// Encrypted backup management: create, verify, restore. Creating requires
// master-password reauthentication plus a backup password; restoring
// replaces the current vault only after an explicit confirmation.

import { useState } from "react";
import { api, isApiError } from "../api";
import type { BackupInfo } from "../types";
import { ConfirmDialog } from "./ConfirmDialog";

export function BackupView(props: { onRestored: () => void }) {
  const [mode, setMode] = useState<"create" | "verify" | "restore">("create");
  const [path, setPath] = useState("");
  const [masterPassword, setMasterPassword] = useState("");
  const [backupPassword, setBackupPassword] = useState("");
  const [confirmBackupPassword, setConfirmBackupPassword] = useState("");
  const [overwrite, setOverwrite] = useState(false);
  const [forceRestore, setForceRestore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<BackupInfo | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmForce, setConfirmForce] = useState(false);

  const reset = () => {
    setError(null);
    setInfo(null);
    setNotice(null);
  };

  const doRestore = async () => {
    reset();
    setBusy(true);
    try {
      const result = await api.backupRestore(path, backupPassword, forceRestore);
      setInfo(result);
      setNotice(
        "Backup restored. The vault is now locked; unlock it with the master password from when the backup was created.",
      );
      setBackupPassword("");
      props.onRestored();
    } catch (err) {
      setError(isApiError(err) ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    reset();
    if (mode === "restore") {
      // Replacing an existing vault needs an explicit in-app confirmation
      // (native window.confirm does not work under the macOS webview).
      if (forceRestore) {
        setConfirmForce(true);
        return;
      }
      await doRestore();
      return;
    }
    setBusy(true);
    try {
      if (mode === "create") {
        if (backupPassword !== confirmBackupPassword) {
          setError("The backup passwords do not match.");
          return;
        }
        const result = await api.backupCreate(path, masterPassword, backupPassword, overwrite);
        setInfo(result);
        setNotice(
          "Backup created. Restoring will require BOTH this backup password and the master password in use when the backup was made.",
        );
      } else {
        const result = await api.backupVerify(path, backupPassword);
        setInfo(result);
        setNotice("The backup decrypts and validates correctly.");
      }
      setMasterPassword("");
      setBackupPassword("");
      setConfirmBackupPassword("");
    } catch (err) {
      setError(isApiError(err) ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h1>Backup and restore</h1>
      <p>
        Backups are single encrypted files you can store anywhere (external drive, cloud
        storage). They contain your projects, credential records, and wrapped keys — never
        plaintext secrets.
      </p>
      <p style={{ display: "flex", gap: "0.5rem" }}>
        {(["create", "verify", "restore"] as const).map((m) => (
          <button
            key={m}
            onClick={() => {
              setMode(m);
              reset();
            }}
            disabled={mode === m}
          >
            {m === "create" ? "Create" : m === "verify" ? "Verify" : "Restore"}
          </button>
        ))}
      </p>
      <form className="stack" onSubmit={(e) => void submit(e)}>
        <label className="field">
          Backup file path
          <input
            className="mono"
            placeholder="/path/to/tethra-backup.json"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            required
          />
        </label>
        {mode === "create" && (
          <>
            <label className="field">
              Master password (reauthentication)
              <input
                type="password"
                value={masterPassword}
                onChange={(e) => setMasterPassword(e.target.value)}
                required
              />
            </label>
            <label className="field">
              Backup password (protects this file; can differ from the master password)
              <input
                type="password"
                value={backupPassword}
                onChange={(e) => setBackupPassword(e.target.value)}
                required
              />
            </label>
            <label className="field">
              Confirm backup password
              <input
                type="password"
                value={confirmBackupPassword}
                onChange={(e) => setConfirmBackupPassword(e.target.value)}
                required
              />
            </label>
            <label>
              <input
                type="checkbox"
                checked={overwrite}
                onChange={(e) => setOverwrite(e.target.checked)}
              />{" "}
              Overwrite the file if it exists
            </label>
          </>
        )}
        {mode !== "create" && (
          <label className="field">
            Backup password
            <input
              type="password"
              value={backupPassword}
              onChange={(e) => setBackupPassword(e.target.value)}
              required
            />
          </label>
        )}
        {mode === "restore" && (
          <label>
            <input
              type="checkbox"
              checked={forceRestore}
              onChange={(e) => setForceRestore(e.target.checked)}
            />{" "}
            Replace the existing vault (it is renamed aside, not deleted)
          </label>
        )}
        {error && <p className="error">{error}</p>}
        {notice && <p className="notice">{notice}</p>}
        {info && (
          <p className="muted">
            {info.project_count} project(s), {info.credential_count} credential(s), created{" "}
            {info.created_at}
          </p>
        )}
        <button type="submit" disabled={busy}>
          {busy
            ? "Working…"
            : mode === "create"
              ? "Create encrypted backup"
              : mode === "verify"
                ? "Verify backup"
                : "Restore backup"}
        </button>
      </form>
      <p className="warnbox">
        Losing both the backup password and the master password makes a backup permanently
        unreadable. There is no recovery bypass.
      </p>
      {confirmForce && (
        <ConfirmDialog
          title="Replace the current vault?"
          body="The existing database is renamed aside (not deleted), and the vault will lock. You will unlock the restored vault with the master password from when the backup was created."
          confirmLabel="Replace and restore"
          danger
          onConfirm={() => {
            setConfirmForce(false);
            void doRestore();
          }}
          onCancel={() => setConfirmForce(false)}
        />
      )}
    </div>
  );
}
