// Destinations: where credential VALUES are deployed (CI secret stores,
// cloud secret managers, the OS keychain). The catalog reports honest
// capability levels; configured destinations hold an encrypted, write-only
// administrative credential; attachments record which credential is deployed
// where. No secret value is ever rendered here.

import { useCallback, useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type {
  Attachment,
  Credential,
  DestSupport,
  Destination,
  DestinationKindInfo,
} from "../types";
import { ENVIRONMENTS } from "../types";
import { formatTimestamp } from "../utils";
import { ConfirmDialog } from "./ConfirmDialog";
import { ReauthDialog } from "./ReauthDialog";

const SUPPORT_LABELS: Record<DestSupport, string> = {
  implemented: "implemented",
  supported_not_implemented: "not implemented yet",
  unsupported: "unsupported",
  platform_unavailable: "unavailable on this platform",
};

function capabilityChip(name: string, support: DestSupport) {
  const cls =
    support === "implemented" ? "badge ok" : support === "unsupported" ? "badge" : "badge warn";
  return (
    <span key={name} className={cls} title={`${name}: ${SUPPORT_LABELS[support]}`}>
      {name}: {SUPPORT_LABELS[support]}
    </span>
  );
}

function driftBadge(drift: string) {
  switch (drift) {
    case "in_sync":
      return <span className="badge ok">in sync</span>;
    case "drifted":
      return <span className="badge bad">drifted</span>;
    case "missing":
      return <span className="badge bad">missing</span>;
    case "present_unverifiable":
      return <span className="badge warn">present (value unverifiable)</span>;
    case "rolled_back":
      return <span className="badge warn">rolled back</span>;
    default:
      return <span className="muted">{drift || "never checked"}</span>;
  }
}

export function DestinationsView() {
  const [catalog, setCatalog] = useState<DestinationKindInfo[]>([]);
  const [destinations, setDestinations] = useState<Destination[]>([]);
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Add form.
  const [showAdd, setShowAdd] = useState(false);
  const [kind, setKind] = useState("aws_secrets_manager");
  const [name, setName] = useState("");
  const [region, setRegion] = useState("");
  const [owner, setOwner] = useState("");
  const [repo, setRepo] = useState("");
  const [projectId, setProjectId] = useState("");
  const [teamId, setTeamId] = useState("");
  const [targets, setTargets] = useState("");
  const [account, setAccount] = useState("");
  const [authToken, setAuthToken] = useState("");
  const [awsAccessKeyId, setAwsAccessKeyId] = useState("");
  const [awsSecretKey, setAwsSecretKey] = useState("");
  // Attach form.
  const [attachCredential, setAttachCredential] = useState("");
  const [attachDestination, setAttachDestination] = useState("");
  const [secretName, setSecretName] = useState("");
  const [attachEnvironment, setAttachEnvironment] = useState("production");
  // Dialogs.
  const [removing, setRemoving] = useState<Destination | null>(null);
  const [detaching, setDetaching] = useState<Attachment | null>(null);

  const configurableKinds = catalog.filter(
    (k) => !["vault", "env_mapping", "env_export"].includes(k.kind),
  );

  const reload = useCallback(async () => {
    try {
      const [d, a, c] = await Promise.all([
        api.destinationList(),
        api.destinationAttachments(null),
        api.credentialList(),
      ]);
      setDestinations(d);
      setAttachments(a);
      setCredentials(c.filter((cr) => !cr.is_reference));
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    api
      .destinationCatalog()
      .then(setCatalog)
      .catch((e) => setError(isApiError(e) ? e.message : String(e)));
    void reload();
  }, [reload]);

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

  const resetAddForm = () => {
    setName("");
    setRegion("");
    setOwner("");
    setRepo("");
    setProjectId("");
    setTeamId("");
    setTargets("");
    setAccount("");
    setAuthToken("");
    setAwsAccessKeyId("");
    setAwsSecretKey("");
  };

  const addDestination = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const config: Record<string, unknown> = {};
      let auth: string | null = null;
      if (kind === "aws_secrets_manager") {
        config.region = region.trim();
        auth = JSON.stringify({
          access_key_id: awsAccessKeyId.trim(),
          secret_access_key: awsSecretKey,
        });
      } else if (kind === "github_actions") {
        config.owner = owner.trim();
        config.repo = repo.trim();
        auth = authToken;
      } else if (kind === "vercel") {
        config.project_id = projectId.trim();
        if (teamId.trim() !== "") config.team_id = teamId.trim();
        const parsed = targets
          .split(",")
          .map((t) => t.trim())
          .filter((t) => t !== "");
        if (parsed.length > 0) config.targets = parsed;
        auth = authToken;
      } else if (kind === "macos_keychain") {
        if (account.trim() !== "") config.account = account.trim();
      }
      const dest = await api.destinationAdd(kind, name.trim(), config, auth);
      resetAddForm();
      setShowAdd(false);
      setNotice(
        `Added destination '${dest.name}'. ` +
          (auth ? "Its credential is stored encrypted and is write-only. " : "") +
          "Use Test to verify it.",
      );
      await reload();
    });
  };

  const test = (d: Destination) =>
    run(async () => {
      const detail = await api.destinationTest(d.id);
      setNotice(`Test '${d.name}': ${detail}`);
      await reload();
    });

  const attach = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await api.destinationAttach(
        attachCredential,
        attachDestination,
        secretName.trim(),
        attachEnvironment,
      );
      setSecretName("");
      setNotice("Attached. Generate a sync plan to deploy the value.");
      await reload();
    });
  };

  const checkDrift = () =>
    run(async () => {
      setAttachments(await api.destinationDriftCheck(null));
      setNotice(
        "Drift check complete. Write-only destinations can only be verified for existence.",
      );
    });

  return (
    <div>
      <h1>Destinations</h1>
      <p className="muted">
        A destination is where a credential&apos;s value is deployed — separate from the
        provider that issued it. All requests go directly from this machine; destination
        credentials are stored encrypted in the vault and never displayed.
      </p>

      <h2>Catalog</h2>
      <table>
        <thead>
          <tr>
            <th>Destination</th>
            <th>Kind</th>
            <th>Platforms</th>
            <th>Status</th>
            <th>Capabilities</th>
          </tr>
        </thead>
        <tbody>
          {catalog.map((k) => (
            <tr key={k.kind}>
              <td>
                {k.name}
                <div className="muted">{k.description}</div>
              </td>
              <td className="mono">{k.kind}</td>
              <td>{k.platforms}</td>
              <td>{k.status}</td>
              <td>
                <div style={{ display: "flex", gap: "0.25rem", flexWrap: "wrap" }}>
                  {capabilityChip("read", k.capabilities.read)}
                  {capabilityChip("write", k.capabilities.write)}
                  {capabilityChip("delete", k.capabilities.delete)}
                  {capabilityChip("versioning", k.capabilities.versioning)}
                  {capabilityChip("rollback", k.capabilities.rollback)}
                  {capabilityChip("validation", k.capabilities.validation)}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Configured destinations</h2>
      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}
      {destinations.length === 0 ? (
        <p>No destinations configured.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Kind</th>
              <th>Auth (masked)</th>
              <th>Last verified</th>
              <th>Last error</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {destinations.map((d) => (
              <tr key={d.id}>
                <td>{d.name}</td>
                <td className="mono">{d.kind}</td>
                <td className="mono">{d.auth_masked ?? "none"}</td>
                <td>{d.last_verified_at ? formatTimestamp(d.last_verified_at) : "never"}</td>
                <td>{d.last_error ? <span className="error">{d.last_error}</span> : "—"}</td>
                <td>
                  <button className="link" onClick={() => void test(d)} disabled={busy}>
                    test
                  </button>{" "}
                  <button className="link danger" onClick={() => setRemoving(d)}>
                    remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <button onClick={() => setShowAdd((v) => !v)}>
        {showAdd ? "Hide add form" : "Add destination…"}
      </button>

      {showAdd && (
        <form className="stack" onSubmit={addDestination}>
          <label className="field">
            Kind
            <select value={kind} onChange={(e) => setKind(e.target.value)}>
              {configurableKinds.map((k) => (
                <option key={k.kind} value={k.kind}>
                  {k.name}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            Name (your label for this destination)
            <input value={name} onChange={(e) => setName(e.target.value)} required />
          </label>
          {kind === "aws_secrets_manager" && (
            <>
              <label className="field">
                Region
                <input
                  className="mono"
                  placeholder="us-east-1"
                  value={region}
                  onChange={(e) => setRegion(e.target.value)}
                  required
                />
              </label>
              <label className="field">
                IAM access key id
                <input
                  className="mono"
                  value={awsAccessKeyId}
                  onChange={(e) => setAwsAccessKeyId(e.target.value)}
                  required
                />
              </label>
              <label className="field">
                IAM secret access key (stored encrypted; write-only after saving)
                <input
                  type="password"
                  value={awsSecretKey}
                  onChange={(e) => setAwsSecretKey(e.target.value)}
                  required
                />
              </label>
            </>
          )}
          {kind === "github_actions" && (
            <>
              <label className="field">
                Repository owner
                <input value={owner} onChange={(e) => setOwner(e.target.value)} required />
              </label>
              <label className="field">
                Repository name
                <input value={repo} onChange={(e) => setRepo(e.target.value)} required />
              </label>
              <label className="field">
                Access token with repository secrets permission (stored encrypted; write-only
                after saving)
                <input
                  type="password"
                  value={authToken}
                  onChange={(e) => setAuthToken(e.target.value)}
                  required
                />
              </label>
            </>
          )}
          {kind === "vercel" && (
            <>
              <label className="field">
                Project id
                <input
                  className="mono"
                  value={projectId}
                  onChange={(e) => setProjectId(e.target.value)}
                  required
                />
              </label>
              <label className="field">
                Team id (optional)
                <input
                  className="mono"
                  value={teamId}
                  onChange={(e) => setTeamId(e.target.value)}
                />
              </label>
              <label className="field">
                Targets (comma-separated; default production,preview,development)
                <input
                  className="mono"
                  value={targets}
                  onChange={(e) => setTargets(e.target.value)}
                />
              </label>
              <label className="field">
                Vercel access token (stored encrypted; write-only after saving)
                <input
                  type="password"
                  value={authToken}
                  onChange={(e) => setAuthToken(e.target.value)}
                  required
                />
              </label>
            </>
          )}
          {kind === "macos_keychain" && (
            <label className="field">
              Keychain account (optional; default &quot;api-tracker&quot;)
              <input value={account} onChange={(e) => setAccount(e.target.value)} />
            </label>
          )}
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button type="submit" disabled={busy}>
              {busy ? "Working…" : "Add destination"}
            </button>
            <button type="button" onClick={() => setShowAdd(false)}>
              Cancel
            </button>
          </div>
        </form>
      )}

      <h2>Attachments</h2>
      <p className="muted">
        An attachment records that a credential is deployed to a destination under a secret
        name. Deploying or updating the value always goes through a reviewed sync plan.
      </p>
      {attachments.length === 0 ? (
        <p>No attachments.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Credential</th>
              <th>Destination</th>
              <th>Secret name</th>
              <th>Environment</th>
              <th>Last synced</th>
              <th>Drift</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {attachments.map((a) => (
              <tr key={`${a.credential_id}:${a.destination_id}:${a.secret_name}`}>
                <td>
                  {a.project_name}/{a.credential_name}
                </td>
                <td>
                  {a.destination_name} <span className="muted mono">{a.destination_kind}</span>
                </td>
                <td className="mono">{a.secret_name}</td>
                <td>{a.environment}</td>
                <td>
                  {a.last_synced_version != null ? `v${a.last_synced_version}` : "never"}
                  {a.last_synced_at && (
                    <span className="muted"> ({formatTimestamp(a.last_synced_at)})</span>
                  )}
                </td>
                <td>{driftBadge(a.drift)}</td>
                <td>
                  <button className="link danger" onClick={() => setDetaching(a)}>
                    detach
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <button onClick={() => void checkDrift()} disabled={busy || attachments.length === 0}>
        {busy ? "Working…" : "Check drift now"}
      </button>

      <form className="stack" style={{ marginTop: "0.75rem" }} onSubmit={attach}>
        <h3>Attach a credential</h3>
        <label className="field">
          Credential
          <select
            value={attachCredential}
            onChange={(e) => setAttachCredential(e.target.value)}
            required
          >
            <option value="">choose credential…</option>
            {credentials.map((c) => (
              <option key={c.id} value={c.id}>
                {c.project_name}/{c.name}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          Destination
          <select
            value={attachDestination}
            onChange={(e) => setAttachDestination(e.target.value)}
            required
          >
            <option value="">choose destination…</option>
            {destinations.map((d) => (
              <option key={d.id} value={d.id}>
                {d.name} ({d.kind})
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          Secret name at the destination
          <input
            className="mono"
            placeholder="OPENAI_API_KEY"
            value={secretName}
            onChange={(e) => setSecretName(e.target.value)}
            required
          />
        </label>
        <label className="field">
          Environment
          <select
            value={attachEnvironment}
            onChange={(e) => setAttachEnvironment(e.target.value)}
          >
            {ENVIRONMENTS.map((env) => (
              <option key={env} value={env}>
                {env}
              </option>
            ))}
          </select>
        </label>
        <div>
          <button type="submit" disabled={busy || !attachCredential || !attachDestination}>
            Attach
          </button>
        </div>
      </form>

      {removing && (
        <ReauthDialog
          title={`Remove destination '${removing.name}'`}
          actionLabel="Remove destination"
          onConfirm={async (password) => {
            await api.destinationRemove(removing.id, password);
            setNotice(
              `Removed '${removing.name}'. Secrets already stored at the destination are NOT deleted.`,
            );
            await reload();
          }}
          onClose={() => setRemoving(null)}
        />
      )}
      {detaching && (
        <ConfirmDialog
          title="Detach credential from destination"
          body={`Stop tracking '${detaching.secret_name}' at '${detaching.destination_name}' for ${detaching.project_name}/${detaching.credential_name}? The secret stored at the destination is not deleted.`}
          confirmLabel="Detach"
          danger
          onConfirm={() => {
            const a = detaching;
            setDetaching(null);
            void run(async () => {
              await api.destinationDetach(a.credential_id, a.destination_id, a.secret_name);
              setNotice("Detached.");
              await reload();
            });
          }}
          onCancel={() => setDetaching(null)}
        />
      )}
    </div>
  );
}
