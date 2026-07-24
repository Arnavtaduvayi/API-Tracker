import { useCallback, useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type { PricingRecord } from "../types";

// Versioned pricing records used for local cost ESTIMATES. Estimates are
// always labeled and kept separate from provider-reported cost; unknown
// models get no estimate. Records are effective-dated, so importing a new
// price never silently reprices older usage.
export function PricingView() {
  const [records, setRecords] = useState<PricingRecord[]>([]);
  const [showAll, setShowAll] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  // Override form.
  const [ovProvider, setOvProvider] = useState("");
  const [ovModel, setOvModel] = useState("");
  const [ovUnit, setOvUnit] = useState<"tokens" | "requests">("tokens");
  const [ovInput, setOvInput] = useState("");
  const [ovOutput, setOvOutput] = useState("");
  const [ovCached, setOvCached] = useState("");
  const [ovPerRequest, setOvPerRequest] = useState("");
  const [ovNote, setOvNote] = useState("");

  // Import/export.
  const [importText, setImportText] = useState("");
  const [exportText, setExportText] = useState("");

  const reload = useCallback(async (all: boolean) => {
    try {
      setRecords(await api.pricingRecords(all));
      setError("");
    } catch (err) {
      if (isApiError(err)) setError(err.message);
    }
  }, []);

  useEffect(() => {
    void reload(showAll);
  }, [reload, showAll]);

  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await action();
      await reload(showAll);
    } catch (err) {
      if (isApiError(err)) setError(err.message);
      else setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  const dollars = (m: number | null) =>
    m === null || m === undefined ? "–" : `$${(m / 1_000_000).toFixed(2)}`;

  const staleCount = records.filter((r) => r.stale).length;

  return (
    <section>
      <h1>Pricing</h1>
      <p className="muted">
        These records drive local cost <strong>estimates</strong> only. Estimates are always
        labeled, are kept strictly separate from provider-reported cost, and are never invented
        for unknown models. Prices are effective-dated: usage is priced as of its own date, so
        updating a price never silently reprices older usage.
      </p>
      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}

      <label>
        <input
          type="checkbox"
          checked={showAll}
          onChange={(e) => setShowAll(e.target.checked)}
        />{" "}
        Show full version history (not just currently effective records)
      </label>
      {staleCount > 0 && (
        <p className="warnbox">
          {staleCount} record(s) were last verified more than 45 days ago and are flagged stale.
          Verify against the source and import a reviewed update or set an override.
        </p>
      )}
      <table>
        <thead>
          <tr>
            <th>Provider</th>
            <th>Model</th>
            <th>Unit</th>
            <th>Input /1M</th>
            <th>Cached /1M</th>
            <th>Output /1M</th>
            <th>Per request</th>
            <th>Effective from</th>
            <th>Last verified</th>
            <th>Origin</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {records.map((r) => (
            <tr key={`${r.provider}/${r.model}/${r.origin}/${r.effective_from}`}>
              <td>{r.provider}</td>
              <td>{r.model}</td>
              <td>{r.unit}</td>
              <td>{dollars(r.input_price_per_m_micros)}</td>
              <td>{dollars(r.cached_input_price_per_m_micros)}</td>
              <td>{dollars(r.output_price_per_m_micros)}</td>
              <td>{dollars(r.per_request_micros)}</td>
              <td>{r.effective_from}</td>
              <td>{r.last_verified}</td>
              <td>{r.origin}</td>
              <td>
                {r.stale && <span className="badge warn">STALE</span>}{" "}
                {r.origin === "override" && (
                  <button
                    disabled={busy}
                    onClick={() =>
                      void run(async () => {
                        await api.pricingRemoveOverride(r.provider, r.model);
                        setNotice(`Removed override for ${r.provider}/${r.model}.`);
                      })
                    }
                  >
                    Remove
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>Manual override</h3>
      <p className="muted">
        An override wins over imported and bundled records. Stored estimates are not recomputed.
      </p>
      <div className="stack">
        <label className="field">
          Provider
          <input value={ovProvider} onChange={(e) => setOvProvider(e.target.value)} />
        </label>
        <label className="field">
          Model / service
          <input value={ovModel} onChange={(e) => setOvModel(e.target.value)} />
        </label>
        <label className="field">
          Unit
          <select
            value={ovUnit}
            onChange={(e) => setOvUnit(e.target.value === "requests" ? "requests" : "tokens")}
          >
            <option value="tokens">tokens</option>
            <option value="requests">requests</option>
          </select>
        </label>
        {ovUnit === "tokens" ? (
          <>
            <label className="field">
              Input $/1M
              <input
                value={ovInput}
                onChange={(e) => setOvInput(e.target.value)}
                placeholder="2.50"
              />
            </label>
            <label className="field">
              Output $/1M
              <input
                value={ovOutput}
                onChange={(e) => setOvOutput(e.target.value)}
                placeholder="10"
              />
            </label>
            <label className="field">
              Cached input $/1M (optional)
              <input value={ovCached} onChange={(e) => setOvCached(e.target.value)} />
            </label>
          </>
        ) : (
          <label className="field">
            $ per request
            <input
              value={ovPerRequest}
              onChange={(e) => setOvPerRequest(e.target.value)}
              placeholder="0.01"
            />
          </label>
        )}
        <label className="field">
          Note
          <input
            value={ovNote}
            onChange={(e) => setOvNote(e.target.value)}
            placeholder="negotiated rate"
          />
        </label>
        <button
          disabled={busy || !ovProvider || !ovModel}
          onClick={() =>
            void run(async () => {
              await api.pricingSetOverride({
                provider: ovProvider,
                model: ovModel,
                unit: ovUnit,
                input: ovInput || null,
                output: ovOutput || null,
                cachedInput: ovCached || null,
                perRequest: ovPerRequest || null,
                note: ovNote || null,
              });
              setNotice(`Override stored for ${ovProvider}/${ovModel}.`);
            })
          }
        >
          Save override
        </button>
      </div>

      <h3>Import reviewed pricing</h3>
      <p className="muted">
        Paste a pricing JSON file (for example one produced by{" "}
        <code>tethra pricing propose</code> and reviewed against the provider&apos;s
        published pricing page). Records are validated; malformed or negative prices are
        rejected. History is preserved.
      </p>
      <textarea
        rows={6}
        value={importText}
        onChange={(e) => setImportText(e.target.value)}
        placeholder='[{"provider":"openai","model":"gpt-4o","input_per_m":"2.50", ...}]'
      />
      <div>
        <button
          disabled={busy || !importText.trim()}
          onClick={() =>
            void run(async () => {
              const outcome = await api.pricingImport(importText);
              setNotice(
                `Imported ${outcome.added} new record(s), replaced ${outcome.replaced}.`,
              );
              setImportText("");
            })
          }
        >
          Validate and import
        </button>{" "}
        <button
          disabled={busy}
          onClick={() =>
            void run(async () => {
              setExportText(await api.pricingExport(null));
              setNotice("Exported the full pricing dataset below.");
            })
          }
        >
          Export all records
        </button>
      </div>
      {exportText && <textarea rows={8} readOnly value={exportText} />}
    </section>
  );
}
