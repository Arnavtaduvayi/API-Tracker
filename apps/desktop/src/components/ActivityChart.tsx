// A small accessible time-series chart, drawn as inline SVG.
//
// No chart library: the desktop has none today, and adding one for a
// deliberately temporary layout would be a large dependency in a
// security-sensitive app for one panel. What this needs is a line, an axis, a
// tooltip and honest gaps — which is less code than the integration would be.
//
// Two rules it exists to keep:
//
//   * A GAP IS NOT A ZERO. `null` breaks the line. Only the requests and errors
//     metrics treat an absent bucket as a real zero, because "no observation
//     recorded" genuinely means "no requests arrived". Tokens, latency and cost
//     are unknown when absent, and a line drawn through them would invent data.
//   * THE SVG IS NOT THE ONLY REPRESENTATION. The chart is `role="img"` with a
//     summary label, and the same numbers are in a visually-hidden table so the
//     series is reachable without seeing it.

import { useId, useMemo, useState } from "react";
import type { ProjectSeriesPoint, SeriesGranularity } from "../types";

/** The metrics a project's series can be viewed as. */
export type ChartMetric =
  | "requests"
  | "input_tokens"
  | "output_tokens"
  | "total_tokens"
  | "latency"
  | "errors"
  | "cost";

export const CHART_METRIC_LABELS: Record<ChartMetric, string> = {
  requests: "Requests",
  input_tokens: "Input tokens",
  output_tokens: "Output tokens",
  total_tokens: "Total tokens",
  latency: "Average latency",
  errors: "Errors",
  cost: "Estimated known cost",
};

/**
 * Whether an absent bucket means zero for this metric.
 *
 * Requests and errors are counted from the observation rows themselves, so a
 * bucket with no rows really did see none. Every other metric depends on a
 * provider having reported something, so absence is unknown.
 */
function absentMeansZero(metric: ChartMetric): boolean {
  return metric === "requests" || metric === "errors";
}

/** The plotted value for one point, or null when it is genuinely unknown. */
function valueOf(p: ProjectSeriesPoint, metric: ChartMetric): number | null {
  switch (metric) {
    case "requests":
      return p.requests;
    case "errors":
      return p.errors;
    case "input_tokens":
      return p.input_tokens;
    case "output_tokens":
      return p.output_tokens;
    case "total_tokens":
      if (p.input_tokens === null && p.output_tokens === null) return null;
      return (p.input_tokens ?? 0) + (p.output_tokens ?? 0);
    case "latency":
      return p.avg_latency_ms;
    case "cost":
      return p.estimated_micros;
    default:
      return null;
  }
}

function formatValue(value: number, metric: ChartMetric): string {
  if (metric === "cost") return `$${(value / 1_000_000).toFixed(4)}`;
  if (metric === "latency") return `${value.toLocaleString()} ms`;
  return value.toLocaleString();
}

/** A short axis label for a bucket, at the granularity being shown. */
export function formatBucket(iso: string, granularity: SeriesGranularity): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  if (granularity === "day") {
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  }
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

const WIDTH = 720;
const HEIGHT = 200;
const PAD_LEFT = 56;
const PAD_RIGHT = 12;
const PAD_TOP = 12;
const PAD_BOTTOM = 28;

export function ActivityChart(props: {
  points: ProjectSeriesPoint[];
  metric: ChartMetric;
  granularity: SeriesGranularity;
  /** Rendered when the metric has no value anywhere in the window. */
  unknownNote?: string | null;
}) {
  const { points, metric, granularity } = props;
  const titleId = useId();
  const descId = useId();
  const gradientId = `activity-fill-${useId().replaceAll(":", "")}`;
  const [hover, setHover] = useState<number | null>(null);

  const series = useMemo(
    () =>
      points.map((p) => {
        const raw = valueOf(p, metric);
        return {
          bucket: p.bucket_start,
          // A metric whose absence is a real zero is plotted as zero; anything
          // else stays null and breaks the line.
          value: raw === null && absentMeansZero(metric) ? 0 : raw,
          costComplete: p.cost_complete,
        };
      }),
    [points, metric],
  );

  const known = series.filter((s) => s.value !== null) as {
    bucket: string;
    value: number;
    costComplete: boolean;
  }[];

  if (points.length === 0) {
    return (
      <p className="muted" data-testid="chart-empty">
        No activity recorded in this period yet. Requests appear here as soon as your project
        makes them.
      </p>
    );
  }
  if (known.length === 0) {
    return (
      <p className="muted" data-testid="chart-unknown">
        {props.unknownNote ??
          `${CHART_METRIC_LABELS[metric]} was not reported for any request in this period.`}
      </p>
    );
  }

  const max = Math.max(...known.map((k) => k.value));
  // A flat all-zero series still needs a non-zero range or every point lands on
  // the axis and the chart reads as broken rather than as empty.
  const top = max <= 0 ? 1 : max;
  const innerW = WIDTH - PAD_LEFT - PAD_RIGHT;
  const innerH = HEIGHT - PAD_TOP - PAD_BOTTOM;
  const stepX = series.length > 1 ? innerW / (series.length - 1) : 0;

  const x = (i: number) => PAD_LEFT + (series.length === 1 ? innerW / 2 : i * stepX);
  const y = (v: number) => PAD_TOP + innerH - (v / top) * innerH;

  // Build one path per unbroken run, so a null leaves a visible gap instead of
  // a straight line implying measured values in between.
  const segments: { line: string; area: string }[] = [];
  let current: string[] = [];
  let firstX = 0;
  let lastX = 0;
  const flushSegment = () => {
    if (current.length === 0) return;
    segments.push({
      line: current.join(" "),
      area: `${current.join(" ")} L${lastX.toFixed(1)},${y(0).toFixed(1)} L${firstX.toFixed(
        1,
      )},${y(0).toFixed(1)} Z`,
    });
    current = [];
  };
  series.forEach((s, i) => {
    if (s.value === null) {
      flushSegment();
      return;
    }
    if (current.length === 0) firstX = x(i);
    lastX = x(i);
    current.push(
      `${current.length === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(s.value).toFixed(1)}`,
    );
  });
  flushSegment();

  const label = `${CHART_METRIC_LABELS[metric]} over time, ${known.length} of ${
    series.length
  } buckets with data, peak ${formatValue(max, metric)}`;

  const ticks = [0, 0.5, 1].map((f) => ({ f, value: top * f }));
  // At most six x labels, whatever the bucket count, so they stay readable.
  const labelEvery = Math.max(1, Math.ceil(series.length / 6));

  return (
    <div className="chartwrap">
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        width="100%"
        height={HEIGHT}
        role="img"
        aria-labelledby={`${titleId} ${descId}`}
        className="activitychart"
      >
        <title id={titleId}>{CHART_METRIC_LABELS[metric]}</title>
        <desc id={descId}>{label}</desc>
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.24" />
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
          </linearGradient>
        </defs>

        {ticks.map((t) => (
          <g key={t.f}>
            <line
              x1={PAD_LEFT}
              x2={WIDTH - PAD_RIGHT}
              y1={y(t.value)}
              y2={y(t.value)}
              className="chartgrid"
            />
            <text x={PAD_LEFT - 8} y={y(t.value) + 4} textAnchor="end" className="charttick">
              {formatValue(Math.round(t.value), metric)}
            </text>
          </g>
        ))}

        {segments.map((segment, i) => (
          <path
            key={`area-${i}`}
            d={segment.area}
            className="chartarea"
            fill={`url(#${gradientId})`}
          />
        ))}

        {segments.map((segment, i) => (
          <path key={i} d={segment.line} className="chartline" fill="none" />
        ))}

        {series.map((s, i) =>
          s.value === null ? null : (
            <circle
              key={s.bucket}
              cx={x(i)}
              cy={y(s.value)}
              r={hover === i ? 4 : 2.5}
              className={s.costComplete ? "chartdot" : "chartdot partial"}
              onMouseEnter={() => setHover(i)}
              onMouseLeave={() => setHover(null)}
            >
              <title>
                {`${formatBucket(s.bucket, granularity)}: ${formatValue(s.value, metric)}${
                  metric === "cost" && !s.costComplete
                    ? " (partial — a floor, not a total)"
                    : ""
                }`}
              </title>
            </circle>
          ),
        )}

        {series.map((s, i) =>
          i % labelEvery === 0 ? (
            <text
              key={`x-${s.bucket}`}
              x={x(i)}
              y={HEIGHT - 8}
              textAnchor="middle"
              className="charttick"
            >
              {formatBucket(s.bucket, granularity)}
            </text>
          ) : null,
        )}
      </svg>

      {/* The same series as text, so it is reachable without seeing the SVG. */}
      <table className="visually-hidden">
        <caption>{label}</caption>
        <thead>
          <tr>
            <th scope="col">Time</th>
            <th scope="col">{CHART_METRIC_LABELS[metric]}</th>
          </tr>
        </thead>
        <tbody>
          {series.map((s) => (
            <tr key={`row-${s.bucket}`}>
              <th scope="row">{formatBucket(s.bucket, granularity)}</th>
              <td>
                {s.value === null
                  ? "not reported"
                  : `${formatValue(s.value, metric)}${
                      metric === "cost" && !s.costComplete
                        ? " (partial — a floor, not a total)"
                        : ""
                    }`}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
