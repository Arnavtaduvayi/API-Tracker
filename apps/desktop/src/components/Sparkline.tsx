// A request-volume glance for a project card.
//
// Deliberately not a chart. `ActivityChart` is the chart: it has axes, ticks,
// hover values, a gap-aware line and a text-equivalent table, because it is
// something a user reads figures off. This is a shape, and it is labelled as
// one — the accessible name states the range and the total, and the exact
// figures live on the card beside it.
//
// Only request counts are ever drawn here. An absent bucket is a real zero for
// requests (the same rule `absentMeansZero` encodes in ActivityChart), so a
// continuous line is honest. It would not be for tokens, latency or cost, and
// those are not offered.

const WIDTH = 200;
const HEIGHT = 34;

export function Sparkline(props: { values: number[]; label: string }) {
  const { values, label } = props;
  if (values.length < 2) return null;

  const peak = Math.max(...values);
  const total = values.reduce((a, b) => a + b, 0);
  // A flat run of zeroes has no shape to draw, and a zero-height baseline
  // reads as "no data" rather than "no traffic" — the card says which.
  if (peak <= 0) return null;

  const step = WIDTH / (values.length - 1);
  const y = (v: number) => HEIGHT - (v / peak) * (HEIGHT - 2) - 1;
  const points = values.map((v, i) => `${(i * step).toFixed(2)},${y(v).toFixed(2)}`);
  const line = `M${points.join(" L")}`;
  const area = `${line} L${WIDTH},${HEIGHT} L0,${HEIGHT} Z`;

  return (
    <svg
      className="sparkline"
      viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
      preserveAspectRatio="none"
      role="img"
      aria-label={`${label}: ${total.toLocaleString()} requests across ${values.length} periods, peaking at ${peak.toLocaleString()}`}
      focusable="false"
    >
      <path className="sparkline-area" d={area} />
      <path className="sparkline-line" d={line} vectorEffect="non-scaling-stroke" />
    </svg>
  );
}
