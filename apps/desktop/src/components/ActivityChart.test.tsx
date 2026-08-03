// The activity chart (ADR 0029).
//
// The assertions that matter are not about pixels: they are about whether the
// chart can imply a number nobody measured. An absent token count must not be
// drawn as zero, and a partially priced bucket must be visibly distinct from a
// complete one.

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { ProjectSeriesPoint } from "../types";
import { ActivityChart, formatBucket } from "./ActivityChart";

function point(
  over: Partial<ProjectSeriesPoint> & { bucket_start: string },
): ProjectSeriesPoint {
  return {
    requests: 0,
    errors: 0,
    avg_latency_ms: null,
    input_tokens: null,
    output_tokens: null,
    estimated_micros: null,
    cost_complete: true,
    ...over,
  };
}

/** Every semantic trend-line segment, excluding the decorative area fill. */
function paths(container: HTMLElement): string[] {
  return Array.from(container.querySelectorAll("path.chartline")).map(
    (p) => p.getAttribute("d") ?? "",
  );
}

describe("ActivityChart", () => {
  it("renders an actionable empty state rather than an empty axis", () => {
    render(<ActivityChart points={[]} metric="requests" granularity="hour" />);
    expect(screen.getByTestId("chart-empty").textContent).toContain(
      "No activity recorded in this period yet",
    );
    expect(document.querySelector("svg")).toBeNull();
  });

  it("draws a single point without collapsing the axis", () => {
    const { container } = render(
      <ActivityChart
        points={[point({ bucket_start: "2026-07-29T10:00:00Z", requests: 3 })]}
        metric="requests"
        granularity="hour"
      />,
    );
    expect(container.querySelectorAll("circle")).toHaveLength(1);
    // One point still gets a rendered marker and a description.
    expect(screen.getByRole("img")).toBeTruthy();
  });

  it("draws multiple points as one connected line", () => {
    const { container } = render(
      <ActivityChart
        points={[
          point({ bucket_start: "2026-07-29T10:00:00Z", requests: 1 }),
          point({ bucket_start: "2026-07-29T11:00:00Z", requests: 5 }),
          point({ bucket_start: "2026-07-29T12:00:00Z", requests: 3 }),
        ]}
        metric="requests"
        granularity="hour"
      />,
    );
    expect(container.querySelectorAll("circle")).toHaveLength(3);
    expect(paths(container)).toHaveLength(1);
  });

  it("treats an absent bucket as zero ONLY for requests and errors", () => {
    const points = [
      point({ bucket_start: "2026-07-29T10:00:00Z", requests: 2, input_tokens: 100 }),
      // A bucket with requests but no reported usage.
      point({ bucket_start: "2026-07-29T11:00:00Z", requests: 2, input_tokens: null }),
      point({ bucket_start: "2026-07-29T12:00:00Z", requests: 2, input_tokens: 300 }),
    ];

    // Requests: three real measurements, one unbroken line.
    const asRequests = render(
      <ActivityChart points={points} metric="requests" granularity="hour" />,
    );
    expect(asRequests.container.querySelectorAll("circle")).toHaveLength(3);
    expect(paths(asRequests.container)).toHaveLength(1);
    asRequests.unmount();

    // Input tokens: the middle bucket is UNKNOWN, so it gets no marker and the
    // line breaks into two segments rather than being drawn through a zero.
    const asTokens = render(
      <ActivityChart points={points} metric="input_tokens" granularity="hour" />,
    );
    expect(asTokens.container.querySelectorAll("circle")).toHaveLength(2);
    expect(paths(asTokens.container)).toHaveLength(2);
  });

  it("says so when a metric was never reported, instead of drawing zeroes", () => {
    render(
      <ActivityChart
        points={[
          point({ bucket_start: "2026-07-29T10:00:00Z", requests: 4 }),
          point({ bucket_start: "2026-07-29T11:00:00Z", requests: 6 }),
        ]}
        metric="total_tokens"
        granularity="hour"
      />,
    );
    expect(screen.getByTestId("chart-unknown").textContent).toContain("not reported");
    expect(document.querySelector("svg")).toBeNull();
  });

  it("uses a caller-supplied note for an unreported metric when given one", () => {
    render(
      <ActivityChart
        points={[point({ bucket_start: "2026-07-29T10:00:00Z", requests: 1 })]}
        metric="cost"
        granularity="hour"
        unknownNote="No request had a model, tokens and local pricing all known."
      />,
    );
    expect(screen.getByTestId("chart-unknown").textContent).toContain(
      "model, tokens and local pricing",
    );
  });

  it("marks a partially priced bucket differently from a complete one", () => {
    const { container } = render(
      <ActivityChart
        points={[
          point({
            bucket_start: "2026-07-29T10:00:00Z",
            requests: 1,
            estimated_micros: 1_000_000,
            cost_complete: true,
          }),
          point({
            bucket_start: "2026-07-29T11:00:00Z",
            requests: 1,
            estimated_micros: 2_000_000,
            cost_complete: false,
          }),
        ]}
        metric="cost"
        granularity="hour"
      />,
    );
    const dots = Array.from(container.querySelectorAll("circle"));
    expect(dots).toHaveLength(2);
    expect(dots[0].getAttribute("class")).toBe("chartdot");
    expect(dots[1].getAttribute("class")).toBe("chartdot partial");
    // And the tooltip says a floor is a floor.
    expect(dots[1].querySelector("title")?.textContent).toContain("floor, not a total");
  });

  it("changing the metric re-renders against the same points", () => {
    const points = [
      point({ bucket_start: "2026-07-29T10:00:00Z", requests: 7, avg_latency_ms: 420 }),
    ];
    const view = render(<ActivityChart points={points} metric="requests" granularity="hour" />);
    expect(screen.getByRole("img").querySelector("desc")?.textContent).toContain("Requests");

    view.rerender(<ActivityChart points={points} metric="latency" granularity="hour" />);
    const desc = screen.getByRole("img").querySelector("desc")?.textContent ?? "";
    expect(desc).toContain("Average latency");
    expect(desc).toContain("420 ms");
  });

  it("changing the granularity changes the axis labels, not the data", () => {
    const points = [point({ bucket_start: "2026-07-29T00:00:00Z", requests: 2 })];
    const view = render(<ActivityChart points={points} metric="requests" granularity="day" />);
    const dayLabels = Array.from(view.container.querySelectorAll("text.charttick")).map(
      (t) => t.textContent,
    );
    view.rerender(<ActivityChart points={points} metric="requests" granularity="hour" />);
    const hourLabels = Array.from(view.container.querySelectorAll("text.charttick")).map(
      (t) => t.textContent,
    );
    expect(dayLabels).not.toEqual(hourLabels);
    expect(view.container.querySelectorAll("circle")).toHaveLength(1);
  });

  it("is labelled for assistive technology and duplicated as a table", () => {
    render(
      <ActivityChart
        points={[
          point({ bucket_start: "2026-07-29T10:00:00Z", requests: 1 }),
          point({ bucket_start: "2026-07-29T11:00:00Z", requests: 9 }),
        ]}
        metric="requests"
        granularity="hour"
      />,
    );
    const svg = screen.getByRole("img");
    // aria-labelledby must point at elements that exist, or the label is empty.
    const ids = (svg.getAttribute("aria-labelledby") ?? "").split(" ").filter(Boolean);
    expect(ids).toHaveLength(2);
    for (const id of ids) {
      expect(document.getElementById(id)).not.toBeNull();
    }
    expect(svg.querySelector("desc")?.textContent).toContain("2 of 2 buckets with data");
    expect(svg.querySelector("desc")?.textContent).toContain("peak 9");

    // The same series, reachable as text.
    const table = screen.getByRole("table");
    expect(table.className).toContain("visually-hidden");
    expect(screen.getAllByRole("row")).toHaveLength(3); // header + 2
  });

  it("reports an unknown value as text in the table, never as 0", () => {
    render(
      <ActivityChart
        points={[
          point({ bucket_start: "2026-07-29T10:00:00Z", requests: 1, input_tokens: 5 }),
          point({ bucket_start: "2026-07-29T11:00:00Z", requests: 1, input_tokens: null }),
        ]}
        metric="input_tokens"
        granularity="hour"
      />,
    );
    const cells = Array.from(document.querySelectorAll("td")).map((c) => c.textContent);
    expect(cells).toContain("not reported");
    expect(cells).not.toContain("0");
  });

  it("stays bounded and labelled with a large dataset", () => {
    const points = Array.from({ length: 720 }, (_, i) =>
      point({
        bucket_start: new Date(Date.UTC(2026, 6, 1, 0, i)).toISOString(),
        requests: i % 17,
      }),
    );
    const { container } = render(
      <ActivityChart points={points} metric="requests" granularity="minute" />,
    );
    expect(container.querySelectorAll("circle")).toHaveLength(720);
    // At most six x-axis labels regardless of point count, plus three y ticks.
    const labels = container.querySelectorAll("text.charttick");
    expect(labels.length).toBeLessThanOrEqual(10);
    expect(screen.getByRole("img").querySelector("desc")?.textContent).toContain(
      "720 of 720 buckets",
    );
  });

  it("an all-zero series renders without collapsing onto the axis", () => {
    const { container } = render(
      <ActivityChart
        points={[
          point({ bucket_start: "2026-07-29T10:00:00Z", requests: 0 }),
          point({ bucket_start: "2026-07-29T11:00:00Z", requests: 0 }),
        ]}
        metric="requests"
        granularity="hour"
      />,
    );
    // The points exist and the y axis has a non-degenerate range.
    expect(container.querySelectorAll("circle")).toHaveLength(2);
    const ticks = Array.from(container.querySelectorAll("text.charttick")).map(
      (t) => t.textContent,
    );
    expect(new Set(ticks).size).toBeGreaterThan(1);
  });
});

describe("formatBucket", () => {
  it("formats a day bucket as a date and an hour bucket as a time", () => {
    const day = formatBucket("2026-07-29T00:00:00Z", "day");
    const hour = formatBucket("2026-07-29T13:00:00Z", "hour");
    expect(day).not.toEqual(hour);
    expect(day).toMatch(/\d/);
    expect(hour).toMatch(/\d/);
  });

  it("passes an unparseable value through instead of showing Invalid Date", () => {
    expect(formatBucket("not-a-date", "hour")).toBe("not-a-date");
  });
});
