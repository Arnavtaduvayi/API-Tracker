// Per-provider visual identity for the provider library and the project /
// credential cards.
//
// Everything here is bundled in the repository and rendered inline. Nothing is
// fetched at runtime: Tethra only ever talks to the providers the user selected
// and official documentation sites, so hot-linking a vendor CDN for a logo is
// not an option (CLAUDE.md, "Local-first requirements").
//
// Each provider gets a brand-coloured tile carrying its initial, or — when an
// official mark has been added to `MARKS` below — that mark drawn in the brand
// colour. The two render at the same size and sit on the same tile, so a
// library that mixes them still reads as one system.
//
// ADDING AN OFFICIAL LOGO
// -----------------------
// Take the vendor's own SVG from their published brand or press kit, confirm
// the licence permits identifying their service, normalise it to a 24×24
// viewBox, and add the path data:
//
//     openai: { color: "#10a37f", path: "M12 2 ..." },
//
// Do not trace a logo by hand and do not approximate one: a wrong mark is a
// misrepresentation of someone else's brand. Until an official path is added,
// the monogram is the honest option and is what ships.

const FALLBACK_COLOR = "#8e8e93";

interface Brand {
  /** The vendor's primary brand colour, used for the tile and any mark. */
  color: string;
  /** Official 24×24 path data. Absent until a vendor's own SVG is added. */
  path?: string;
  /** Overrides the initial taken from the display name. */
  initial?: string;
}

/** Keyed by the manifest `id` in `provider-manifests/`. */
const MARKS: Record<string, Brand> = {
  anthropic: { color: "#d97757" },
  "aws-bedrock": { color: "#ff9900", initial: "B" },
  "azure-openai": { color: "#0078d4", initial: "Az" },
  cerebras: { color: "#f15a29" },
  cohere: { color: "#ff7759" },
  deepseek: { color: "#4d6bfe" },
  fireworks: { color: "#5019c5" },
  github: { color: "#ffffff" },
  "google-gemini": { color: "#4285f4", initial: "G" },
  groq: { color: "#f55036" },
  huggingface: { color: "#ffd21e", initial: "H" },
  langsmith: { color: "#1c9c7c", initial: "L" },
  mistral: { color: "#fa520f" },
  openai: { color: "#10a37f" },
  openrouter: { color: "#6467f2", initial: "OR" },
  perplexity: { color: "#20808d" },
  replicate: { color: "#ea2805" },
  stripe: { color: "#635bff" },
  supabase: { color: "#3ecf8e" },
  together: { color: "#0f6fff" },
  xai: { color: "#ffffff" },
};

export function providerColor(id: string): string {
  return MARKS[id]?.color ?? FALLBACK_COLOR;
}

function initialFor(id: string, name: string): string {
  const override = MARKS[id]?.initial;
  if (override) return override;
  const first = name.trim().charAt(0);
  return first.length > 0 ? first.toUpperCase() : "?";
}

/**
 * A provider's mark at card size.
 *
 * Decorative: the provider's name is always rendered beside it, so the tile is
 * hidden from assistive technology rather than repeating that name.
 */
export function ProviderMark(props: { id: string; name: string; className?: string }) {
  const brand = MARKS[props.id];
  const color = brand?.color ?? FALLBACK_COLOR;

  if (brand?.path) {
    return (
      <span
        className={props.className ? `entity-mark ${props.className}` : "entity-mark"}
        style={{ background: tint(color) }}
        aria-hidden="true"
      >
        <svg viewBox="0 0 24 24" fill={color} aria-hidden="true" focusable="false">
          <path d={brand.path} />
        </svg>
      </span>
    );
  }

  return (
    <span
      className={
        props.className ? `entity-mark monogram ${props.className}` : "entity-mark monogram"
      }
      style={{ background: tint(color), color }}
      aria-hidden="true"
    >
      {initialFor(props.id, props.name)}
    </span>
  );
}

/**
 * The tile wash behind a mark. A flat brand colour at full strength fights the
 * dark surface and makes a grid of cards unreadable, so the colour is used at
 * low alpha and carried by the glyph instead.
 */
function tint(hex: string): string {
  const m = /^#([0-9a-f]{6})$/i.exec(hex);
  if (!m) return "rgba(255, 255, 255, 0.06)";
  const n = parseInt(m[1], 16);
  const r = (n >> 16) & 255;
  const g = (n >> 8) & 255;
  const b = n & 255;
  return `rgba(${r}, ${g}, ${b}, 0.16)`;
}
