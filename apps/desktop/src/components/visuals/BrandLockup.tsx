import keyMark from "../../assets/tethra-key.png";

export function BrandLockup(props: { className?: string }) {
  return (
    <span className={["brand-lockup", props.className].filter(Boolean).join(" ")}>
      <img className="brand-symbol" src={keyMark} alt="" aria-hidden="true" />
      <span className="brand-wordmark">tethra.</span>
    </span>
  );
}
