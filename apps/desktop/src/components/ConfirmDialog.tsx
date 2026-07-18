// In-app confirm/prompt dialogs. The native window.confirm / window.prompt
// do NOT work under the macOS WKWebView that Tauri uses (wry does not
// implement the JS-dialog delegate methods), so all confirmations and text
// prompts must be rendered by the app itself.

import { useState } from "react";

export function ConfirmDialog(props: {
  title: string;
  body?: string;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <dialog open>
      <h2>{props.title}</h2>
      {props.body && <p>{props.body}</p>}
      <div style={{ display: "flex", gap: "0.5rem" }}>
        <button className={props.danger ? "danger" : undefined} onClick={props.onConfirm}>
          {props.confirmLabel}
        </button>
        <button onClick={props.onCancel}>Cancel</button>
      </div>
    </dialog>
  );
}

export function PromptDialog(props: {
  title: string;
  body?: string;
  placeholder?: string;
  confirmLabel: string;
  onConfirm: (value: string) => void;
  onCancel: () => void;
}) {
  const [value, setValue] = useState("");
  return (
    <dialog open>
      <h2>{props.title}</h2>
      {props.body && <p className="muted">{props.body}</p>}
      <form
        className="stack"
        onSubmit={(e) => {
          e.preventDefault();
          props.onConfirm(value);
        }}
      >
        <input
          value={value}
          placeholder={props.placeholder}
          onChange={(e) => setValue(e.target.value)}
          autoFocus
        />
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button type="submit">{props.confirmLabel}</button>
          <button type="button" onClick={props.onCancel}>
            Cancel
          </button>
        </div>
      </form>
    </dialog>
  );
}
