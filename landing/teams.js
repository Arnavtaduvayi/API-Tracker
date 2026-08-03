(() => {
  "use strict";

  const noticeVersion = "2026-08-01";
  const dialog = document.querySelector("[data-waitlist-dialog]");
  const form = document.querySelector("[data-waitlist-form]");
  const formView = document.querySelector("[data-waitlist-form-view]");
  const successView = document.querySelector("[data-waitlist-success]");
  const status = document.querySelector("[data-waitlist-status]");

  if (
    !(dialog instanceof HTMLDialogElement) ||
    !(form instanceof HTMLFormElement)
  )
    return;

  const setStatus = (message) => {
    if (status instanceof HTMLElement) status.textContent = message;
  };

  const open = () => {
    setStatus("");
    if (!dialog.open) dialog.showModal();
    window.requestAnimationFrame(() =>
      form.elements.namedItem("name")?.focus(),
    );
  };

  const close = () => {
    if (dialog.open) dialog.close();
  };

  document.querySelectorAll("[data-open-waitlist]").forEach((button) => {
    button.addEventListener("click", open);
  });
  document.querySelectorAll("[data-close-waitlist]").forEach((button) => {
    button.addEventListener("click", close);
  });
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) close();
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    setStatus("");
    if (!form.reportValidity()) return;

    const submit = form.querySelector("button[type='submit']");
    if (!(submit instanceof HTMLButtonElement) || submit.disabled) return;
    submit.disabled = true;
    submit.textContent = "Joining…";

    const data = new FormData(form);
    const payload = {
      name: String(data.get("name") || ""),
      email: String(data.get("email") || ""),
      phone: String(data.get("phone") || ""),
      company: String(data.get("company") || ""),
      website: String(data.get("website") || ""),
      noticeVersion,
    };

    try {
      const response = await fetch("/api/waitlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        credentials: "same-origin",
        referrerPolicy: "same-origin",
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) {
        if (result.code === "invalid_email")
          throw new Error("Enter a valid email address or leave it blank.");
        if (result.code === "invalid_phone")
          throw new Error("Enter a valid phone number or leave it blank.");
        if (result.code === "rate_limited")
          throw new Error(
            "Too many attempts. Please try again in about an hour.",
          );
        if (result.code === "notice_refresh_required")
          throw new Error("This form changed. Refresh the page and try again.");
        throw new Error(
          "We couldn’t record your interest right now. Please try again.",
        );
      }

      form.reset();
      if (formView instanceof HTMLElement) formView.hidden = true;
      if (successView instanceof HTMLElement) successView.hidden = false;
    } catch (error) {
      setStatus(
        error instanceof Error
          ? error.message
          : "We couldn’t record your interest right now.",
      );
    } finally {
      submit.disabled = false;
      submit.textContent = "Join waitlist";
    }
  });
})();
