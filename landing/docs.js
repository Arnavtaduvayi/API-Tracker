(() => {
  const originalLabels = new WeakMap();

  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    originalLabels.set(button, button.textContent ?? "Copy");
    button.addEventListener("click", async () => {
      const target = document.getElementById(button.dataset.copyTarget ?? "");
      const value = target?.textContent?.trim();
      if (!value) return;

      try {
        await navigator.clipboard.writeText(value);
        button.textContent = "Copied";
      } catch {
        const selection = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(target);
        selection?.removeAllRanges();
        selection?.addRange(range);
        button.textContent = "Select + copy";
      }

      window.setTimeout(() => {
        button.textContent = originalLabels.get(button) ?? "Copy";
      }, 1800);
    });
  });
})();
