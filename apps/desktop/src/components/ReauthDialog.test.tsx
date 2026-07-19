import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ReauthDialog } from "./ReauthDialog";

// User-visible security behavior of the reauthentication prompt: the typed
// master password must be cleared from the field after a SUCCESSFUL confirm,
// retained after a FAILED confirm (so the user can correct a typo), and a
// backend error must be shown honestly rather than silently swallowed.

function passwordField(): HTMLInputElement {
  return screen.getByLabelText(/master password/i) as HTMLInputElement;
}

describe("ReauthDialog", () => {
  it("passes the password to onConfirm and clears the field on success", async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    const onClose = vi.fn();
    render(
      <ReauthDialog
        title="Reveal credential"
        actionLabel="Reveal"
        onConfirm={onConfirm}
        onClose={onClose}
      />,
    );
    await user.type(passwordField(), "master-pw");
    await user.click(screen.getByRole("button", { name: "Reveal" }));

    expect(onConfirm).toHaveBeenCalledWith("master-pw");
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    // Field cleared after success (defense in depth before unmount).
    expect(passwordField().value).toBe("");
  });

  it("keeps the password and shows the error after a failed confirm", async () => {
    const user = userEvent.setup();
    const onConfirm = vi
      .fn()
      .mockRejectedValue({ code: "wrong_password", message: "wrong password" });
    const onClose = vi.fn();
    render(
      <ReauthDialog
        title="Delete credential"
        actionLabel="Delete permanently"
        onConfirm={onConfirm}
        onClose={onClose}
      />,
    );
    await user.type(passwordField(), "bad-pw");
    await user.click(screen.getByRole("button", { name: "Delete permanently" }));

    // The honest backend error is shown; the dialog stays open; the password
    // is retained for a retry (never silently cleared or the action faked).
    expect(await screen.findByText("wrong password")).toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();
    expect(passwordField().value).toBe("bad-pw");
  });

  it("does not invoke onConfirm when the required field is empty", async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    render(
      <ReauthDialog
        title="Reveal"
        actionLabel="Reveal"
        onConfirm={onConfirm}
        onClose={vi.fn()}
      />,
    );
    await user.click(screen.getByRole("button", { name: "Reveal" }));
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("Cancel closes without confirming", async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    const onClose = vi.fn();
    render(
      <ReauthDialog
        title="Reveal"
        actionLabel="Reveal"
        onConfirm={onConfirm}
        onClose={onClose}
      />,
    );
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onClose).toHaveBeenCalled();
    expect(onConfirm).not.toHaveBeenCalled();
  });
});
