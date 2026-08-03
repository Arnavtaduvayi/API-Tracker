"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  NOTICE_VERSION,
  WaitlistInputError,
  isAllowedOrigin,
  normalizeWaitlistSubmission,
} = require("./waitlist");

test("accepts a submission with every user field blank", () => {
  assert.deepEqual(
    normalizeWaitlistSubmission({
      name: "",
      email: "",
      phone: "",
      company: "",
      website: "",
      noticeVersion: NOTICE_VERSION,
    }),
    { name: "", email: "", phone: "", company: "" },
  );
});

test("normalizes optional fields without changing their meaning", () => {
  assert.deepEqual(
    normalizeWaitlistSubmission({
      name: "  Ada Lovelace ",
      email: " ada@example.com ",
      phone: " +1 (404) 555-0100 ",
      company: " Analytical Engines ",
      website: "",
      noticeVersion: NOTICE_VERSION,
    }),
    {
      name: "Ada Lovelace",
      email: "ada@example.com",
      phone: "+1 (404) 555-0100",
      company: "Analytical Engines",
    },
  );
});

test("rejects invalid contact data and oversized fields", () => {
  assert.throws(
    () =>
      normalizeWaitlistSubmission({
        email: "no-at-sign",
        noticeVersion: NOTICE_VERSION,
      }),
    (error) =>
      error instanceof WaitlistInputError && error.code === "invalid_email",
  );
  assert.throws(
    () =>
      normalizeWaitlistSubmission({
        name: "x".repeat(121),
        noticeVersion: NOTICE_VERSION,
      }),
    (error) =>
      error instanceof WaitlistInputError && error.code === "invalid_name",
  );
});

test("rejects honeypot, stale notice, control characters, and unexpected fields", () => {
  const invalid = [
    [{ website: "bot", noticeVersion: NOTICE_VERSION }, "spam_rejected"],
    [{ noticeVersion: "old" }, "notice_refresh_required"],
    [
      { company: "bad\nvalue", noticeVersion: NOTICE_VERSION },
      "invalid_company",
    ],
    [{ role: "admin", noticeVersion: NOTICE_VERSION }, "unexpected_field"],
  ];
  invalid.forEach(([input, code]) => {
    assert.throws(
      () => normalizeWaitlistSubmission(input),
      (error) => error instanceof WaitlistInputError && error.code === code,
    );
  });
});

test("allows only owned production origins and local emulator origins", () => {
  assert.equal(isAllowedOrigin("https://usetethra.com"), true);
  assert.equal(isAllowedOrigin("https://example.com"), false);
  assert.equal(isAllowedOrigin("http://127.0.0.1:5002"), false);
  assert.equal(isAllowedOrigin("http://127.0.0.1:5002", true), true);
});
