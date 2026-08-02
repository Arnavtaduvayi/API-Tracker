"use strict";

const NOTICE_VERSION = "2026-08-01";
const ALLOWED_FIELDS = new Set([
  "name",
  "email",
  "phone",
  "company",
  "website",
  "noticeVersion",
]);
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/u;
const PHONE = /^[0-9A-Za-z+().#*\-\s]*$/u;

class WaitlistInputError extends Error {
  constructor(code, status = 400) {
    super(code);
    this.name = "WaitlistInputError";
    this.code = code;
    this.status = status;
  }
}

function textField(value, field, maximum) {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string")
    throw new WaitlistInputError(`invalid_${field}`);
  const normalized = value.normalize("NFKC").trim();
  if (normalized.length > maximum || CONTROL_CHARACTERS.test(normalized)) {
    throw new WaitlistInputError(`invalid_${field}`);
  }
  return normalized;
}

function normalizeWaitlistSubmission(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new WaitlistInputError("invalid_body");
  }
  for (const field of Object.keys(input)) {
    if (!ALLOWED_FIELDS.has(field))
      throw new WaitlistInputError("unexpected_field");
  }

  const website = textField(input.website, "website", 200);
  if (website) throw new WaitlistInputError("spam_rejected");
  if (input.noticeVersion !== NOTICE_VERSION) {
    throw new WaitlistInputError("notice_refresh_required", 409);
  }

  const submission = {
    name: textField(input.name, "name", 120),
    email: textField(input.email, "email", 254),
    phone: textField(input.phone, "phone", 40),
    company: textField(input.company, "company", 160),
  };

  if (submission.email && !EMAIL.test(submission.email)) {
    throw new WaitlistInputError("invalid_email");
  }
  if (submission.phone && !PHONE.test(submission.phone)) {
    throw new WaitlistInputError("invalid_phone");
  }
  return submission;
}

function isAllowedOrigin(origin, emulator = false) {
  if (emulator && /^https?:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/u.test(origin))
    return true;
  return new Set([
    "https://usetethra.com",
    "https://www.usetethra.com",
    "https://usetethra.web.app",
    "https://usetethra.firebaseapp.com",
  ]).has(origin);
}

module.exports = {
  NOTICE_VERSION,
  WaitlistInputError,
  isAllowedOrigin,
  normalizeWaitlistSubmission,
};
