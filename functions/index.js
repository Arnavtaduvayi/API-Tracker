"use strict";

const crypto = require("node:crypto");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, Timestamp } = require("firebase-admin/firestore");
const logger = require("firebase-functions/logger");
const { defineSecret } = require("firebase-functions/params");
const { onRequest } = require("firebase-functions/v2/https");
const { onSchedule } = require("firebase-functions/v2/scheduler");
const {
  NOTICE_VERSION,
  WaitlistInputError,
  isAllowedOrigin,
  normalizeWaitlistSubmission,
} = require("./waitlist");

initializeApp();

const database = getFirestore();
const waitlistHashSecret = defineSecret("WAITLIST_HASH_SECRET");
const FUNCTION_REGION = "us-east1";
const MAX_REQUEST_BYTES = 8_192;
const RATE_LIMIT = 5;
const RATE_WINDOW_MS = 60 * 60 * 1_000;
const RATE_RECORD_MS = 2 * 60 * 60 * 1_000;
const WAITLIST_RETENTION_MS = 365 * 24 * 60 * 60 * 1_000;

function digest(secret, value) {
  return crypto.createHmac("sha256", secret).update(value).digest("hex");
}

function requestAddress(request) {
  return request.ip || request.socket?.remoteAddress || "unknown";
}

function safeResponseHeaders(response) {
  response.set({
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  });
}

exports.joinTeamsWaitlist = onRequest(
  {
    region: FUNCTION_REGION,
    secrets: [waitlistHashSecret],
    cors: false,
    invoker: "public",
    maxInstances: 10,
    concurrency: 40,
    timeoutSeconds: 10,
    memory: "256MiB",
  },
  async (request, response) => {
    safeResponseHeaders(response);
    if (request.method !== "POST") {
      response
        .set("Allow", "POST")
        .status(405)
        .send(JSON.stringify({ ok: false }));
      return;
    }

    const origin = request.get("origin") || "";
    const emulator = process.env.FUNCTIONS_EMULATOR === "true";
    const fetchSite = request.get("sec-fetch-site");
    if (
      !isAllowedOrigin(origin, emulator) ||
      (fetchSite && fetchSite !== "same-origin" && fetchSite !== "same-site")
    ) {
      response.status(403).send(JSON.stringify({ ok: false }));
      return;
    }
    if (
      !request.is("application/json") ||
      (request.rawBody?.length ?? 0) > MAX_REQUEST_BYTES
    ) {
      response.status(415).send(JSON.stringify({ ok: false }));
      return;
    }

    try {
      const submission = normalizeWaitlistSubmission(request.body);
      const nowMs = Date.now();
      const secret = waitlistHashSecret.value();
      const address = requestAddress(request);
      const addressHash = digest(secret, `rate\0${address}`);
      const day = Math.floor(nowMs / (24 * 60 * 60 * 1_000));
      const normalizedIdentity = JSON.stringify({
        ...submission,
        email: submission.email.toLowerCase(),
      });
      const waitlistId = digest(
        secret,
        `waitlist\0${address}\0${day}\0${normalizedIdentity}`,
      );
      const rateRef = database
        .collection("waitlist_rate_limits")
        .doc(addressHash);
      const waitlistRef = database.collection("waitlist").doc(waitlistId);

      await database.runTransaction(async (transaction) => {
        const [rateSnapshot, existingSubmission] = await Promise.all([
          transaction.get(rateRef),
          transaction.get(waitlistRef),
        ]);
        const rate = rateSnapshot.data();
        const windowStartedAt = rate?.windowStartedAt?.toMillis?.() ?? 0;
        const withinWindow = nowMs - windowStartedAt < RATE_WINDOW_MS;
        const count = withinWindow ? Number(rate?.count ?? 0) : 0;
        if (count >= RATE_LIMIT)
          throw new WaitlistInputError("rate_limited", 429);

        transaction.set(rateRef, {
          count: count + 1,
          windowStartedAt: Timestamp.fromMillis(
            withinWindow ? windowStartedAt : nowMs,
          ),
          expiresAt: Timestamp.fromMillis(nowMs + RATE_RECORD_MS),
        });

        if (!existingSubmission.exists) {
          transaction.create(waitlistRef, {
            ...submission,
            source: "teams_waitlist",
            noticeVersion: NOTICE_VERSION,
            followUpRequested: Boolean(submission.email || submission.phone),
            createdAt: Timestamp.fromMillis(nowMs),
            expiresAt: Timestamp.fromMillis(nowMs + WAITLIST_RETENTION_MS),
          });
        }
      });

      response.status(202).send(JSON.stringify({ ok: true }));
    } catch (error) {
      if (error instanceof WaitlistInputError) {
        if (error.status === 429) response.set("Retry-After", "3600");
        logger.warn("Teams waitlist request rejected", { code: error.code });
        response
          .status(error.status)
          .send(JSON.stringify({ ok: false, code: error.code }));
        return;
      }
      logger.error("Teams waitlist request failed", { code: "internal" });
      response.status(500).send(JSON.stringify({ ok: false }));
    }
  },
);

async function deleteExpired(collectionName) {
  let deleted = 0;
  for (let batchNumber = 0; batchNumber < 8; batchNumber += 1) {
    const snapshot = await database
      .collection(collectionName)
      .where("expiresAt", "<=", Timestamp.now())
      .limit(250)
      .get();
    if (snapshot.empty) break;
    const batch = database.batch();
    snapshot.docs.forEach((document) => batch.delete(document.ref));
    await batch.commit();
    deleted += snapshot.size;
    if (snapshot.size < 250) break;
  }
  return deleted;
}

exports.cleanupTeamsWaitlist = onSchedule(
  {
    region: FUNCTION_REGION,
    schedule: "17 * * * *",
    timeZone: "Etc/UTC",
    maxInstances: 1,
    timeoutSeconds: 120,
    memory: "256MiB",
  },
  async () => {
    const [waitlistDeleted, limitsDeleted] = await Promise.all([
      deleteExpired("waitlist"),
      deleteExpired("waitlist_rate_limits"),
    ]);
    logger.info("Teams waitlist expiry cleanup complete", {
      waitlistDeleted,
      limitsDeleted,
    });
  },
);
