# Tethra website functions

The Teams waitlist is a server-only Firestore flow. Browser clients submit to
`/api/waitlist`, Firebase Hosting rewrites that path to `joinTeamsWaitlist`, and
the Admin SDK writes the private `waitlist` collection. Firestore rules deny
every direct client read and write; do not loosen them for the form.

## Production prerequisites

Cloud Functions requires the Firebase project to use the Blaze plan. Create the
HMAC secret without printing or committing its value:

```sh
openssl rand -hex 32 | firebase functions:secrets:set WAITLIST_HASH_SECRET --data-file - --project usetethra
```

Deploy the deny-all rules before the function, then deploy the function and
Hosting configuration:

```sh
firebase deploy --only firestore:rules,firestore:indexes --project usetethra
firebase deploy --only functions --project usetethra
firebase deploy --only hosting --project usetethra
```

The production database uses the North America multi-region and deletion
protection. Submitted name, email, phone, and company fields are all optional.
Raw IP addresses are not written to waitlist documents. Keyed IP hashes support
rate limiting, and automated cleanup uses each record's `expiresAt` timestamp.

## Local validation

Place a non-production value in ignored `functions/.secret.local`, then run:

```sh
firebase emulators:start --only hosting,functions,firestore --project usetethra
```

Local submissions appear only in the Firestore emulator; they never appear in
the production Firebase console.
