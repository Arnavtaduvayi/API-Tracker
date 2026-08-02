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

The `usetethra` organization enforces Domain Restricted Sharing, so it cannot
accept Firebase's normal `allUsers` invoker binding. Production instead uses
Cloud Run's documented service-level `--no-invoker-iam-check` setting on
`jointeamswaitlist`. Both functions run as the dedicated
`tethra-waitlist-runtime@usetethra.iam.gserviceaccount.com` account, which has
only `roles/datastore.user` and access to `WAITLIST_HASH_SECRET`. The function
manifest uses that account as a fail-closed fallback invoker so routine Firebase
deploys do not retry the blocked `allUsers` policy.

One-time production IAM and service configuration:

```sh
gcloud projects add-iam-policy-binding usetethra \
  --member=serviceAccount:1088538145643-compute@developer.gserviceaccount.com \
  --role=roles/cloudbuild.builds.builder --condition=None
gcloud iam service-accounts create tethra-waitlist-runtime \
  --project=usetethra \
  --display-name="Tethra waitlist runtime"
gcloud projects add-iam-policy-binding usetethra \
  --member=serviceAccount:tethra-waitlist-runtime@usetethra.iam.gserviceaccount.com \
  --role=roles/datastore.user --condition=None
gcloud secrets add-iam-policy-binding WAITLIST_HASH_SECRET \
  --project=usetethra \
  --member=serviceAccount:tethra-waitlist-runtime@usetethra.iam.gserviceaccount.com \
  --role=roles/secretmanager.secretAccessor --condition=None
gcloud run services update jointeamswaitlist \
  --region=us-east1 --project=usetethra --no-invoker-iam-check
gcloud scheduler jobs update http \
  firebase-schedule-cleanupTeamsWaitlist-us-east1 \
  --location=us-east1 --project=usetethra \
  --oidc-service-account-email=tethra-waitlist-runtime@usetethra.iam.gserviceaccount.com \
  --oidc-token-audience=https://us-east1-usetethra.cloudfunctions.net/cleanupTeamsWaitlist
```

The scheduler identity update matters for projects where the job was originally
created before the dedicated runtime account existed; Firebase preserves that
existing OIDC identity on later function updates.

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
