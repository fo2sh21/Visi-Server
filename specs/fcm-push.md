# Push-token registration + data-only wakeups (FCM)

## Why
Closed-app message arrival currently waits for next launch. Data-only FCM
wakes the app to drain the queue headlessly; the user sees ONLY the decoy
hydration notification. FCM never sees content (data payload is `{ping:true}`).

## Endpoints
1. `POST /api/v1/push-token {username, fcm_token}` → `{status:ok}`.
   Upsert into `push_tokens(username PK, fcm_token, updated_at)`. Tokens are
   routing metadata; store them like usernames (no extra secrecy, but never
   log them). Auth: require the caller's Bearer WS token (a user registers
   only their OWN token — enforce `username == token owner`).
2. Optional `POST /api/v1/push-token/delete {username}` (Bearer-authed) for
   logout/wipe hygiene. Client also clears locally regardless.

## Send path (on every message insert into offline_queue)
- If recipient has a stored token AND is offline (no open socket): send a
  **data-only** FCM message `{data:{ping:"true"}}` — never a `notification`
  block (that would let FCM/System render uncontrolled text and leak
  metadata into system notification logs).
- Needs a server-side FCM service-account credential (env var path), used
  server-side only. Token-send failures (unregistered token) → delete the
  stored token (stale) and continue — the queue remains the source of truth.

## What this does NOT do
- No content, sender, count, or timestamp in pushes (timing alone leaks
  "something arrived" — accepted and documented in-app).
- No badge counts. No sound customization per sender.
- The client fetches everything over its own authenticated WS after wake;
  FCM is a doorbell, never a mailbox.

## Client status (already implemented app-side)
`VisiMessagingService` (data-only intent filter), headless wrapped-key drain
(`HeadlessSync`: quiet-timeout 8s, hard cap 60s), decoy-only notification
("Hydration Reminder / Time for a glass of water!"), token auto-register on
login/register + `onNewToken`, silent skip without Play Services.
Missing on device until user input: `app/google-services.json` (gitignored)
+ applying the `com.google.gms.google-services` Gradle plugin.
