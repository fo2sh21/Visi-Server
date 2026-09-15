# Visi relay — production deploy spec (Render free + Neon free + keeper)

Target: public API at Render, Postgres at Neon, zero local state, no sleep
that matters, no restarts for content updates. Read with the other specs in
`specs/`: `fcm-push.md`, `ota-latest-json.md`, `delivered-receipt.md`,
`durable-receipts.md`, `presence.md` (endpoint), plus `opaque-sidecar/SPEC.md`.

## 0. Secrets inventory (what lives where — READ FIRST)

| Secret / config | Lives in | NEVER in |
|---|---|---|
| `.env` (`DATABASE_URL`, `DATABASE_URL_POOLED`, `R2_DEV_URL`, `S3_API`, …) | Local dev only, gitignored (verified) | git, chat, screenshots |
| Same KEYS' values | Render dashboard → Environment (user pasted) | `render.yaml` if that file is ever committed |
| `google-services.json` (Android client config, `visi-53766`) | Nowhere near prod — dev-only | server repo (present untracked: **do not `git add` it**) |
| Firebase SERVICE ACCOUNT key | MISSING — generate: Firebase console → Project settings → Service accounts → Generate new private key. Then either Render env (`FCM_CREDENTIALS_JSON`, whole file as one env value) or server dir untracked + `.gitignore`'d. Never git, never chat. | git, chat, client app |

The Android `google-services.json` currently sitting in `server/` is the
WRONG file for anything server-side (it configures the phone app, not FCM
send). Leave it untracked; the service-account key above is the one FCM
sending needs.

## 1. Build: multi-stage Dockerfile (repo root of `server/`)

Render builds on Linux — the Windows `opaque-sidecar.exe` in this folder
cannot run there. Build the sidecar inside the image:

```dockerfile
# Build stage floats latest stable slim: lockfile transitive deps (askama /
# cargo_metadata via uniffi) keep raising MSRV past pinned toolchains.
FROM rust:slim AS rustbuild
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY core-crypto ./core-crypto
COPY opaque-sidecar ./opaque-sidecar
RUN cargo build --release -p opaque-sidecar

FROM python:3.13-slim
WORKDIR /srv
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY --from=rustbuild /build/target/release/opaque-sidecar /srv/bin/opaque-sidecar
ENV OPAQUE_SIDECAR_BIN=/srv/bin/opaque-sidecar
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "10000"]
```

Render free web service: Docker runtime, port 10000 (or `$PORT`), one
instance, no disk (none needed — see §3).

## 2. Config: env vars (Render dashboard; dev mirrors in local `.env`)

| Key | Value | Notes |
|---|---|---|
| `DATABASE_URL` | Neon pooled URL (`DATABASE_URL_POOLED`), pasted verbatim | asyncpg + pgbouncer: code normalizes `postgresql://`→`+asyncpg`, strips libpq-only `sslmode`/`channel_binding` into `ssl=True`, and sets `statement_cache_size=0` (prepared statements die on pgbouncer otherwise) |
| `UPDATE_BUCKET_BASE` | R2 public base (same as local `R2_DEV_URL` if that is the `r2.dev` download base; else the `pub-….r2.dev` URL) | feeds the `latest.json` reader (`ota-latest-json.md`) |
| `FCM_CREDENTIALS_JSON` | service-account file content (§0) | required for push sends (`fcm-push.md`) |
| `WS_TOKEN_TTL_DAYS` | `30` | locked cap |
| `LOGIN_STATE_TTL_SEC` | `300` | default fine |
| Rate-limit / OTA dev vars | as today | unchanged |

## 3. Zero local state (Render disk evaporates per restart — design for it)

- `ServerSetup`, password files, bundles, envelopes, queue, tokens,
  Merkle state, login states: **all Postgres** (SPEC M4). Grep the codebase
  for `open(`, `write_bytes`, `Path(`, `sqlite` — any hit outside tests is a
  deploy blocker.
- `visi.db` (local SQLite) is dev-only. Nothing in prod may reference it.
- Sidecar binary comes from the image (`OPAQUE_SIDECAR_BIN`), never committed.

## 4. Keeper (the documented hack — see root brief for accepted risks)

- External cron (UptimeRobot free / cron-job.org) → `GET /healthz` every
  10 min. Budget: one service 24/7 ≈ 730h vs the 750h monthly cap — fits,
  no second service on this workspace, ever.
- No DB keeper: Neon sleeps (5 min) and self-wakes in ~300ms — invisible in
  practice and it preserves the 100 CU-hr budget. Keep-alive queries would
  burn budget for nothing.
- Failure modes accepted: ~1 min cold first message after maintenance;
  month-end suspension past 750h (watch Billing; escape hatch ≈ $7/mo paid,
  which also ends sleep permanently); no Render shell — logs-only debugging
  (still never IPs/secrets).

## 5. Bring-up order
1. Neon project → paste pooled URL to `.env` + Render env.
2. `latest.json` reader + anti-downgrade guard (`ota-latest-json.md`).
3. Push endpoints + data-only send (`fcm-push.md`) + service-account key (§0).
4. Receipt/presence follow-ups (`delivered-receipt.md`, `durable-receipts.md`,
   rekey routing, presence endpoint) — client code for all four is already
   implemented and dormant; they activate on arrival.
5. Dockerfile → Render deploy → keeper monitor → drill: register → DM →
   kill app → push → decoy note → tap → message present → OTA tamper/match.

## 6. Later (not this round)
Oracle VM replaces Render+keeper with zero protocol changes (same image +
disk-backed DB). Out-of-band hash pinning via the Merkle ledger. CI upload
for R2 (token stays in GitHub Secrets).
