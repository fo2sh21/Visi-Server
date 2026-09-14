# `opaque-sidecar` — Server-Agent Integration Spec

## What this is
A tiny Rust binary that performs the **server side** of OPAQUE registration and
login using the exact same crate and cipher suite as the Android client
(`opaque-ke` v4, OPRF Ristretto255-SHA512, KEX TripleDH-SHA512, KSF
Argon2id m=65536 KiB / t=3 / p=1). You never touch cryptography: you pass JSON
strings between the app and this binary and persist opaque blobs.

Source lives in the client monorepo (`Visi-Messenger`, `opaque-sidecar/`); a
copy is vendored here so this repo builds standalone.

## Build
Requires a Rust toolchain (`rustup`, stable ≥ 1.85), then from this directory:

```sh
# from this directory (workspace root: Cargo.toml + Cargo.lock + both crates)
cargo build --release -p opaque-sidecar
# binary: ./target/release/opaque-sidecar[.exe]
```

Deploy the single static binary next to FastAPI. No config files, no network,
no database access of its own.

## Protocol (stdin → stdout, one JSON object each)
Request: `{"op": "<name>", ...fields}` — all binary fields are base64 (std).
- Success → stdout `{"ok": {...}}`, exit 0.
- Auth outcome failure (e.g. wrong password at `login_finish`) → stdout
  `{"error": "<message>"}`, exit 0. This is a NORMAL auth result, not a crash.
- Crash (panic, broken stdin) → stderr text, **nonzero exit**. This is the ONLY
  case to treat as an infrastructure fault (500). Never convert it into an
  auth success/failure.

### Ops
| op | input fields | output (`ok`) |
|----|--------------|----------------|
| `setup_new` | — | `{"setup": b64}` — run ONCE per deployment, store the blob in a `server_setup` table (single row). Losing it invalidates every password file. |
| `register_start` | `setup`, `request`, `user_id` | `{"response": b64}` |
| `register_finish` | `upload` | `{"password_file": b64}` — store per username (PK). Also store the client's key `bundle` (sent alongside, see below) in the directory table. |
| `login_start` | `setup`, `request`, `user_id`, `password_file` (omit/`null` for unknown users → **dummy response**, indistinguishable by design) | `{"response": b64, "login_state": b64}` — hold `login_state` server-side (memory/Redis, minutes TTL) and pass it to `login_finish`. It is an opaque blob, not a secret. |
| `login_finish` | `login_state`, `finalization` | `{"session_key": b64}` — matches the client's session key. Mint the WS token from it (e.g. HMAC it with a server secret), then forget it. On wrong password this returns `{"error": ...}` instead. |

## Endpoint mapping (client contract §Auth)
- `POST /api/v1/opaque/register/start` → `register_start` (needs stored `setup`)
- `POST /api/v1/opaque/register/finish` → `register_finish` + persist
  `password_file`; request body also carries `bundle` =
  `{identity_pub_ed_b64, signed_pre_pub_x_b64, signed_pre_sig_b64, onetime_pub_x_b64|null}`
  for `GET /api/v1/keys/{username}` and the Merkle ledger. The bundle is PUBLIC.
- `POST /api/v1/opaque/login/start` → `login_start` (pass stored file, or omit
  for unknown usernames — same code path, no `if user_exists` branching in responses)
- `POST /api/v1/opaque/login/finish` → `login_finish` + return the user backup
  `envelope_b64` (stored at registration; you cannot read it — it is encrypted
  under the OPAQUE export key, which never leaves the client).

## Rules
1. Never log `request`/`response`/`upload`/`finalization`/`password_file`/`session_key`/`login_state` contents, usernames-to-IP mappings, or IPs at all.
2. `login_start` for unknown users must take the same path and time-shape as for
   known users (the binary handles indistinguishability; don't add timing oracles
   around it, e.g. no extra DB lookups that change latency shape — fetch-or-null).
3. Rate-limit login endpoints; never reveal "user exists" via status codes or timing.
4. `ServerSetup` rotation is out of scope for v1 (would invalidate all password files).

## Suggested Postgres schema (you own this)
```sql
CREATE TABLE server_setup (id INT PRIMARY KEY CHECK (id = 1), blob BYTEA NOT NULL);
CREATE TABLE password_files (username TEXT PRIMARY KEY, blob BYTEA NOT NULL);
-- directory bundles + Merkle ledger per project-rules.md §E
CREATE TABLE key_bundles (username TEXT PRIMARY KEY, bundle JSONB NOT NULL);
```

## Verified interop
`opaque-sidecar/tests/interop.rs` proves client(crate)↔server(sidecar):
register+login roundtrip with matching session/export keys, wrong-password
rejection, dummy login for unknown users. Run: `cargo test -p opaque-sidecar`.
If your endpoints shell out per this spec, auth works by construction.
