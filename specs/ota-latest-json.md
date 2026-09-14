# OTA without restarts: `latest.json` as source of truth

## Why
Per-release env edits (`UPDATE_VERSION_CODE/URL/SHA256`) + uvicorn restarts
for every update is toil and downtime. The bucket already holds the release;
let it describe itself.

## Change
1. Bucket layout (public R2):
   - `visi-<versionCode>.apk` — release-signed (OS mandates matching
     signatures for updates; automation never touches this).
   - `latest.json` — `{"version_code": N, "file": "visi-N.apk",
     "sha256": "<hex>"}`. Uploaded alongside the APK (manual now, CI later).
2. `/update-check?version_code=X`:
   - Fetch `latest.json` from the configured bucket base URL (new env
     `UPDATE_BUCKET_BASE`, e.g. `https://pub-<hash>.r2.dev`), 5-min in-memory
     cache (not per-request, not persistent).
   - Return `{version_code, download_url=<base>/<file>, sha256}` iff
     `latest.version_code > X`, else the current "no update" shape.
   - **Anti-downgrade guard**: persist `max_seen_version` (tiny table or file);
     if `latest.json` ever reports lower, keep serving the higher cached
     manifest and log loudly. A poisoned/rolled-back bucket then fails closed.
   - Keep the current env-var manifest as local-dev fallback when
     `UPDATE_BUCKET_BASE` is unset.
3. Client: unchanged (polls, compares, verifies hash, deletes on mismatch).

## Trust note (stated, not hidden)
The hash defeats transit corruption and mismatched uploads. A full bucket
takeover could rewrite APK + `latest.json` together — mitigated by a
write-scoped R2 token, the monotonicity guard above, and a small trusted
circle. True out-of-band hash pinning (hash via the signed Merkle ledger) is
tracked follow-up work.
