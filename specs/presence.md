# Presence: online + last-seen per contact (visible-to-all v1)

## Why
The app shows per-chat presence ("online" / "last seen …"). The server
already tracks sockets in `presence`; it just never exposes it. No broadcast
(the server has no contact graph, and broadcast-to-all would leak) — plain
query endpoint, polled by the client on thread-open / reconnect / minute tick.

## Change
1. Schema: `presence(username PK, online BOOLEAN, connected_at, last_seen)`.
   - Connect: upsert `online=true, connected_at=now` (existing behavior).
   - Last socket disconnect: `online=false, last_seen=now` INSTEAD of row
     delete (one-line change in the disconnect path).
2. Endpoint: `GET /api/v1/presence/{username}` → `{online: bool,
   last_seen: int|null}` (unix seconds, null when never seen). Require a
   valid Bearer token (any user) — presence is public-by-design in v1, but
   anonymous harvesting should still need no encouragement.
3. No storage of history, no new tables, no protocol versioning.

## Client contract (implemented app-side)
- Query on thread open, on socket reconnect, and on the existing 60s UI tick.
- Renders "online" (green) or "last seen HH:MM / yesterday / date".
- Absent row → "never seen". Timer skew across devices is display-only noise.

## Privacy note (accepted v1, joint follow-up)
Presence is visible to all, exactly like the directory. Contact-gating both
is tracked follow-up work once the circle grows beyond friends.
