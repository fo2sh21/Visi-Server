# Delivered-receipt spec (client needs 2-grey ticks)

## Problem
The sender currently learns nothing between "sent" and "read". WhatsApp-style
ticks need a real delivery signal: the server already knows the exact moment
(the recipient's ack that triggers the hard `DELETE`).

## Change (relay.py ack path only, nothing else moves)
In the scoped ack handler, **before** `DELETE`, load the queued row
(`msg_id` + `to_user` = acker — already in hand for the R2 ownership check)
and best-effort push to the ORIGINAL sender:

```json
{"type": "delivered", "msg_id": "<id>", "to": "<original sender>"}
```

Rules:
- Send only if the original sender currently has an open socket (`broker.is_online`).
  Offline senders simply miss this tick (documented v1 limitation — see below).
- Never persist the receipt. Never log `msg_id` contents beyond debug counters.
- Idempotent by construction: duplicate acks re-push the same payload; the
  client dedups by `msg_id` and re-acks without reprocessing (already locked).
- No new tables, no schema change, no new endpoints.

## Client contract (already implemented app-side, activates on first receipt)
- `1 grey ✓` = stored/sent, `2 grey ✓✓` = delivered receipt seen,
  `2 blue ✓✓` = read receipt seen. All realtime over the open socket.
- Receipts for unknown `msg_id` are ignored.

## Known v1 limitation (accepted, not fixed here)
Ticks are live-only: a sender offline at delivery/read time misses that tick
(the row is gone, nothing to reconcile on reconnect). Tick-state sync on
reconnect is deferred work, tracked separately — it needs a per-thread
high-water-mark endpoint that does not exist yet.
