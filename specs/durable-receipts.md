# Durable receipts (REQUIRED for both-ends shred — no client backstop exists)

## Why
The app team rejected a client-side safety-net expiry. Consequence: if the
sender is offline when the peer reads, the sender misses the live receipt and
its copy NEVER expires. Both-ends 6h shred is then guaranteed only when both
sides are online — unacceptable as the steady state.

Fix: receipts persist (addressed to the original sender) until the sender
acks them — same lifecycle as messages, same "stored only until acknowledged,
never archived" rule. This AMENDS "read receipts routed, never stored": live
routing stays the fast path; persistence is the offline backstop.

## Change (relay.py + one table)
1. New table `pending_receipts(id PK uuid, to_user FK, kind TEXT, msg_id TEXT,
   created_at)`. `kind` ∈ {`delivered`, `read`}. Index `(to_user, created_at)`.
2. Generation points (existing code):
   - Recipient ack of a message → in addition to DELETE, INSERT
     `{to: <original sender>, kind: delivered, msg_id}` — but ONLY if the
     sender is offline (`broker.is_online` false). Online senders keep the
     current live push (add the live push of `delivered` here too if missing —
     the client already handles `{type:"delivered"}`).
   - Inbound `{type:"read"}` with an offline target → INSERT
     `{to: <target>, kind: read, msg_id}` instead of dropping it.
   - Online targets: unchanged live routing, no rows.
3. Flush on connect (existing `flush_queue` shape, second query): after the
   message queue, SELECT pending receipts for the user ORDER BY created_at,
   push each as `{type:<kind>, msg_id, receipt_id}` (receipt row uuid),
   DELETE each **only after the sender's ack** `{type:"ack", receipt_id}`.
   The `receipt_id` disambiguates receipt-acks from message-acks (`msg_id`),
   so the two tables never cross-delete. Live (online) receipts MAY omit
   `receipt_id` — the client acks those with plain `msg_id`, matched against
   pending rows best-effort and otherwise ignored.
4. Retention hygiene: receipts older than 30 days are hard-deleted by a
   periodic sweep (a receipt nobody collected in 30 days is dead weight, and
   the sender's copy is long past its own policy window anyway).

## Client contract (implemented app-side, activates on arrival)
- Acks every receipt frame (dedup by id, re-ack-without-reprocess — same as
  messages). On reconnect the client opens its threads, which reconciles
  `delivered`/`readAt` columns from the flushed receipts.
- No new endpoints. No schema change on the client (columns already exist).

## What this does NOT do
- No read-state sync for senders offline > 30 days (swept).
- No per-message "seen" sync beyond these two receipt kinds (no high-water
  marks — still deferred).
