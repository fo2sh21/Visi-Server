# Server-side shred backstop: 7-day TTL on `offline_queue`

## Why
Message rows live until acked. Recipients who never return (dead accounts)
accumulate queue storage without bound. Client-side 6h shred only covers
messages the client actually holds; the server needs its own bound.

## Change (relay.py + main.py, no schema change)
- `QUEUE_TTL_SEC = 7 * 24 * 3600`, enforced on the existing `created_at`.
- **Lazy:** `flush_queue` deletes this user's rows older than the TTL before
  delivering — same pattern as the 30-day receipt sweep, no new infra.
- **Periodic:** in-process daily sweep task in `lifespan`
  (`sweep_expired_queues`, idempotent DELETEs — safe under a future second
  instance). The keeper keeps the free instance awake enough for it to run.
- Shutdown joins the sweeper (cancel + await) so teardown never leaks a
  pending sleep.

## Accepted tradeoff (locked)
Recipients gone >7d miss those messages on return — tighter than the 30d
receipt retention, chosen deliberately: message ciphertext is bulkier than
receipts and its policy window is shorter. No protocol change — vanished
rows are simply never delivered, which every client version tolerates
(absent/dropped frames are the norm, not an error).
