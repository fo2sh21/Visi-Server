# Typing flicker (ephemeral, live-only)

## Frame
New ephemeral frame, routed never stored:
`{type:"typing", to:<peer>, state:"start"|"stop"}`.

## Server (relay.py, same branch family as read/rekey)
Route to `to` if online, drop otherwise. Validate `state ∈ {"start","stop"}`
and non-empty `to`; anything else is dropped. No table, no ack, no
persistence — a lost frame is a missed flicker, never a stuck state.
Routed frame shape: `{type:"typing", from:<sender>, to:<peer>, state:<state>}`
(`from` is required — current clients read it; see below).

## Client (already implemented app-side; activates on first routed frame)
- Sends: `start` on first keystroke after idle; re-`start` at most every 5s
  during continuous typing (storm suppression); `stop` on send,
  thread-close, or 4s keystroke silence. Only while the thread is open —
  never from background (no presence leakage beyond the open chat).
- Receives: header subtitle flips name → "typing…" (green, presence-dot
  language); 8s failsafe clears it with no refresh, so a lost `stop` can
  never wedge it on.
- `WsManager.sendTyping` + `onTyping` callback; `TypingBus`; no changes to
  message storage, expiry, or session handling.

## Backward compatibility (verified, not assumed)
Clients without the typing branch fall through to envelope parsing inside
the existing try/catch (`WsManager.onMessage`) — one "bad inbound frame"
log line, never a crash. Offline old clients never receive these frames
at all (dropped when the peer is offline, same as rekey).
