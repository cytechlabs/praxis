/**
 * PRA-251: single gate for outbound terminal input bytes.
 *
 * The browser terminal has three input paths that can push bytes to the session
 * WebSocket: xterm `onData` (keystrokes), the Ctrl+Shift+V clipboard-paste
 * shortcut, and the native/DOM `paste` event. Observer-mode sessions are
 * read-only, but previously only `onData` checked the mode — both paste paths
 * sent directly. Routing all three through `sendTerminalInput` makes the
 * read-only contract hold everywhere and keeps a client-side defense in depth if
 * server-side enforcement ever regresses.
 *
 * Only terminal INPUT bytes go through this gate. Resize messages are session
 * metadata (not input) and are intentionally still allowed in observer mode by
 * their own send path — do not route them here.
 */

// WebSocket.OPEN. Declared as a plain constant so this module stays free of DOM
// globals and can be unit-tested with a minimal fake socket in plain Node.
export const WS_OPEN = 1;

/** The minimal socket surface `sendTerminalInput` needs. */
export interface TerminalSocket {
  readyState: number;
  send: (data: Uint8Array) => void;
}

/**
 * Send terminal input bytes through the one mode-enforcing gate.
 *
 * Sends the UTF-8 encoded `data` over `ws` only when ALL hold:
 *  - the session is not in observer mode (`joinMode !== 'observe'`);
 *  - `data` is non-empty;
 *  - `ws` exists and is `OPEN`.
 *
 * Returns `true` when bytes were sent, `false` when the input was gated/dropped
 * (so callers like the native paste handler can decide whether to
 * `preventDefault`). It never throws for a missing/closed socket.
 */
export function sendTerminalInput(
  joinMode: string | null | undefined,
  data: string,
  ws: TerminalSocket | null | undefined,
): boolean {
  // Observers are read-only — no terminal bytes ever leave the client.
  if (joinMode === 'observe') return false;
  if (!data) return false;
  if (!ws || ws.readyState !== WS_OPEN) return false;
  ws.send(new TextEncoder().encode(data));
  return true;
}
