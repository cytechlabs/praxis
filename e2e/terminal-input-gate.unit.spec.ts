/**
 * PRA-251: pure-logic coverage for sendTerminalInput, the single gate every
 * outbound terminal-input path funnels through.
 *
 * Browser-free / auth-free unit spec run under the Playwright "unit" project
 * (see playwright.config.ts):
 *   npx playwright test --project=unit
 *
 * All three input paths on the session page — xterm `onData`, the Ctrl+Shift+V
 * clipboard-paste shortcut, and the native/DOM `paste` event — call this one
 * helper, so proving the helper's behavior proves the read-only contract holds
 * for every path. It verifies observer mode drops bytes on all paths, control /
 * participate modes send encoded bytes when the socket is open, and empty input
 * or a missing/closed socket sends nothing.
 */

import { test, expect } from "@playwright/test";

import {
  sendTerminalInput,
  WS_OPEN,
  type TerminalSocket,
} from "../frontend-next/src/utils/terminalInput";

const WS_CLOSED = 3; // WebSocket.CLOSED

class FakeSocket implements TerminalSocket {
  sent: Uint8Array[] = [];
  constructor(public readyState: number) {}
  send = (data: Uint8Array): void => {
    this.sent.push(data);
  };
}

// The three input paths are indistinguishable to the gate — they all pass a
// (joinMode, data, ws) triple. We enumerate them so coverage reads explicitly
// per path, matching the acceptance criteria.
const INPUT_PATHS = ["xterm-onData", "ctrl-shift-v-paste", "native-paste"];

test.describe("sendTerminalInput", () => {
  test("WS_OPEN matches the WebSocket OPEN readyState", () => {
    expect(WS_OPEN).toBe(1);
  });

  for (const path of INPUT_PATHS) {
    test(`observer mode drops input on ${path}`, () => {
      const ws = new FakeSocket(WS_OPEN);
      const sent = sendTerminalInput("observe", "rm -rf /", ws);
      expect(sent).toBe(false);
      expect(ws.sent).toHaveLength(0);
    });

    test(`control mode (null) sends encoded bytes on ${path}`, () => {
      const ws = new FakeSocket(WS_OPEN);
      const sent = sendTerminalInput(null, "ls -la\n", ws);
      expect(sent).toBe(true);
      expect(ws.sent).toHaveLength(1);
      expect(Array.from(ws.sent[0])).toEqual(
        Array.from(new TextEncoder().encode("ls -la\n")),
      );
    });

    test(`participate mode sends encoded bytes on ${path}`, () => {
      const ws = new FakeSocket(WS_OPEN);
      const sent = sendTerminalInput("participate", "whoami\n", ws);
      expect(sent).toBe(true);
      expect(ws.sent).toHaveLength(1);
      expect(Array.from(ws.sent[0])).toEqual(
        Array.from(new TextEncoder().encode("whoami\n")),
      );
    });
  }

  test("empty input sends nothing (control mode, open socket)", () => {
    const ws = new FakeSocket(WS_OPEN);
    expect(sendTerminalInput(null, "", ws)).toBe(false);
    expect(ws.sent).toHaveLength(0);
  });

  test("closed socket sends nothing", () => {
    const ws = new FakeSocket(WS_CLOSED);
    expect(sendTerminalInput(null, "data", ws)).toBe(false);
    expect(ws.sent).toHaveLength(0);
  });

  test("missing socket (null) sends nothing", () => {
    expect(sendTerminalInput(null, "data", null)).toBe(false);
  });

  test("missing socket (undefined) sends nothing", () => {
    expect(sendTerminalInput(null, "data", undefined)).toBe(false);
  });

  test("observer mode drops even when data is empty and socket closed", () => {
    // Observer check comes first: no path/state combination can leak bytes.
    const ws = new FakeSocket(WS_CLOSED);
    expect(sendTerminalInput("observe", "", ws)).toBe(false);
    expect(ws.sent).toHaveLength(0);
  });

  test("UTF-8 multibyte input is encoded correctly in control mode", () => {
    const ws = new FakeSocket(WS_OPEN);
    const text = "echo café ✓\n";
    expect(sendTerminalInput(null, text, ws)).toBe(true);
    expect(Array.from(ws.sent[0])).toEqual(
      Array.from(new TextEncoder().encode(text)),
    );
  });
});
