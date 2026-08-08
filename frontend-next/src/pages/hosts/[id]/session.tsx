import { useCallback, useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/router';
import Head from 'next/head';
import { toast } from 'sonner';
import {
  AlertTriangle,
  Download,
  KeyRound,
  Minus,
  Plus,
  Power,
  RotateCcw,
  Search,
  X,
} from 'lucide-react';
import MainLayout from '../../../components/MainLayout';
import { sendTerminalInput } from '../../../utils/terminalInput';
import { Badge, Button, Card, CardBody, Input, Modal } from '@/components/ui';
import {
  AttachedSubscriber,
  InteractiveSession,
  closeSession,
  getJoinTicket,
  getSession,
  getWsTicket,
  openSession,
} from '../../../services/sessionService';
import { getApproval } from '../../../services/sessionApprovalService';
import { stepUp } from '../../../services/totpService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { humanizeStatus } from '@/utils/humanize';

// xterm.js CSS is pulled in via the module's own import path. All DOM work
// happens in a useEffect so SSR stays untouched.
import '@xterm/xterm/css/xterm.css';

const DEFAULT_FONT = 13;
const MIN_FONT = 9;
const MAX_FONT = 22;

const wsUrlFor = (sessionId: number, token: string): string => {
  if (typeof window === 'undefined') return '';
  // Go through the Next.js /api/backend/:path* rewrite so we stay same-origin.
  const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
  return `${scheme}://${window.location.host}/api/backend/sessions/${sessionId}/ws?token=${encodeURIComponent(token)}`;
};

const fmtRemaining = (ms: number): string => {
  if (ms <= 0) return '0:00';
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}:${m.toString().padStart(2, '0')}:${sec.toString().padStart(2, '0')}`;
  return `${m}:${sec.toString().padStart(2, '0')}`;
};

type JoinMode = 'observe' | 'participate' | null;

const SessionPage = () => {
  const formatTimestamp = useFormatTimestamp();
  const router = useRouter();
  const systemId = Number(router.query.id);
  const joinMode: JoinMode = router.query.join === 'observe' || router.query.join === 'participate'
    ? router.query.join
    : null;
  const joinSessionId = router.query.sid ? Number(router.query.sid) : null;

  const containerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<import('@xterm/xterm').Terminal | null>(null);
  const fitRef = useRef<import('@xterm/addon-fit').FitAddon | null>(null);
  const searchRef = useRef<import('@xterm/addon-search').SearchAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const [session, setSession] = useState<InteractiveSession | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [disconnected, setDisconnected] = useState(false);
  const [reconnecting, setReconnecting] = useState(false);

  const [fontSize, setFontSize] = useState(DEFAULT_FONT);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [remainingMs, setRemainingMs] = useState<number | null>(null);

  // TOTP step-up prompt state
  const [needsTotp, setNeedsTotp] = useState(false);
  const [totpCode, setTotpCode] = useState('');
  const [totpBusy, setTotpBusy] = useState(false);

  // PRA-147: pending session approval state
  const [pendingApprovalId, setPendingApprovalId] = useState<number | null>(null);
  const [approvalState, setApprovalState] = useState<string | null>(null);

  // PRA-148: subscribers attached to my session (owner banner) - poll-refreshed
  const [attached, setAttached] = useState<AttachedSubscriber[]>([]);

  const tearDown = useCallback(() => {
    try { wsRef.current?.close(); } catch { /* ignore */ }
    wsRef.current = null;
    try { termRef.current?.dispose(); } catch { /* ignore */ }
    termRef.current = null;
    fitRef.current = null;
    searchRef.current = null;
  }, []);

  const handleOpen = useCallback(async () => {
    if (!systemId) return;
    setError(null);
    setConnecting(true);
    try {
      const result = await openSession(systemId);
      if (result.status === 'pending') {
        setPendingApprovalId(result.approval_id);
        setApprovalState('pending');
      } else {
        setSession(result.session);
        setPendingApprovalId(null);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to open session';
      if (msg.includes('totp_required')) {
        setNeedsTotp(true);
      } else {
        setError(msg);
      }
    } finally {
      setConnecting(false);
    }
  }, [systemId]);

  // PRA-147: poll the pending approval every 3s until granted or denied/expired
  useEffect(() => {
    if (!pendingApprovalId) return undefined;
    let cancelled = false;
    const tick = async () => {
      try {
        const a = await getApproval(pendingApprovalId);
        if (cancelled) return;
        setApprovalState(a.state);
        if (a.state === 'granted') {
          // Re-attempt open - backend will atomically consume the grant.
          await handleOpen();
        } else if (a.state === 'denied' || a.state === 'expired') {
          setError(`Session approval ${a.state}${a.decision_reason ? `: ${a.decision_reason}` : ''}`);
          setPendingApprovalId(null);
        }
      } catch {
        // Transient network errors are fine - keep polling.
      }
    };
    const id = setInterval(tick, 3000);
    return () => { cancelled = true; clearInterval(id); };
  }, [pendingApprovalId, handleOpen]);

  const handleTotpSubmit = async () => {
    if (!totpCode.trim()) return;
    setTotpBusy(true);
    try {
      await stepUp(totpCode.trim());
      setNeedsTotp(false);
      setTotpCode('');
      toast.success('Step-up accepted');
      await handleOpen();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Step-up failed');
    } finally {
      setTotpBusy(false);
    }
  };

  // Kick off the open once the router is ready.
  useEffect(() => {
    if (router.isReady && systemId && !session && !connecting && !error && !needsTotp && !pendingApprovalId) {
      if (joinMode && joinSessionId) {
        // PRA-148 path: don't open a new session, attach to the existing one.
        setConnecting(true);
        getSession(joinSessionId)
          .then((s) => setSession(s))
          .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load session'))
          .finally(() => setConnecting(false));
      } else {
        handleOpen();
      }
    }
  }, [router.isReady, systemId, session, connecting, error, needsTotp, pendingApprovalId, joinMode, joinSessionId, handleOpen]);

  // PRA-148: poll my session every 5s for the attached-subscriber list.
  // Only the owner cares - moderators never need to see other moderators.
  useEffect(() => {
    if (!session || joinMode) return undefined;
    let cancelled = false;
    const tick = async () => {
      try {
        const fresh = await getSession(session.id);
        if (cancelled) return;
        setAttached((fresh.attached || []).filter((a) => a.mode !== 'owner'));
      } catch {
        /* ignore transient */
      }
    };
    tick();
    const id = setInterval(tick, 5000);
    return () => { cancelled = true; clearInterval(id); };
  }, [session, joinMode]);

  // ------------------------------------------------------------- WS helpers

  /** Open a fresh WebSocket for the active session. Called on initial mount
   *  and by the Reconnect button. The server-side runtime survives WS drops
   *  until the idle/max-duration sweep closes it; a new WS attaches cleanly. */
  const connectWebSocket = useCallback(async (): Promise<void> => {
    const term = termRef.current;
    if (!session || !term) return;

    let ticket: { token: string };
    try {
      ticket = joinMode
        ? await getJoinTicket(session.id, joinMode)
        : await getWsTicket(session.id);
    } catch (err) {
      term.write(`\r\n\x1b[31mFailed to mint WebSocket ticket: ${err instanceof Error ? err.message : err}\x1b[0m\r\n`);
      return;
    }

    const ws = new WebSocket(wsUrlFor(session.id, ticket.token));
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;

    ws.onopen = () => {
      setDisconnected(false);
      setReconnecting(false);
      ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
      term.focus();
    };
    ws.onmessage = (ev) => {
      if (ev.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(ev.data));
      } else if (typeof ev.data === 'string') {
        term.write(ev.data);
      }
    };
    ws.onerror = () => {
      term.write('\r\n\x1b[33m-- WebSocket error --\x1b[0m\r\n');
    };
    ws.onclose = () => {
      setDisconnected(true);
      setReconnecting(false);
      term.write('\r\n\x1b[33m-- Session disconnected (Reconnect to resume) --\x1b[0m\r\n');
    };
  }, [session, joinMode]);

  const handleReconnect = useCallback(async () => {
    if (!session || reconnecting) return;
    setReconnecting(true);
    try { wsRef.current?.close(); } catch { /* ignore */ }
    wsRef.current = null;
    await connectWebSocket();
  }, [session, reconnecting, connectWebSocket]);

  // ---------------------------------------------------------------- attach

  useEffect(() => {
    if (!session || !containerRef.current) return;

    let cancelled = false;

    (async () => {
      const xtermMod = await import('@xterm/xterm');
      const fitMod = await import('@xterm/addon-fit');
      const searchMod = await import('@xterm/addon-search');
      if (cancelled) return;

      const term = new xtermMod.Terminal({
        cursorBlink: true,
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
        fontSize: DEFAULT_FONT,
        theme: {
          background: '#0a0a0d',
          foreground: '#e5e7eb',
          cursor: '#ef4444',
          selectionBackground: '#3b3b3f',
        },
        scrollback: 10000,
      });
      const fit = new fitMod.FitAddon();
      term.loadAddon(fit);
      const searchAddon = new searchMod.SearchAddon();
      term.loadAddon(searchAddon);

      if (!containerRef.current) return;
      term.open(containerRef.current);
      fit.fit();
      termRef.current = term;
      fitRef.current = fit;
      searchRef.current = searchAddon;

      // --- input -> server ---
      // PRA-148 / PRA-251: every terminal-input path (keystrokes here, plus the
      // two paste paths below) goes through sendTerminalInput, the single gate
      // that drops input in observer mode and when the socket is missing/closed.
      // The server also enforces read-only; this keeps the local UI honest.
      term.onData((data: string) => {
        sendTerminalInput(joinMode, data, wsRef.current);
      });
      term.onResize(({ cols, rows }: { cols: number; rows: number }) => {
        const ws = wsRef.current;
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'resize', cols, rows }));
        }
      });

      // --- copy on select: mirror gnome-terminal behaviour ---
      term.onSelectionChange(() => {
        const sel = term.getSelection();
        if (!sel) return;
        try { void navigator.clipboard.writeText(sel); } catch { /* no-op */ }
      });

      // --- keyboard shortcuts (font size, search, copy/paste) ---
      const onKey = async (ev: KeyboardEvent) => {
        // Font size: Ctrl+= / Ctrl+- / Ctrl+0 (works with or without Shift).
        if (ev.ctrlKey && !ev.altKey) {
          if (ev.key === '=' || ev.key === '+') {
            setFontSize((n) => Math.min(MAX_FONT, n + 1));
            ev.preventDefault();
            return;
          }
          if (ev.key === '-' || ev.key === '_') {
            setFontSize((n) => Math.max(MIN_FONT, n - 1));
            ev.preventDefault();
            return;
          }
          if (ev.key === '0') {
            setFontSize(DEFAULT_FONT);
            ev.preventDefault();
            return;
          }
        }
        // Ctrl+Shift+F - open search bar
        if (ev.ctrlKey && ev.shiftKey && ev.key.toLowerCase() === 'f') {
          setSearchOpen(true);
          ev.preventDefault();
          return;
        }
        // Ctrl+Shift+C - explicit copy (belt-and-suspenders alongside copy-on-select)
        if (ev.ctrlKey && ev.shiftKey && ev.key.toLowerCase() === 'c') {
          const sel = term.getSelection();
          if (sel) {
            try { await navigator.clipboard.writeText(sel); } catch { /* no-op */ }
            ev.preventDefault();
          }
          return;
        }
        // Ctrl+Shift+V - paste (gated by sendTerminalInput: no bytes in observer
        // mode). We always preventDefault since this shortcut is fully handled here.
        if (ev.ctrlKey && ev.shiftKey && ev.key.toLowerCase() === 'v') {
          try {
            const text = await navigator.clipboard.readText();
            sendTerminalInput(joinMode, text, wsRef.current);
          } catch { /* denied */ }
          ev.preventDefault();
        }
      };
      const onPaste = (ev: ClipboardEvent) => {
        const text = ev.clipboardData?.getData('text') ?? '';
        // Only consume the event when the gate actually sent bytes; in observer
        // mode nothing is sent and nothing is pasted into the terminal.
        if (sendTerminalInput(joinMode, text, wsRef.current)) {
          ev.preventDefault();
        }
      };

      const node = containerRef.current;
      node?.addEventListener('keydown', onKey);
      node?.addEventListener('paste', onPaste);

      const onResize = () => fit.fit();
      window.addEventListener('resize', onResize);

      // Stash cleanup on the term so the unmount can run it.
      (term as import('@xterm/xterm').Terminal & { _cleanup?: () => void })._cleanup = () => {
        window.removeEventListener('resize', onResize);
        node?.removeEventListener('keydown', onKey);
        node?.removeEventListener('paste', onPaste);
      };

      // Open the initial WebSocket now that the term is live.
      await connectWebSocket();
    })();

    return () => {
      cancelled = true;
      const t = termRef.current as (import('@xterm/xterm').Terminal & { _cleanup?: () => void }) | null;
      t?._cleanup?.();
      tearDown();
    };
  }, [session, connectWebSocket, tearDown, joinMode]);

  // ----------------------------------------------------- font size re-apply

  useEffect(() => {
    const term = termRef.current;
    const fit = fitRef.current;
    if (!term) return;
    term.options.fontSize = fontSize;
    try { fit?.fit(); } catch { /* ignore */ }
  }, [fontSize]);

  // ---------------------------------------------------- expiry countdown

  useEffect(() => {
    if (!session) return;
    const target = new Date(session.max_expires_at).getTime();
    const tick = () => setRemainingMs(target - Date.now());
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [session]);

  // --------------------------------------------------- search integration

  useEffect(() => {
    if (!searchRef.current) return;
    if (searchTerm) searchRef.current.findNext(searchTerm, { incremental: true });
  }, [searchTerm]);

  const handleSearchKey = (ev: React.KeyboardEvent<HTMLInputElement>) => {
    if (!searchRef.current) return;
    if (ev.key === 'Enter') {
      if (ev.shiftKey) searchRef.current.findPrevious(searchTerm);
      else searchRef.current.findNext(searchTerm);
      ev.preventDefault();
    } else if (ev.key === 'Escape') {
      setSearchOpen(false);
      setSearchTerm('');
      termRef.current?.focus();
    }
  };

  // -------------------------------------------------------- actions

  const handleDisconnect = async () => {
    if (!session) return;
    // PRA-148: moderators must NOT close the owner's session - just detach the WS.
    if (!joinMode) {
      try {
        await closeSession(session.id);
      } catch {
        /* ignore */
      }
    }
    tearDown();
    router.push(joinMode ? '/access/active-sessions' : `/system-management/system/${systemId}`);
  };

  const handleDownloadScrollback = () => {
    const term = termRef.current;
    if (!term) return;
    const buf = term.buffer.active;
    const lines: string[] = [];
    for (let i = 0; i < buf.length; i++) {
      const line = buf.getLine(i);
      if (line) lines.push(line.translateToString(true));
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `session-${session?.id ?? 'scrollback'}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // ------------------------------------------------------------- render

  const ttlBadge = (() => {
    if (remainingMs === null) return null;
    const minutes = remainingMs / 60000;
    const variant: 'success' | 'warning' | 'danger' | 'neutral' =
      remainingMs <= 0 ? 'neutral' : minutes < 1 ? 'danger' : minutes < 5 ? 'warning' : 'success';
    return (
      <Badge variant={variant} className="ml-2 tabular-nums">
        {fmtRemaining(remainingMs)} left
      </Badge>
    );
  })();

  return (
    <MainLayout>
      <Head><title>Session | Praxis</title></Head>
      <div className="flex items-center justify-between mb-4 gap-3 flex-wrap">
        <div className="min-w-0">
          <h1 className="text-lg font-semibold text-content">
            Session {session ? `#${session.id}` : ''}
          </h1>
          <div className="text-xs text-content-subtle mt-1 flex flex-wrap items-center gap-x-1">
            {session ? (
              <>
                <span>as <span className="font-mono text-content">{session.login}</span></span>
                <span>·</span>
                <span title="Interactive sessions connect over SSH">over SSH</span>
                <span>·</span>
                <span>expires {formatTimestamp(session.max_expires_at)}</span>
                <span>·</span>
                <Badge variant={disconnected ? 'neutral' : 'success'} className="ml-1">
                  {disconnected ? 'disconnected' : humanizeStatus(session.status)}
                </Badge>
                {ttlBadge}
              </>
            ) : connecting ? 'opening…' : ''}
          </div>
        </div>
        <div className="flex gap-1 items-center">
          {/* Font controls */}
          <div className="flex items-center border border-border rounded-md mr-2 bg-black/30" title="Font size">
            <button
              className="px-2 py-1 text-content-muted hover:text-content disabled:opacity-30"
              onClick={() => setFontSize((n) => Math.max(MIN_FONT, n - 1))}
              disabled={fontSize <= MIN_FONT}
              aria-label="Decrease font size"
            >
              <Minus size={13} />
            </button>
            <button
              className="px-2 py-1 text-xs text-content-subtle hover:text-content tabular-nums"
              onClick={() => setFontSize(DEFAULT_FONT)}
              title="Reset font size"
            >
              {fontSize}
            </button>
            <button
              className="px-2 py-1 text-content-muted hover:text-content disabled:opacity-30"
              onClick={() => setFontSize((n) => Math.min(MAX_FONT, n + 1))}
              disabled={fontSize >= MAX_FONT}
              aria-label="Increase font size"
            >
              <Plus size={13} />
            </button>
          </div>
          <Button variant="ghost" size="sm" onClick={() => setSearchOpen(true)} disabled={!session} title="Search (Ctrl+Shift+F)">
            <Search size={14} className="mr-1" /> Search
          </Button>
          <Button variant="ghost" size="sm" onClick={handleDownloadScrollback} disabled={!session} title="Save scrollback">
            <Download size={14} className="mr-1" /> Save
          </Button>
          {disconnected && (
            <Button variant="primary" size="sm" onClick={handleReconnect} disabled={reconnecting} loading={reconnecting}>
              <RotateCcw size={14} className="mr-1" />
              {reconnecting ? 'Reconnecting…' : 'Reconnect'}
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={handleDisconnect} disabled={!session}>
            <Power size={14} className="mr-1" /> Disconnect
          </Button>
        </div>
      </div>

      {error && (
        <div className="mb-4 p-4 rounded-md bg-red-900/30 border border-red-700 text-red-200 text-sm flex gap-2">
          <AlertTriangle size={16} className="shrink-0 mt-0.5" />
          <div>{error}</div>
        </div>
      )}

      {joinMode && (
        <div className={`mb-4 p-3 rounded-md border text-sm flex gap-2 ${
          joinMode === 'observe'
            ? 'bg-sky-900/20 border-sky-700/60 text-sky-100'
            : 'bg-amber-900/20 border-amber-700/60 text-amber-100'
        }`}>
          <AlertTriangle size={16} className="shrink-0 mt-0.5" />
          <div>
            You are attached as <span className="font-semibold">{joinMode}</span>.
            {joinMode === 'observe' ? ' Your keystrokes are ignored.' : ' Your input is multiplexed into the live shell.'}
          </div>
        </div>
      )}

      {!joinMode && attached.length > 0 && (
        <div className="mb-4 p-3 rounded-md bg-purple-900/20 border border-purple-700/60 text-purple-100 text-sm flex gap-2">
          <AlertTriangle size={16} className="shrink-0 mt-0.5" />
          <div>
            Watching: {attached.map((a, i) => (
              <span key={a.sid}>
                {i > 0 && ', '}
                <span className="font-mono">{a.username}</span>
                <span className="text-purple-300/70"> ({a.mode})</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {pendingApprovalId && !session && !error && (
        <div className="mb-4 p-4 rounded-md bg-yellow-900/20 border border-yellow-700/60 text-yellow-100 text-sm flex gap-3">
          <KeyRound size={16} className="shrink-0 mt-0.5" />
          <div>
            <div className="font-medium">Awaiting operator approval</div>
            <div className="text-xs text-yellow-200/80 mt-1">
              Request <span className="font-mono">#{pendingApprovalId}</span> is {approvalState || 'pending'}. The session will open automatically once an operator approves it.
            </div>
          </div>
        </div>
      )}

      <Card>
        <CardBody className="p-0">
          <div className="relative">
            {searchOpen && (
              <div className="absolute top-2 right-2 z-10 flex items-center gap-1 rounded-md border border-border bg-surface-overlay p-1 shadow-lg">
                <Search size={13} className="ml-1 text-content-subtle" />
                <input
                  autoFocus
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  onKeyDown={handleSearchKey}
                  placeholder="Find in scrollback"
                  className="bg-transparent px-2 py-1 text-sm text-content focus:outline-none w-60 font-mono"
                />
                <button
                  onClick={() => searchRef.current?.findPrevious(searchTerm)}
                  className="px-1.5 py-0.5 text-xs text-content-subtle hover:text-content"
                  title="Previous (Shift+Enter)"
                >
                  ↑
                </button>
                <button
                  onClick={() => searchRef.current?.findNext(searchTerm)}
                  className="px-1.5 py-0.5 text-xs text-content-subtle hover:text-content"
                  title="Next (Enter)"
                >
                  ↓
                </button>
                <button
                  onClick={() => { setSearchOpen(false); setSearchTerm(''); termRef.current?.focus(); }}
                  className="px-1 py-0.5 text-content-subtle hover:text-content"
                  aria-label="Close search"
                >
                  <X size={13} />
                </button>
              </div>
            )}
            <div
              ref={containerRef}
              className="w-full bg-[#0a0a0d] p-2"
              style={{ height: '70vh' }}
            />
          </div>
        </CardBody>
      </Card>

      <div className="mt-2 text-[11px] text-content-subtle">
        Ctrl+Shift+F search · Ctrl+Shift+C/V copy/paste · Ctrl+= / Ctrl+- / Ctrl+0 font · selection auto-copies
      </div>

      <Modal
        open={needsTotp}
        onClose={() => { setNeedsTotp(false); setTotpCode(''); router.push(`/system-management/system/${systemId}`); }}
        title="TOTP step-up required"
        maxWidth="max-w-md"
      >
        <div className="space-y-4">
          <div className="flex gap-2 text-sm text-content">
            <KeyRound size={16} className="mt-0.5 shrink-0 text-yellow-400" />
            <p>This fleet role requires a second factor. Enter your authenticator code to continue.</p>
          </div>
          <Input
            value={totpCode}
            onChange={(e) => setTotpCode(e.target.value)}
            placeholder="123456"
            maxLength={16}
            className="font-mono"
          />
          <div className="flex justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={() => { setNeedsTotp(false); setTotpCode(''); router.push(`/system-management/system/${systemId}`); }} disabled={totpBusy}>
              Cancel
            </Button>
            <Button variant="primary" size="sm" onClick={handleTotpSubmit} disabled={totpBusy || !totpCode.trim()} loading={totpBusy}>
              Verify
            </Button>
          </div>
        </div>
      </Modal>
    </MainLayout>
  );
};

export default SessionPage;
