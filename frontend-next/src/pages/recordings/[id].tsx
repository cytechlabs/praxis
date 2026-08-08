import { useCallback, useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/router';
import Head from 'next/head';
import { toast } from 'sonner';
import { Pause, Play, RotateCcw, SkipForward } from 'lucide-react';
import MainLayout from '../../components/MainLayout';
import { Badge, Button, Card, CardBody } from '@/components/ui';
import {
  ParsedCast,
  Recording,
  fetchCast,
  getRecording,
} from '../../services/recordingService';
import { humanizeStatus } from '@/utils/humanize';
import '@xterm/xterm/css/xterm.css';

/**
 * Homegrown asciinema v2 player. We already have xterm.js loaded for the
 * live terminal - the replay path reuses it rather than pulling in the
 * asciinema-player bundle.
 *
 * Playback algorithm:
 *   - parse .cast into [elapsed, channel, text] frames
 *   - clock tick every frame: schedule next write via setTimeout at
 *     (frame.elapsed - cursor.elapsed) / speed
 *   - user controls: play/pause, restart, 1x/2x/4x/8x
 */

const SPEEDS = [1, 2, 4, 8] as const;

const RecordingPlayerPage = () => {
  const router = useRouter();
  const id = Number(router.query.id);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<import('@xterm/xterm').Terminal | null>(null);
  const fitRef = useRef<import('@xterm/addon-fit').FitAddon | null>(null);

  const [rec, setRec] = useState<Recording | null>(null);
  const [cast, setCast] = useState<ParsedCast | null>(null);
  const [loading, setLoading] = useState(true);

  const [frameIdx, setFrameIdx] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState<(typeof SPEEDS)[number]>(1);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const cancelTimer = () => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  };

  // Initial load
  useEffect(() => {
    if (!router.isReady || !id) return;
    (async () => {
      try {
        const [meta, parsed] = await Promise.all([getRecording(id), fetchCast(id)]);
        setRec(meta);
        setCast(parsed);
      } catch (err) {
        toast.error(err instanceof Error ? err.message : 'Failed to load recording');
      } finally {
        setLoading(false);
      }
    })();
  }, [router.isReady, id]);

  // xterm attach once cast is ready
  useEffect(() => {
    if (!cast || !containerRef.current) return;
    let cancelled = false;
    (async () => {
      const xtermMod = await import('@xterm/xterm');
      const fitMod = await import('@xterm/addon-fit');
      if (cancelled) return;
      const term = new xtermMod.Terminal({
        cursorBlink: false,
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
        fontSize: 13,
        theme: { background: '#0a0a0d', foreground: '#e5e7eb', cursor: '#ef4444' },
        scrollback: 10000,
      });
      const fit = new fitMod.FitAddon();
      term.loadAddon(fit);
      if (!containerRef.current) return;
      term.open(containerRef.current);
      fit.fit();
      term.resize(cast.header.width || 120, cast.header.height || 32);
      termRef.current = term;
      fitRef.current = fit;
    })();
    return () => {
      cancelled = true;
      cancelTimer();
      try { termRef.current?.dispose(); } catch { /* ignore */ }
      termRef.current = null;
      fitRef.current = null;
    };
  }, [cast]);

  // Playback driver
  useEffect(() => {
    if (!playing || !cast || !termRef.current) return;
    if (frameIdx >= cast.frames.length) {
      setPlaying(false);
      return;
    }
    const frame = cast.frames[frameIdx];
    const prevElapsed = frameIdx === 0 ? 0 : cast.frames[frameIdx - 1][0];
    const delta = Math.max(0, (frame[0] - prevElapsed) / speed);
    timerRef.current = setTimeout(() => {
      if (!termRef.current) return;
      if (frame[1] === 'o') termRef.current.write(frame[2]);
      setFrameIdx(i => i + 1);
    }, Math.min(delta * 1000, 2000)); // cap idle gap at 2s for replay sanity
    return cancelTimer;
  }, [playing, frameIdx, cast, speed]);

  const handleRestart = () => {
    cancelTimer();
    setPlaying(false);
    setFrameIdx(0);
    termRef.current?.reset();
  };

  const handleJumpToEnd = useCallback(() => {
    if (!cast || !termRef.current) return;
    cancelTimer();
    setPlaying(false);
    termRef.current.reset();
    for (const frame of cast.frames) {
      if (frame[1] === 'o') termRef.current.write(frame[2]);
    }
    setFrameIdx(cast.frames.length);
  }, [cast]);

  const progress = cast && cast.frames.length
    ? Math.min(100, (frameIdx / cast.frames.length) * 100)
    : 0;

  const currentElapsed = cast && frameIdx > 0
    ? cast.frames[Math.min(frameIdx - 1, cast.frames.length - 1) as number][0]
    : 0;

  return (
    <MainLayout>
      <Head><title>Replay | Praxis</title></Head>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-lg font-semibold text-content">
            Recording {rec ? `#${rec.id}` : ''}
          </h1>
          <div className="text-xs text-content-subtle mt-1">
            {rec && (
              <>
                session #{rec.session_id} ·{' '}
                {rec.hostname && <span className="font-mono text-content-muted">{rec.hostname}</span>}{' '}
                {rec.login && <span className="font-mono text-content-muted">as {rec.login}</span>} ·
                <Badge variant="info" className="ml-2">{humanizeStatus(rec.status)}</Badge>
              </>
            )}
          </div>
        </div>
        <Button variant="ghost" size="sm" onClick={() => router.push('/recordings')}>
          ← All recordings
        </Button>
      </div>

      {/* Controls */}
      <div className="mb-3 flex items-center gap-3">
        <Button size="sm" variant="primary" onClick={() => setPlaying(p => !p)} disabled={loading || !cast}>
          {playing ? <><Pause size={14} className="mr-1" /> Pause</> : <><Play size={14} className="mr-1" /> Play</>}
        </Button>
        <Button size="sm" variant="ghost" onClick={handleRestart} disabled={loading || !cast}>
          <RotateCcw size={14} className="mr-1" /> Restart
        </Button>
        <Button size="sm" variant="ghost" onClick={handleJumpToEnd} disabled={loading || !cast}>
          <SkipForward size={14} className="mr-1" /> To end
        </Button>
        <div className="flex items-center gap-1 ml-4">
          <span className="text-xs uppercase tracking-wide text-content-subtle mr-1">Speed</span>
          {SPEEDS.map(s => (
            <button
              key={s}
              onClick={() => setSpeed(s)}
              className={`px-2 py-1 rounded text-xs font-mono ${
                s === speed ? 'bg-red-700/30 text-red-200 border border-red-700/60' : 'text-content-muted hover:text-content'
              }`}
            >
              {s}x
            </button>
          ))}
        </div>
        <div className="ml-auto text-xs text-content-subtle tabular-nums">
          {currentElapsed.toFixed(1)}s / {cast ? cast.duration.toFixed(1) : '-'}s
        </div>
      </div>

      <div className="mb-3 h-1 rounded-full bg-surface-overlay overflow-hidden">
        <div className="h-full bg-red-600 transition-[width] duration-150 ease-linear" style={{ width: `${progress}%` }} />
      </div>

      <Card>
        <CardBody className="p-0">
          <div ref={containerRef} className="w-full bg-[#0a0a0d] p-2" style={{ height: '70vh' }} />
        </CardBody>
      </Card>

      {loading && <div className="text-sm text-content-subtle mt-3">Loading recording…</div>}
    </MainLayout>
  );
};

export default RecordingPlayerPage;
