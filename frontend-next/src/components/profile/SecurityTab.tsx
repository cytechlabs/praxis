import { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';
import { Copy, KeyRound, ShieldCheck, ShieldOff, AlertTriangle } from 'lucide-react';
import { Button, Card, CardBody, CardHeader, Input, Modal } from '@/components/ui';
import {
  TotpStatus,
  beginEnrollment,
  disableTotp,
  getTotpStatus,
  regenerateRecoveryCodes,
  verifyEnrollment,
} from '../../services/totpService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

const SecurityTab = () => {
  const formatTimestamp = useFormatTimestamp();
  const [status, setStatus] = useState<TotpStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);

  // enrollment
  const [enrolling, setEnrolling] = useState<{ secret: string; uri: string } | null>(null);
  const [code, setCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);

  // disable / rotate
  const [showDisable, setShowDisable] = useState(false);
  const [showRotate, setShowRotate] = useState(false);
  const [confirmCode, setConfirmCode] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setStatus(await getTotpStatus());
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load TOTP status');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const copyToClipboard = async (value: string, label: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toast.success(`${label} copied`);
    } catch {
      toast.error('Clipboard unavailable - copy manually');
    }
  };

  const handleBegin = async () => {
    setBusy(true);
    try {
      setEnrolling(await beginEnrollment());
      setCode('');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to begin enrollment');
    } finally {
      setBusy(false);
    }
  };

  const handleConfirmEnroll = async () => {
    if (!code.trim()) return;
    setBusy(true);
    try {
      const r = await verifyEnrollment(code.trim());
      setRecoveryCodes(r.recovery_codes);
      setEnrolling(null);
      setCode('');
      await load();
      toast.success('TOTP enrolled');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setBusy(false);
    }
  };

  const handleDisable = async () => {
    if (!confirmCode.trim()) return;
    setBusy(true);
    try {
      await disableTotp(confirmCode.trim());
      setShowDisable(false);
      setConfirmCode('');
      await load();
      toast.success('TOTP disabled');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Disable failed');
    } finally {
      setBusy(false);
    }
  };

  const handleRotate = async () => {
    if (!confirmCode.trim()) return;
    setBusy(true);
    try {
      const r = await regenerateRecoveryCodes(confirmCode.trim());
      setRecoveryCodes(r.recovery_codes);
      setShowRotate(false);
      setConfirmCode('');
      await load();
      toast.success('Recovery codes rotated');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Rotation failed');
    } finally {
      setBusy(false);
    }
  };

  if (loading) return <div className="text-content-subtle text-sm">Loading…</div>;

  const enrolled = !!status?.enrolled;

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            {enrolled ? <ShieldCheck className="text-green-400" size={18} /> : <ShieldOff className="text-gray-500" size={18} />}
            <div>
              <div>Two-Factor Authentication (TOTP)</div>
              <div className="text-xs font-normal text-content-subtle mt-0.5">
                Required for sensitive fleet roles (session open / command exec with <code className="font-mono">totp_required</code>).
              </div>
            </div>
          </div>
        </CardHeader>
        <CardBody>
          {!enrolled && !enrolling && (
            <div className="flex items-center justify-between gap-4">
              <p className="text-sm text-content">
                Add an authenticator app (Authy, 1Password, Aegis, Bitwarden, etc.) to protect
                privileged actions with a 6-digit second factor.
              </p>
              <Button variant="primary" size="sm" onClick={handleBegin} disabled={busy} loading={busy}>
                <KeyRound size={14} className="mr-1.5" />
                Begin enrollment
              </Button>
            </div>
          )}

          {enrolling && (
            <div className="space-y-4">
              <p className="text-sm text-content">
                Add the following to your authenticator app, then enter the 6-digit code below.
              </p>
              <div className="space-y-2">
                <div>
                  <label className="block text-xs uppercase tracking-wide text-content-subtle mb-1">Secret</label>
                  <div className="flex gap-2">
                    <div className="flex-1 font-mono text-sm text-content bg-black/40 border border-border rounded px-3 py-2 break-all">
                      {enrolling.secret}
                    </div>
                    <Button variant="ghost" size="sm" onClick={() => copyToClipboard(enrolling.secret, 'Secret')}>
                      <Copy size={14} />
                    </Button>
                  </div>
                </div>
                <div>
                  <label className="block text-xs uppercase tracking-wide text-content-subtle mb-1">otpauth URI (tap on mobile)</label>
                  <div className="flex gap-2">
                    <a
                      href={enrolling.uri}
                      className="flex-1 font-mono text-xs text-content bg-black/40 border border-border rounded px-3 py-2 break-all hover:text-content transition-colors"
                    >
                      {enrolling.uri}
                    </a>
                    <Button variant="ghost" size="sm" onClick={() => copyToClipboard(enrolling.uri, 'URI')}>
                      <Copy size={14} />
                    </Button>
                  </div>
                </div>
              </div>
              <div>
                <label className="block text-xs uppercase tracking-wide text-content-subtle mb-1">Enter 6-digit code</label>
                <div className="flex gap-2">
                  <Input
                    value={code}
                    onChange={e => setCode(e.target.value)}
                    placeholder="123456"
                    maxLength={8}
                    className="w-40 font-mono"
                  />
                  <Button variant="primary" size="sm" onClick={handleConfirmEnroll} disabled={busy || !code.trim()} loading={busy}>
                    Confirm
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => { setEnrolling(null); setCode(''); }} disabled={busy}>
                    Cancel
                  </Button>
                </div>
              </div>
            </div>
          )}

          {enrolled && (
            <div className="flex items-center justify-between">
              <div className="text-sm">
                <div className="text-content">
                  Enrolled {status?.enrolled_at ? formatTimestamp(status.enrolled_at, { dateOnly: true }) : ''}.
                </div>
                <div className="text-xs text-content-subtle mt-0.5">
                  {status?.recovery_codes_remaining ?? 0} recovery code{status?.recovery_codes_remaining === 1 ? '' : 's'} remaining.
                </div>
              </div>
              <div className="flex gap-2">
                <Button variant="ghost" size="sm" onClick={() => setShowRotate(true)} disabled={busy}>
                  Rotate recovery codes
                </Button>
                <Button variant="outline" size="sm" onClick={() => setShowDisable(true)} disabled={busy}>
                  Disable
                </Button>
              </div>
            </div>
          )}
        </CardBody>
      </Card>

      {/* Recovery codes modal (post-enrollment or post-rotate) */}
      <Modal
        open={recoveryCodes !== null}
        onClose={() => setRecoveryCodes(null)}
        title="Save your recovery codes"
        maxWidth="max-w-md"
      >
        <div className="space-y-4">
          <div className="flex gap-2 p-3 rounded-md bg-amber-500/10 border border-amber-500/30 text-xs text-amber-200">
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            <div>
              Save these <strong>now</strong>. They&apos;re shown once. Each code works once if you lose
              your authenticator app.
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2 font-mono text-sm">
            {recoveryCodes?.map((c, i) => (
              <div key={i} className="bg-black/40 border border-border rounded px-3 py-1.5 text-content">{c}</div>
            ))}
          </div>
          <div className="flex justify-end gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => copyToClipboard((recoveryCodes || []).join('\n'), 'Recovery codes')}
            >
              <Copy size={14} className="mr-1.5" /> Copy all
            </Button>
            <Button variant="primary" size="sm" onClick={() => setRecoveryCodes(null)}>
              I&apos;ve saved them
            </Button>
          </div>
        </div>
      </Modal>

      {/* Disable modal */}
      <Modal open={showDisable} onClose={() => { setShowDisable(false); setConfirmCode(''); }} title="Disable TOTP" maxWidth="max-w-md">
        <div className="space-y-4">
          <p className="text-sm text-content">
            Enter your current TOTP code to disable two-factor authentication.
          </p>
          <Input value={confirmCode} onChange={e => setConfirmCode(e.target.value)} placeholder="123456" className="font-mono" />
          <div className="flex justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={() => { setShowDisable(false); setConfirmCode(''); }} disabled={busy}>Cancel</Button>
            <Button variant="danger" size="sm" onClick={handleDisable} disabled={busy || !confirmCode.trim()} loading={busy}>Disable</Button>
          </div>
        </div>
      </Modal>

      {/* Rotate recovery codes modal */}
      <Modal open={showRotate} onClose={() => { setShowRotate(false); setConfirmCode(''); }} title="Rotate recovery codes" maxWidth="max-w-md">
        <div className="space-y-4">
          <p className="text-sm text-content">
            Enter your current TOTP code. Existing recovery codes will be invalidated and a new set issued.
          </p>
          <Input value={confirmCode} onChange={e => setConfirmCode(e.target.value)} placeholder="123456" className="font-mono" />
          <div className="flex justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={() => { setShowRotate(false); setConfirmCode(''); }} disabled={busy}>Cancel</Button>
            <Button variant="primary" size="sm" onClick={handleRotate} disabled={busy || !confirmCode.trim()} loading={busy}>Rotate</Button>
          </div>
        </div>
      </Modal>
    </div>
  );
};

export default SecurityTab;
