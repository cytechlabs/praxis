import React, { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { Copy, Check, ShieldCheck, AlertTriangle, ShoppingCart, RefreshCw } from 'lucide-react';
import { Button, Card, CardBody, CardHeader } from '@/components/ui';
import { useAuth } from '@/context/AuthContext';
import { useEntitlements } from '@/context/EntitlementsContext';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import {
  applyLicense,
  removeLicense,
  refreshLicense,
  getBuyUrl,
  ENTITLEMENTS,
} from '@/services/editionService';

const REFRESH_RESULT_LABELS: Record<string, string> = {
  ok: 'License renewed',
  not_configured: 'Not configured',
  unavailable: 'Service unavailable',
  rejected: 'Declined',
  error: 'Error',
};

const ENTITLEMENT_LABELS: Record<string, string> = {
  [ENTITLEMENTS.HOSTS_OVER_FREE_CAP]: 'Hosts above free cap',
  [ENTITLEMENTS.SESSION_LOCKS]: 'Session locks',
  [ENTITLEMENTS.SESSION_APPROVALS]: 'Session approvals',
  [ENTITLEMENTS.ACCESS_REVIEWS]: 'Access reviews',
  [ENTITLEMENTS.COMMAND_APPROVALS]: 'Command approvals',
  [ENTITLEMENTS.COMMAND_METRICS]: 'Command metrics',
  [ENTITLEMENTS.COMPLIANCE_BULK_EXPORTS]: 'Bulk compliance exports',
  [ENTITLEMENTS.REPORTS_SCHEDULED_EXPORTS]: 'Scheduled report exports',
};

const Field: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div className="flex flex-col gap-1">
    <span className="text-[11px] uppercase tracking-wide text-content-subtle">{label}</span>
    <span className="text-sm text-content">{children}</span>
  </div>
);

const LicenseTab: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const { isAdmin } = useAuth();
  const {
    edition,
    tier,
    licenseState,
    instanceId,
    issuedTo,
    hostCap,
    hostCount,
    expiresAt,
    overCap,
    inGrace,
    graceUntil,
    entitlements,
    onlineRefresh,
    refresh,
    loading,
  } = useEntitlements();

  const [token, setToken] = useState('');
  // Optional online-refresh token. Kept in component state only and sent to the
  // backend on apply - NEVER persisted to localStorage or any browser store.
  const [refreshToken, setRefreshToken] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [copied, setCopied] = useState(false);
  const [buyUrl, setBuyUrl] = useState('');

  const isPaid = edition !== 'free';
  const capLabel = hostCap === null ? 'Unlimited' : String(hostCap);

  useEffect(() => {
    if (!isAdmin) return;
    let active = true;
    // Prefetch the buy URL so the button opens the site synchronously on click
    // (no popup blocker). The site is the buy surface; the app starts no checkout.
    getBuyUrl()
      .then((url) => {
        if (active) setBuyUrl(url);
      })
      .catch(() => {
        /* optional UI; ignore load failure */
      });
    return () => {
      active = false;
    };
  }, [isAdmin]);

  const onBuy = () => {
    if (!buyUrl) return;
    window.open(buyUrl, '_blank', 'noopener,noreferrer');
  };

  const copyInstanceId = async () => {
    if (!instanceId) return;
    try {
      await navigator.clipboard.writeText(instanceId);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      toast.error('Copy failed');
    }
  };

  const onApply = async () => {
    if (!token.trim()) return;
    setSubmitting(true);
    try {
      await applyLicense(token.trim(), refreshToken.trim() || undefined);
      await refresh();
      setToken('');
      // Clear the refresh token from the form once it's been handed to the
      // backend; it lives server-side now, never in the browser.
      setRefreshToken('');
      toast.success('License applied');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'License was rejected');
    } finally {
      setSubmitting(false);
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    try {
      const res = await refreshLicense();
      await refresh();
      if (res.result === 'ok') {
        toast.success('License renewed');
      } else if (res.result === 'not_configured') {
        toast.error('Online refresh is not configured for this installation');
      } else {
        toast.error(res.detail || 'License refresh did not complete');
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'License refresh failed');
    } finally {
      setRefreshing(false);
    }
  };

  const onRemove = async () => {
    setSubmitting(true);
    try {
      await removeLicense();
      await refresh();
      toast.success('License removed');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to remove license');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6 max-w-3xl">
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <ShieldCheck size={16} className={isPaid ? 'text-emerald-400' : 'text-gray-500'} />
            <span>Edition &amp; License</span>
          </div>
        </CardHeader>
        <CardBody>
          {loading ? (
            <p className="text-sm text-content-subtle">Loading…</p>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Field label="Edition">
                <span className="capitalize">{tier || edition}</span>
                {!isPaid && <span className="text-content-subtle"> (free)</span>}
              </Field>
              <Field label="License state">
                <span className="capitalize">{licenseState.replace('_', ' ')}</span>
              </Field>
              <Field label="Issued to">
                {/* Organization/licensee name - authority is the signed license's
                    issued_to claim only; there is no manual entry. */}
                <span data-testid="license-issued-to">{issuedTo || '-'}</span>
              </Field>
              <Field label="Expires">{expiresAt ? formatTimestamp(expiresAt, { dateOnly: true }) : '-'}</Field>
              <Field label="Managed hosts">
                {hostCount ?? '-'} / {capLabel}
              </Field>
              <Field label="Installation ID">
                <span className="inline-flex items-center gap-2">
                  <code className="text-xs text-content break-all">{instanceId || '-'}</code>
                  {instanceId && (
                    <button
                      type="button"
                      onClick={copyInstanceId}
                      className="text-content-muted hover:text-content"
                      title="Copy installation ID"
                    >
                      {copied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
                    </button>
                  )}
                </span>
              </Field>
            </div>
          )}

          {overCap && (
            <div className="mt-4 flex items-start gap-2 p-3 rounded border border-amber-500/40 bg-amber-500/10 text-amber-200 text-xs">
              <AlertTriangle size={14} className="mt-0.5 shrink-0" />
              <span>
                This installation is over its host cap ({hostCount}/{capLabel}). Existing hosts keep
                running; new hosts are blocked until you reduce usage or apply a license.
                {inGrace && graceUntil && (
                  <> Grace period ends {formatTimestamp(graceUntil, { dateOnly: true })}.</>
                )}
              </span>
            </div>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader>Entitlements</CardHeader>
        <CardBody>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {Object.keys(ENTITLEMENT_LABELS).map((key) => (
              <div key={key} className="flex items-center gap-2 text-sm">
                <span
                  className={`inline-block w-2 h-2 rounded-full ${
                    entitlements[key] ? 'bg-emerald-400' : 'bg-gray-600'
                  }`}
                />
                <span className={entitlements[key] ? 'text-content' : 'text-content-subtle'}>
                  {ENTITLEMENT_LABELS[key]}
                </span>
              </div>
            ))}
          </div>
        </CardBody>
      </Card>

      {isAdmin && (
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <ShoppingCart size={16} className="text-content-muted" />
              <span>Buy or upgrade</span>
            </div>
          </CardHeader>
          <CardBody>
            <p className="text-xs text-content-subtle mb-3">
              Purchasing unlocks a higher host cap and paid governance; the free
              edition remains free. This opens the Praxis website with your
              Installation ID{' '}
              <code className="text-content-muted">{instanceId || '-'}</code> prefilled -
              choose a plan there to complete checkout.
            </p>
            <Button
              variant="primary"
              size="sm"
              onClick={onBuy}
              disabled={!buyUrl}
              data-testid="buy-license-button"
            >
              Buy / Upgrade
            </Button>
          </CardBody>
        </Card>
      )}

      {isAdmin && (
        <Card>
          <CardHeader>Apply a license</CardHeader>
          <CardBody>
            <p className="text-xs text-content-subtle mb-2">
              Paste a license key issued for installation ID{' '}
              <code className="text-content-muted">{instanceId || '-'}</code>. Validation is offline; no
              data leaves this install.
            </p>
            <textarea
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="Paste license token…"
              rows={4}
              className="w-full rounded border border-border bg-surface-sunken p-2 text-xs font-mono text-content"
              data-testid="license-token-input"
            />
            <label className="mt-3 block text-[11px] uppercase tracking-wide text-content-subtle">
              Refresh token (optional)
            </label>
            <input
              type="password"
              value={refreshToken}
              onChange={(e) => setRefreshToken(e.target.value)}
              placeholder="Enable automatic renewal…"
              autoComplete="off"
              className="mt-1 w-full rounded border border-border bg-surface-sunken p-2 text-xs font-mono text-content"
              data-testid="license-refresh-token-input"
            />
            <p className="mt-1 text-[11px] text-content-subtle">
              Paste the refresh token from your purchase to let this install renew the
              license automatically after each billing renewal. It is stored securely on
              the server and never in your browser. Leave blank to keep using manual
              license import.
            </p>
            <div className="mt-3 flex items-center gap-2">
              <Button variant="primary" size="sm" onClick={onApply} loading={submitting} disabled={!token.trim()}>
                Apply license
              </Button>
              {isPaid && (
                <Button variant="outline" size="sm" onClick={onRemove} disabled={submitting}>
                  Remove license
                </Button>
              )}
            </div>
          </CardBody>
        </Card>
      )}

      {isAdmin && (
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <RefreshCw size={16} className="text-content-muted" />
              <span>Online refresh</span>
            </div>
          </CardHeader>
          <CardBody>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Field label="Status">
                {onlineRefresh?.configured ? (
                  <span className="text-emerald-400">Configured</span>
                ) : (
                  <span className="text-content-subtle">Not configured</span>
                )}
              </Field>
              <Field label="Last attempt">
                {onlineRefresh?.last_attempt_at
                  ? formatTimestamp(onlineRefresh.last_attempt_at)
                  : '-'}
              </Field>
              <Field label="Last result">
                {onlineRefresh?.last_result
                  ? REFRESH_RESULT_LABELS[onlineRefresh.last_result] ?? onlineRefresh.last_result
                  : '-'}
              </Field>
              {onlineRefresh?.last_detail && (
                <Field label="Detail">
                  <span className="text-content-muted">{onlineRefresh.last_detail}</span>
                </Field>
              )}
            </div>
            <p className="mt-3 text-[11px] text-content-subtle">
              {onlineRefresh?.configured
                ? 'This install can renew its license automatically after a billing renewal. You can also refresh now.'
                : 'Apply a license with a refresh token to enable automatic renewal. Manual license import always works without it.'}
            </p>
            <div className="mt-3">
              <Button
                variant="outline"
                size="sm"
                onClick={onRefresh}
                loading={refreshing}
                disabled={!onlineRefresh?.configured}
                data-testid="refresh-license-button"
              >
                Refresh license
              </Button>
            </div>
          </CardBody>
        </Card>
      )}
    </div>
  );
};

export default LicenseTab;
