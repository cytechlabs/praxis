/**
 * PRA-338: thin-agent status section for the host detail page.
 *
 * Surfaces the PRA-324 `/agent/status/{id}` contract as two separate
 * signals - enrollment lifecycle and broker-tunnel liveness - plus agent
 * version + last-seen. This is the Praxis AGENT, deliberately distinct from
 * the SSH access broker panel (CA trust + principals) elsewhere on the page.
 *
 * Resilience: fetches independently of the host page's own load, in this
 * component's effect, and swallows failures into a local "unavailable"
 * state (never the same as "offline"). A slow or broken broker/API call
 * therefore renders a degraded card and a Retry button - it never stalls or
 * breaks the rest of host detail.
 *
 * Admin-only: the backend gates `/agent/status` on the admin role, so we
 * fetch only for admins and show a short note otherwise (rather than firing
 * a request that 403s).
 */
import { useCallback, useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { Badge, Button } from '@/components/ui';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { fetchThinAgentStatus, ThinAgentStatus } from '@/services/systemService';
import {
  UNAVAILABLE_PRESENTATION,
  hasThinAgent,
  lifecyclePresentation,
  livenessPresentation,
  showsLiveness,
} from './thinAgentStatus';

interface Props {
  systemId: number;
  isAdmin: boolean;
}

type LoadState = 'loading' | 'loaded' | 'error';

const SectionShell = ({ children }: { children: React.ReactNode }) => (
  <section className="md:col-span-2">
    <h2 className="text-xl font-semibold text-content mb-4">Thin agent</h2>
    <div className="bg-surface-raised/30 p-4 rounded-lg border border-border">
      <p className="text-xs text-content-subtle mb-4">
        The Praxis thin agent and its broker tunnel - a separate mechanism from
        the SSH access broker (CA trust + principals) shown elsewhere on this
        page.
      </p>
      {children}
    </div>
  </section>
);

const Signal = ({
  term,
  label,
  variant,
  description,
}: {
  term: string;
  label: string;
  variant: 'success' | 'warning' | 'danger' | 'info' | 'neutral' | 'orange';
  description: string;
}) => (
  <div>
    <p className="text-sm text-content-muted mb-1">{term}</p>
    <div className="flex items-start gap-3">
      <Badge variant={variant}>{label}</Badge>
      <span className="text-sm text-content-muted">{description}</span>
    </div>
  </div>
);

const ThinAgentStatusCard = ({ systemId, isAdmin }: Props) => {
  const formatTimestamp = useFormatTimestamp();
  const [status, setStatus] = useState<ThinAgentStatus | null>(null);
  const [loadState, setLoadState] = useState<LoadState>('loading');

  const load = useCallback(async () => {
    setLoadState('loading');
    try {
      const data = await fetchThinAgentStatus(systemId);
      setStatus(data);
      setLoadState('loaded');
    } catch {
      // Broker/API unreachable - degrade locally, never bubble to the page.
      setStatus(null);
      setLoadState('error');
    }
  }, [systemId]);

  useEffect(() => {
    if (!isAdmin) return;
    let cancelled = false;
    (async () => {
      setLoadState('loading');
      try {
        const data = await fetchThinAgentStatus(systemId);
        if (!cancelled) {
          setStatus(data);
          setLoadState('loaded');
        }
      } catch {
        if (!cancelled) {
          setStatus(null);
          setLoadState('error');
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [systemId, isAdmin]);

  if (!isAdmin) {
    return (
      <SectionShell>
        <p className="text-sm text-content-subtle">
          Thin-agent status is available to administrators.
        </p>
      </SectionShell>
    );
  }

  if (loadState === 'loading') {
    return (
      <SectionShell>
        <p className="text-sm text-content-subtle" role="status">
          Loading thin-agent status…
        </p>
      </SectionShell>
    );
  }

  if (loadState === 'error' || !status) {
    // Explicit unavailable - distinct from a definitive "offline".
    return (
      <SectionShell>
        <div className="flex items-start justify-between gap-3">
          <Signal
            term="Status"
            label={UNAVAILABLE_PRESENTATION.label}
            variant={UNAVAILABLE_PRESENTATION.variant}
            description={UNAVAILABLE_PRESENTATION.description}
          />
          <Button variant="ghost" size="sm" onClick={load}>
            <RefreshCw size={14} className="mr-1" />
            Retry
          </Button>
        </div>
      </SectionShell>
    );
  }

  const lifecycle = lifecyclePresentation(status.agent_status, {
    statusReason: status.agent_status_reason,
    revocationReason: status.agent_revocation_reason,
  });
  const liveness = livenessPresentation(status.agent_liveness);
  const enrolled = hasThinAgent(status.agent_status);
  const liveShown = showsLiveness(status.agent_status);

  return (
    <SectionShell>
      <div className="flex flex-col gap-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex flex-col gap-4">
            <Signal
              term="Enrollment"
              label={lifecycle.label}
              variant={lifecycle.variant}
              description={lifecycle.description}
            />
            {liveShown && (
              <Signal
                term="Tunnel"
                label={liveness.label}
                variant={liveness.variant}
                description={liveness.description}
              />
            )}
          </div>
          <Button variant="ghost" size="sm" onClick={load}>
            <RefreshCw size={14} className="mr-1" />
            Refresh
          </Button>
        </div>

        {enrolled && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2 border-t border-border">
            <div>
              <p className="text-sm text-content-muted">Agent version</p>
              <p className="text-content">
                {status.agent_version ?? (
                  <span className="text-content-subtle">Not reported yet</span>
                )}
              </p>
            </div>
            <div>
              <p className="text-sm text-content-muted">Last seen</p>
              <p className="text-content">
                {status.agent_last_seen_at ? (
                  formatTimestamp(status.agent_last_seen_at)
                ) : (
                  <span className="text-content-subtle">Never connected</span>
                )}
              </p>
            </div>
            <div>
              <p className="text-sm text-content-muted">Certificate expires</p>
              <p className="text-content">
                {status.agent_cert_expires_at ? (
                  formatTimestamp(status.agent_cert_expires_at)
                ) : (
                  <span className="text-content-subtle">-</span>
                )}
              </p>
            </div>
          </div>
        )}
      </div>
    </SectionShell>
  );
};

export default ThinAgentStatusCard;
