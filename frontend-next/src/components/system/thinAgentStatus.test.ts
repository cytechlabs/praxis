import { describe, it, expect } from 'vitest';

import type { AgentLifecycle, AgentLiveness } from '../../services/systemService';
import {
  UNAVAILABLE_PRESENTATION,
  hasThinAgent,
  lifecyclePresentation,
  livenessPresentation,
  showsLiveness,
} from './thinAgentStatus';

const ALL_LIFECYCLE: AgentLifecycle[] = ['not_enrolled', 'active', 'disabled', 'revoked'];
const ALL_LIVENESS: AgentLiveness[] = ['online', 'stale', 'offline', 'unknown'];

describe('lifecyclePresentation', () => {
  it('covers every lifecycle state with a non-empty label + description', () => {
    for (const s of ALL_LIFECYCLE) {
      const p = lifecyclePresentation(s);
      expect(p.label.length).toBeGreaterThan(0);
      expect(p.description.length).toBeGreaterThan(0);
    }
  });

  it('maps severity to sensible badge variants', () => {
    expect(lifecyclePresentation('not_enrolled').variant).toBe('neutral');
    expect(lifecyclePresentation('active').variant).toBe('success');
    expect(lifecyclePresentation('disabled').variant).toBe('warning');
    expect(lifecyclePresentation('revoked').variant).toBe('danger');
  });

  it('appends the revocation reason only for revoked', () => {
    const revoked = lifecyclePresentation('revoked', { revocationReason: 'key compromised' });
    expect(revoked.description).toContain('key compromised');
    // A revocation reason must not leak onto an unrelated state.
    const active = lifecyclePresentation('active', { revocationReason: 'key compromised' });
    expect(active.description).not.toContain('key compromised');
  });

  it('appends the status reason only for disabled', () => {
    const disabled = lifecyclePresentation('disabled', { statusReason: 'maintenance' });
    expect(disabled.description).toContain('maintenance');
  });
});

describe('livenessPresentation', () => {
  it('covers every liveness state', () => {
    for (const s of ALL_LIVENESS) {
      const p = livenessPresentation(s);
      expect(p.label.length).toBeGreaterThan(0);
      expect(p.description.length).toBeGreaterThan(0);
    }
  });

  it('keeps unknown DISTINCT from offline (the core PRA-324 semantic)', () => {
    const unknown = livenessPresentation('unknown');
    const offline = livenessPresentation('offline');
    expect(unknown.label).not.toBe(offline.label);
    expect(unknown.variant).not.toBe(offline.variant);
    // unknown must never assert the agent is absent/offline.
    expect(unknown.description.toLowerCase()).toContain('not the same as offline');
    expect(offline.variant).toBe('neutral');
    expect(unknown.variant).toBe('warning');
  });

  it('maps online healthy and stale as a warning', () => {
    expect(livenessPresentation('online').variant).toBe('success');
    expect(livenessPresentation('stale').variant).toBe('warning');
  });
});

describe('hasThinAgent / showsLiveness gates', () => {
  it('hasThinAgent is false only for not_enrolled', () => {
    expect(hasThinAgent('not_enrolled')).toBe(false);
    expect(hasThinAgent('active')).toBe(true);
    expect(hasThinAgent('disabled')).toBe(true);
    expect(hasThinAgent('revoked')).toBe(true);
  });

  it('showsLiveness is true only for active (no live tunnel otherwise)', () => {
    expect(showsLiveness('active')).toBe(true);
    expect(showsLiveness('not_enrolled')).toBe(false);
    expect(showsLiveness('disabled')).toBe(false);
    expect(showsLiveness('revoked')).toBe(false);
  });
});

describe('unavailable state', () => {
  it('is an explicit "unavailable", never a confident offline/not-enrolled', () => {
    expect(UNAVAILABLE_PRESENTATION.variant).toBe('warning');
    const desc = UNAVAILABLE_PRESENTATION.description.toLowerCase();
    expect(desc).toContain('not mean the agent is offline');
  });
});

describe('copy boundary: thin-agent copy must not mention the SSH access broker', () => {
  // The whole point of PRA-338 is that operators can tell thin-agent status
  // apart from SSH access broker enrollment. Guard against the two vocabularies
  // bleeding into each other.
  const FORBIDDEN = ['access broker', 'ca trust', 'principals', 'sshd', 'allowusers'];

  const allCopy: string[] = [
    ...ALL_LIFECYCLE.flatMap((s) => {
      const p = lifecyclePresentation(s);
      return [p.label, p.description];
    }),
    ...ALL_LIVENESS.flatMap((s) => {
      const p = livenessPresentation(s);
      return [p.label, p.description];
    }),
    UNAVAILABLE_PRESENTATION.label,
    UNAVAILABLE_PRESENTATION.description,
  ];

  it('contains no SSH-access-broker vocabulary', () => {
    for (const text of allCopy) {
      const lower = text.toLowerCase();
      for (const term of FORBIDDEN) {
        expect(lower, `"${text}" should not mention "${term}"`).not.toContain(term);
      }
    }
  });
});
