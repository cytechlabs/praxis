import { describe, it, expect } from 'vitest';

import { humanizeLabel, humanizeStatus } from './humanize';

describe('humanizeLabel', () => {
  it('sentence-cases snake/kebab/camel case', () => {
    expect(humanizeLabel('in_progress')).toBe('In progress');
    expect(humanizeLabel('auth-failed')).toBe('Auth failed');
    expect(humanizeLabel('maxSessionDuration')).toBe('Max session duration');
    expect(humanizeLabel('access_request')).toBe('Access request');
  });

  it('preserves known acronyms', () => {
    expect(humanizeLabel('ssh_key')).toBe('SSH key');
    expect(humanizeLabel('ca_trust_deployed')).toBe('CA trust deployed');
    expect(humanizeLabel('os_version')).toBe('OS version');
    expect(humanizeLabel('cpu_cores')).toBe('CPU cores');
  });

  it('handles empty/null/undefined', () => {
    expect(humanizeLabel('')).toBe('');
    expect(humanizeLabel(null)).toBe('');
    expect(humanizeLabel(undefined)).toBe('');
  });

  it('is sentence case, not title case', () => {
    // only the first word is capitalized
    expect(humanizeLabel('pending host cleanup')).toBe('Pending host cleanup');
  });
});

describe('humanizeStatus', () => {
  it('uses shared overrides where defined', () => {
    expect(humanizeStatus('not_enrolled')).toBe('Not enrolled');
    expect(humanizeStatus('auth_failed')).toBe('Auth failed');
    expect(humanizeStatus('ok')).toBe('OK');
    expect(humanizeStatus('eol')).toBe('End of life');
    expect(humanizeStatus('dead_letter')).toBe('Dead letter');
  });

  it('PRA-271: humanizes awkward rollback/state enums', () => {
    expect(humanizeStatus('rollback_attempted_failed')).toBe('Rollback failed');
    expect(humanizeStatus('rollback_attempted')).toBe('Rollback attempted');
    expect(humanizeStatus('not_applicable')).toBe('Not applicable');
    // no raw underscores ever leak through for a plain enum
    expect(humanizeStatus('via_direct_host')).toBe('Via direct host');
  });

  it('falls back to humanizeLabel for unknown statuses', () => {
    expect(humanizeStatus('running')).toBe('Running');
    expect(humanizeStatus('queued')).toBe('Queued');
    expect(humanizeStatus('some_new_state')).toBe('Some new state');
  });

  it('is case-insensitive on the override key', () => {
    expect(humanizeStatus('NOT_ENROLLED')).toBe('Not enrolled');
    expect(humanizeStatus('In_Progress')).toBe('In progress');
  });

  it('handles empty/null', () => {
    expect(humanizeStatus('')).toBe('');
    expect(humanizeStatus(null)).toBe('');
  });

  it('PRA-357: humanizes the missed mirror / content-profile enum families', () => {
    // mirror.package_family — package-format initialisms stay uppercased.
    expect(humanizeStatus('deb')).toBe('DEB');
    expect(humanizeStatus('rpm')).toBe('RPM');
    // mirror.source_mode — underscore enums must not leak raw.
    expect(humanizeStatus('upstream_sync')).toBe('Upstream sync');
    expect(humanizeStatus('imported_offline')).toBe('Imported offline');
    // content-profile via_kind (rendered lower-cased mid-sentence).
    expect(humanizeLabel('smart_group').toLowerCase()).toBe('smart group');
    expect(humanizeLabel('direct').toLowerCase()).toBe('direct');
    // apply outcome + execution states surfaced by rollback/apply flows.
    expect(humanizeStatus('refused_no_profile')).toBe('Refused no profile');
    expect(humanizeStatus('refused_conflict')).toBe('Refused conflict');
  });
});
