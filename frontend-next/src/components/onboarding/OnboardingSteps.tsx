import React from 'react';
import type { NextRouter } from 'next/router';
import { AlertTriangle, Info, Plus } from 'lucide-react';

import VerificationReport, {
  HostKeyReview,
} from '@/components/onboarding/VerificationReport';
import { Button, FormField, nativeSelectClass } from '@/components/ui';
import {
  fetchCredentialOptions,
  fetchOrganizationOptions,
} from '@/services/onboardingService';
import type {
  Capabilities,
  ConfirmResponse,
  CredentialSummary,
  Draft,
  Verification,
} from '@/services/onboardingService';

export type CredentialOptions = Awaited<ReturnType<typeof fetchCredentialOptions>>;
export type OrganizationOptions = Awaited<
  ReturnType<typeof fetchOrganizationOptions>
>;

export type CompletedSystem = {
  system_id: number;
  hostname: string;
  status: string;
  verification_skipped: boolean;
};

export const inputClass =
  'w-full px-3 py-2 bg-surface-sunken border border-border rounded-md text-sm text-content placeholder:text-content-subtle focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong';

/**
 * The seven surfaces of the guided setup.
 *
 * Each step renders what the operator sees at that point and nothing else: the
 * page owns the draft, the transitions and every request, so a step cannot
 * advance itself or reach the server on its own.
 */

export const ConnectStep: React.FC<{
  address: string;
  sshPort: string;
  hostname: string;
  setAddress: (value: string) => void;
  setSshPort: (value: string) => void;
  setHostname: (value: string) => void;
}> = ({ address, sshPort, hostname, setAddress, setSshPort, setHostname }) => (
    <div className="space-y-4">
      <p className="text-sm text-content-muted">
        Start with where the host is. Praxis works out the rest by
        looking at it, so you do not need to describe it yet.
      </p>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <FormField
          label="Address"
          htmlFor="ob-address"
          required
          helper="IPv4, IPv6, or a hostname Praxis can resolve."
        >
          <input
            id="ob-address"
            className={inputClass}
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="10.0.0.10 or host.example.com"
            autoComplete="off"
          />
        </FormField>
        <FormField label="SSH port" htmlFor="ob-port" required>
          <input
            id="ob-port"
            className={inputClass}
            value={sshPort}
            onChange={(e) => setSshPort(e.target.value)}
            inputMode="numeric"
          />
        </FormField>
        <FormField
          label="Display name"
          htmlFor="ob-hostname"
          helper="Optional. Praxis uses what the host calls itself if you leave this blank."
          className="sm:col-span-2"
        >
          <input
            id="ob-hostname"
            className={inputClass}
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
            placeholder="web-01"
            autoComplete="off"
          />
        </FormField>
      </div>
    </div>
);

export const AuthenticateStep: React.FC<{
  capabilities: Capabilities | null;
  credentialOptions: CredentialOptions | null;
  credentialId: string;
  policyId: string;
  setCredentialId: (value: string) => void;
  setPolicyId: (value: string) => void;
  router: NextRouter;
}> = ({ capabilities, credentialOptions, credentialId, policyId, setCredentialId, setPolicyId, router }) => (
    <div className="space-y-4">
      {capabilities && !capabilities.can_create_credential && (
        <div className="flex gap-2 rounded-md border border-border bg-surface-sunken p-3">
          <Info size={14} className="mt-0.5 shrink-0 text-content-muted" aria-hidden="true" />
          <p className="text-xs text-content-muted">
            Your access lets you use existing credentials but not
            create new ones. Pick one below, or ask an administrator
            to add the credential you need.
          </p>
        </div>
      )}
      <FormField label="Credential" htmlFor="ob-credential" required>
        <select
          id="ob-credential"
          className={nativeSelectClass}
          value={credentialId}
          onChange={(e) => setCredentialId(e.target.value)}
        >
          <option value="">Choose a credential</option>
          {credentialOptions?.credentials.map((c: CredentialSummary) => (
            <option key={c.id} value={c.id}>
              {c.name} - {c.username ?? 'no username'} - {c.auth_method}
              {c.sudo_method !== 'none' ? ` - sudo: ${c.sudo_method}` : ''}
              {` (${c.source})`}
            </option>
          ))}
        </select>
      </FormField>
      {capabilities?.can_create_credential && (
        <Button
          variant="secondary"
          size="sm"
          icon={<Plus size={14} />}
          onClick={() =>
            router.push({
              pathname: '/credentials',
              query: { returnTo: router.asPath },
            })
          }
        >
          Create a credential
        </Button>
      )}
      <FormField
        label="SSH policy"
        htmlFor="ob-policy"
        helper="Sets the algorithms allowed and whether the host key must be verified."
      >
        <select
          id="ob-policy"
          className={nativeSelectClass}
          value={policyId}
          onChange={(e) => setPolicyId(e.target.value)}
        >
          {credentialOptions?.ssh_security_policies.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
              {p.is_default ? ' (default)' : ''}
              {p.requires_host_key_verification
                ? ''
                : ' - host key not verified'}
            </option>
          ))}
        </select>
      </FormField>
    </div>
);

export const VerifyStep: React.FC<{
  draft: Draft | null;
  verification: Verification | null;
  needsHostKeyDecision: boolean;
  canLeaveVerify: boolean;
  busy: boolean;
  verify: () => void;
  skip: () => void;
  decideHostKey: (accept: boolean) => void;
}> = ({ draft, verification, needsHostKeyDecision, canLeaveVerify, busy, verify, skip, decideHostKey }) => (
    <div className="space-y-4">
      <p className="text-sm text-content-muted">
        Praxis connects and checks each part separately. Nothing is
        added to your inventory by this step.
      </p>

      {needsHostKeyDecision && draft?.host_key.fingerprint && (
        <HostKeyReview
          fingerprint={draft.host_key.fingerprint}
          keyType={draft.host_key.key_type}
          decision={draft.host_key.decision}
          busy={busy}
          onDecide={decideHostKey}
        />
      )}

      {verification && (
        <VerificationReport
          checks={verification.checks}
          verified={verification.verified}
        />
      )}

      {draft?.verification_skipped && (
        <div className="flex gap-2 rounded-md border border-warning/40 bg-warning/10 p-3">
          <AlertTriangle size={14} className="mt-0.5 shrink-0 text-warning" aria-hidden="true" />
          <p className="text-xs text-content-muted">
            You chose to skip verification. This host will be added
            as Inactive with nothing confirmed about it.
          </p>
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        <Button variant="primary" onClick={verify} loading={busy}>
          {verification ? 'Check again' : 'Check the connection'}
        </Button>
        {!canLeaveVerify && (
          <Button variant="ghost" onClick={skip} disabled={busy}>
            Skip and add it as Inactive
          </Button>
        )}
      </div>
    </div>
);

export const DiscoverStep: React.FC<{
  draft: Draft | null;
  organizationOptions: OrganizationOptions | null;
  chosenDistroId: string;
  setChosenDistroId: (value: string) => void;
  busy: boolean;
  discover: () => void;
  submitDiscoveryConfirmation: () => void;
}> = ({ draft, organizationOptions, chosenDistroId, setChosenDistroId, busy, discover, submitDiscoveryConfirmation }) => (
    <div className="space-y-4">
      {draft?.discovery ? (
        <>
          <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {[
              ['Hostname', draft.discovery.effective_hostname],
              ['Full name', draft.discovery.fqdn],
              [
                'Distribution',
                draft.discovery.distro_name
                  ? `${draft.discovery.distro_name} ${draft.discovery.distro_version ?? ''}`.trim()
                  : null,
              ],
              ['Architecture', draft.discovery.architecture],
              ['Packages', draft.discovery.package_manager],
            ].map(([label, value]) => (
              <div key={label as string}>
                <dt className="text-[11px] uppercase tracking-wider text-content-subtle">
                  {label}
                </dt>
                <dd className="text-sm text-content break-words">
                  {(value as string) || 'Not reported'}
                </dd>
              </div>
            ))}
          </dl>

          {draft.discovery.support_mapping === 'unknown' && (
            <div className="space-y-3 rounded-md border border-warning/40 bg-warning/10 p-4">
              <p className="text-sm text-content">
                Praxis does not recognise this distribution.
              </p>
              <p className="text-xs text-content-muted">
                You can still add the host, but package and patch
                features may not work until it is supported. Pick the
                closest match, or continue without one.
              </p>
              <FormField label="Distribution" htmlFor="ob-distro">
                <select
                  id="ob-distro"
                  className={nativeSelectClass}
                  value={chosenDistroId}
                  onChange={(e) => setChosenDistroId(e.target.value)}
                >
                  <option value="">Continue without a match</option>
                  {organizationOptions?.distros.map((d) => (
                    <option key={d.id} value={d.id}>
                      {d.name} {d.version}
                    </option>
                  ))}
                </select>
              </FormField>
              <Button
                variant="primary"
                size="sm"
                onClick={submitDiscoveryConfirmation}
                loading={busy}
              >
                Confirm and continue
              </Button>
            </div>
          )}
        </>
      ) : (
        <>
          <p className="text-sm text-content-muted">
            {draft?.verification_skipped
              ? 'Verification was skipped, so Praxis has not looked at this host. Choose its distribution to continue.'
              : "Read this host's name, distribution and architecture."}
          </p>
          {draft?.verification_skipped ? (
            <>
              <FormField label="Distribution" htmlFor="ob-distro-skip" required>
                <select
                  id="ob-distro-skip"
                  className={nativeSelectClass}
                  value={chosenDistroId}
                  onChange={(e) => setChosenDistroId(e.target.value)}
                >
                  <option value="">Choose a distribution</option>
                  {organizationOptions?.distros.map((d) => (
                    <option key={d.id} value={d.id}>
                      {d.name} {d.version}
                    </option>
                  ))}
                </select>
              </FormField>
              <Button
                variant="primary"
                onClick={submitDiscoveryConfirmation}
                loading={busy}
                disabled={!chosenDistroId}
              >
                Continue
              </Button>
            </>
          ) : (
            <Button variant="primary" onClick={discover} loading={busy}>
              Read host details
            </Button>
          )}
        </>
      )}
    </div>
);

export const OrganizeStep: React.FC<{
  organizationOptions: OrganizationOptions | null;
  groupId: string;
  setGroupId: (value: string) => void;
  environment: string;
  setEnvironment: (value: string) => void;
  description: string;
  setDescription: (value: string) => void;
  transport: string;
  setTransport: (value: string) => void;
  tags: string[];
  setTags: (value: string[]) => void;
  tagInput: string;
  setTagInput: (value: string) => void;
  addTag: () => void;
}> = ({ organizationOptions, groupId, setGroupId, environment, setEnvironment, description, setDescription, transport, setTransport, tags, setTags, tagInput, setTagInput, addTag }) => (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
      <FormField label="Group" htmlFor="ob-group">
        <select
          id="ob-group"
          className={nativeSelectClass}
          value={groupId}
          onChange={(e) => setGroupId(e.target.value)}
        >
          {organizationOptions?.groups.map((g) => (
            <option key={g.id} value={g.id}>
              {g.name}
            </option>
          ))}
        </select>
      </FormField>
      <FormField label="Environment" htmlFor="ob-environment">
        <select
          id="ob-environment"
          className={nativeSelectClass}
          value={environment}
          onChange={(e) => setEnvironment(e.target.value)}
        >
          {organizationOptions?.environments.map((env) => (
            <option key={env} value={env}>
              {env}
            </option>
          ))}
        </select>
      </FormField>
      <FormField
        label="Transport"
        htmlFor="ob-transport"
        helper="SSH is used unless an agent is enrolled later."
      >
        <select
          id="ob-transport"
          className={nativeSelectClass}
          value={transport}
          onChange={(e) => setTransport(e.target.value)}
        >
          {organizationOptions?.transport_preferences.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </FormField>
      <FormField label="Tags" htmlFor="ob-tags">
        <div className="flex gap-2">
          <input
            id="ob-tags"
            className={inputClass}
            value={tagInput}
            onChange={(e) => setTagInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                addTag();
              }
            }}
            placeholder="Type a tag and press Enter"
          />
          <Button variant="secondary" size="sm" onClick={addTag} type="button">
            Add
          </Button>
        </div>
        {tags.length > 0 && (
          <ul className="mt-2 flex flex-wrap gap-1.5">
            {tags.map((tag) => (
              <li key={tag}>
                <button
                  type="button"
                  onClick={() => setTags(tags.filter((t) => t !== tag))}
                  className="rounded-full border border-border bg-surface-sunken px-2 py-0.5 text-xs text-content-muted hover:border-border-strong focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                  aria-label={`Remove tag ${tag}`}
                >
                  {tag} &times;
                </button>
              </li>
            ))}
          </ul>
        )}
      </FormField>
      <FormField label="Description" htmlFor="ob-description" className="sm:col-span-2">
        <textarea
          id="ob-description"
          className={inputClass}
          rows={3}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="What is this host for?"
        />
      </FormField>
    </div>
);

export const ConfirmStep: React.FC<{
  draft: Draft | null;
  confirmation: ConfirmResponse | null;
}> = ({ draft, confirmation }) => (
    <div className="space-y-4">
      {confirmation ? (
        <>
          <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {[
              ['Hostname', confirmation.preview.hostname],
              ['Address', confirmation.preview.ip_address],
              ['SSH port', String(confirmation.preview.ssh_port ?? 22)],
              ['Group', confirmation.preview.group?.name],
              ['Environment', confirmation.preview.environment],
              [
                'SSH policy',
                confirmation.preview.ssh_security_policy?.name,
              ],
              ['Credential', draft?.credential?.name],
              ['Transport', confirmation.preview.transport_preference],
              [
                'Distribution',
                draft?.discovery?.distro_name
                  ? `${draft.discovery.distro_name} ${draft.discovery.distro_version ?? ''}`.trim()
                  : 'Not identified',
              ],
              [
                'Tags',
                confirmation.preview.tags.length
                  ? confirmation.preview.tags.join(', ')
                  : 'None',
              ],
              ['Description', confirmation.preview.description],
              [
                'Host key',
                confirmation.preview.host_key_fingerprint
                  ? `${confirmation.preview.host_key_decision} - ${confirmation.preview.host_key_fingerprint.slice(0, 24)}...`
                  : 'Not reviewed',
              ],
            ].map(([label, value]) => (
              <div key={label as string}>
                <dt className="text-[11px] uppercase tracking-wider text-content-subtle">
                  {label}
                </dt>
                <dd className="text-sm text-content break-words">
                  {(value as string) || 'Not set'}
                </dd>
              </div>
            ))}
          </dl>

          <div
            className={`rounded-md border p-3 ${
              confirmation.preview.verified
                ? 'border-success/40 bg-success/10'
                : 'border-warning/40 bg-warning/10'
            }`}
          >
            <p className="text-sm text-content">
              This host will be added as{' '}
              <strong>{confirmation.preview.status}</strong>.
            </p>
            <p className="mt-1 text-xs text-content-muted">
              {confirmation.preview.verified
                ? 'Verification succeeded, so Praxis can manage it straight away.'
                : 'Verification did not succeed, so it will not be treated as reachable until it does.'}
            </p>
          </div>

          <div>
            <h3 className="text-sm font-medium text-content">
              Available afterwards
            </h3>
            <ul className="mt-2 space-y-1.5">
              {confirmation.follow_ups.map((f) => (
                <li key={f.key} className="text-xs text-content-muted">
                  <span className="text-content">{f.label}</span> -{' '}
                  {f.description}
                </li>
              ))}
            </ul>
          </div>
        </>
      ) : (
        <p className="text-sm text-content-muted">
          Building the summary...
        </p>
      )}
    </div>
);

export const FinishStep: React.FC<{
  completed: CompletedSystem;
  restart: () => void;
  router: NextRouter;
}> = ({ completed, restart, router }) => (
    <div className="space-y-4">
      <p className="text-sm text-content">
        <strong>{completed.hostname}</strong> was added as{' '}
        <strong>{completed.status}</strong>.
      </p>
      {completed.verification_skipped && (
        <div className="flex gap-2 rounded-md border border-warning/40 bg-warning/10 p-3">
          <AlertTriangle size={14} className="mt-0.5 shrink-0 text-warning" aria-hidden="true" />
          <div>
            <p className="text-sm text-content">
              This host has not been verified.
            </p>
            <p className="mt-1 text-xs text-content-muted">
              Praxis cannot manage it until a connection succeeds.
              Open it and choose Test connection when you are ready.
            </p>
          </div>
        </div>
      )}
      <div className="flex flex-wrap gap-2">
        <Button
          variant="primary"
          onClick={() =>
            router.push(`/system-management/system/${completed.system_id}`)
          }
        >
          Open this host
        </Button>
        <Button
          variant="secondary"
          onClick={() => router.push('/system-management/all-systems')}
        >
          Back to all systems
        </Button>
        <Button variant="ghost" onClick={restart}>
          Add another
        </Button>
      </div>
    </div>
);

