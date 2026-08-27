import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Head from 'next/head';
import { useRouter } from 'next/router';
import { toast } from 'sonner';
import { AlertTriangle, ArrowLeft, ArrowRight, Info, Plus } from 'lucide-react';

import MainLayout from '@/components/MainLayout';
import HelpLink from '@/components/help/HelpLink';
import StepIndicator, { STEP_ORDER } from '@/components/onboarding/StepIndicator';
import VerificationReport, {
  HostKeyReview,
} from '@/components/onboarding/VerificationReport';
import {
  Button,
  Card,
  CardBody,
  FormField,
  PageHeader,
  nativeSelectClass,
} from '@/components/ui';
import { useAuth } from '@/context/AuthContext';
import * as onboarding from '@/services/onboardingService';
import type {
  Capabilities,
  ConfirmResponse,
  CredentialSummary,
  Draft,
  OnboardingStep,
} from '@/services/onboardingService';

const inputClass =
  'w-full px-3 py-2 bg-surface-sunken border border-border rounded-md text-sm text-content placeholder:text-content-subtle focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong';

type CredentialOptions = Awaited<ReturnType<typeof onboarding.fetchCredentialOptions>>;
type OrganizationOptions = Awaited<
  ReturnType<typeof onboarding.fetchOrganizationOptions>
>;

/**
 * Guided first-system onboarding.
 *
 * The draft on the server is the single source of truth: every step posts, and
 * the response replaces local state. That is what makes Back safe, makes a
 * reload resume where the operator left off, and means the summary on Confirm
 * is the thing that will actually be created rather than a local reconstruction
 * of it.
 *
 * Errors arrive with a structured code. The code decides what the page offers
 * next, so an expired setup gets a restart, a stale one gets a reload, and a
 * duplicate gets pointed at the host that already exists.
 */
const OnboardSystem: React.FC = () => {
  const router = useRouter();
  const { canWrite } = useAuth();

  const [draft, setDraft] = useState<Draft | null>(null);
  const [capabilities, setCapabilities] = useState<Capabilities | null>(null);
  const [credentialOptions, setCredentialOptions] = useState<CredentialOptions | null>(
    null,
  );
  const [organizationOptions, setOrganizationOptions] =
    useState<OrganizationOptions | null>(null);
  const [confirmation, setConfirmation] = useState<ConfirmResponse | null>(null);
  const [completed, setCompleted] = useState<{
    system_id: number;
    hostname: string;
    status: string;
    verification_skipped: boolean;
  } | null>(null);

  const [step, setStep] = useState<OnboardingStep>('connect');
  const [furthest, setFurthest] = useState<OnboardingStep>('connect');
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<{ code: string; message: string } | null>(null);
  const [announcement, setAnnouncement] = useState('');

  // Local form state. Seeded from the draft, posted on Next.
  const [address, setAddress] = useState('');
  const [sshPort, setSshPort] = useState('22');
  const [hostname, setHostname] = useState('');
  const [credentialId, setCredentialId] = useState('');
  const [policyId, setPolicyId] = useState('');
  const [groupId, setGroupId] = useState('');
  const [environment, setEnvironment] = useState('Production');
  const [description, setDescription] = useState('');
  const [tags, setTags] = useState<string[]>([]);
  const [tagInput, setTagInput] = useState('');
  const [transport, setTransport] = useState('auto');
  const [chosenDistroId, setChosenDistroId] = useState('');

  const headingRef = useRef<HTMLHeadingElement>(null);
  const firstRender = useRef(true);

  // Focus the step heading on every change of step so keyboard and screen
  // reader users land at the new content instead of the top of the document.
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    headingRef.current?.focus();
  }, [step]);

  const applyDraft = useCallback((next: Draft) => {
    setDraft(next);
    setAddress(next.connection.address ?? '');
    setSshPort(String(next.connection.ssh_port ?? 22));
    setHostname(next.connection.hostname ?? '');
    setCredentialId(next.credential ? String(next.credential.id) : '');
    setPolicyId(next.ssh_security_policy ? String(next.ssh_security_policy.id) : '');
    setGroupId(
      next.organization.group_id ? String(next.organization.group_id) : '',
    );
    setEnvironment(next.organization.environment ?? 'Production');
    setDescription(next.organization.description ?? '');
    setTags(next.organization.tags ?? []);
    setTransport(next.organization.transport_preference ?? 'auto');
    setChosenDistroId(
      next.discovery?.distro_id ? String(next.discovery.distro_id) : '',
    );
  }, []);

  const advance = useCallback((to: OnboardingStep) => {
    setStep(to);
    setFurthest((prev) =>
      STEP_ORDER.indexOf(to) > STEP_ORDER.indexOf(prev) ? to : prev,
    );
  }, []);

  const handleError = useCallback((err: unknown) => {
    if (err instanceof onboarding.OnboardingError) {
      setError({ code: err.code, message: err.message });
      setAnnouncement(err.message);
    } else {
      const message = 'Something went wrong. Try again.';
      setError({ code: 'unknown', message });
      setAnnouncement(message);
    }
  }, []);

  // Start or resume. A draft id in the URL is resumed; otherwise a new one is
  // opened and the id put in the URL so a reload does not start over.
  useEffect(() => {
    if (!router.isReady || !canWrite) return;
    let cancelled = false;

    (async () => {
      setLoading(true);
      try {
        const existing = typeof router.query.draft === 'string' ? router.query.draft : null;
        const result = existing
          ? await onboarding.fetchDraft(existing)
          : await onboarding.createDraft();
        if (cancelled) return;

        applyDraft(result.draft);
        setCapabilities(result.capabilities);
        advance(result.draft.current_step);

        if (!existing) {
          const query = { ...router.query, draft: result.draft.id };
          router.replace({ pathname: router.pathname, query }, undefined, {
            shallow: true,
          });
        }

        const [creds, orgs] = await Promise.all([
          onboarding.fetchCredentialOptions(),
          onboarding.fetchOrganizationOptions(),
        ]);
        if (cancelled) return;
        setCredentialOptions(creds);
        setOrganizationOptions(orgs);
        if (!result.draft.ssh_security_policy && creds.default_ssh_security_policy_id) {
          setPolicyId(String(creds.default_ssh_security_policy_id));
        }
        if (!result.draft.organization.group_id && orgs.default_group_id) {
          setGroupId(String(orgs.default_group_id));
        }
      } catch (err) {
        if (!cancelled) handleError(err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
    // Deliberately keyed on readiness alone: re-running on every query change
    // would open a second draft the moment the id lands in the URL.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router.isReady, canWrite]);

  // Warn before an in-progress setup is abandoned. Nothing is lost that cannot
  // be redone, but silently discarding a verified host key is worth a prompt.
  useEffect(() => {
    const inProgress = draft && !completed && step !== 'connect';
    if (!inProgress) return;
    const onBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = '';
    };
    window.addEventListener('beforeunload', onBeforeUnload);
    return () => window.removeEventListener('beforeunload', onBeforeUnload);
  }, [draft, completed, step]);

  const run = useCallback(
    async (action: () => Promise<{ draft: Draft }>, next?: OnboardingStep) => {
      setBusy(true);
      setError(null);
      try {
        const result = await action();
        applyDraft(result.draft);
        if (next) advance(next);
        return result.draft;
      } catch (err) {
        handleError(err);
        return null;
      } finally {
        setBusy(false);
      }
    },
    [applyDraft, advance, handleError],
  );

  const restart = useCallback(() => {
    setError(null);
    setCompleted(null);
    setConfirmation(null);
    router.replace(
      { pathname: router.pathname, query: {} },
      undefined,
      { shallow: false },
    );
  }, [router]);

  // ---------------------------------------------------------------- actions

  const submitConnect = async () => {
    if (!draft) return;
    const port = Number(sshPort);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      setError({ code: 'invalid_port', message: 'SSH port must be between 1 and 65535.' });
      return;
    }
    await run(
      () =>
        onboarding.saveConnection(
          draft.id,
          { address: address.trim(), ssh_port: port, hostname: hostname.trim() || null },
          draft.state_version,
        ),
      'authenticate',
    );
  };

  const submitAuthenticate = async () => {
    if (!draft || !credentialId) return;
    await run(
      () =>
        onboarding.saveAuthentication(
          draft.id,
          {
            credential_id: Number(credentialId),
            ssh_security_policy_id: policyId ? Number(policyId) : null,
          },
          draft.state_version,
        ),
      'verify',
    );
  };

  const verify = async () => {
    if (!draft) return;
    setAnnouncement('Verifying. This can take a few seconds.');
    const next = await run(() => onboarding.runVerification(draft.id, draft.state_version));
    if (next) {
      setAnnouncement(
        next.verification?.verified
          ? 'Verification succeeded.'
          : 'Verification did not complete. Review the results below.',
      );
    }
  };

  const decideHostKey = async (accept: boolean) => {
    if (!draft?.host_key.fingerprint) return;
    await run(() =>
      onboarding.decideHostKey(
        draft.id,
        { accept, fingerprint: draft.host_key.fingerprint as string },
        draft.state_version,
      ),
    );
  };

  const skip = async () => {
    if (!draft) return;
    await run(() => onboarding.skipVerification(draft.id, draft.state_version), 'discover');
  };

  const discover = async () => {
    if (!draft) return;
    setAnnouncement("Reading this host's details.");
    const next = await run(() => onboarding.runDiscovery(draft.id, draft.state_version));
    if (next?.discovery?.support_mapping === 'matched') {
      advance('organize');
      setAnnouncement('Discovery complete.');
    } else if (next) {
      setAnnouncement('Praxis could not match this distribution. Choose one to continue.');
    }
  };

  const submitDiscoveryConfirmation = async () => {
    if (!draft) return;
    await run(
      () =>
        onboarding.confirmDiscovery(
          draft.id,
          {
            distro_id: chosenDistroId ? Number(chosenDistroId) : null,
            confirmed_unknown: true,
          },
          draft.state_version,
        ),
      'organize',
    );
  };

  const submitOrganize = async () => {
    if (!draft) return;
    await run(
      () =>
        onboarding.saveOrganization(
          draft.id,
          {
            group_id: groupId ? Number(groupId) : null,
            environment,
            description: description.trim() || null,
            tags,
            transport_preference: transport,
          },
          draft.state_version,
        ),
      'confirm',
    );
  };

  const loadConfirmation = useCallback(async () => {
    if (!draft) return;
    setBusy(true);
    setError(null);
    try {
      const result = await onboarding.confirmDraft(draft.id);
      setConfirmation(result);
      applyDraft(result.draft);
    } catch (err) {
      handleError(err);
    } finally {
      setBusy(false);
    }
  }, [draft, applyDraft, handleError]);

  useEffect(() => {
    if (step === 'confirm' && draft && !confirmation) {
      void loadConfirmation();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step, draft?.id]);

  const finish = async () => {
    if (!draft || !confirmation?.draft.finalize_token) return;
    setBusy(true);
    setError(null);
    try {
      const result = await onboarding.finishDraft(draft.id, {
        finalize_token: confirmation.draft.finalize_token,
        state_version: confirmation.draft.state_version,
      });
      setCompleted(result);
      advance('finish');
      toast.success(`${result.hostname} added`);
      setAnnouncement(`${result.hostname} was added.`);
    } catch (err) {
      handleError(err);
      // The confirmation is spent or stale; rebuild it so the operator sees
      // what would now be created rather than resubmitting the old view.
      setConfirmation(null);
    } finally {
      setBusy(false);
    }
  };

  const cancel = async () => {
    if (!draft) return;
    try {
      await onboarding.cancelDraft(draft.id);
    } catch {
      // Cancelling a setup that already expired is not worth an error: nothing
      // was created either way.
    }
    router.push('/system-management/all-systems');
  };

  // ---------------------------------------------------------------- render

  const addTag = () => {
    const value = tagInput.trim();
    if (value && !tags.includes(value)) setTags([...tags, value]);
    setTagInput('');
  };

  const verification = draft?.verification ?? null;
  const needsHostKeyDecision =
    !!draft?.host_key.fingerprint && draft.host_key.decision === 'pending';
  const canLeaveVerify = !!verification?.verified || !!draft?.verification_skipped;

  const stepHeading = useMemo(
    () =>
      ({
        connect: 'Where is this host?',
        authenticate: 'How should Praxis sign in?',
        verify: 'Check the connection',
        discover: 'What is this host?',
        organize: 'Where does it belong?',
        confirm: 'Review before adding',
        finish: 'Done',
      })[step],
    [step],
  );

  if (!canWrite) {
    return (
      <MainLayout>
        <Head>
          <title>Add System | Praxis</title>
        </Head>
        <PageHeader title="Add a system" />
        <Card>
          <CardBody>
            <h1 className="text-lg font-semibold text-content">
              You do not have access to add systems
            </h1>
            <p className="mt-2 text-sm text-content-muted">
              Adding a host requires the admin or maintainer role. Ask an
              administrator to add a host, or to grant you the role.
            </p>
          </CardBody>
        </Card>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Head>
        <title>Add System | Praxis</title>
      </Head>
      <PageHeader
        title="Add a system"
        actions={<HelpLink slug="guide-add-first-system" />}
      />

      {/* Status changes are announced without stealing focus. */}
      <p aria-live="polite" className="sr-only">
        {announcement}
      </p>

      <StepIndicator current={step} furthest={furthest} />

      {error && (
        <div
          role="alert"
          className="mb-4 rounded-md border border-danger/40 bg-danger/10 p-4"
        >
          <p className="text-sm text-danger">{error.message}</p>
          <p className="mt-1 font-mono text-[11px] text-content-subtle">{error.code}</p>
          {['draft_expired', 'draft_canceled', 'authority_changed'].includes(
            error.code,
          ) && (
            <p className="mt-2 text-xs text-content-muted">
              Nothing was added, so no host or licence seat was used.{' '}
              <button
                type="button"
                onClick={restart}
                className="text-link underline underline-offset-2 hover:text-link-hover"
              >
                Start again
              </button>
              .
            </p>
          )}
          {error.code === 'draft_stale' && (
            <p className="mt-2 text-xs text-content-muted">
              This setup changed somewhere else.{' '}
              <button
                type="button"
                onClick={() => router.reload()}
                className="text-link underline underline-offset-2 hover:text-link-hover"
              >
                Reload it
              </button>
              .
            </p>
          )}
          {error.code === 'duplicate_host' && (
            <p className="mt-2 text-xs text-content-muted">
              <button
                type="button"
                onClick={() => router.push('/system-management/all-systems')}
                className="text-link underline underline-offset-2 hover:text-link-hover"
              >
                Look at the systems you already have
              </button>
              .
            </p>
          )}
        </div>
      )}

      <Card>
        <CardBody>
          {loading ? (
            <p className="text-sm text-content-muted">Preparing the setup...</p>
          ) : (
            <div className="space-y-6">
              <h2
                ref={headingRef}
                tabIndex={-1}
                className="text-lg font-semibold text-content focus:outline-none"
              >
                {stepHeading}
              </h2>

              {/* ---------------------------------------------- 1. Connect */}
              {step === 'connect' && (
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
              )}

              {/* ----------------------------------------- 2. Authenticate */}
              {step === 'authenticate' && (
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
              )}

              {/* ----------------------------------------------- 3. Verify */}
              {step === 'verify' && (
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
              )}

              {/* --------------------------------------------- 4. Discover */}
              {step === 'discover' && (
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
              )}

              {/* --------------------------------------------- 5. Organize */}
              {step === 'organize' && (
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
              )}

              {/* ---------------------------------------------- 6. Confirm */}
              {step === 'confirm' && (
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
              )}

              {/* ----------------------------------------------- 7. Finish */}
              {step === 'finish' && completed && (
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
              )}

              {/* ------------------------------------------- Step controls */}
              {step !== 'finish' && (
                <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-4">
                  <Button
                    variant="ghost"
                    icon={<ArrowLeft size={14} />}
                    disabled={busy || step === 'connect'}
                    onClick={() => {
                      const index = STEP_ORDER.indexOf(step);
                      if (index > 0) setStep(STEP_ORDER[index - 1]);
                    }}
                  >
                    Back
                  </Button>
                  <div className="flex flex-wrap gap-2">
                    <Button variant="ghost" onClick={cancel} disabled={busy}>
                      Cancel
                    </Button>
                    {step === 'connect' && (
                      <Button
                        variant="primary"
                        icon={<ArrowRight size={14} />}
                        onClick={submitConnect}
                        loading={busy}
                        disabled={!address.trim()}
                      >
                        Next
                      </Button>
                    )}
                    {step === 'authenticate' && (
                      <Button
                        variant="primary"
                        icon={<ArrowRight size={14} />}
                        onClick={submitAuthenticate}
                        loading={busy}
                        disabled={!credentialId}
                      >
                        Next
                      </Button>
                    )}
                    {step === 'verify' && (
                      <Button
                        variant="primary"
                        icon={<ArrowRight size={14} />}
                        onClick={() => advance('discover')}
                        disabled={busy || !canLeaveVerify}
                      >
                        Next
                      </Button>
                    )}
                    {step === 'discover' && (
                      <Button
                        variant="primary"
                        icon={<ArrowRight size={14} />}
                        onClick={() => advance('organize')}
                        disabled={busy || !draft?.discovery}
                      >
                        Next
                      </Button>
                    )}
                    {step === 'organize' && (
                      <Button
                        variant="primary"
                        icon={<ArrowRight size={14} />}
                        onClick={submitOrganize}
                        loading={busy}
                      >
                        Next
                      </Button>
                    )}
                    {step === 'confirm' && (
                      <Button
                        variant="primary"
                        onClick={finish}
                        loading={busy}
                        disabled={!confirmation?.draft.finalize_token}
                      >
                        Add this system
                      </Button>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </CardBody>
      </Card>
    </MainLayout>
  );
};

export default OnboardSystem;
