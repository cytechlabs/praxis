import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Head from 'next/head';
import { useRouter } from 'next/router';
import { toast } from 'sonner';
import { AlertTriangle, ArrowLeft, ArrowRight, Info, Plus } from 'lucide-react';

import MainLayout from '@/components/MainLayout';
import HelpLink from '@/components/help/HelpLink';
import StepIndicator, { STEP_ORDER } from '@/components/onboarding/StepIndicator';
import {
  AuthenticateStep,
  ConfirmStep,
  ConnectStep,
  DiscoverStep,
  FinishStep,
  OrganizeStep,
  VerifyStep,
} from '@/components/onboarding/OnboardingSteps';
import type {
  CompletedSystem,
  CredentialOptions,
  OrganizationOptions,
} from '@/components/onboarding/OnboardingSteps';
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
import {
  cancelDraft,
  confirmDiscovery,
  confirmDraft,
  createDraft,
  fetchCredentialOptions,
  fetchDraft,
  fetchOrganizationOptions,
  finishDraft,
  OnboardingError,
  runDiscovery,
  runVerification,
  saveAuthentication,
  saveConnection,
  saveOrganization,
  skipVerification,
  decideHostKey as requestHostKeyDecision,
} from '@/services/onboardingService';
import type {
  Capabilities,
  ConfirmResponse,
  CredentialSummary,
  Draft,
  OnboardingStep,
} from '@/services/onboardingService';


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
  const [completed, setCompleted] = useState<CompletedSystem | null>(null);

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
    if (err instanceof OnboardingError) {
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
          ? await fetchDraft(existing)
          : await createDraft();
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
          fetchCredentialOptions(),
          fetchOrganizationOptions(),
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
        saveConnection(
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
        saveAuthentication(
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
    const next = await run(() => runVerification(draft.id, draft.state_version));
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
      requestHostKeyDecision(
        draft.id,
        { accept, fingerprint: draft.host_key.fingerprint as string },
        draft.state_version,
      ),
    );
  };

  const skip = async () => {
    if (!draft) return;
    await run(() => skipVerification(draft.id, draft.state_version), 'discover');
  };

  const discover = async () => {
    if (!draft) return;
    setAnnouncement("Reading this host's details.");
    const next = await run(() => runDiscovery(draft.id, draft.state_version));
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
        confirmDiscovery(
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
        saveOrganization(
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
      const result = await confirmDraft(draft.id);
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
      const result = await finishDraft(draft.id, {
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
      await cancelDraft(draft.id);
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
  const needsHostKeyDecision = Boolean(
    draft?.host_key.fingerprint && draft.host_key.decision === 'pending',
  );
  const canLeaveVerify =
    Boolean(verification?.verified) || Boolean(draft?.verification_skipped);

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
                <ConnectStep
                  address={address}
                  sshPort={sshPort}
                  hostname={hostname}
                  setAddress={setAddress}
                  setSshPort={setSshPort}
                  setHostname={setHostname}
                />
              )}

              {/* ----------------------------------------- 2. Authenticate */}
              {step === 'authenticate' && (
                <AuthenticateStep
                  capabilities={capabilities}
                  credentialOptions={credentialOptions}
                  credentialId={credentialId}
                  policyId={policyId}
                  setCredentialId={setCredentialId}
                  setPolicyId={setPolicyId}
                  router={router}
                />
              )}

              {/* ----------------------------------------------- 3. Verify */}
              {step === 'verify' && (
                <VerifyStep
                  draft={draft}
                  verification={verification}
                  needsHostKeyDecision={needsHostKeyDecision}
                  canLeaveVerify={canLeaveVerify}
                  busy={busy}
                  verify={verify}
                  skip={skip}
                  decideHostKey={decideHostKey}
                />
              )}

              {/* --------------------------------------------- 4. Discover */}
              {step === 'discover' && (
                <DiscoverStep
                  draft={draft}
                  organizationOptions={organizationOptions}
                  chosenDistroId={chosenDistroId}
                  setChosenDistroId={setChosenDistroId}
                  busy={busy}
                  discover={discover}
                  submitDiscoveryConfirmation={submitDiscoveryConfirmation}
                />
              )}

              {/* --------------------------------------------- 5. Organize */}
              {step === 'organize' && (
                <OrganizeStep
                  organizationOptions={organizationOptions}
                  groupId={groupId}
                  setGroupId={setGroupId}
                  environment={environment}
                  setEnvironment={setEnvironment}
                  description={description}
                  setDescription={setDescription}
                  transport={transport}
                  setTransport={setTransport}
                  tags={tags}
                  setTags={setTags}
                  tagInput={tagInput}
                  setTagInput={setTagInput}
                  addTag={addTag}
                />
              )}

              {/* ---------------------------------------------- 6. Confirm */}
              {step === 'confirm' && (
                <ConfirmStep
                  draft={draft}
                  confirmation={confirmation}
                  hostname={hostname}
                  environment={environment}
                  description={description}
                  tags={tags}
                />
              )}

              {/* ----------------------------------------------- 7. Finish */}
              {step === 'finish' && completed && (
                <FinishStep
                  completed={completed}
                  hostname={hostname}
                  restart={restart}
                  router={router}
                />
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
