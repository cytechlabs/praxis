import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useRouter } from 'next/router';
import { toast } from 'sonner';

import { STEP_ORDER } from '@/components/onboarding/StepIndicator';
import type {
  CompletedSystem,
  CredentialOptions,
  OrganizationOptions,
} from '@/components/onboarding/OnboardingSteps';
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
  Draft,
  OnboardingStep,
} from '@/services/onboardingService';

/**
 * Draft state and step transitions for guided onboarding.
 *
 * The draft on the server is the single source of truth: every step posts and
 * the response replaces local state, which is what makes Back safe and lets a
 * reload resume where the operator left off. Every request goes through `run`,
 * so exactly one is in flight at a time and a structured failure code reaches
 * the page unchanged. The page renders; it does not decide transitions.
 */
export function useOnboardingWizard() {
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
    let cancelled = false;

    if (router.isReady && canWrite) {
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
    }

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
    const onBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = '';
    };
    if (inProgress) {
      window.addEventListener('beforeunload', onBeforeUnload);
    }
    return () => {
      window.removeEventListener('beforeunload', onBeforeUnload);
    };
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

  const goBack = useCallback(() => {
    const index = STEP_ORDER.indexOf(step);
    if (index > 0) setStep(STEP_ORDER[index - 1]);
  }, [step]);

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
      loadConfirmation();
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


  return {
    router,
    canWrite,
    draft,
    setDraft,
    capabilities,
    setCapabilities,
    credentialOptions,
    setCredentialOptions,
    organizationOptions,
    setOrganizationOptions,
    confirmation,
    setConfirmation,
    completed,
    setCompleted,
    step,
    setStep,
    furthest,
    setFurthest,
    busy,
    setBusy,
    loading,
    setLoading,
    error,
    setError,
    announcement,
    setAnnouncement,
    address,
    setAddress,
    sshPort,
    setSshPort,
    hostname,
    setHostname,
    credentialId,
    setCredentialId,
    policyId,
    setPolicyId,
    groupId,
    setGroupId,
    environment,
    setEnvironment,
    description,
    setDescription,
    tags,
    setTags,
    tagInput,
    setTagInput,
    transport,
    setTransport,
    chosenDistroId,
    setChosenDistroId,
    headingRef,
    applyDraft,
    advance,
    handleError,
    run,
    goBack,
    restart,
    submitConnect,
    submitAuthenticate,
    verify,
    decideHostKey,
    skip,
    discover,
    submitDiscoveryConfirmation,
    submitOrganize,
    loadConfirmation,
    finish,
    cancel,
    addTag,
    verification,
    needsHostKeyDecision,
    canLeaveVerify,
    stepHeading,
  };
}
