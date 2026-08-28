import React from 'react';
import Head from 'next/head';

import MainLayout from '@/components/MainLayout';
import HelpLink from '@/components/help/HelpLink';
import StepIndicator from '@/components/onboarding/StepIndicator';
import {
  OnboardingErrorBanner,
  StepFooter,
} from '@/components/onboarding/OnboardingChrome';
import {
  AuthenticateStep,
  ConfirmStep,
  ConnectStep,
  DiscoverStep,
  FinishStep,
  OrganizeStep,
  VerifyStep,
} from '@/components/onboarding/OnboardingSteps';
import { Card, CardBody, PageHeader } from '@/components/ui';
import { useOnboardingWizard } from '@/hooks/useOnboardingWizard';

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
  const {
    router,
    canWrite,
    draft,
    capabilities,
    credentialOptions,
    organizationOptions,
    confirmation,
    completed,
    step,
    furthest,
    busy,
    loading,
    error,
    announcement,
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
    advance,
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
    finish,
    cancel,
    addTag,
    verification,
    needsHostKeyDecision,
    canLeaveVerify,
    stepHeading,
  } = useOnboardingWizard();

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
        <OnboardingErrorBanner
          error={error}
          onRestart={restart}
          onReload={() => router.reload()}
          onViewSystems={() => router.push('/system-management/all-systems')}
        />
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
                <ConfirmStep draft={draft} confirmation={confirmation} />
              )}

              {/* ----------------------------------------------- 7. Finish */}
              {step === 'finish' && completed && (
                <FinishStep
                  completed={completed}
                  restart={restart}
                  router={router}
                />
              )}

              {/* ------------------------------------------- Step controls */}
              {step !== 'finish' && (
                <StepFooter
                  step={step}
                  busy={busy}
                  canLeaveVerify={canLeaveVerify}
                  hasAddress={Boolean(address.trim())}
                  hasCredential={Boolean(credentialId)}
                  hasDiscovery={Boolean(draft?.discovery)}
                  canFinish={Boolean(confirmation?.draft.finalize_token)}
                  onBack={goBack}
                  onCancel={cancel}
                  onConnect={submitConnect}
                  onAuthenticate={submitAuthenticate}
                  onLeaveVerify={() => advance('discover')}
                  onLeaveDiscover={() => advance('organize')}
                  onOrganize={submitOrganize}
                  onFinish={finish}
                />
              )}
            </div>
          )}
        </CardBody>
      </Card>
    </MainLayout>
  );
};

export default OnboardSystem;
