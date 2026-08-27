import React, { useEffect } from 'react';
import Head from 'next/head';
import { useRouter } from 'next/router';

import MainLayout from '@/components/MainLayout';
import { Card, CardBody, PageHeader } from '@/components/ui';

/**
 * The former single-page registration form.
 *
 * Adding a host now runs through the guided flow, which connects, verifies and
 * discovers before anything is created. Existing bookmarks and in-app links
 * keep working: this forwards to the wizard and carries any query parameters
 * with it, so a deep link does not lose what it was carrying.
 *
 * Registering through the API directly is unchanged.
 */
const RegisterSystemRedirect: React.FC = () => {
  const router = useRouter();

  useEffect(() => {
    if (!router.isReady) return;
    router.replace({
      pathname: '/system-management/onboard',
      query: router.query,
    });
  }, [router]);

  return (
    <MainLayout>
      <Head>
        <title>Add System | Praxis</title>
      </Head>
      <PageHeader title="Add a system" />
      <Card>
        <CardBody>
          <p className="text-sm text-content-muted" role="status">
            Taking you to the guided setup...
          </p>
        </CardBody>
      </Card>
    </MainLayout>
  );
};

export default RegisterSystemRedirect;
