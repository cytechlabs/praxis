import React from 'react';
import Head from 'next/head';
import Link from 'next/link';
import MainLayout from '@/components/MainLayout';
import { NotFoundState, Button } from '@/components/ui';

/**
 * PRA-274: 404 rendered inside the normal app chrome (top bar + shell) with a
 * clear way back - not a bare Next.js default page.
 */
const NotFoundPage: React.FC = () => (
  <MainLayout>
    <Head>
      <title>Not found · Praxis</title>
    </Head>
    <NotFoundState
      title="Page not found"
      description="This page doesn’t exist or may have moved. Use the workspace tabs above, or head back to the dashboard."
      action={
        <Link href="/fleet-dashboard">
          <Button variant="secondary" size="sm">Back to dashboard</Button>
        </Link>
      }
    />
  </MainLayout>
);

export default NotFoundPage;
