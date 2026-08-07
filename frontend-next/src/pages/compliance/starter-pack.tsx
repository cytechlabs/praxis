/**
 * PRA-165 Slice 4: CIS-aligned starter-pack preview + admin-only seed.
 *
 * Lists every entry in the starter pack with a per-card "seeded /
 * not seeded" indicator. The Seed CTA is admin-only - the backend
 * already enforces this; the hide is for UX so an auditor never
 * sees a button that will 403.
 *
 * Seeding is idempotent: after a successful POST the page re-fetches
 * both the starter-pack list (to flip the indicator) and the policy
 * list (so the new built-ins show up immediately on the next visit).
 */
import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { Bookmark, PackageOpen, ShieldCheck } from 'lucide-react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import {
  Badge,
  Button,
  Card,
  CardBody,
  EmptyState,
  PageHeader,
  SkeletonTable,
} from '@/components/ui';
import { useAuth } from '@/context/AuthContext';
import {
  ComplianceApiError,
  CompliancePolicy,
  getStarterPack,
  listCompliancePolicies,
  seedStarterPack,
  SEVERITY_LABELS,
  severityBadgeVariant,
  StarterPackEntry,
} from '@/services/complianceService';

const ComplianceStarterPackPage: React.FC = () => {
  const [entries, setEntries] = useState<StarterPackEntry[] | null>(null);
  const [seededKeys, setSeededKeys] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [seeding, setSeeding] = useState(false);
  const { isAdmin } = useAuth();

  const refresh = useCallback(async () => {
    try {
      const [pack, policies] = await Promise.all([
        getStarterPack(),
        listCompliancePolicies({ built_in_only: true, limit: 500 }),
      ]);
      setEntries(pack);
      setSeededKeys(
        new Set(
          policies
            .map((p: CompliancePolicy) => p.starter_pack_key)
            .filter((k): k is string => k !== null),
        ),
      );
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleSeed = async () => {
    setSeeding(true);
    try {
      const result = await seedStarterPack();
      if (result.seeded.length === 0) {
        toast.success('Starter pack already up to date - nothing to seed.');
      } else {
        toast.success(
          `Seeded ${result.seeded.length} starter pack ${
            result.seeded.length === 1 ? 'policy' : 'policies'
          }.`,
        );
      }
      await refresh();
    } catch (e) {
      const msg = e instanceof ComplianceApiError ? e.message : String(e);
      toast.error(`Seed failed: ${msg}`);
    } finally {
      setSeeding(false);
    }
  };

  const totalEntries = entries?.length ?? 0;
  const seededCount = entries?.filter((e) => seededKeys.has(e.starter_pack_key)).length ?? 0;
  const allSeeded = totalEntries > 0 && seededCount === totalEntries;

  return (
    <MainLayout>
      <Head>
        <title>Compliance Starter Pack · Praxis</title>
      </Head>

      <div className="p-6 space-y-6">
        <PageHeader
          title="Compliance Starter Pack"
          subtitle="CIS-aligned spot checks. Not a compliance attestation; running them does not certify your fleet against any framework."
          actions={
            isAdmin ? (
              <Button
                variant="primary"
                onClick={handleSeed}
                loading={seeding}
                disabled={allSeeded || seeding}
              >
                <Bookmark size={14} /> {allSeeded ? 'All seeded' : 'Seed starter pack'}
              </Button>
            ) : undefined
          }
        />

        {error && (
          <Card>
            <CardBody>
              <p className="text-red-400 text-sm">
                Something went wrong. Please try again.
              </p>
            </CardBody>
          </Card>
        )}

        {entries === null ? (
          <Card>
            <CardBody>
              <SkeletonTable rows={4} cols={4} />
            </CardBody>
          </Card>
        ) : entries.length === 0 ? (
          <Card>
            <CardBody>
              <EmptyState
                icon={<PackageOpen size={32} />}
                title="No starter pack entries"
                description="The backend reports an empty starter pack; this is unexpected - contact an admin."
              />
            </CardBody>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {entries.map((e) => {
              const seeded = seededKeys.has(e.starter_pack_key);
              return (
                <Card key={e.starter_pack_key}>
                  <CardBody>
                    <div className="flex justify-between items-start mb-3">
                      <div>
                        <h2 className="text-lg font-semibold text-gray-200">
                          {e.name}
                        </h2>
                        <p className="text-xs text-gray-500 font-mono mt-1">
                          {e.starter_pack_key}
                        </p>
                      </div>
                      {seeded ? (
                        <Badge variant="success">Seeded</Badge>
                      ) : (
                        <Badge variant="neutral">Not seeded</Badge>
                      )}
                    </div>

                    <div className="flex flex-wrap gap-2 mb-3">
                      <Badge variant={severityBadgeVariant(e.severity)}>
                        {SEVERITY_LABELS[e.severity]}
                      </Badge>
                      <Badge variant="info">{e.category}</Badge>
                      <Badge variant="neutral">
                        {e.check_count} {e.check_count === 1 ? 'check' : 'checks'}
                      </Badge>
                      {e.has_coverage_pending && (
                        <Badge variant="info">
                          {e.coverage_pending_count} coverage pending
                        </Badge>
                      )}
                    </div>

                    {e.description && (
                      <p className="text-sm text-gray-300 mb-3">{e.description}</p>
                    )}

                    {e.has_coverage_pending && (
                      <p className="text-xs text-gray-400 mb-3">
                        {e.coverage_pending_count} of these checks need host
                        facts Praxis doesn&apos;t collect yet, so they show as
                        “Coverage pending” rather than pass/fail until that
                        coverage lands.
                      </p>
                    )}

                    {seeded && (
                      <Link
                        href="/compliance/policies"
                        className="text-sm text-blue-400 hover:underline inline-flex items-center gap-1"
                      >
                        <ShieldCheck size={14} /> Open in policies
                      </Link>
                    )}
                  </CardBody>
                </Card>
              );
            })}
          </div>
        )}
      </div>
    </MainLayout>
  );
};

export default ComplianceStarterPackPage;
