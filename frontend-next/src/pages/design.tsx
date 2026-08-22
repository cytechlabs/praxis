import React from 'react';
import Head from 'next/head';
import { Trash2 } from 'lucide-react';
import {
  Button,
  Badge,
  StatusBadge,
  Card,
  CardHeader,
  CardBody,
  StatCard,
  Input,
  FormField,
  FormActions,
  DataTable,
  EmptyState,
  LoadingState,
  ErrorState,
  PageHeader,
  type Column,
  nativeSelectClass,
} from '@/components/ui';
import { BrandWordmark, BrandIcon } from '@/components/ui/BrandLogo';
import { UnsupportedViewportContent } from '@/components/layout/UnsupportedViewport';
import BrandedLoadingScreen from '@/components/layout/BrandedLoadingScreen';
import { MIN_SUPPORTED_WIDTH } from '@/config/viewport';

/**
 * Design foundation showcase.
 *
 * Renders the semantic tokens + representative shared components in BOTH themes
 * side by side (each panel forces its theme via `data-theme`, which the token
 * system scopes to a subtree). This is the reviewable "both modes" artifact:
 * light mode is verified at the token/shared-component level here even though
 * the global runtime default stays dark until the page sweeps.
 */

const Swatch = ({ name, className }: { name: string; className: string }) => (
  <div className="flex flex-col gap-1">
    <div className={`h-10 rounded-md border border-border ${className}`} />
    <span className="text-[11px] text-content-subtle font-mono">{name}</span>
  </div>
);

function Showcase() {
  return (
    <div className="bg-surface text-content p-6 space-y-6">
      <div className="flex items-center gap-3">
        <BrandIcon size={28} />
        <BrandWordmark height={24} />
      </div>

      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-content-muted uppercase tracking-wider">Surfaces &amp; text</h3>
        <div className="grid grid-cols-4 gap-3">
          <Swatch name="surface" className="bg-surface" />
          <Swatch name="surface-raised" className="bg-surface-raised" />
          <Swatch name="surface-overlay" className="bg-surface-overlay" />
          <Swatch name="surface-sunken" className="bg-surface-sunken" />
        </div>
        <div className="flex flex-wrap gap-4 pt-1">
          <span className="text-content">content</span>
          <span className="text-content-muted">content-muted</span>
          <span className="text-content-subtle">content-subtle</span>
        </div>
      </section>

      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-content-muted uppercase tracking-wider">Semantic roles</h3>
        <div className="grid grid-cols-4 gap-3">
          <Swatch name="brand (Signal Red)" className="bg-brand" />
          <Swatch name="danger" className="bg-danger" />
          <Swatch name="action (neutral)" className="bg-action" />
          <Swatch name="success" className="bg-success" />
          <Swatch name="warning" className="bg-warning" />
          <Swatch name="info (neutral)" className="bg-info" />
          <Swatch name="border" className="bg-border" />
          <Swatch name="border-strong" className="bg-border-strong" />
        </div>
      </section>

      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-content-muted uppercase tracking-wider">Buttons</h3>
        <div className="flex flex-wrap gap-2">
          <Button variant="primary">Primary</Button>
          <Button variant="outline">Secondary</Button>
          <Button variant="ghost">Ghost</Button>
          <Button variant="danger">Delete</Button>
          <Button variant="primary" loading>Loading</Button>
          <Button variant="outline" disabled>Disabled</Button>
        </div>
      </section>

      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-content-muted uppercase tracking-wider">Badges</h3>
        <div className="flex flex-wrap gap-2">
          <Badge variant="success">Healthy</Badge>
          <Badge variant="warning">Pending</Badge>
          <Badge variant="danger" pulse>Failed</Badge>
          <Badge variant="info">Running</Badge>
          <Badge variant="neutral">Inactive</Badge>
          <Badge variant="orange">Attention</Badge>
        </div>
      </section>

      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-content-muted uppercase tracking-wider">Links, inputs &amp; focus</h3>
        <p className="text-sm text-content-muted">
          A{' '}
          <a href="#" className="text-link hover:text-link-hover underline">
            neutral underlined link
          </a>{' '}
          turns Signal Red on hover. Tab through the controls to see the neutral focus ring.
        </p>
        <div className="max-w-sm space-y-2">
          <Input label="Hostname" placeholder="host.example.com" />
          <button className="rounded-md border border-border px-3 py-1.5 text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring">
            Focusable control
          </button>
        </div>
      </section>

      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-content-muted uppercase tracking-wider">Cards</h3>
        <div className="grid grid-cols-2 gap-3">
          <Card hover>
            <CardHeader>Neutral card</CardHeader>
            <CardBody>
              <p className="text-sm text-content-muted">
                Neutral chrome - no glow, no red top-edge gradient.
              </p>
            </CardBody>
          </Card>
          <StatCard label="Systems" value={128} subtitle="online" />
        </div>
      </section>

      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-content-muted uppercase tracking-wider">Button variants</h3>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="primary">Primary</Button>
          <Button variant="secondary">Secondary</Button>
          <Button variant="ghost">Ghost</Button>
          <Button variant="danger">Danger</Button>
          <Button variant="link">Link</Button>
          <Button variant="secondary" iconOnly aria-label="Delete" icon={<Trash2 size={15} />} />
          <Button variant="primary" loading>Submitting</Button>
        </div>
      </section>

      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-content-muted uppercase tracking-wider">StatusBadge (humanized)</h3>
        <div className="flex flex-wrap gap-2">
          <StatusBadge status="active" />
          <StatusBadge status="in_progress" />
          <StatusBadge status="not_enrolled" />
          <StatusBadge status="auth_failed" pulse />
          <StatusBadge status="queued" />
          <StatusBadge status="decommissioned" />
        </div>
      </section>

      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-content-muted uppercase tracking-wider">DataTable</h3>
        <DataTable
          density="compact"
          rowKey={(r) => r.id}
          columns={
            [
              { key: 'host', header: 'Host' },
              { key: 'status', header: 'Status', render: (r) => <StatusBadge status={r.status} /> },
              { key: 'seen', header: 'Last seen', align: 'right' },
            ] as Column<{ id: number; host: string; status: string; seen: string }>[]
          }
          rows={[
            { id: 1, host: 'web-01', status: 'active', seen: '2m ago' },
            { id: 2, host: 'db-02', status: 'auth_failed', seen: '1h ago' },
          ]}
          rowActions={() => (
            <Button variant="ghost" size="sm" iconOnly aria-label="Remove" icon={<Trash2 size={14} />} />
          )}
          pagination={{ page: 1, pageSize: 2, total: 8, onPageChange: () => {} }}
        />
      </section>

      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-content-muted uppercase tracking-wider">Form field</h3>
        <div className="max-w-sm space-y-3">
          <Input label="Hostname" placeholder="host.example.com" />
          <FormField label="Environment" required helper="Used for grouping and policy.">
            <select className={`w-full border border-border rounded-md text-sm px-3 py-2 ${nativeSelectClass}`}>
              <option>Production</option>
              <option>Staging</option>
            </select>
          </FormField>
          <FormField label="Token" required error="This field is required.">
            <input className="w-full bg-surface-sunken border border-danger rounded-md text-sm text-content px-3 py-2" />
          </FormField>
          <FormActions>
            <Button variant="ghost" size="sm">Cancel</Button>
            <Button variant="primary" size="sm">Save</Button>
          </FormActions>
        </div>
      </section>

      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-content-muted uppercase tracking-wider">
          Support boundary &amp; shells
        </h3>
        <p className="text-xs text-content-subtle">
          Desktop support minimum: {MIN_SUPPORTED_WIDTH}px. Below it, the app hides
          and this branded shell shows instead of clipped chrome.
        </p>
        <div className="grid grid-cols-2 gap-3">
          <div className="rounded-md border border-border overflow-hidden">
            <div className="h-56 flex items-center justify-center bg-surface">
              <UnsupportedViewportContent />
            </div>
          </div>
          <div className="rounded-md border border-border overflow-hidden">
            <div className="h-56 overflow-hidden">
              {/* BrandedLoadingScreen is h-screen; clip it into a preview box. */}
              <BrandedLoadingScreen label="Signing in" />
            </div>
          </div>
        </div>
      </section>

      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-content-muted uppercase tracking-wider">States</h3>
        <div className="grid grid-cols-2 gap-3">
          <div className="border border-border rounded-md">
            <LoadingState label="Loading systems…" />
          </div>
          <div className="border border-border rounded-md">
            <ErrorState onRetry={() => {}} />
          </div>
          <div className="border border-border rounded-md">
            <EmptyState variant="no-activity" />
          </div>
          <div className="border border-border rounded-md">
            <EmptyState variant="locked" action={<Button variant="secondary" size="sm">Upgrade</Button>} />
          </div>
        </div>
      </section>
    </div>
  );
}

export default function DesignShowcase() {
  return (
    <>
      <Head>
        <title>Praxis - Design Foundation</title>
      </Head>
      <div className="min-h-screen bg-surface text-content p-6 space-y-6" style={{ overflow: 'auto' }}>
        <PageHeader
          title="Design foundation"
          subtitle="Semantic tokens + shared components, verified in both themes."
        />
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div>
            <div className="text-xs font-semibold text-content-subtle uppercase tracking-wider mb-2">Dark (1.0 default)</div>
            <div data-theme="dark" className="rounded-lg border border-border overflow-hidden">
              <Showcase />
            </div>
          </div>
          <div>
            <div className="text-xs font-semibold text-content-subtle uppercase tracking-wider mb-2">Light (foundation)</div>
            <div data-theme="light" className="rounded-lg border border-border overflow-hidden">
              <Showcase />
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
