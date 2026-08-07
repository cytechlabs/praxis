import { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';
import { Play, RefreshCw, Users } from 'lucide-react';
import { Badge, Button, Card, CardBody, CardHeader, EmptyState } from '@/components/ui';
import {
  HostUserState,
  listHostUsers,
  reconcileSystem,
} from '../../services/fleetAccessService';
import { humanizeStatus } from '@/utils/humanize';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

interface Props {
  systemId: number;
  systemHostname?: string;
  principalsHookDeployed?: boolean;
}

const stateVariant = (state: HostUserState['state']) => {
  switch (state) {
    case 'provisioned':
      return 'success';
    case 'pending':
    case 'pending_removal':
      return 'warning';
    case 'error':
      return 'danger';
    case 'removed':
      return 'neutral';
    default:
      return 'neutral';
  }
};

const ProvisionedUsersCard = ({ systemId, systemHostname, principalsHookDeployed }: Props) => {
  const formatTimestamp = useFormatTimestamp();
  const [rows, setRows] = useState<HostUserState[]>([]);
  const [loading, setLoading] = useState(true);
  const [reconciling, setReconciling] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setRows(await listHostUsers(systemId));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load provisioned users');
    } finally {
      setLoading(false);
    }
  }, [systemId]);

  useEffect(() => { load(); }, [load]);

  const handleReconcile = async () => {
    setReconciling(true);
    try {
      const r = await reconcileSystem(systemId);
      toast.success(
        `${systemHostname || 'Host'}: ${r.provisioned} provisioned, ${r.removed} removed, ${r.errors} errors`,
      );
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Reconcile failed');
    } finally {
      setReconciling(false);
    }
  };

  return (
    <Card className="mt-4">
      <CardHeader
        action={
          <div className="flex gap-2">
            <Button variant="ghost" size="sm" onClick={load} disabled={loading}>
              <RefreshCw size={14} className="mr-1" /> Refresh
            </Button>
            <Button variant="primary" size="sm" onClick={handleReconcile} disabled={reconciling}>
              <Play size={14} className="mr-1" />
              {reconciling ? 'Reconciling…' : 'Reconcile Host'}
            </Button>
          </div>
        }
      >
        <div>
          <div>Provisioned Users</div>
          <div className="text-xs font-normal text-gray-500 mt-0.5">
            Linux accounts Praxis manages on this host.
          </div>
        </div>
      </CardHeader>
      <CardBody>
        {principalsHookDeployed === false && (
          <div className="mb-3 rounded-md bg-amber-500/10 border border-amber-500/30 p-3 text-xs text-amber-200">
            Access broker not enrolled on this host. Provisioned accounts will be created
            but sshd will not yet consult <code className="font-mono">/etc/praxis/principals.d/</code>.
            Enroll via the panel above to wire up cert-based login.
          </div>
        )}
        {loading ? (
          <div className="text-gray-500 text-sm">Loading…</div>
        ) : rows.length === 0 ? (
          <EmptyState
            title="No managed accounts"
            description="Praxis has not provisioned any accounts on this host yet. Create an access binding and reconcile."
            icon={<Users size={28} />}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wide text-gray-500 border-b border-gray-800">
                  <th className="py-2 pr-4">Login</th>
                  <th className="py-2 pr-4">Mode</th>
                  <th className="py-2 pr-4">State</th>
                  <th className="py-2 pr-4">Last reconciled</th>
                  <th className="py-2 pr-4">Details</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(r => (
                  <tr key={r.id} className="border-b border-gray-900 hover:bg-white/5">
                    <td className="py-3 pr-4 font-mono text-gray-300">{r.login}</td>
                    <td className="py-3 pr-4 text-gray-400 text-xs">{r.mode}</td>
                    <td className="py-3 pr-4">
                      <Badge variant={stateVariant(r.state)}>{humanizeStatus(r.state)}</Badge>
                    </td>
                    <td className="py-3 pr-4 text-gray-400 text-xs">
                      {r.last_reconciled_at ? formatTimestamp(r.last_reconciled_at) : '-'}
                    </td>
                    <td className="py-3 pr-4 text-xs text-gray-400 truncate max-w-xs">
                      {r.state === 'error' && r.last_error ? (
                        <span className="text-red-400">{r.last_error}</span>
                      ) : r.state === 'removed' && r.home_archive_path ? (
                        <span title={r.home_archive_path}>archived: {r.home_archive_path.split('/').pop()}</span>
                      ) : (
                        '-'
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardBody>
    </Card>
  );
};

export default ProvisionedUsersCard;
