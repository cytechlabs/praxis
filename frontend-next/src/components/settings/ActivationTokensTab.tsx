import { useCallback, useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';
import { Plus } from 'lucide-react';
import { Button, Card, CardBody, CardHeader, ConfirmModal } from '@/components/ui';
import {
  ActivationToken,
  listActivationTokens,
  revokeActivationToken,
} from '../../services/activationTokenService';
import { fetchGroups } from '../../services/systemService';
import { Tag, fetchTags } from '../../services/tagService';
import { fetchUsers } from '../../services/userService';
import ActivationTokensTable from './activation-tokens/ActivationTokensTable';
import CreateActivationTokenDialog from './activation-tokens/CreateActivationTokenDialog';

interface UserLite {
  id: number;
  username: string;
}

const ActivationTokensTab = () => {
  const [tokens, setTokens] = useState<ActivationToken[]>([]);
  const [groupNamesById, setGroupNamesById] = useState<Record<number, string>>({});
  const [tagsById, setTagsById] = useState<Record<number, Tag>>({});
  const [usernamesById, setUsernamesById] = useState<Record<number, string>>({});
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<ActivationToken | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [tokensRes, groups, tags, users] = await Promise.all([
        listActivationTokens(),
        fetchGroups(),
        fetchTags(),
        fetchUsers(),
      ]);
      setTokens(tokensRes);
      setGroupNamesById(
        Object.fromEntries(groups.map((g) => [g.id, g.name])),
      );
      setTagsById(Object.fromEntries(tags.map((t) => [t.id, t])));
      setUsernamesById(
        Object.fromEntries(
          (users as UserLite[]).map((u) => [u.id, u.username]),
        ),
      );
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Load failed');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const onRevokeConfirm = async () => {
    if (!revokeTarget) return;
    setBusyId(revokeTarget.id);
    try {
      const updated = await revokeActivationToken(revokeTarget.id);
      setTokens((prev) => prev.map((t) => (t.id === updated.id ? updated : t)));
      toast.success(`Revoked "${updated.name}"`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Revoke failed');
    } finally {
      setBusyId(null);
      setRevokeTarget(null);
    }
  };

  const sortedTokens = useMemo(
    () => [...tokens].sort((a, b) => b.id - a.id),
    [tokens],
  );

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-slate-200">Activation tokens</h2>
            <p className="mt-1 text-xs text-slate-500">
              One-line agent enrollment. Each token binds to one pre-registered host and
              can be redeemed once.
            </p>
          </div>
          <Button
            variant="primary"
            icon={<Plus className="h-4 w-4" />}
            onClick={() => setShowCreate(true)}
          >
            New token
          </Button>
        </div>
      </CardHeader>
      <CardBody>
        {loading ? (
          <div className="py-8 text-center text-sm text-slate-500">Loading…</div>
        ) : (
          <ActivationTokensTable
            tokens={sortedTokens}
            groupNamesById={groupNamesById}
            tagsById={tagsById}
            usernamesById={usernamesById}
            onRevoke={(t) => setRevokeTarget(t)}
            busyId={busyId}
          />
        )}
      </CardBody>

      <CreateActivationTokenDialog
        open={showCreate}
        onClose={() => setShowCreate(false)}
        onCreated={load}
      />

      <ConfirmModal
        open={revokeTarget !== null}
        onClose={() => setRevokeTarget(null)}
        onConfirm={onRevokeConfirm}
        title="Revoke activation token"
        message={
          revokeTarget
            ? `Revoke "${revokeTarget.name}"? Any host that has not yet enrolled with this token will fail with "invalid activation token". This cannot be undone.`
            : ''
        }
        confirmLabel="Revoke"
        variant="danger"
        loading={busyId !== null}
      />
    </Card>
  );
};

export default ActivationTokensTab;
