import { useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';
import { Button, Input, Modal, nativeSelectClass, Select } from '@/components/ui';
import {
  ActivationTokenCreated,
  TTL_PRESETS,
  createActivationToken,
} from '../../../services/activationTokenService';
import { SystemListItem, fetchAllSystems } from '../../../services/systemService';
import { Tag, fetchTags } from '../../../services/tagService';
import BootstrapCommandReveal from './BootstrapCommandReveal';

interface Props {
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}

const DEFAULT_TTL_SECONDS = 60 * 60 * 24; // 24h

const CreateActivationTokenDialog = ({ open, onClose, onCreated }: Props) => {
  const [name, setName] = useState('');
  const [systemId, setSystemId] = useState<number | ''>('');
  const [systemSearch, setSystemSearch] = useState('');
  const [tagIds, setTagIds] = useState<number[]>([]);
  const [ttlSeconds, setTtlSeconds] = useState<number>(DEFAULT_TTL_SECONDS);

  const [systems, setSystems] = useState<SystemListItem[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [created, setCreated] = useState<ActivationTokenCreated | null>(null);

  // Reset form whenever the dialog opens.
  useEffect(() => {
    if (!open) return;
    setName('');
    setSystemId('');
    setSystemSearch('');
    setTagIds([]);
    setTtlSeconds(DEFAULT_TTL_SECONDS);
    setCreated(null);
    Promise.all([fetchAllSystems(), fetchTags()])
      .then(([s, t]) => {
        setSystems(s);
        setTags(t);
      })
      .catch((err) => {
        toast.error(err instanceof Error ? err.message : 'Failed to load form data');
      });
  }, [open]);

  const filteredSystems = useMemo(() => {
    const q = systemSearch.trim().toLowerCase();
    if (!q) return systems;
    return systems.filter(
      (s) =>
        s.hostname.toLowerCase().includes(q) ||
        s.ip_address.toLowerCase().includes(q) ||
        s.group_name.toLowerCase().includes(q),
    );
  }, [systems, systemSearch]);

  const targetSystem = useMemo(
    () => (systemId === '' ? null : systems.find((s) => s.id === systemId) ?? null),
    [systems, systemId],
  );

  const canSubmit = name.trim().length > 0 && systemId !== '' && !submitting;

  const submit = async () => {
    if (systemId === '' || !targetSystem) return;
    setSubmitting(true);
    try {
      const result = await createActivationToken({
        name: name.trim(),
        // Backend validates target_system.group_id == default_group_id
        // inside issue_token; we just send the resolved group from the
        // system list so there's never a drift to chase.
        default_group_id: targetSystem.group_id,
        target_system_id: targetSystem.id,
        default_tag_ids: tagIds,
        ttl_seconds: ttlSeconds,
        max_uses: 1,
      });
      setCreated(result);
      onCreated();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Create failed');
    } finally {
      setSubmitting(false);
    }
  };

  const close = () => {
    setCreated(null);
    onClose();
  };

  return (
    <Modal open={open} onClose={close} title="Create activation token" maxWidth="max-w-2xl">
      {created ? (
        <BootstrapCommandReveal created={created} onClose={close} />
      ) : (
        <div className="space-y-4">
          <Input
            label="Name"
            placeholder="e.g. enroll-web-01"
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={255}
            required
          />

          <div className="space-y-1">
            <label className="block text-xs font-medium uppercase tracking-wider text-content-muted">
              Target system
            </label>
            <input
              type="text"
              placeholder="Search by hostname, IP, or group…"
              value={systemSearch}
              onChange={(e) => setSystemSearch(e.target.value)}
              className="w-full rounded-md border border-border-strong bg-surface-sunken/50 px-3 py-2 text-sm text-content focus-visible:border-border-strong focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
            />
            <select
              value={systemId === '' ? '' : String(systemId)}
              onChange={(e) =>
                setSystemId(e.target.value === '' ? '' : Number(e.target.value))
              }
              size={6}
              className={`w-full rounded-md border border-border-strong px-3 py-2 text-sm ${nativeSelectClass}`}
            >
              {filteredSystems.length === 0 ? (
                <option value="" disabled>
                  No systems match
                </option>
              ) : (
                filteredSystems.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.hostname} - {s.ip_address} ({s.group_name})
                  </option>
                ))
              )}
            </select>
            {targetSystem && (
              <p className="text-xs text-content-muted">
                Will enroll <strong className="text-content">{targetSystem.hostname}</strong> in
                group <strong className="text-content">{targetSystem.group_name}</strong>.
              </p>
            )}
          </div>

          <div className="space-y-1">
            <label className="block text-xs font-medium uppercase tracking-wider text-content-muted">
              Default tags (optional)
            </label>
            <select
              multiple
              size={Math.min(6, Math.max(3, tags.length))}
              value={tagIds.map(String)}
              onChange={(e) =>
                setTagIds(Array.from(e.target.selectedOptions, (o) => Number(o.value)))
              }
              className={`w-full rounded-md border border-border-strong px-3 py-2 text-sm ${nativeSelectClass}`}
            >
              {tags.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
            <p className="text-xs text-content-subtle">
              Tags are added to the host on successful enrollment, in addition to whatever is
              already attached.
            </p>
          </div>

          <Select
            label="Token lifetime"
            value={String(ttlSeconds)}
            onChange={(e) => setTtlSeconds(Number(e.target.value))}
          >
            {TTL_PRESETS.map((p) => (
              <option key={p.seconds} value={p.seconds}>
                {p.label}
              </option>
            ))}
          </Select>

          <p className="text-xs text-content-subtle">
            This token enrolls one host. After redemption it cannot be reused for a different
            system.
          </p>

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="ghost" onClick={close} disabled={submitting}>
              Cancel
            </Button>
            <Button variant="primary" onClick={submit} disabled={!canSubmit} loading={submitting}>
              Create token
            </Button>
          </div>
        </div>
      )}
    </Modal>
  );
};

export default CreateActivationTokenDialog;
