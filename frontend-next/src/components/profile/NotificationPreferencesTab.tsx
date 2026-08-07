import React, { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { apiFetch, formatApiError } from '@/utils/api';
import { Bell, Save } from 'lucide-react';

interface PreferencesData {
  disabled_types: string[];
  all_types: string[];
}

const CATEGORIES: { label: string; types: { key: string; label: string; description: string }[] }[] = [
  {
    label: 'Jobs',
    types: [
      { key: 'job_completed', label: 'Job Completed', description: 'A scheduled job finished successfully' },
      { key: 'job_failed', label: 'Job Failed', description: 'A scheduled job encountered errors' },
      { key: 'job_cancelled', label: 'Job Cancelled', description: 'A job was cancelled by a user' },
      { key: 'job_rollback', label: 'Job Rollback', description: 'Packages were rolled back after a failed job' },
    ],
  },
  {
    label: 'Systems',
    types: [
      { key: 'system_unreachable', label: 'System Unreachable', description: 'A system failed consecutive health checks' },
      { key: 'system_recovered', label: 'System Recovered', description: 'A previously unreachable system came back online' },
      { key: 'system_added', label: 'System Added', description: 'A new system was registered' },
      { key: 'system_removed', label: 'System Removed', description: 'A system was deleted from the platform' },
    ],
  },
  {
    label: 'Security',
    types: [
      { key: 'security_updates', label: 'Security Updates', description: 'Security vulnerabilities detected during scan' },
      { key: 'credential_change', label: 'Credential Change', description: 'A credential was created, updated, or deleted' },
      { key: 'host_key_changed', label: 'Host Key Changed', description: 'A system\'s SSH host key changed - possible MITM or OS reinstall' },
      { key: 'host_eol_approaching', label: 'Host Approaching EOL', description: 'A managed host is within 90/30/7 days of distro end of life' },
      { key: 'host_eol_reached', label: 'Host Reached EOL', description: 'A managed host has reached its distro end-of-life date' },
    ],
  },
  {
    label: 'Operations',
    types: [
      { key: 'package_scan_complete', label: 'Package Scan Complete', description: 'A package inventory scan finished' },
      { key: 'bulk_operation_complete', label: 'Bulk Operation Complete', description: 'A bulk fleet operation finished' },
    ],
  },
  // PRA-178 Slice 3: patch / compliance / remediation lifecycle events.
  // Backed by the alert_service + notification_preferences vocabulary
  // expansion in this slice; emission hooks fire beside each service's
  // existing audit event so the operator sees one notification per
  // stable state transition.
  {
    label: 'Patch Lifecycle',
    types: [
      { key: 'patch.executed', label: 'Patch Executed', description: 'A patch update execution reached a terminal state' },
      { key: 'patch.reboot_required', label: 'Reboot Required', description: 'A patched host requires a reboot for changes to take effect' },
      { key: 'patch.reboot_completed', label: 'Reboot Completed', description: 'A post-patch reboot finished (healthy or failed)' },
      { key: 'patch.rollback_started', label: 'Rollback Started', description: 'A patch rollback dispatch began on an execution' },
      { key: 'patch.rollback_completed', label: 'Rollback Completed', description: 'A patch rollback dispatch finalized' },
    ],
  },
  {
    label: 'Compliance & Remediation',
    types: [
      { key: 'compliance.evaluated', label: 'Compliance Evaluated', description: 'A compliance probe finished for a system' },
      { key: 'remediation.requested', label: 'Remediation Requested', description: 'An operator opened a remediation request for a failing finding' },
      { key: 'remediation.ready', label: 'Remediation Ready', description: 'An acknowledged plan became ready for execution' },
      { key: 'remediation.executed', label: 'Remediation Executed', description: 'A remediation execution attempt succeeded' },
      { key: 'remediation.failed', label: 'Remediation Failed', description: 'A remediation execution attempt failed' },
    ],
  },
];

const NotificationPreferencesTab: React.FC = () => {
  const [disabledTypes, setDisabledTypes] = useState<Set<string>>(new Set());
  const [original, setOriginal] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    loadPreferences();
  }, []);

  const loadPreferences = async () => {
    try {
      const res = await apiFetch('/api/backend/notification-preferences');
      if (!res.ok) throw new Error('Failed to load preferences');
      const data: PreferencesData = await res.json();
      const disabled = new Set(data.disabled_types);
      setDisabledTypes(disabled);
      setOriginal(new Set(disabled));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load preferences');
    } finally {
      setLoading(false);
    }
  };

  const handleToggle = (type: string) => {
    setDisabledTypes(prev => {
      const next = new Set(prev);
      if (next.has(type)) {
        next.delete(type);
      } else {
        next.add(type);
      }
      return next;
    });
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const res = await apiFetch('/api/backend/notification-preferences', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ disabled_types: Array.from(disabledTypes) }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(formatApiError(err, 'Failed to save'));
      }
      const data: PreferencesData = await res.json();
      const disabled = new Set(data.disabled_types);
      setDisabledTypes(disabled);
      setOriginal(new Set(disabled));
      toast.success('Notification preferences saved');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to save preferences');
    } finally {
      setSaving(false);
    }
  };

  const setsEqual = (a: Set<string>, b: Set<string>) => {
    if (a.size !== b.size) return false;
    for (const item of a) {
      if (!b.has(item)) return false;
    }
    return true;
  };

  const hasChanges = !setsEqual(disabledTypes, original);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-500" />
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center gap-3 mb-6">
        <Bell className="text-red-500" size={24} />
        <div>
          <h2 className="text-lg font-semibold text-gray-200">Notification Preferences</h2>
          <p className="text-sm text-gray-400">
            Choose which notification types appear in your notification bell. Disabled types are hidden from your feed.
          </p>
        </div>
      </div>

      <div className="space-y-6">
        {CATEGORIES.map((category) => (
          <div key={category.label} className="bg-gray-800 border border-gray-700 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-3">
              {category.label}
            </h3>
            <div className="space-y-3">
              {category.types.map(({ key, label, description }) => {
                const enabled = !disabledTypes.has(key);
                return (
                  <div key={key} className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="text-sm text-gray-200">{label}</div>
                      <div className="text-xs text-gray-500">{description}</div>
                    </div>
                    <button
                      onClick={() => handleToggle(key)}
                      className={`
                        relative inline-flex h-6 w-11 items-center rounded-full transition-colors
                        ${enabled ? 'bg-red-600' : 'bg-gray-600'}
                      `}
                    >
                      <span
                        className={`
                          inline-block h-4 w-4 transform rounded-full bg-white transition-transform
                          ${enabled ? 'translate-x-6' : 'translate-x-1'}
                        `}
                      />
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      <div className="flex justify-end mt-6 pt-4 border-t border-gray-700">
        <button
          onClick={handleSave}
          disabled={!hasChanges || saving}
          className="flex items-center gap-2 px-4 py-2 text-sm bg-red-600 text-white rounded hover:bg-red-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          <Save size={14} />
          {saving ? 'Saving...' : 'Save Preferences'}
        </button>
      </div>
    </div>
  );
};

export default NotificationPreferencesTab;
