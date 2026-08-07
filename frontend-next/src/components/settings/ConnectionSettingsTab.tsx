import React, { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { apiFetch, formatApiError } from '@/utils/api';
import { Wifi, Save, RotateCcw } from 'lucide-react';
import { Button } from '@/components/ui';

interface ConnectionSettings {
  connection_timeout: number;
  max_pool_size: number;
  pool_cleanup_interval: number;
  max_idle_time: number;
  unreachable_threshold: number;
  default_ssh_port: number;
  transport_failure_threshold: number;
  transport_cooldown_seconds: number;
}

const DEFAULTS: ConnectionSettings = {
  connection_timeout: 10,
  max_pool_size: 50,
  pool_cleanup_interval: 300,
  max_idle_time: 600,
  unreachable_threshold: 2,
  default_ssh_port: 22,
  transport_failure_threshold: 3,
  transport_cooldown_seconds: 60,
};

const FIELD_META: {
  key: keyof ConnectionSettings;
  label: string;
  description: string;
  unit: string;
  min: number;
  max: number;
}[] = [
  {
    key: 'connection_timeout',
    label: 'Connection Timeout',
    description: 'How long to wait when establishing an SSH connection before giving up.',
    unit: 'seconds',
    min: 1,
    max: 120,
  },
  {
    key: 'max_pool_size',
    label: 'Max Pool Size',
    description: 'Maximum number of concurrent SSH connections held in the connection pool.',
    unit: 'connections',
    min: 1,
    max: 500,
  },
  {
    key: 'pool_cleanup_interval',
    label: 'Pool Cleanup Interval',
    description: 'How often the system checks for and removes idle connections from the pool.',
    unit: 'seconds',
    min: 30,
    max: 3600,
  },
  {
    key: 'max_idle_time',
    label: 'Max Idle Time',
    description: 'How long an unused connection stays in the pool before being closed.',
    unit: 'seconds',
    min: 60,
    max: 7200,
  },
  {
    key: 'unreachable_threshold',
    label: 'Unreachable Threshold',
    description: 'Number of consecutive connection failures before a system is marked as Unreachable.',
    unit: 'failures',
    min: 1,
    max: 100,
  },
  {
    key: 'default_ssh_port',
    label: 'Default SSH Port',
    description: 'Default port used for SSH connections when a system has no port configured.',
    unit: '',
    min: 1,
    max: 65535,
  },
  {
    key: 'transport_failure_threshold',
    label: 'Transport Failure Threshold',
    description: 'Consecutive SSH/banner/connect transport failures against a host before it enters a cooldown and its operations start failing fast.',
    unit: 'failures',
    min: 1,
    max: 20,
  },
  {
    key: 'transport_cooldown_seconds',
    label: 'Transport Cooldown',
    description: 'How long normal operations against a cooling-down host fast-fail before a retry is allowed (an explicit recheck can retry sooner).',
    unit: 'seconds',
    min: 5,
    max: 3600,
  },
];

const ConnectionSettingsTab: React.FC = () => {
  const [settings, setSettings] = useState<ConnectionSettings>(DEFAULTS);
  const [original, setOriginal] = useState<ConnectionSettings>(DEFAULTS);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      const res = await apiFetch('/api/backend/connection-settings');
      if (!res.ok) throw new Error('Failed to load connection settings');
      const data = await res.json();
      setSettings(data);
      setOriginal(data);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load settings');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const res = await apiFetch('/api/backend/connection-settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(formatApiError(err, 'Failed to save'));
      }
      const data = await res.json();
      setSettings(data);
      setOriginal(data);
      toast.success('Connection settings saved');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const handleReset = () => {
    setSettings({ ...original });
  };

  const handleRestoreDefaults = () => {
    setSettings({ ...DEFAULTS });
  };

  const hasChanges = JSON.stringify(settings) !== JSON.stringify(original);

  const handleChange = (key: keyof ConnectionSettings, value: string) => {
    const num = parseInt(value, 10);
    if (!isNaN(num)) {
      setSettings(prev => ({ ...prev, [key]: num }));
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-500" />
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Wifi className="text-red-500" size={24} />
          <div>
            <h2 className="text-lg font-semibold text-gray-200">Connection Settings</h2>
            <p className="text-sm text-gray-400">
              Global SSH connection pool and timeout configuration. Changes apply to new connections.
            </p>
          </div>
        </div>
      </div>

      <div className="grid gap-6">
        {FIELD_META.map(({ key, label, description, unit, min, max }) => {
          const isDefault = settings[key] === DEFAULTS[key];
          return (
            <div
              key={key}
              className="bg-[#0c0c0f] border border-gray-800/60 rounded-lg p-4"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  <label className="block text-sm font-medium text-gray-200 mb-1">
                    {label}
                    {!isDefault && (
                      <span className="ml-2 text-xs text-yellow-500 font-normal">modified</span>
                    )}
                  </label>
                  <p className="text-xs text-gray-400 mb-3">{description}</p>
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    value={settings[key]}
                    onChange={(e) => handleChange(key, e.target.value)}
                    min={min}
                    max={max}
                    className="w-24 bg-[#09090b] border border-gray-700/60 rounded px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600 text-right"
                  />
                  {unit && (
                    <span className="text-xs text-gray-500 w-20">{unit}</span>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-4 mt-1">
                <span className="text-xs text-gray-500">
                  Range: {min.toLocaleString()} – {max.toLocaleString()}
                </span>
                <span className="text-xs text-gray-500">
                  Default: {DEFAULTS[key].toLocaleString()}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      <div className="flex items-center justify-between mt-6 pt-4 border-t border-gray-800/60">
        <Button
          variant="outline"
          onClick={handleRestoreDefaults}
          icon={<RotateCcw size={14} />}
        >
          Restore Defaults
        </Button>
        <div className="flex items-center gap-3">
          <Button
            variant="ghost"
            onClick={handleReset}
            disabled={!hasChanges}
          >
            Discard Changes
          </Button>
          <Button
            variant="primary"
            onClick={handleSave}
            disabled={!hasChanges || saving}
            loading={saving}
            icon={<Save size={14} />}
          >
            {saving ? 'Saving...' : 'Save Settings'}
          </Button>
        </div>
      </div>
    </div>
  );
};

export default ConnectionSettingsTab;
