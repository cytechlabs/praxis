import React, { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { Save, RotateCcw, Globe, Calendar, Clock, Type } from 'lucide-react';
import { fetchAppSettings, updateAppSettings } from '@/services/appSettingsService';
import { useTimestampPreferences } from '@/context/TimestampPreferencesContext';
import { normalizeTimezone } from '@/utils/formatTimestamp';
import { Button } from '@/components/ui';

const TIMEZONE_OPTIONS = [
  { value: 'UTC', label: 'UTC' },
  { value: 'America/New_York', label: 'Eastern Time (US)' },
  { value: 'America/Chicago', label: 'Central Time (US)' },
  { value: 'America/Denver', label: 'Mountain Time (US)' },
  { value: 'America/Los_Angeles', label: 'Pacific Time (US)' },
  { value: 'America/Anchorage', label: 'Alaska Time (US)' },
  { value: 'Pacific/Honolulu', label: 'Hawaii Time (US)' },
  { value: 'America/Toronto', label: 'Eastern Time (Canada)' },
  { value: 'America/Vancouver', label: 'Pacific Time (Canada)' },
  { value: 'America/Mexico_City', label: 'Mexico City' },
  { value: 'America/Sao_Paulo', label: 'Sao Paulo' },
  { value: 'America/Argentina/Buenos_Aires', label: 'Buenos Aires' },
  { value: 'Europe/London', label: 'London (GMT/BST)' },
  { value: 'Europe/Paris', label: 'Paris (CET/CEST)' },
  { value: 'Europe/Berlin', label: 'Berlin (CET/CEST)' },
  { value: 'Europe/Amsterdam', label: 'Amsterdam (CET/CEST)' },
  { value: 'Europe/Madrid', label: 'Madrid (CET/CEST)' },
  { value: 'Europe/Rome', label: 'Rome (CET/CEST)' },
  { value: 'Europe/Zurich', label: 'Zurich (CET/CEST)' },
  { value: 'Europe/Stockholm', label: 'Stockholm (CET/CEST)' },
  { value: 'Europe/Warsaw', label: 'Warsaw (CET/CEST)' },
  { value: 'Europe/Helsinki', label: 'Helsinki (EET/EEST)' },
  { value: 'Europe/Athens', label: 'Athens (EET/EEST)' },
  { value: 'Europe/Bucharest', label: 'Bucharest (EET/EEST)' },
  { value: 'Europe/Moscow', label: 'Moscow (MSK)' },
  { value: 'Europe/Istanbul', label: 'Istanbul (TRT)' },
  { value: 'Asia/Dubai', label: 'Dubai (GST)' },
  { value: 'Asia/Kolkata', label: 'India (IST)' },
  { value: 'Asia/Bangkok', label: 'Bangkok (ICT)' },
  { value: 'Asia/Singapore', label: 'Singapore (SGT)' },
  { value: 'Asia/Hong_Kong', label: 'Hong Kong (HKT)' },
  { value: 'Asia/Shanghai', label: 'Shanghai (CST)' },
  { value: 'Asia/Tokyo', label: 'Tokyo (JST)' },
  { value: 'Asia/Seoul', label: 'Seoul (KST)' },
  { value: 'Australia/Sydney', label: 'Sydney (AEST/AEDT)' },
  { value: 'Australia/Melbourne', label: 'Melbourne (AEST/AEDT)' },
  { value: 'Australia/Perth', label: 'Perth (AWST)' },
  { value: 'Pacific/Auckland', label: 'Auckland (NZST/NZDT)' },
  { value: 'Africa/Cairo', label: 'Cairo (EET)' },
  { value: 'Africa/Johannesburg', label: 'Johannesburg (SAST)' },
  { value: 'Africa/Lagos', label: 'Lagos (WAT)' },
];

const DATE_FORMAT_OPTIONS = [
  { value: 'YYYY-MM-DD', label: '2026-04-15 (ISO)' },
  { value: 'MM/DD/YYYY', label: '04/15/2026 (US)' },
  { value: 'DD/MM/YYYY', label: '15/04/2026 (EU)' },
  { value: 'DD.MM.YYYY', label: '15.04.2026 (EU alt)' },
  { value: 'MMM DD, YYYY', label: 'Apr 15, 2026' },
];

const TIME_FORMAT_OPTIONS = [
  { value: '24h', label: '14:30 (24-hour)' },
  { value: '12h', label: '2:30 PM (12-hour)' },
];

interface FormState {
  app_name: string;
  timezone: string;
  date_format: string;
  time_format: string;
}

const DEFAULTS: FormState = {
  app_name: 'Praxis',
  timezone: 'UTC',
  date_format: 'YYYY-MM-DD',
  time_format: '24h',
};

const GeneralSettingsTab: React.FC = () => {
  const { refresh: refreshTimestampPreferences } = useTimestampPreferences();
  const [form, setForm] = useState<FormState>(DEFAULTS);
  const [original, setOriginal] = useState<FormState>(DEFAULTS);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const load = async () => {
      try {
        const settings = await fetchAppSettings();
        const state: FormState = { ...DEFAULTS };
        for (const s of settings) {
          if (s.setting_key in state) {
            (state as unknown as Record<string, string>)[s.setting_key] = s.setting_value;
          }
        }
        // Coerce a legacy/bad stored timezone (e.g. `EDT`) to an allowed IANA ID
        // so Settings can't display or silently re-save the invalid durable value.
        state.timezone = normalizeTimezone(state.timezone);
        setForm(state);
        setOriginal(state);
      } catch (err) {
        toast.error(err instanceof Error ? err.message : 'Failed to load settings');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const hasChanges = JSON.stringify(form) !== JSON.stringify(original);

  const handleSave = async () => {
    setSaving(true);
    try {
      // Normalize before persisting so the durable timezone is always an allowed
      // IANA ID, never an abbreviation-like value that reached the form some other
      // way. In the normal picker flow this is a no-op.
      const normalized: FormState = { ...form, timezone: normalizeTimezone(form.timezone) };
      await updateAppSettings(normalized as unknown as Record<string, string>);
      // Reload provider state so every subscribed timestamp re-renders with the
      // new timezone/date/time preferences immediately (PRA-258).
      await refreshTimestampPreferences();
      setForm(normalized);
      setOriginal(normalized);
      toast.success('Settings saved');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const handleReset = () => setForm({ ...original });

  // Always render the currently-selected zone as an option, even if it is a
  // valid IANA id outside the curated shortlist (PRA-347 normalization can
  // yield one), so the control never shows a blank/wrong selection.
  const timezoneOptions = TIMEZONE_OPTIONS.some((tz) => tz.value === form.timezone)
    ? TIMEZONE_OPTIONS
    : [{ value: form.timezone, label: form.timezone }, ...TIMEZONE_OPTIONS];

  if (loading) {
    return <div className="text-content-muted py-8">Loading settings...</div>;
  }

  return (
    <div className="max-w-2xl">
      <div className="space-y-6">
        {/* App Name */}
        <div className="bg-surface-raised border border-border/60 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-1">
            <Type size={16} className="text-red-500" />
            <label className="text-sm font-medium text-content">Application Name</label>
          </div>
          <p className="text-xs text-content-subtle mb-2">Display name shown in the browser tab and navigation.</p>
          <input
            type="text"
            value={form.app_name}
            onChange={(e) => setForm({ ...form, app_name: e.target.value })}
            className="w-full bg-surface-sunken border border-border-strong/60 rounded px-3 py-2 text-sm text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
          />
        </div>

        {/* Timezone */}
        <div className="bg-surface-raised border border-border/60 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-1">
            <Globe size={16} className="text-red-500" />
            <label htmlFor="general-timezone" className="text-sm font-medium text-content">Timezone</label>
          </div>
          <p className="text-xs text-content-subtle mb-2">All timestamps will be displayed in this timezone. Backend always stores UTC.</p>
          <select
            id="general-timezone"
            value={form.timezone}
            onChange={(e) => setForm({ ...form, timezone: e.target.value })}
            className="w-full bg-surface-sunken border border-border-strong/60 rounded px-3 py-2 text-sm text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
          >
            {timezoneOptions.map((tz) => (
              <option key={tz.value} value={tz.value}>
                {tz.label} ({tz.value})
              </option>
            ))}
          </select>
        </div>

        {/* Date Format */}
        <div className="bg-surface-raised border border-border/60 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-1">
            <Calendar size={16} className="text-red-500" />
            <label className="text-sm font-medium text-content">Date Format</label>
          </div>
          <p className="text-xs text-content-subtle mb-2">How dates appear throughout the application.</p>
          <select
            value={form.date_format}
            onChange={(e) => setForm({ ...form, date_format: e.target.value })}
            className="w-full bg-surface-sunken border border-border-strong/60 rounded px-3 py-2 text-sm text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
          >
            {DATE_FORMAT_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>

        {/* Time Format */}
        <div className="bg-surface-raised border border-border/60 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-1">
            <Clock size={16} className="text-red-500" />
            <label className="text-sm font-medium text-content">Time Format</label>
          </div>
          <p className="text-xs text-content-subtle mb-2">12-hour or 24-hour clock display.</p>
          <div className="flex gap-4">
            {TIME_FORMAT_OPTIONS.map((opt) => (
              <label key={opt.value} className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="time_format"
                  value={opt.value}
                  checked={form.time_format === opt.value}
                  onChange={(e) => setForm({ ...form, time_format: e.target.value })}
                  className="accent-red-600"
                />
                <span className="text-sm text-content">{opt.label}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-3">
          <Button
            variant="primary"
            onClick={handleSave}
            disabled={!hasChanges || saving}
            loading={saving}
            icon={<Save size={16} />}
          >
            {saving ? 'Saving...' : 'Save Changes'}
          </Button>
          <Button
            variant="outline"
            onClick={handleReset}
            disabled={!hasChanges}
            icon={<RotateCcw size={16} />}
          >
            Reset
          </Button>
        </div>
      </div>
    </div>
  );
};

export default GeneralSettingsTab;
