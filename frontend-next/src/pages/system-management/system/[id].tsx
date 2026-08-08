import React, { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { useAuth } from '../../../context/AuthContext';
import { useRouter } from 'next/router';
import MainLayout from '../../../components/MainLayout';
import {
  fetchSystemDetails,
  SystemDetails as SystemDetailsType,
  fetchAgentHealth,
  updateTransportPreference,
  SystemAgentHealth,
  TransportPreference,
} from '../../../services/systemService';
import TransportBadge from '../../../components/transport/TransportBadge';
import TransportPreferenceToggle from '../../../components/transport/TransportPreferenceToggle';
import { fetchTags, createTag, assignTagToSystems, removeTagFromSystems, Tag } from '../../../services/tagService';
import { apiFetch, formatApiError } from '../../../utils/api';
import { systemPackageInventoryHref } from '../../../services/packageScope';
import { ShieldCheck, ShieldOff } from 'lucide-react';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { PageHeader, Button, StatusBadge, Card, CardBody, ConfirmModal, SkeletonTable, EmptyState, Tabs } from '@/components/ui';
import ProvisionedUsersCard from '../../../components/system/ProvisionedUsersCard';
import EffectivePatchPolicyCard from '../../../components/system/EffectivePatchPolicyCard';
import HostAdvisoryCard from '../../../components/system/HostAdvisoryCard';
import HostContentProfileCard from '../../../components/profile/HostContentProfileCard';
import FileTransferPanel from '../../../components/system/FileTransferPanel';
import SystemFactsPanel from '../../../components/system/SystemFactsPanel';
import ThinAgentStatusCard from '../../../components/system/ThinAgentStatusCard';

interface EolEntry {
  system_id: number;
  hostname: string;
  distro_name: string;
  distro_version: string;
  end_of_life_date: string;
  days_until_eol: number;
}

interface ApiError {
  message: string;
}

// PRA-234: sshd allow-list compatibility check payload.
interface AllowlistResult {
  login: string;
  checked: boolean;
  blocked: boolean;
  reason: string | null;
  kind: string | null;
  source_file: string | null;
  indeterminate_reason: string | null;
  remediation: string[];
}

interface AllowlistCheck {
  system_id: number;
  hostname: string | null;
  checked: boolean;
  blocked_logins: string[];
  results: AllowlistResult[];
}

const SystemDetails = () => {
  const formatTimestamp = useFormatTimestamp();
  const { user, canWrite, isAdmin } = useAuth();
  const router = useRouter();
  const { id } = router.query;

  const [system, setSystem] = useState<SystemDetailsType | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [allTags, setAllTags] = useState<Tag[]>([]);
  const [showTagDropdown, setShowTagDropdown] = useState(false);
  const [newTagName, setNewTagName] = useState('');
  const [newTagColor, setNewTagColor] = useState('#6B7280');
  const [eolInfo, setEolInfo] = useState<EolEntry | null>(null);
  // PRA-155 #2c: Facts tab. Default to overview so existing
  // operator muscle-memory (deep-link to system detail) keeps showing
  // the same content; Facts is one click away.
  const [activeTab, setActiveTab] = useState<'overview' | 'facts'>('overview');
  // PRA-153 #4: agent-health snapshot (loaded after system details
  // so the page renders even if the broker call lags or fails).
  const [agentHealth, setAgentHealth] = useState<SystemAgentHealth | null>(null);
  const [transportSaving, setTransportSaving] = useState(false);
  // PRA-234: native sshd allow-list (AllowUsers/AllowGroups) compatibility.
  // CA trust + principals hook being healthy does NOT prove provisioned logins
  // can pass the host's account allow-list, so we surface a dedicated check.
  const [allowlist, setAllowlist] = useState<AllowlistCheck | null>(null);
  const [allowlistBusy, setAllowlistBusy] = useState(false);

  useEffect(() => {
    const fetchDetails = async () => {
      if (user && id) {
        try {
          setLoading(true);
          const [data, tagsData] = await Promise.all([
            fetchSystemDetails(Number(id)),
            fetchTags(),
          ]);
          setSystem(data);
          setAllTags(tagsData);

          // Fetch EOL status for this system
          try {
            const eolRes = await apiFetch('/api/backend/systems/eol-status');
            if (eolRes.ok) {
              const eolData = await eolRes.json();
              const sysId = Number(id);
              const found = [...eolData.eol_systems, ...eolData.warning_systems].find(
                (e: EolEntry) => e.system_id === sysId
              );
              if (found) setEolInfo(found);
            }
          } catch { /* EOL fetch is non-critical */ }

          // PRA-153 #4: agent-health is non-critical too. The badge
          // renders a "Loading…" placeholder until this resolves;
          // a broker outage leaves it at "Loading…" → null path,
          // which the badge component handles.
          try {
            const health = await fetchAgentHealth(Number(id));
            setAgentHealth(health);
          } catch { /* agent-health is non-critical */ }
        } catch (err: unknown) {
          const error = err as ApiError;
          setError(error.message || 'Failed to fetch system details');
        } finally {
          setLoading(false);
        }
      }
    };

    fetchDetails();
  }, [user, id]);

  const handleAddTag = async (tagId: number) => {
    if (!system) return;
    try {
      await assignTagToSystems(tagId, [system.id]);
      const data = await fetchSystemDetails(system.id);
      setSystem(data);
      setShowTagDropdown(false);
      toast.success('Tag added');
    } catch (err: unknown) {
      const error = err as ApiError;
      toast.error(error.message || 'Failed to add tag');
    }
  };

  const [caBusy, setCaBusy] = useState(false);
  const [showDeployConfirm, setShowDeployConfirm] = useState(false);
  const [showRevokeConfirm, setShowRevokeConfirm] = useState(false);

  // PRA-153 #4: admin-only PATCH + refetch. Backend gates this on
  // the admin role too, but we hide the toggle for non-admins so
  // they never see a broken interaction.
  const handleTransportPreferenceChange = async (next: TransportPreference) => {
    if (!system) return;
    setTransportSaving(true);
    try {
      await updateTransportPreference(system.id, next);
      // Refetch both: system details (transport_preference column)
      // and agent-health (badge_state may flip if the new pref
      // makes the current tunnel state usable or not).
      const refreshed = await fetchSystemDetails(system.id);
      setSystem(refreshed);
      // Clear the cached badge BEFORE the refetch so the UI can't
      // render a confident-but-stale state if the broker call hangs
      // or fails - e.g. switching auto→ssh while the refetch errors
      // would otherwise leave the previous "Agent connected" badge
      // showing alongside the new "Preference: ssh" line.
      setAgentHealth(null);
      try {
        const health = await fetchAgentHealth(system.id);
        setAgentHealth(health);
      } catch {
        // Couldn't reach the broker post-PATCH. Surface that
        // honestly: badge_state="unknown" is the explicit "we don't
        // know" signal - never imply agent is usable when we
        // couldn't check.
        setAgentHealth({
          system_id: system.id,
          transport_preference: next,
          agent_health: {
            state: 'unknown',
            tunnel_session_id: null,
            since_seconds: null,
            last_heartbeat_age_seconds: null,
          },
          effective_transport: next === 'ssh' ? 'ssh' : null,
          badge_state: next === 'ssh' ? 'ssh_forced' : 'unknown',
        });
      }
      toast.success(`Transport preference set to ${next}`);
    } catch (err: unknown) {
      const error = err as ApiError;
      toast.error(error.message || 'Failed to update transport preference');
    } finally {
      setTransportSaving(false);
    }
  };

  const handleDeployCATrust = async () => {
    if (!system) return;
    setShowDeployConfirm(false);
    setCaBusy(true);
    try {
      const res = await apiFetch(`/api/backend/ssh-identity/deploy/${system.id}`, { method: 'POST' });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(formatApiError(err, 'Failed to deploy'));
      }
      toast.success('CA trust deployed');
      const data = await fetchSystemDetails(system.id);
      setSystem(data);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to deploy');
    } finally {
      setCaBusy(false);
    }
  };

  const handleRevokeCATrust = async () => {
    if (!system) return;
    setShowRevokeConfirm(false);
    setCaBusy(true);
    try {
      const res = await apiFetch(`/api/backend/ssh-identity/revoke/${system.id}`, { method: 'DELETE' });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(formatApiError(err, 'Failed to revoke'));
      }
      toast.success('CA trust revoked');
      const data = await fetchSystemDetails(system.id);
      setSystem(data);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to revoke');
    } finally {
      setCaBusy(false);
    }
  };

  const handleEnrollAccessBroker = async () => {
    if (!system) return;
    setCaBusy(true);
    try {
      const res = await apiFetch(`/api/backend/ssh-identity/systems/${system.id}/enroll-access-broker`, { method: 'POST' });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(formatApiError(err, 'Enrollment failed'));
      }
      // PRA-234: enrollment now returns a proactive allow-list check. CA trust +
      // principals hook succeeding does NOT prove provisioned logins pass host
      // sshd AllowUsers/AllowGroups policy, so consume the result and warn
      // instead of unconditionally reporting success.
      const data = await res.json().catch(() => ({}));
      const enrollAllowlist: AllowlistCheck | undefined = data?.allowlist;
      if (enrollAllowlist) {
        setAllowlist(enrollAllowlist);
      }
      const blocked: string[] = enrollAllowlist?.blocked_logins ?? data?.allowlist_blocked_logins ?? [];
      if (blocked.length > 0) {
        toast.error(`Enrolled, but ${blocked.length} provisioned login(s) are blocked by host sshd allow-list policy`);
      } else if (enrollAllowlist && !enrollAllowlist.checked) {
        toast.message('Enrolled - allow-list not verified; could not read effective sshd policy');
      } else {
        toast.success('Access broker enrolled');
      }
      setSystem(await fetchSystemDetails(system.id));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Enrollment failed');
    } finally {
      setCaBusy(false);
    }
  };

  const handleRevokePrincipalsHook = async () => {
    if (!system) return;
    setCaBusy(true);
    try {
      const res = await apiFetch(`/api/backend/ssh-identity/systems/${system.id}/revoke-principals-hook`, { method: 'POST' });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(formatApiError(err, 'Disable failed'));
      }
      toast.success('Access broker disabled (CA trust retained)');
      setSystem(await fetchSystemDetails(system.id));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Disable failed');
    } finally {
      setCaBusy(false);
    }
  };

  const handleSelfTest = async () => {
    if (!system) return;
    setCaBusy(true);
    try {
      const res = await apiFetch(`/api/backend/ssh-identity/systems/${system.id}/self-test`, { method: 'POST' });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(formatApiError(err, 'Self-test failed'));
      }
      toast.success('Self-test OK - cert auth works');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Self-test failed');
    } finally {
      setCaBusy(false);
    }
  };

  // PRA-234: probe effective sshd AllowUsers/AllowGroups policy for provisioned
  // logins so the operator learns about account-gate denials here, instead of
  // hitting a generic "Authentication failed" on Connect.
  const handleCheckAllowlist = async () => {
    if (!system) return;
    setAllowlistBusy(true);
    try {
      const res = await apiFetch(`/api/backend/ssh-identity/systems/${system.id}/check-allowlist`, { method: 'POST' });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(formatApiError(err, 'Allow-list check failed'));
      }
      const data: AllowlistCheck = await res.json();
      setAllowlist(data);
      if (data.blocked_logins.length > 0) {
        toast.error(`${data.blocked_logins.length} provisioned login(s) blocked by host sshd policy`);
      } else if (!data.checked) {
        toast.message('Allow-list not verified - could not read effective sshd policy');
      } else {
        toast.success('All provisioned logins pass host sshd allow-list policy');
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Allow-list check failed');
    } finally {
      setAllowlistBusy(false);
    }
  };

  const handleRemoveTag = async (tagId: number) => {
    if (!system) return;
    try {
      await removeTagFromSystems(tagId, [system.id]);
      const data = await fetchSystemDetails(system.id);
      setSystem(data);
      toast.success('Tag removed');
    } catch (err: unknown) {
      const error = err as ApiError;
      toast.error(error.message || 'Failed to remove tag');
    }
  };

  const handleCreateAndAddTag = async () => {
    if (!system || !newTagName.trim()) return;
    try {
      const tag = await createTag({ name: newTagName.trim(), color: newTagColor });
      setAllTags(prev => [...prev, tag]);
      await assignTagToSystems(tag.id, [system.id]);
      const data = await fetchSystemDetails(system.id);
      setSystem(data);
      setNewTagName('');
      setShowTagDropdown(false);
      toast.success(`Tag '${tag.name}' created and added`);
    } catch (err: unknown) {
      const error = err as ApiError;
      toast.error(error.message || 'Failed to create tag');
    }
  };

  const availableTags = allTags.filter(
    t => !system?.tags?.some(st => st.id === t.id)
  );


  return (
    <MainLayout>
        <Head>
          <title>System Details | Praxis</title>
        </Head>
        <PageHeader
          title={loading ? 'Loading System Details...' : system ? system.hostname : 'System Details'}
          actions={
            <div className="flex gap-2">
              {system && system.principals_hook_deployed && (
                <Button variant="primary" onClick={() => router.push(`/hosts/${system.id}/session`)}>
                  Connect
                </Button>
              )}
              <Button variant="ghost" onClick={() => router.push('/system-management/all-systems')}>
                ← Back to All Systems
              </Button>
            </div>
          }
        />

        {error && (
          <div className="mb-4 p-4 bg-red-900/40 border border-red-700 text-red-200 rounded" role="alert">
            {error}
          </div>
        )}

        {/* EOL warning banner */}
        {eolInfo && (
          <div className={`mb-4 p-4 rounded border ${
            eolInfo.days_until_eol < 0
              ? 'bg-red-900/30 border-red-700 text-red-300'
              : 'bg-yellow-900/30 border-yellow-700 text-yellow-300'
          }`}>
            <span className="font-medium">
              {eolInfo.days_until_eol < 0
                ? `Distro EOL: ${eolInfo.distro_name} ${eolInfo.distro_version} reached end of life ${Math.abs(eolInfo.days_until_eol)} days ago (${eolInfo.end_of_life_date})`
                : `Distro EOL Soon: ${eolInfo.distro_name} ${eolInfo.distro_version} reaches end of life in ${eolInfo.days_until_eol} days (${eolInfo.end_of_life_date})`
              }
            </span>
          </div>
        )}

        {/* PRA-44 + PRA-138: Access broker enrollment panel */}
        {system && canWrite && (() => {
          const caOn = !!system.ca_trust_deployed;
          const hookOn = !!system.principals_hook_deployed;
          const status = hookOn ? 'enrolled' : caOn ? 'partial' : 'not_enrolled';
          return (
            <div className="mb-4 bg-gray-800 border border-gray-700 rounded-lg p-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                {status === 'enrolled' ? (
                  <ShieldCheck className="text-green-400" size={24} />
                ) : (
                  <ShieldOff className="text-gray-500" size={24} />
                )}
                <div>
                  <div className="text-sm font-medium text-gray-200">
                    Access Broker
                  </div>
                  <div className="text-xs text-gray-400">
                    {status === 'enrolled' && `Enrolled ${system.principals_hook_deployed_at ? formatTimestamp(system.principals_hook_deployed_at) : ''} - sshd trusts the Praxis CA and resolves principals per-login. Run Check access to confirm host AllowUsers/AllowGroups policy admits provisioned logins.`}
                    {status === 'partial' && `CA trust deployed ${system.ca_trust_deployed_at ? formatTimestamp(system.ca_trust_deployed_at) : ''} - principals hook not installed; finish enrollment to allow fleet-role based access`}
                    {status === 'not_enrolled' && 'Not enrolled - SSH connections use stored credentials only'}
                  </div>
                </div>
              </div>
              <div className="flex gap-2">
                {status === 'enrolled' && (
                  <>
                    <Button size="sm" variant="ghost" onClick={handleCheckAllowlist} disabled={allowlistBusy} loading={allowlistBusy}>
                      Check access
                    </Button>
                    <Button size="sm" variant="ghost" onClick={handleSelfTest} disabled={caBusy} loading={caBusy}>
                      Self-test
                    </Button>
                    <Button size="sm" variant="outline" onClick={handleRevokePrincipalsHook} disabled={caBusy} loading={caBusy}>
                      Disable
                    </Button>
                  </>
                )}
                {status === 'partial' && (
                  <>
                    <Button size="sm" variant="primary" onClick={handleEnrollAccessBroker} disabled={caBusy} loading={caBusy}>
                      {caBusy ? 'Working...' : 'Finish Enrollment'}
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => setShowRevokeConfirm(true)} disabled={caBusy}>
                      Revoke CA
                    </Button>
                  </>
                )}
                {status === 'not_enrolled' && (
                  <Button size="sm" variant="primary" onClick={handleEnrollAccessBroker} disabled={caBusy} loading={caBusy}>
                    {caBusy ? 'Enrolling...' : 'Enroll Access Broker'}
                  </Button>
                )}
              </div>
            </div>
          );
        })()}

        {/* PRA-234: native sshd allow-list compatibility result. A healthy CA +
            principals hook does not guarantee provisioned logins pass the host's
            AllowUsers/AllowGroups gate; this banner reports blocked logins with
            explicit, operator-owned remediation instead of a silent Connect failure. */}
        {system && canWrite && allowlist && allowlist.blocked_logins.length > 0 && (
          <div className="mb-4 p-4 rounded border bg-red-900/30 border-red-700 text-red-200" role="alert">
            <div className="font-medium mb-2">
              Access Broker blocked by host sshd allow-list policy
            </div>
            <div className="text-sm space-y-3">
              {allowlist.results.filter(r => r.blocked).map(r => (
                <div key={r.login}>
                  <div>{r.reason}</div>
                  {r.remediation.length > 0 && (
                    <ul className="list-disc list-inside mt-1 text-red-300/90">
                      {r.remediation.map((rem, i) => (
                        <li key={i}>{rem}</li>
                      ))}
                    </ul>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
        {system && canWrite && allowlist && allowlist.checked && allowlist.blocked_logins.length === 0 && (
          <div className="mb-4 p-3 rounded border bg-green-900/20 border-green-800 text-green-300 text-sm" role="status">
            All provisioned logins pass this host&apos;s sshd AllowUsers/AllowGroups policy.
          </div>
        )}

        {/* PRA-155 #2c: tabs above the detail surface. Overview keeps
            the existing card + auxiliary panels; Facts renders the
            inventory panel against /systems/{id}/facts. */}
        {system && (
          <div className="mb-4">
            <Tabs
              tabs={[
                { id: 'overview', label: 'Overview' },
                { id: 'facts', label: 'Facts' },
              ]}
              active={activeTab}
              onChange={(id) => setActiveTab(id as 'overview' | 'facts')}
            />
          </div>
        )}

        {system && activeTab === 'facts' && (
          <Card>
            <CardBody>
              <SystemFactsPanel systemId={system.id} canRefresh={isAdmin} />
            </CardBody>
          </Card>
        )}

        {activeTab === 'overview' && loading ? (
          <Card>
            <CardBody>
              <SkeletonTable rows={6} cols={2} />
            </CardBody>
          </Card>
        ) : activeTab === 'overview' && system ? (
          <Card>
            <CardBody>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Basic Information Section */}
              <div className="md:col-span-2">
                <h2 className="text-xl font-semibold text-gray-200 mb-4">Basic Information</h2>
                <div className="bg-gray-900/30 p-4 rounded-lg border border-gray-800">
                  <div className="flex justify-between items-center mb-4">
                    <div>
                      <h3 className="text-lg font-medium text-gray-200">{system.hostname}</h3>
                      <p className="text-gray-400">{system.ip_address}</p>
                    </div>
                    <div className="flex items-center gap-3">
                      <StatusBadge status={system.status} />
                      {/* PRA-153 #4: full-form transport badge. Visible
                          to all roles; only admin sees the toggle below. */}
                      <TransportBadge
                        badgeState={agentHealth?.badge_state}
                        transportPreference={system.transport_preference ?? agentHealth?.transport_preference}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <p className="text-sm text-gray-400">Distribution</p>
                      <p className="text-gray-200">
                        <span className="font-medium">{system.distribution.name}</span>
                        <span className="ml-1 text-gray-400">{system.os_version}</span>
                      </p>
                    </div>
                    <div>
                      <p className="text-sm text-gray-400">Group</p>
                      <p className="text-gray-200">{system.group.name}</p>
                    </div>
                    <div>
                      <p className="text-sm text-gray-400">Registered At</p>
                      <p className="text-gray-200">{formatTimestamp(system.registered_at)}</p>
                    </div>
                    <div>
                      <p className="text-sm text-gray-400">Update Policy</p>
                      <p className="text-gray-200">{system.update_policy || 'Not specified'}</p>
                    </div>
                    <div className="md:col-span-2">
                      <p className="text-sm text-gray-400 mb-1">Tags</p>
                      <div className="flex flex-wrap gap-2 items-center">
                        {system.tags && system.tags.length > 0 ? (
                          system.tags.map(tag => (
                            <span
                              key={tag.id}
                              className="px-2 py-0.5 rounded-full text-xs text-white inline-flex items-center gap-1"
                              style={{ backgroundColor: tag.color }}
                            >
                              {tag.name}
                              {canWrite && (
                                <button
                                  onClick={() => handleRemoveTag(tag.id)}
                                  className="ml-0.5 hover:text-red-200 font-bold"
                                  aria-label="Remove tag" title="Remove tag"
                                >
                                  x
                                </button>
                              )}
                            </span>
                          ))
                        ) : (
                          <span className="text-gray-500 text-sm">No tags assigned</span>
                        )}
                        {canWrite && (
                          <div className="relative">
                            <button
                              onClick={() => setShowTagDropdown(!showTagDropdown)}
                              className="px-2 py-0.5 rounded-full text-xs border border-dashed border-gray-500 text-gray-400 hover:border-red-500 hover:text-red-400"
                            >
                              + Add Tag
                            </button>
                            {showTagDropdown && (
                              <div className="absolute top-8 left-0 z-50 bg-gray-800 border border-gray-800 rounded-lg p-3 w-64 shadow-lg">
                                {availableTags.length > 0 && (
                                  <div className="mb-2 max-h-32 overflow-y-auto">
                                    <p className="text-xs text-gray-400 mb-1">Existing tags</p>
                                    {availableTags.map(tag => (
                                      <button
                                        key={tag.id}
                                        onClick={() => handleAddTag(tag.id)}
                                        className="flex items-center gap-2 w-full text-left px-2 py-1 rounded hover:bg-gray-700 text-sm text-gray-300"
                                      >
                                        <span className="w-3 h-3 rounded-full inline-block flex-shrink-0" style={{ backgroundColor: tag.color }} />
                                        {tag.name}
                                      </button>
                                    ))}
                                  </div>
                                )}
                                <div className="border-t border-gray-700 pt-2">
                                  <p className="text-xs text-gray-400 mb-1">Create new tag</p>
                                  <div className="flex gap-2">
                                    <input
                                      type="color"
                                      value={newTagColor}
                                      onChange={e => setNewTagColor(e.target.value)}
                                      className="w-8 h-8 rounded cursor-pointer bg-transparent border-0"
                                    />
                                    <input
                                      type="text"
                                      value={newTagName}
                                      onChange={e => setNewTagName(e.target.value)}
                                      placeholder="Tag name"
                                      className="flex-1 bg-gray-900 border border-gray-600 rounded px-2 py-1 text-sm text-gray-200 focus:outline-none focus:border-red-500"
                                      onKeyDown={e => e.key === 'Enter' && handleCreateAndAddTag()}
                                    />
                                    <Button
                                      variant="primary"
                                      size="sm"
                                      onClick={handleCreateAndAddTag}
                                      disabled={!newTagName.trim()}
                                    >
                                      Add
                                    </Button>
                                  </div>
                                </div>
                                <button
                                  onClick={() => setShowTagDropdown(false)}
                                  className="mt-2 text-xs text-gray-500 hover:text-gray-300 w-full text-center"
                                >
                                  Close
                                </button>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* PRA-338: thin-agent status (enrollment lifecycle + broker
                  tunnel liveness + version/last-seen), kept as its own
                  clearly-labeled section distinct from the SSH access broker
                  panel above and the transport routing toggle below. Fetches
                  independently and degrades to "unavailable" on broker/API
                  failure, so it never stalls the rest of host detail. */}
              <ThinAgentStatusCard systemId={system.id} isAdmin={isAdmin} />

              {/* PRA-153 #4: admin-only transport preference toggle.
                  Maintainers + auditors see the badge above but no
                  toggle. Switching to "agent" prompts a confirmation
                  inside the toggle component. */}
              {isAdmin && (
                <div className="md:col-span-2">
                  <h2 className="text-xl font-semibold text-gray-200 mb-4">Transport</h2>
                  <div className="bg-gray-900/30 p-4 rounded-lg border border-gray-800">
                    <div className="flex flex-col gap-3">
                      <p className="text-sm text-gray-400">
                        Routing preference for non-interactive ops on this host (command exec, file transfer, facts). <span className="text-gray-300">Auto</span> uses the agent when its tunnel is healthy and SSH otherwise; <span className="text-gray-300">SSH</span> always uses SSH; <span className="text-gray-300">Agent</span> forces the agent and disables SSH fallback for those supported ops.
                      </p>
                      <p className="text-xs text-gray-500">
                        Interactive browser terminal sessions always use SSH regardless of this setting - the agent does not provide browser shells in this release. <span className="text-gray-400">Connect</span> requires SSH reachability and deployed CA trust.
                      </p>
                      <TransportPreferenceToggle
                        value={(system.transport_preference ?? 'auto') as TransportPreference}
                        onChange={handleTransportPreferenceChange}
                        disabled={transportSaving}
                      />
                    </div>
                  </div>
                </div>
              )}

              {/* Metadata Section */}
              {system.metadata && (
                <div className="md:col-span-2">
                  <h2 className="text-xl font-semibold text-gray-200 mb-4">System Metadata</h2>
                  <div className="bg-gray-900/30 p-4 rounded-lg border border-gray-800">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div>
                        <p className="text-sm text-gray-400">Environment</p>
                        <p className="text-gray-200">{system.metadata.environment_type || 'Not specified'}</p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-400">Owner Contact</p>
                        <p className="text-gray-200">{system.metadata.owner_contact || 'Not specified'}</p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-400">SSH Port</p>
                        <p className="text-gray-200">{system.metadata.ssh_port || '22'}</p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-400">Connection Status</p>
                        <p className="text-gray-200">{system.metadata.connection_status || 'Unknown'}</p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-400">Last Connection</p>
                        <p className="text-gray-200">
                          {system.metadata.last_connection
                            ? formatTimestamp(system.metadata.last_connection)
                            : 'Never connected'}
                        </p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-400">Location</p>
                        <p className="text-gray-200">{system.metadata.location || 'Not specified'}</p>
                      </div>
                      {system.metadata.cpu_arch && (
                        <div>
                          <p className="text-sm text-gray-400">CPU Architecture</p>
                          <p className="text-gray-200">{system.metadata.cpu_arch}</p>
                        </div>
                      )}
                      {system.metadata.cpu_cores && (
                        <div>
                          <p className="text-sm text-gray-400">CPU Cores</p>
                          <p className="text-gray-200">{system.metadata.cpu_cores}</p>
                        </div>
                      )}
                      {system.metadata.memory_total && (
                        <div>
                          <p className="text-sm text-gray-400">Memory</p>
                          <p className="text-gray-200">{Math.round(system.metadata.memory_total / (1024 * 1024 * 1024))} GB</p>
                        </div>
                      )}
                      {system.metadata.disk_total && (
                        <div>
                          <p className="text-sm text-gray-400">Disk Space</p>
                          <p className="text-gray-200">{Math.round(system.metadata.disk_total / (1024 * 1024 * 1024))} GB</p>
                        </div>
                      )}
                      {system.metadata.maintenance_window && (
                        <div>
                          <p className="text-sm text-gray-400">Maintenance Window</p>
                          <p className="text-gray-200">{system.metadata.maintenance_window}</p>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* Actions Section */}
              <div className="md:col-span-2 mt-4">
                {/* PRA-270: Connect (header) is the single primary command for
                    this view; these supporting navigations are all secondary. */}
                <div className="flex justify-end space-x-4">
                  <Button variant="secondary" onClick={() => router.push(`/ssh/command-execution?system_id=${system.id}`)}>
                    Run Command
                  </Button>
                  <Button variant="secondary" onClick={() => router.push(`/system-management/edit/${system.id}`)}>
                    Edit System
                  </Button>
                  <Button variant="secondary" onClick={() => router.push(systemPackageInventoryHref(system.id))}>
                    View Packages
                  </Button>
                </div>
              </div>
            </div>
            </CardBody>
          </Card>
        ) : activeTab === 'overview' ? (
          <EmptyState title="System not found" description="The system you are looking for does not exist or has been removed." />
        ) : null}

        {/* Auxiliary panels live inside the Overview tab so the Facts
            tab stays a focused inventory surface. */}
        {activeTab === 'overview' && system && (
          <ProvisionedUsersCard
            systemId={system.id}
            systemHostname={system.hostname}
            principalsHookDeployed={system.principals_hook_deployed}
          />
        )}

        {activeTab === 'overview' && system && (
          <EffectivePatchPolicyCard systemId={system.id} />
        )}

        {activeTab === 'overview' && system && (
          <HostContentProfileCard systemId={system.id} canWrite={canWrite} />
        )}

        {activeTab === 'overview' && system && (
          <HostAdvisoryCard systemId={system.id} />
        )}

        {activeTab === 'overview' && system && system.principals_hook_deployed && (
          <FileTransferPanel systemId={system.id} systemHostname={system.hostname} />
        )}

      {/* Deploy CA Trust Confirmation */}
      <ConfirmModal
        open={showDeployConfirm}
        onClose={() => setShowDeployConfirm(false)}
        onConfirm={handleDeployCATrust}
        title="Deploy CA Trust"
        message={`Deploy Vault SSH CA trust to ${system?.hostname || ''}? This will push the CA public key and reload sshd.`}
        confirmLabel="Deploy"
        variant="warning"
        loading={caBusy}
      />

      {/* Revoke CA Trust Confirmation */}
      <ConfirmModal
        open={showRevokeConfirm}
        onClose={() => setShowRevokeConfirm(false)}
        onConfirm={handleRevokeCATrust}
        title="Revoke CA Trust"
        message={`Revoke CA trust from ${system?.hostname || ''}? Future SSH connections will fall back to credential auth.`}
        confirmLabel="Revoke"
        variant="danger"
        loading={caBusy}
      />
    </MainLayout>
  );
};

export default SystemDetails;
