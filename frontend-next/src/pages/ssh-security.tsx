import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/router';
import { useAuth } from '../context/AuthContext';
import { apiFetch, formatApiError } from '../utils/api';
import MainLayout from '../components/MainLayout';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { PageHeader, Button, Card, CardBody, Badge, statusToBadgeVariant, ConfirmModal, EmptyState, SkeletonTable } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';

interface SSHSecurityPolicy {
  id: number;
  name: string;
  description?: string;
  max_auth_tries: number;
  connection_timeout: number;
  idle_timeout: number;
  require_host_key_verification: boolean;
  minimum_key_size: number;
  allowed_auth_methods: string;
  allowed_ciphers: string;
  allowed_macs: string;
  allowed_kex: string;
  log_commands: boolean;
  log_file_transfers: boolean;
  created_at?: string;
  updated_at?: string;
  created_by: number;
}

interface SSHSecurityLog {
  id: number;
  system_id: number;
  event_type: string;
  source_ip?: string;
  username?: string;
  success: boolean;
  event_details?: string;
  timestamp?: string;
}

interface SSHHostKey {
  id: number;
  system_id: number;
  hostname: string;
  key_type: string;
  public_key: string;
  fingerprint: string;
  verified: boolean;
  first_seen?: string;
  last_seen?: string;
}

export default function SSHSecurityPage() {
  const formatTimestamp = useFormatTimestamp();
  const router = useRouter();
  const { user, loading: authLoading } = useAuth();
  const [activeTab, setActiveTab] = useState('policies');
  const [policies, setPolicies] = useState<SSHSecurityPolicy[]>([]);
  const [logs, setLogs] = useState<SSHSecurityLog[]>([]);
  const [hostKeys, setHostKeys] = useState<SSHHostKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<SSHSecurityPolicy | null>(null);
  const [reviewingHostKey, setReviewingHostKey] = useState<SSHHostKey | null>(null);

  // Confirm modal state
  const [showDeletePolicyConfirm, setShowDeletePolicyConfirm] = useState(false);
  const [deletePolicyId, setDeletePolicyId] = useState<number | null>(null);
  const [showDeleteHostKeyConfirm, setShowDeleteHostKeyConfirm] = useState(false);
  const [deleteHostKeyId, setDeleteHostKeyId] = useState<number | null>(null);

  const [newPolicy, setNewPolicy] = useState<Partial<SSHSecurityPolicy>>({
    name: '',
    description: '',
    max_auth_tries: 3,
    connection_timeout: 10,
    idle_timeout: 600,
    require_host_key_verification: true,
    minimum_key_size: 2048,
    allowed_auth_methods: 'publickey,password',
    allowed_ciphers: 'aes256-ctr,aes192-ctr,aes128-ctr',
    allowed_macs: 'hmac-sha2-512,hmac-sha2-256',
    allowed_kex: 'diffie-hellman-group-exchange-sha256',
    log_commands: false,
    log_file_transfers: true,
  });

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      if (authLoading) return;

      if (!user) {
        router.push('/login');
        return;
      }

      const headers = {
        'Content-Type': 'application/json',
      };

      if (activeTab === 'policies') {
        const response = await apiFetch('/api/backend/ssh-security/policies', { headers });
        if (response.ok) {
          const data = await response.json();
          setPolicies(data.policies || []);
        } else {
          throw new Error('Failed to fetch policies');
        }
      } else if (activeTab === 'logs') {
        const response = await apiFetch('/api/backend/ssh-security/logs?limit=50', { headers });
        if (response.ok) {
          const data = await response.json();
          setLogs(data.logs || []);
        } else {
          throw new Error('Failed to fetch logs');
        }
      } else if (activeTab === 'host-keys') {
        const response = await apiFetch('/api/backend/ssh-security/host-keys', { headers });
        if (response.ok) {
          const data = await response.json();
          setHostKeys(data.host_keys || []);
        } else {
          throw new Error('Failed to fetch host keys');
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  }, [activeTab, authLoading, user, router]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleCreatePolicy = async () => {
    try {
      const response = await apiFetch('/api/backend/ssh-security/policies', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(newPolicy),
      });

      if (response.ok) {
        setShowCreateModal(false);
        setNewPolicy({
          name: '',
          description: '',
          max_auth_tries: 3,
          connection_timeout: 10,
          idle_timeout: 600,
          require_host_key_verification: true,
          minimum_key_size: 2048,
          allowed_auth_methods: 'publickey,password',
          allowed_ciphers: 'aes256-ctr,aes192-ctr,aes128-ctr',
          allowed_macs: 'hmac-sha2-512,hmac-sha2-256',
          allowed_kex: 'diffie-hellman-group-exchange-sha256',
          log_commands: false,
          log_file_transfers: true,
        });
        fetchData();
      } else {
        const errorData = await response.json();
        setError(formatApiError(errorData, 'Failed to create policy'));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    }
  };

  const handleUpdatePolicy = async () => {
    if (!editingPolicy) return;

    try {
      const response = await apiFetch(`/api/backend/ssh-security/policies/${editingPolicy.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(editingPolicy),
      });

      if (response.ok) {
        setEditingPolicy(null);
        fetchData();
      } else {
        const errorData = await response.json();
        setError(formatApiError(errorData, 'Failed to update policy'));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    }
  };

  const handleDeletePolicy = async (policyId: number) => {
    try {
      const response = await apiFetch(`/api/backend/ssh-security/policies/${policyId}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        fetchData();
      } else {
        const errorData = await response.json();
        setError(formatApiError(errorData, 'Failed to delete policy'));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    }
    setShowDeletePolicyConfirm(false);
    setDeletePolicyId(null);
  };

  const handleDeleteHostKey = async (hostKeyId: number) => {
    try {
      const response = await apiFetch(`/api/backend/ssh-security/host-keys/${hostKeyId}`, {
        method: 'DELETE',
      });
      if (response.ok) {
        fetchData();
        if (reviewingHostKey && reviewingHostKey.id === hostKeyId) {
          setReviewingHostKey(null);
        }
      } else {
        const errorData = await response.json();
        setError(formatApiError(errorData, 'Failed to delete host key'));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    }
    setShowDeleteHostKeyConfirm(false);
    setDeleteHostKeyId(null);
  };

  const handleVerifyHostKey = async (hostKeyId: number, verified: boolean) => {
    try {
      const endpoint = verified
        ? `/api/backend/ssh-security/host-keys/${hostKeyId}/verify`
        : `/api/backend/ssh-security/host-keys/${hostKeyId}/unverify`;

      const response = await apiFetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        fetchData();
        if (reviewingHostKey && reviewingHostKey.id === hostKeyId) {
          setReviewingHostKey(null);
        }
      } else {
        const errorData = await response.json();
        setError(formatApiError(errorData, 'Failed to update host key'));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    }
  };

  return (
    <MainLayout>
        <Head>
          <title>SSH Security | Praxis</title>
        </Head>
        <PageHeader
          title="SSH Security Management"
          actions={
            <div className="flex items-center gap-2">
              {activeTab === 'policies' && (
                <Button variant="primary" onClick={() => setShowCreateModal(true)}>
                  Create Policy
                </Button>
              )}
              <HelpLink slug="ssh-and-security" />
            </div>
          }
        />

        {error && (
          <div className="mb-4 p-4 bg-red-900/40 border border-red-700 text-red-200 rounded">
            {error}
          </div>
        )}

        {/* Tabs */}
        <div className="border-b border-gray-800 mb-6">
          <nav className="-mb-px flex space-x-8">
            {[
              { id: 'policies', name: 'Security Policies' },
              { id: 'logs', name: 'Security Logs' },
              { id: 'host-keys', name: 'Host Keys' },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`py-2 px-1 border-b-2 font-medium text-sm ${
                  activeTab === tab.id
                    ? 'border-red-500 text-red-400'
                    : 'border-transparent text-gray-400 hover:text-gray-100 hover:border-gray-600'
                }`}
              >
                {tab.name}
              </button>
            ))}
          </nav>
        </div>

        {loading ? (
          <SkeletonTable rows={5} cols={4} />
        ) : (
          <>
            {/* Policies Tab */}
            {activeTab === 'policies' && (
              <Card>
                <CardBody className="p-0">
                  <ul className="divide-y divide-gray-800">
                    {policies.map((policy) => (
                      <li key={policy.id} className="px-6 py-4">
                        <div className="flex items-center justify-between">
                          <div className="flex-1">
                            <h3 className="text-lg font-medium text-gray-100">{policy.name}</h3>
                            {policy.description && (
                              <p className="text-sm text-gray-400 mt-1">{policy.description}</p>
                            )}
                            <div className="mt-2 grid grid-cols-2 md:grid-cols-4 gap-4 text-sm text-gray-400">
                              <div>Max Auth Tries: {policy.max_auth_tries}</div>
                              <div>Connection Timeout: {policy.connection_timeout}s</div>
                              <div>Host Key Verification: {policy.require_host_key_verification ? 'Yes' : 'No'}</div>
                              <div>Min Key Size: {policy.minimum_key_size} bits</div>
                            </div>
                          </div>
                          <div className="flex space-x-2">
                            <Button variant="ghost" size="sm" onClick={() => setEditingPolicy(policy)}>
                              Edit
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setDeletePolicyId(policy.id);
                                setShowDeletePolicyConfirm(true);
                              }}
                            >
                              Delete
                            </Button>
                          </div>
                        </div>
                      </li>
                    ))}
                  </ul>
                  {policies.length === 0 && (
                    <EmptyState
                      title="No security policies found"
                      description="Create one to get started."
                    />
                  )}
                </CardBody>
              </Card>
            )}

            {/* Logs Tab */}
            {activeTab === 'logs' && (
              <Card>
                <CardBody className="p-0">
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-800">
                      <thead className="bg-gray-950">
                        <tr>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                            Timestamp
                          </th>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                            Event Type
                          </th>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                            System ID
                          </th>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                            Username
                          </th>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                            Status
                          </th>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                            Source IP
                          </th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-800">
                        {logs.map((log) => (
                          <tr key={log.id}>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                              {log.timestamp ? formatTimestamp(log.timestamp) : 'N/A'}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                              {log.event_type}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                              {log.system_id}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                              {log.username || 'N/A'}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <Badge variant={statusToBadgeVariant(log.success ? 'success' : 'failed')}>
                                {log.success ? 'Success' : 'Failed'}
                              </Badge>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                              {log.source_ip || 'N/A'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {logs.length === 0 && (
                    <EmptyState title="No security logs found" />
                  )}
                </CardBody>
              </Card>
            )}

            {/* Host Keys Tab */}
            {activeTab === 'host-keys' && (
              <Card>
                <CardBody className="p-0">
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-800">
                      <thead className="bg-gray-950">
                        <tr>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                            Hostname
                          </th>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                            Key Type
                          </th>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                            Fingerprint
                          </th>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                            Verified
                          </th>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                            Last Seen
                          </th>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                            Actions
                          </th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-800">
                        {hostKeys.map((hostKey) => (
                          <tr key={hostKey.id}>
                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-100">
                              {hostKey.hostname}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                              {hostKey.key_type}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400 font-mono">
                              {hostKey.fingerprint.substring(0, 16)}...
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <Badge variant={hostKey.verified ? 'success' : 'warning'}>
                                {hostKey.verified ? 'Verified' : 'Unverified'}
                              </Badge>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                              {hostKey.last_seen ? formatTimestamp(hostKey.last_seen) : 'N/A'}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                              <div className="flex space-x-2">
                                <Button variant="ghost" size="sm" onClick={() => setReviewingHostKey(hostKey)}>
                                  Review
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => handleVerifyHostKey(hostKey.id, !hostKey.verified)}
                                >
                                  {hostKey.verified ? 'Unverify' : 'Verify'}
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => {
                                    setDeleteHostKeyId(hostKey.id);
                                    setShowDeleteHostKeyConfirm(true);
                                  }}
                                >
                                  Delete
                                </Button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {hostKeys.length === 0 && (
                    <EmptyState title="No host keys found" />
                  )}
                </CardBody>
              </Card>
            )}
          </>
        )}

        {/* Host Key Review Modal */}
        {reviewingHostKey && (
          <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
            <div className="relative top-10 mx-auto p-5 border border-gray-800 w-11/12 md:w-3/4 lg:w-2/3 shadow-lg rounded-md bg-gray-950">
              <div className="mt-3">
                <div className="flex justify-between items-center mb-4">
                  <h3 className="text-lg font-medium text-gray-100">SSH Host Key Review</h3>
                  <button
                    onClick={() => setReviewingHostKey(null)}
                    className="text-gray-400 hover:text-gray-200"
                  >
                    <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                </div>

                <div className="space-y-4">
                  <div className="bg-gray-950 border border-gray-800 rounded-lg p-4">
                    <h4 className="text-md font-medium text-gray-100 mb-3">Host Information</h4>
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="text-gray-400">Hostname:</span>
                        <span className="text-gray-100 ml-2 font-mono">{reviewingHostKey.hostname}</span>
                      </div>
                      <div>
                        <span className="text-gray-400">System ID:</span>
                        <span className="text-gray-100 ml-2">{reviewingHostKey.system_id}</span>
                      </div>
                      <div>
                        <span className="text-gray-400">Key Type:</span>
                        <span className="text-gray-100 ml-2 font-mono">{reviewingHostKey.key_type}</span>
                      </div>
                      <div>
                        <span className="text-gray-400">Status:</span>
                        <Badge className="ml-2" variant={reviewingHostKey.verified ? 'success' : 'warning'}>
                          {reviewingHostKey.verified ? 'Verified' : 'Unverified'}
                        </Badge>
                      </div>
                      <div>
                        <span className="text-gray-400">First Seen:</span>
                        <span className="text-gray-100 ml-2">
                          {reviewingHostKey.first_seen ? formatTimestamp(reviewingHostKey.first_seen) : 'N/A'}
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-400">Last Seen:</span>
                        <span className="text-gray-100 ml-2">
                          {reviewingHostKey.last_seen ? formatTimestamp(reviewingHostKey.last_seen) : 'N/A'}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gray-950 border border-gray-800 rounded-lg p-4">
                    <h4 className="text-md font-medium text-gray-100 mb-3">SSH Key Fingerprint</h4>
                    <div className="bg-gray-950 border border-gray-700 rounded p-3">
                      <code className="text-green-400 text-sm break-all">{reviewingHostKey.fingerprint}</code>
                    </div>
                    <p className="text-xs text-gray-600 mt-2">
                      Verify this fingerprint matches your server&apos;s actual host key before marking as verified.
                    </p>
                  </div>

                  <div className="bg-gray-950 border border-gray-800 rounded-lg p-4">
                    <h4 className="text-md font-medium text-gray-100 mb-3">Public Key</h4>
                    <div className="bg-gray-950 border border-gray-700 rounded p-3 max-h-32 overflow-y-auto">
                      <code className="text-green-400 text-xs break-all whitespace-pre-wrap">{reviewingHostKey.public_key}</code>
                    </div>
                  </div>

                  <div className="bg-gray-950 border border-gray-800 rounded-lg p-4">
                    <h4 className="text-md font-medium text-gray-100 mb-3">Verification Instructions</h4>
                    <div className="text-sm text-gray-400 space-y-2">
                      <p>To verify this host key, run the following command on your server:</p>
                      <div className="bg-gray-950 border border-gray-700 rounded p-2">
                        <code className="text-green-400 text-xs">
                          ssh-keyscan -t {reviewingHostKey.key_type.replace('ssh-', '')} {reviewingHostKey.hostname} | ssh-keygen -lf -
                        </code>
                      </div>
                      <p>Compare the fingerprint output with the one shown above. If they match, you can safely verify this key.</p>
                    </div>
                  </div>
                </div>

                <div className="flex justify-end space-x-3 mt-6">
                  <Button variant="outline" onClick={() => setReviewingHostKey(null)}>
                    Close
                  </Button>
                  <Button
                    variant={reviewingHostKey.verified ? 'primary' : 'primary'}
                    onClick={() => handleVerifyHostKey(reviewingHostKey.id, !reviewingHostKey.verified)}
                  >
                    {reviewingHostKey.verified ? 'Mark as Unverified' : 'Mark as Verified'}
                  </Button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Create Policy Modal */}
        {showCreateModal && (
          <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
            <div className="relative top-20 mx-auto p-5 border border-gray-800 w-11/12 md:w-3/4 lg:w-1/2 shadow-lg rounded-md bg-gray-950">
              <div className="mt-3">
                <h3 className="text-lg font-medium text-gray-100 mb-4">Create SSH Security Policy</h3>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-400">Name</label>
                    <input
                      type="text"
                      value={newPolicy.name || ''}
                      onChange={(e) => setNewPolicy({ ...newPolicy, name: e.target.value })}
                      className="mt-1 block w-full bg-white/[0.02] border border-gray-700 rounded-md px-3 py-2 text-gray-200 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-400">Description</label>
                    <textarea
                      value={newPolicy.description || ''}
                      onChange={(e) => setNewPolicy({ ...newPolicy, description: e.target.value })}
                      className="mt-1 block w-full bg-white/[0.02] border border-gray-700 rounded-md px-3 py-2 text-gray-200 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
                      rows={3}
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-400">Max Auth Tries</label>
                      <input
                        type="number"
                        value={newPolicy.max_auth_tries || 3}
                        onChange={(e) => setNewPolicy({ ...newPolicy, max_auth_tries: parseInt(e.target.value) })}
                        className="mt-1 block w-full bg-white/[0.02] border border-gray-700 rounded-md px-3 py-2 text-gray-200 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
                        min="1"
                        max="10"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-400">Connection Timeout (seconds)</label>
                      <input
                        type="number"
                        value={newPolicy.connection_timeout || 10}
                        onChange={(e) => setNewPolicy({ ...newPolicy, connection_timeout: parseInt(e.target.value) })}
                        className="mt-1 block w-full bg-white/[0.02] border border-gray-700 rounded-md px-3 py-2 text-gray-200 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
                        min="5"
                        max="300"
                      />
                    </div>
                  </div>
                  <div className="flex justify-end space-x-3 mt-6">
                    <Button variant="outline" onClick={() => setShowCreateModal(false)}>
                      Cancel
                    </Button>
                    <Button variant="primary" onClick={handleCreatePolicy}>
                      Create Policy
                    </Button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Edit Policy Modal */}
        {editingPolicy && (
          <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
            <div className="relative top-20 mx-auto p-5 border border-gray-800 w-11/12 md:w-3/4 lg:w-1/2 shadow-lg rounded-md bg-gray-950">
              <div className="mt-3">
                <h3 className="text-lg font-medium text-gray-100 mb-4">Edit SSH Security Policy</h3>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-400">Name</label>
                    <input
                      type="text"
                      value={editingPolicy.name || ''}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, name: e.target.value })}
                      className="mt-1 block w-full bg-white/[0.02] border border-gray-700 rounded-md px-3 py-2 text-gray-200 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-400">Description</label>
                    <textarea
                      value={editingPolicy.description || ''}
                      onChange={(e) => setEditingPolicy({ ...editingPolicy, description: e.target.value })}
                      className="mt-1 block w-full bg-white/[0.02] border border-gray-700 rounded-md px-3 py-2 text-gray-200 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
                      rows={3}
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-400">Max Auth Tries</label>
                      <input
                        type="number"
                        value={editingPolicy.max_auth_tries || 3}
                        onChange={(e) => setEditingPolicy({ ...editingPolicy, max_auth_tries: parseInt(e.target.value) })}
                        className="mt-1 block w-full bg-white/[0.02] border border-gray-700 rounded-md px-3 py-2 text-gray-200 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
                        min="1"
                        max="10"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-400">Connection Timeout (seconds)</label>
                      <input
                        type="number"
                        value={editingPolicy.connection_timeout || 10}
                        onChange={(e) => setEditingPolicy({ ...editingPolicy, connection_timeout: parseInt(e.target.value) })}
                        className="mt-1 block w-full bg-white/[0.02] border border-gray-700 rounded-md px-3 py-2 text-gray-200 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
                        min="5"
                        max="300"
                      />
                    </div>
                  </div>
                  <div className="flex justify-end space-x-3 mt-6">
                    <Button variant="outline" onClick={() => setEditingPolicy(null)}>
                      Cancel
                    </Button>
                    <Button variant="primary" onClick={handleUpdatePolicy}>
                      Update Policy
                    </Button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Confirm Modals */}
        <ConfirmModal
          open={showDeletePolicyConfirm}
          onClose={() => { setShowDeletePolicyConfirm(false); setDeletePolicyId(null); }}
          onConfirm={() => deletePolicyId && handleDeletePolicy(deletePolicyId)}
          title="Delete Policy"
          message="Are you sure you want to delete this policy?"
          confirmLabel="Delete"
          variant="danger"
        />

        <ConfirmModal
          open={showDeleteHostKeyConfirm}
          onClose={() => { setShowDeleteHostKeyConfirm(false); setDeleteHostKeyId(null); }}
          onConfirm={() => deleteHostKeyId && handleDeleteHostKey(deleteHostKeyId)}
          title="Delete Host Key"
          message="Delete this host key? The next SSH connection to this system will re-capture and trust the key on first use (TOFU)."
          confirmLabel="Delete"
          variant="danger"
        />
    </MainLayout>
  );
}
