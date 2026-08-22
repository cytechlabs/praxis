import React, { useState, useEffect } from 'react';
import { useAuth } from '../../../context/AuthContext';
import { useRouter } from 'next/router';
import MainLayout from '../../../components/MainLayout';
import { fetchSystemDetails, updateSystem, fetchGroups, fetchDistros, fetchCredentials } from '../../../services/systemService';
import { fetchSSHSecurityPolicies } from '../../../services/sshSecurityService';
import Head from 'next/head';
import { PageHeader, Card, CardBody, Button, nativeSelectClass } from '@/components/ui';

interface Group {
  id: number;
  name: string;
  description?: string;
}

interface Distro {
  id: number;
  name: string;
  version: string;
}

interface Credential {
  id: number;
  name: string;
  auth_method: string;
}

interface SSHSecurityPolicy {
  id: number;
  name: string;
  description?: string;
}

interface ApiError {
  message: string;
  details?: string[];
}

const EditSystem = () => {
  const { user } = useAuth();
  const router = useRouter();
  const { id } = router.query;

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [success, setSuccess] = useState(false);
  const [initialLoading, setInitialLoading] = useState(true);

  const [groups, setGroups] = useState<Group[]>([]);
  const [distros, setDistros] = useState<Distro[]>([]);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [sshPolicies, setSshPolicies] = useState<SSHSecurityPolicy[]>([]);

  const [formData, setFormData] = useState({
    hostname: '',
    ip_address: '',
    distro_id: '',
    status: 'Active',
    group_id: '',
    credentials_id: '',
    ssh_security_policy_id: '',
    update_policy: '',
    description: '',
    environment: 'Production',
    tags: [] as string[]
  });

  // For managing tags input
  const [tagInput, setTagInput] = useState('');

  useEffect(() => {
    const fetchData = async () => {
      if (user && id && !Array.isArray(id)) {
        try {
          setInitialLoading(true);

          // Fetch system details and reference data in parallel
          const [systemData, groupsData, distrosData, credsData, sshPoliciesData] = await Promise.all([
            fetchSystemDetails(Number(id)),
            fetchGroups(),
            fetchDistros(),
            fetchCredentials(),
            fetchSSHSecurityPolicies()
          ]);

          // Set reference data
          setGroups(groupsData);
          setDistros(distrosData);
          setCredentials(credsData);
          setSshPolicies(sshPoliciesData.policies || []);

          // Populate form with system data
          setFormData({
            hostname: systemData.hostname,
            ip_address: systemData.ip_address,
            distro_id: systemData.distribution.id.toString(),
            status: systemData.status,
            group_id: systemData.group.id.toString(),
            credentials_id: systemData.credentials_id?.toString() || '',
            ssh_security_policy_id: (systemData as { ssh_security_policy_id?: number }).ssh_security_policy_id?.toString() || '',
            update_policy: systemData.update_policy || '',
            description: systemData.description || '',
            environment: systemData.metadata?.environment_type || 'Production',
            tags: systemData.tags?.map((t: { name: string }) => t.name) || []
          });
        } catch (err: unknown) {
          const error = err as ApiError;
          setError(error.message || 'Failed to fetch system data');
        } finally {
          setInitialLoading(false);
        }
      }
    };

    fetchData();
  }, [user, id]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleTagInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setTagInput(e.target.value);
  };

  const handleTagInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && tagInput.trim()) {
      e.preventDefault();
      if (!formData.tags.includes(tagInput.trim())) {
        setFormData(prev => ({
          ...prev,
          tags: [...prev.tags, tagInput.trim()]
        }));
      }
      setTagInput('');
    }
  };

  const removeTag = (tagToRemove: string) => {
    setFormData(prev => ({
      ...prev,
      tags: prev.tags.filter(tag => tag !== tagToRemove)
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setValidationErrors([]);
    setSuccess(false);

    try {
      if (!user || !id || Array.isArray(id)) {
        throw new Error('Not authenticated or invalid system ID');
      }

      const submitData = {
        ...formData,
        distro_id: parseInt(formData.distro_id),
        group_id: parseInt(formData.group_id),
        credentials_id: parseInt(formData.credentials_id),
        ssh_security_policy_id: formData.ssh_security_policy_id ? parseInt(formData.ssh_security_policy_id) : undefined
      };

      await updateSystem(Number(id), submitData);

      setSuccess(true);

      // Wait a moment before redirecting
      setTimeout(() => {
        router.push(`/system-management/system/${id}`);
      }, 1500);
    } catch (err: unknown) {
      const error = err as ApiError;
      setError(error.message || 'Failed to update system');

      // Handle validation errors if they exist
      if (error.details && Array.isArray(error.details)) {
        setValidationErrors(error.details);
      }
    } finally {
      setLoading(false);
    }
  };

  if (initialLoading) {
    return (
      <MainLayout>
        <Head>
          <title>Edit System | Praxis</title>
        </Head>
        <PageHeader title="Edit System" />
        <div className="flex justify-center items-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-brand"></div>
        </div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Head>
        <title>Edit System | Praxis</title>
      </Head>
      <PageHeader title="Edit System" />

        {error && (
          <div className="mb-4 p-4 bg-danger/10 border border-danger/40 text-danger rounded" role="alert">
            <p className="font-bold">Error:</p>
            <p>{error}</p>
            {validationErrors.length > 0 && (
              <ul className="list-disc pl-5 mt-2">
                {validationErrors.map((err, index) => (
                  <li key={index}>{err}</li>
                ))}
              </ul>
            )}
          </div>
        )}

        {success && (
          <div className="mb-4 p-4 bg-success/10 border border-success/40 text-success rounded" role="status">
            <p className="font-bold">Success!</p>
            <p>System updated successfully! Redirecting to system details...</p>
          </div>
        )}

        <Card>
          <CardBody>
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Basic Information Section */}
              <div className="md:col-span-2">
                <h2 className="text-xl font-semibold text-content mb-4">Basic Information</h2>
              </div>

              <div>
                <label className="block text-sm font-medium text-content-muted mb-2">
                  Hostname <span className="text-danger">*</span>
                </label>
                <input
                  type="text"
                  name="hostname"
                  value={formData.hostname}
                  onChange={handleChange}
                  required
                  className="w-full px-3 py-2 bg-surface-sunken border border-border rounded-md text-sm text-content placeholder:text-content-subtle focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                  placeholder="Enter hostname"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-content-muted mb-2">
                  IP Address <span className="text-danger">*</span>
                </label>
                <input
                  type="text"
                  name="ip_address"
                  value={formData.ip_address}
                  onChange={handleChange}
                  required
                  className="w-full px-3 py-2 bg-surface-sunken border border-border rounded-md text-sm text-content placeholder:text-content-subtle focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                  placeholder="Enter IP address"
                />
              </div>

              <div className="md:col-span-2">
                <label className="block text-sm font-medium text-content-muted mb-2">
                  Distribution <span className="text-danger">*</span>
                </label>
                <select
                  name="distro_id"
                  value={formData.distro_id}
                  onChange={(e) => {
                    const selectedDistroId = e.target.value;

                    // Update the distro_id in the form data
                    setFormData(prev => ({
                      ...prev,
                      distro_id: selectedDistroId
                    }));
                  }}
                  required
                  className={`w-full px-3 py-2 border border-border rounded-md text-sm ${nativeSelectClass}`}
                >
                  <option value="">Select Distribution</option>
                  {distros.map(distro => (
                    <option key={distro.id} value={distro.id}>
                      {distro.name} {distro.version}
                    </option>
                  ))}
                </select>
                <p className="text-xs text-content-subtle mt-1">
                  The distribution includes both the OS name and version (e.g., Ubuntu 22.04, RHEL 9)
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-content-muted mb-2">
                  Status <span className="text-danger">*</span>
                </label>
                <select
                  name="status"
                  value={formData.status}
                  onChange={handleChange}
                  required
                  className={`w-full px-3 py-2 border border-border rounded-md text-sm ${nativeSelectClass}`}
                >
                  <option value="Active">Active</option>
                  <option value="Inactive">Inactive</option>
                  <option value="Maintenance">Maintenance</option>
                  <option value="Decommissioned">Decommissioned</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-content-muted mb-2">
                  Environment
                </label>
                <select
                  name="environment"
                  value={formData.environment}
                  onChange={handleChange}
                  className={`w-full px-3 py-2 border border-border rounded-md text-sm ${nativeSelectClass}`}
                >
                  <option value="Production">Production</option>
                  <option value="Staging">Staging</option>
                  <option value="Development">Development</option>
                  <option value="Testing">Testing</option>
                </select>
              </div>

              {/* Group and Access Section */}
              <div className="md:col-span-2 mt-4">
                <h2 className="text-xl font-semibold text-content mb-4">Group and Access</h2>
              </div>

              <div>
                <label className="block text-sm font-medium text-content-muted mb-2">
                  System Group <span className="text-danger">*</span>
                </label>
                <select
                  name="group_id"
                  value={formData.group_id}
                  onChange={handleChange}
                  required
                  className={`w-full px-3 py-2 border border-border rounded-md text-sm ${nativeSelectClass}`}
                >
                  <option value="">Select Group</option>
                  {groups.map(group => (
                    <option key={group.id} value={group.id}>
                      {group.name}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-content-muted mb-2">
                  Credentials <span className="text-danger">*</span>
                </label>
                <select
                  name="credentials_id"
                  value={formData.credentials_id}
                  onChange={handleChange}
                  required
                  className={`w-full px-3 py-2 border border-border rounded-md text-sm ${nativeSelectClass}`}
                >
                  <option value="">Select Credentials</option>
                  {credentials.map(cred => (
                    <option key={cred.id} value={cred.id}>
                      {cred.name} ({cred.auth_method})
                    </option>
                  ))}
                </select>
              </div>

              {/* Security Section */}
              <div className="md:col-span-2 mt-4">
                <h2 className="text-xl font-semibold text-content mb-4">Security Configuration</h2>
              </div>

              <div className="md:col-span-2">
                <label className="block text-sm font-medium text-content-muted mb-2">
                  SSH Security Policy
                </label>
                <select
                  name="ssh_security_policy_id"
                  value={formData.ssh_security_policy_id}
                  onChange={handleChange}
                  className={`w-full px-3 py-2 border border-border rounded-md text-sm ${nativeSelectClass}`}
                >
                  <option value="">No SSH Security Policy</option>
                  {sshPolicies.map(policy => (
                    <option key={policy.id} value={policy.id}>
                      {policy.name} {policy.description && `- ${policy.description}`}
                    </option>
                  ))}
                </select>
                <p className="text-xs text-content-subtle mt-1">
                  Optional: Select an SSH security policy to apply enhanced security settings for SSH connections to this system.
                </p>
              </div>

              {/* Additional Information Section */}
              <div className="md:col-span-2 mt-4">
                <h2 className="text-xl font-semibold text-content mb-4">Additional Information</h2>
              </div>

              <div>
                <label className="block text-sm font-medium text-content-muted mb-2">
                  Update Policy
                </label>
                <input
                  type="text"
                  name="update_policy"
                  value={formData.update_policy}
                  onChange={handleChange}
                  className="w-full px-3 py-2 bg-surface-sunken border border-border rounded-md text-sm text-content placeholder:text-content-subtle focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                  placeholder="Enter update policy (optional)"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-content-muted mb-2">
                  Tags
                </label>
                <input
                  type="text"
                  value={tagInput}
                  onChange={handleTagInputChange}
                  onKeyDown={handleTagInputKeyDown}
                  className="w-full px-3 py-2 bg-surface-sunken border border-border rounded-md text-sm text-content placeholder:text-content-subtle focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                  placeholder="Type tag and press Enter"
                />
                {formData.tags.length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-2">
                    {formData.tags.map(tag => (
                      <span
                        key={tag}
                        className="px-2 py-1 bg-surface-overlay text-content-muted border border-border rounded-md flex items-center text-sm"
                      >
                        {tag}
                        <button
                          type="button"
                          onClick={() => removeTag(tag)}
                          aria-label={`Remove tag ${tag}`}
                          className="ml-2 text-content-subtle hover:text-content"
                        >
                          ×
                        </button>
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div className="md:col-span-2">
                <label className="block text-sm font-medium text-content-muted mb-2">
                  Description
                </label>
                <textarea
                  name="description"
                  value={formData.description}
                  onChange={handleChange}
                  rows={3}
                  className="w-full px-3 py-2 bg-surface-sunken border border-border rounded-md text-sm text-content placeholder:text-content-subtle focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                  placeholder="Enter system description (optional)"
                />
              </div>
            </div>

            <div className="flex justify-end space-x-4 mt-6">
              <Button
                type="button"
                variant="outline"
                onClick={() => router.push(`/system-management/system/${id}`)}
              >
                Cancel
              </Button>
              <Button type="submit" variant="primary" loading={loading}>
                {loading ? 'Updating...' : 'Update System'}
              </Button>
            </div>
          </form>
          </CardBody>
        </Card>
    </MainLayout>
  );
};

export default EditSystem;
