import { useAuth } from '../../context/AuthContext';
import { useState, useEffect } from 'react';
import { createVaultConfig, getActiveVaultConfig, checkVaultHealth } from '../../services/vaultService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { Button } from '@/components/ui';

interface VaultConfig {
  id: number;
  is_internal: boolean;
  token: string;
  server_url: string | null;
  is_active: boolean;
  health_status: string | null;
  last_health_check: string | null;
}

interface VaultHealth {
  healthy: boolean;
  status: string;
  initialized?: boolean;
  sealed?: boolean;
  version?: string;
}

interface VaultSettingsTabProps {
  onConfigSaved?: () => void;
}

const VaultSettingsTab = ({ onConfigSaved }: VaultSettingsTabProps = {}) => {
  const formatTimestamp = useFormatTimestamp();
  const { user } = useAuth();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [vaultConfig, setVaultConfig] = useState<VaultConfig | null>(null);
  const [health, setHealth] = useState<VaultHealth | null>(null);
  const [isFormOpen, setIsFormOpen] = useState(false);
  const [formData, setFormData] = useState({
    is_internal: true,
    token: '',
    server_url: '',
  });

  // Fetch active Vault configuration
  useEffect(() => {
    const fetchVaultConfig = async () => {
      if (!user) return;

      try {
        setLoading(true);
        const config = await getActiveVaultConfig();

        if (config) {
          setVaultConfig(config);
          // Check health if config exists
          const healthData = await checkVaultHealth();
          setHealth(healthData);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'An error occurred');
      } finally {
        setLoading(false);
      }
    };

    fetchVaultConfig();
  }, [user]);

  // Check Vault health
  const checkVaultHealthStatus = async () => {
    try {
      const healthData = await checkVaultHealth();
      setHealth(healthData);
    } catch (err) {
      console.error('Health check error:', err);
      setHealth({
        healthy: false,
        status: err instanceof Error ? err.message : 'Health check error',
      });
    }
  };

  // Handle form input changes
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type, checked } = e.target;
    setFormData({
      ...formData,
      [name]: type === 'checkbox' ? checked : value,
    });
  };

  // Handle form submission
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user) return;

    try {
      setLoading(true);
      const configData = {
        is_internal: formData.is_internal,
        token: formData.token,
        server_url: formData.is_internal ? null : formData.server_url,
      };

      const newConfig = await createVaultConfig(configData);

      setVaultConfig(newConfig);
      setSuccessMessage('Vault configuration saved successfully');
      setIsFormOpen(false);
      checkVaultHealthStatus();
      onConfigSaved?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  // Clear success message after 5 seconds
  useEffect(() => {
    if (successMessage) {
      const timer = setTimeout(() => {
        setSuccessMessage('');
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [successMessage]);

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-xl">Vault Integration</h2>
        {!isFormOpen && (
          <Button
            variant="primary"
            onClick={() => {
              if (vaultConfig) {
                setFormData({
                  is_internal: vaultConfig.is_internal,
                  token: '',
                  server_url: vaultConfig.server_url || '',
                });
              }
              setIsFormOpen(true);
            }}
          >
            {vaultConfig ? 'Update Configuration' : 'Configure Vault'}
          </Button>
        )}
      </div>

      {/* Success Message Toast */}
      {successMessage && (
        <div className="fixed top-4 right-4 z-50 bg-green-600 text-white px-6 py-3 rounded shadow-lg animate-fade-in">
          {successMessage}
        </div>
      )}

      {/* Error Message */}
      {error && <div className="text-red-500 mb-4">{error}</div>}

      {loading && !isFormOpen ? (
        <div>Loading Vault configuration...</div>
      ) : (
        <>
          {/* Current Configuration */}
          {vaultConfig ? (
            <div className="bg-[#0c0c0f] border border-gray-800/60 rounded p-4">
              <h3 className="text-lg font-medium mb-4">Current Configuration</h3>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-gray-400">Type:</p>
                  <p className="text-white">
                    {vaultConfig.is_internal ? 'Internal Vault' : 'External Vault'}
                  </p>
                </div>
                {!vaultConfig.is_internal && (
                  <div>
                    <p className="text-gray-400">Server URL:</p>
                    <p className="text-white">{vaultConfig.server_url}</p>
                  </div>
                )}
                <div>
                  <p className="text-gray-400">Status:</p>
                  <div
                    className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                      health?.healthy
                        ? 'bg-emerald-500/15 text-emerald-400'
                        : 'bg-red-500/15 text-red-400'
                    }`}
                  >
                    {health?.healthy ? 'Healthy' : 'Unhealthy'}
                  </div>
                </div>
                {health && (
                  <div>
                    <p className="text-gray-400">Details:</p>
                    <p className="text-white">
                      {health.status}
                      {health.version && ` (v${health.version})`}
                    </p>
                  </div>
                )}
                <div>
                  <p className="text-gray-400">Last Health Check:</p>
                  <p className="text-white">
                    {vaultConfig.last_health_check
                      ? formatTimestamp(vaultConfig.last_health_check)
                      : 'Never'}
                  </p>
                </div>
              </div>

              <div className="mt-4">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => checkVaultHealthStatus()}
                  disabled={!user}
                >
                  Check Health
                </Button>
              </div>
            </div>
          ) : (
            <div className="bg-[#0c0c0f] border border-gray-800/60 rounded p-4">
              <p className="text-gray-300">No Vault configuration found. Please configure Vault to enable integration.</p>
            </div>
          )}

          {/* Configuration Form */}
          {isFormOpen && (
            <div className="bg-[#0c0c0f] border border-gray-800/60 rounded p-4 mt-4">
              <h3 className="text-lg font-medium mb-4">
                {vaultConfig ? 'Update Vault Configuration' : 'New Vault Configuration'}
              </h3>
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="flex items-center space-x-2 mb-4">
                    <input
                      type="checkbox"
                      name="is_internal"
                      checked={formData.is_internal}
                      onChange={handleInputChange}
                      className="form-checkbox h-5 w-5 text-red-600"
                    />
                    <span>Use Internal Vault Container</span>
                  </label>
                </div>

                {!formData.is_internal && (
                  <div className="mb-4">
                    <label className="block text-gray-300 mb-2">Server URL</label>
                    <input
                      type="text"
                      name="server_url"
                      value={formData.server_url}
                      onChange={handleInputChange}
                      placeholder="https://vault.example.com:8200"
                      className="w-full px-3 py-2 bg-[#09090b] border border-gray-700/60 rounded text-white focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
                      required={!formData.is_internal}
                    />
                    <p className="text-gray-400 text-sm mt-1">
                      The URL of your external Vault server
                    </p>
                  </div>
                )}

                <div className="mb-4">
                  <label className="block text-gray-300 mb-2">
                    {formData.is_internal ? 'Backend Service Token' : 'Authentication Token'}
                  </label>
                  <input
                    type="password"
                    name="token"
                    value={formData.token}
                    onChange={handleInputChange}
                    placeholder="s.example123token"
                    className="w-full px-3 py-2 bg-[#09090b] border border-gray-700/60 rounded text-white focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
                    required
                  />
                  <p className="text-gray-400 text-sm mt-1">
                    {formData.is_internal
                      ? 'The backend service token generated during Vault initialization. Retrieve it with: docker compose exec vault cat /vault/data/backend-token'
                      : 'A token with appropriate permissions for your external Vault server'}
                  </p>
                </div>

                <div className="flex justify-end space-x-3">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setIsFormOpen(false)}
                  >
                    Cancel
                  </Button>
                  <Button
                    type="submit"
                    variant="primary"
                    disabled={loading}
                    loading={loading}
                  >
                    {loading ? 'Saving...' : 'Save Configuration'}
                  </Button>
                </div>
              </form>
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default VaultSettingsTab;
