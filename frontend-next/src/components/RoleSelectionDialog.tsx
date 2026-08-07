import { useEffect, useState } from 'react';
import { fetchAvailableRoles } from '../services/userService';

interface RoleSelectionDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (roles: string[]) => Promise<void>;
  username: string;
  currentRoles: string[];
}

const RoleSelectionDialog = ({
  isOpen,
  onClose,
  onSubmit,
  username,
  currentRoles,
}: RoleSelectionDialogProps) => {
  const [selectedRoles, setSelectedRoles] = useState<string[]>(currentRoles);
  const [availableRoles, setAvailableRoles] = useState<string[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const loadRoles = async () => {
      try {
        const roles = await fetchAvailableRoles();
        setAvailableRoles(roles);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch roles');
      }
    };

    if (isOpen) {
      loadRoles();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const unassignedRoles = availableRoles.filter(role => !selectedRoles.includes(role));

  const handleAddRole = (role: string) => {
    setSelectedRoles([...selectedRoles, role]);
  };

  const handleRemoveRole = (role: string) => {
    setSelectedRoles(selectedRoles.filter(r => r !== role));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await onSubmit(selectedRoles);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update roles');
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-[#0c0c0f] bg-opacity-50 flex items-center justify-center z-40">
      <div className="bg-[#0c0c0f] rounded-lg p-6 w-[800px] border border-gray-800/60">
        <h2 className="text-xl mb-4 text-gray-200">Manage Roles for {username}</h2>

        <form onSubmit={handleSubmit}>
          <div className="flex gap-4 mb-6">
            {/* Available Roles */}
            <div className="flex-1">
              <h3 className="text-sm font-medium text-gray-300 mb-2">Available Roles</h3>
              <div className="bg-gray-800 border border-gray-800/60 rounded p-4 min-h-[200px]">
                {unassignedRoles.map(role => (
                  <div
                    key={role}
                    className="flex items-center justify-between p-2 hover:bg-white/[0.05] rounded cursor-pointer group"
                    onClick={() => handleAddRole(role)}
                  >
                    <span className="text-gray-300">{role}</span>
                    <span className="text-green-500 opacity-0 group-hover:opacity-100">→</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Selected Roles */}
            <div className="flex-1">
              <h3 className="text-sm font-medium text-gray-300 mb-2">Current Roles</h3>
              <div className="bg-gray-800 border border-gray-800/60 rounded p-4 min-h-[200px]">
                {selectedRoles.map(role => (
                  <div
                    key={role}
                    className="flex items-center justify-between p-2 hover:bg-white/[0.05] rounded cursor-pointer group"
                    onClick={() => handleRemoveRole(role)}
                  >
                    <span className="text-red-500 opacity-0 group-hover:opacity-100">←</span>
                    <span className="text-gray-300">{role}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {error && (
            <div className="mb-4 text-red-500 text-sm">{error}</div>
          )}

          <div className="flex justify-end space-x-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-gray-300 hover:text-white"
              disabled={loading}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 bg-red-600 text-white text-sm font-medium rounded hover:bg-red-700 disabled:opacity-50"
              disabled={loading}
            >
              {loading ? 'Updating...' : 'Update Roles'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default RoleSelectionDialog;
