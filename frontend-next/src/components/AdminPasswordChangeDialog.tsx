import { useState } from 'react';

interface AdminPasswordChangeDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (newPassword: string, confirmPassword: string) => Promise<void>;
  username: string;
}

const AdminPasswordChangeDialog = ({ isOpen, onClose, onSubmit, username }: AdminPasswordChangeDialogProps) => {
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    // Validate password length
    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters long');
      return;
    }

    // Validate passwords match
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setLoading(true);

    try {
      await onSubmit(newPassword, confirmPassword);
      // Don't close here - let parent handle it
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to change password');
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-surface/50 flex items-center justify-center z-40">
      <div className="bg-surface-overlay rounded-lg p-6 w-96 border border-border/60">
        <h2 className="text-xl mb-4 text-content">Change Password for {username}</h2>

        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label htmlFor="newPassword" className="block text-sm font-medium text-content mb-1">
              New Password
            </label>
            <input
              type="password"
              id="newPassword"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full px-3 py-2 bg-surface-sunken border border-border/60 rounded text-content"
              required
              minLength={8}
              placeholder="Minimum 8 characters"
            />
          </div>

          <div className="mb-4">
            <label htmlFor="confirmPassword" className="block text-sm font-medium text-content mb-1">
              Confirm Password
            </label>
            <input
              type="password"
              id="confirmPassword"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="w-full px-3 py-2 bg-surface-sunken border border-border/60 rounded text-content"
              required
              minLength={8}
            />
          </div>

          {error && (
            <div className="mb-4 text-red-500 text-sm">{error}</div>
          )}

          <div className="flex justify-end space-x-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-content hover:text-white"
              disabled={loading}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 bg-red-600 text-white text-sm font-medium rounded hover:bg-red-700 disabled:opacity-50"
              disabled={loading}
            >
              {loading ? 'Changing...' : 'Change Password'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default AdminPasswordChangeDialog;
