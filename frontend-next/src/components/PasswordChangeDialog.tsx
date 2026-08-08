import React, { useState } from 'react';

interface PasswordChangeDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (currentPassword: string, newPassword: string) => Promise<void>;
}

export const PasswordChangeDialog: React.FC<PasswordChangeDialogProps> = ({
  isOpen,
  onClose,
  onSubmit
}) => {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (newPassword.length < 8) {
      setError('New password must be at least 8 characters long');
      return;
    }

    if (newPassword !== confirmPassword) {
      setError('New passwords do not match');
      return;
    }

    try {
      setIsLoading(true);
      await onSubmit(currentPassword, newPassword);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to change password');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-surface/80 flex items-center justify-center z-50">
      <div className="bg-surface-overlay border border-border/60 rounded-lg p-6 w-full max-w-md text-content-muted">
        <h2 className="text-xl font-semibold mb-4 text-red-500">Change Password</h2>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-content-muted">
              Current Password
            </label>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="mt-1 block w-full rounded bg-surface-sunken border-border/60 text-content shadow-sm focus-visible:border-border-strong focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-content-muted">
              New Password
            </label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="mt-1 block w-full rounded bg-surface-sunken border-border/60 text-content shadow-sm focus-visible:border-border-strong focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
              required
              minLength={8}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-content-muted">
              Confirm New Password
            </label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="mt-1 block w-full rounded bg-surface-sunken border-border/60 text-content shadow-sm focus-visible:border-border-strong focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
              required
            />
          </div>

          {error && (
            <div className="text-red-500 text-sm">{error}</div>
          )}

          <div className="flex justify-end space-x-3 mt-6">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-content-muted bg-action-secondary border border-border/60 rounded hover:text-white hover:border-red-500 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading}
              className="px-4 py-2 text-sm font-medium text-content-muted bg-action-secondary border border-border/60 rounded hover:text-white hover:border-red-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? 'Changing...' : 'Change Password'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
