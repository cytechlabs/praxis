import { useState } from 'react';

interface DeleteConfirmationDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => Promise<void>;
  username: string;
}

const DeleteConfirmationDialog = ({
  isOpen,
  onClose,
  onConfirm,
  username,
}: DeleteConfirmationDialogProps) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleConfirm = async () => {
    setError('');
    setLoading(true);

    try {
      await onConfirm();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete user');
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-surface/50 flex items-center justify-center z-40">
      <div className="bg-surface-overlay rounded-lg p-6 w-[500px] border border-border/60">
        <h2 className="text-xl mb-4 text-content">Delete User</h2>

        <div className="mb-6">
          <p className="text-content mb-2">
            Are you sure you want to delete user <span className="font-semibold">{username}</span>?
          </p>
          <p className="text-red-500 text-sm">
            This action is irreversible and will permanently delete the user.
          </p>
        </div>

        {error && <div className="text-red-500 text-sm mb-4">{error}</div>}

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
            type="button"
            onClick={handleConfirm}
            className="px-4 py-2 bg-red-600 text-white text-sm font-medium rounded hover:bg-red-700 disabled:opacity-50"
            disabled={loading}
          >
            {loading ? 'Deleting...' : 'Delete User'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default DeleteConfirmationDialog;
