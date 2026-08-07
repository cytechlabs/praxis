import React from 'react';
import Modal from './Modal';
import Button from './Button';
import { AlertTriangle } from 'lucide-react';

interface ConfirmModalProps {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title?: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: 'danger' | 'warning';
  loading?: boolean;
}

const ConfirmModal: React.FC<ConfirmModalProps> = ({
  open,
  onClose,
  onConfirm,
  title = 'Confirm Action',
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  variant = 'danger',
  loading,
}) => {
  return (
    <Modal open={open} onClose={onClose} title={title} maxWidth="max-w-md">
      <div className="flex gap-4">
        <div className="flex-shrink-0 mt-0.5">
          <div className={`p-2 rounded-full ${
            variant === 'danger' ? 'bg-danger/15' : 'bg-warning/15'
          }`}>
            <AlertTriangle size={20} className={
              variant === 'danger' ? 'text-danger' : 'text-warning'
            } />
          </div>
        </div>
        <div className="flex-1">
          <p className="text-sm text-content-muted leading-relaxed">{message}</p>
        </div>
      </div>
      <div className="flex justify-end gap-3 mt-6">
        <Button variant="ghost" onClick={onClose} disabled={loading}>
          {cancelLabel}
        </Button>
        <Button
          variant={variant === 'danger' ? 'danger' : 'primary'}
          onClick={onConfirm}
          loading={loading}
        >
          {confirmLabel}
        </Button>
      </div>
    </Modal>
  );
};

export default ConfirmModal;
