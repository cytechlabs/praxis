import { useState } from 'react';
import { toast } from 'sonner';
import { Copy, Check, AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui';
import { ActivationTokenCreated } from '../../../services/activationTokenService';

interface Props {
  created: ActivationTokenCreated;
  onClose: () => void;
}

/**
 * One-time post-create reveal. Plaintext + bootstrap command live in
 * component state only; closing the parent drops them. The user is
 * warned that the token cannot be retrieved again.
 */
const BootstrapCommandReveal = ({ created, onClose }: Props) => {
  const [copiedField, setCopiedField] = useState<'token' | 'curl' | null>(null);

  const copy = async (value: string, field: 'token' | 'curl') => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedField(field);
      setTimeout(() => setCopiedField(null), 2000);
    } catch {
      toast.error('Could not copy to clipboard; copy manually.');
    }
  };

  const cmd = created.bootstrap_command;

  return (
    <div className="space-y-4">
      <div className="rounded-md border border-yellow-500/30 bg-yellow-500/5 p-3 text-sm text-yellow-300">
        <div className="flex items-start gap-2">
          <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
          <div>
            <strong>Copy this token now.</strong> You will not be able to retrieve
            it again. The token is valid until it expires, is revoked, or is
            redeemed.
          </div>
        </div>
      </div>

      <div>
        <label className="mb-1 block text-xs font-medium uppercase tracking-wide text-content-muted">
          Activation token
        </label>
        <div className="flex gap-2">
          <code className="flex-1 break-all rounded-md border border-border-strong bg-surface-raised p-2 font-mono text-sm text-content">
            {created.plaintext}
          </code>
          <Button variant="outline" onClick={() => copy(created.plaintext, 'token')}>
            {copiedField === 'token' ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
          </Button>
        </div>
      </div>

      <div>
        <label className="mb-1 block text-xs font-medium uppercase tracking-wide text-content-muted">
          One-line bootstrap command
        </label>
        {cmd ? (
          <div className="flex gap-2">
            <code className="flex-1 break-all rounded-md border border-border-strong bg-surface-raised p-2 font-mono text-xs text-content">
              {cmd}
            </code>
            <Button variant="outline" onClick={() => copy(cmd, 'curl')}>
              {copiedField === 'curl' ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
            </Button>
          </div>
        ) : (
          <div className="rounded-md border border-border-strong bg-surface-raised p-3 text-sm text-content-muted">
            <strong className="text-content">No bootstrap command available.</strong>{' '}
            {created.bootstrap_command_unavailable_reason ?? 'Not configured.'} The
            token is still valid; assemble the curl command manually using the
            token above.
          </div>
        )}
      </div>

      <div className="flex justify-end pt-2">
        <Button onClick={onClose}>Done</Button>
      </div>
    </div>
  );
};

export default BootstrapCommandReveal;
