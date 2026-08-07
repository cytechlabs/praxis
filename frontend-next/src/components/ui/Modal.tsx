import React, { useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X } from 'lucide-react';

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title?: string;
  children: React.ReactNode;
  maxWidth?: string;
}

const FOCUSABLE = 'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

const Modal: React.FC<ModalProps> = ({ open, onClose, title, children, maxWidth = 'max-w-lg' }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const restoreFocusRef = useRef<HTMLElement | null>(null);

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
        return;
      }
      if (e.key !== 'Tab' || !containerRef.current) return;
      const focusable = containerRef.current.querySelectorAll<HTMLElement>(FOCUSABLE);
      if (focusable.length === 0) {
        e.preventDefault();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement as HTMLElement | null;
      if (e.shiftKey) {
        if (active === first || !containerRef.current.contains(active)) {
          e.preventDefault();
          last.focus();
        }
      } else if (active === last) {
        e.preventDefault();
        first.focus();
      }
    },
    [onClose]
  );

  // Only fire on open/close transitions. Including handleKeyDown in the
  // deps (as ESLint would prefer) would re-run this effect whenever a
  // parent re-renders with a new inline onClose closure - which refocuses
  // the first focusable element (the X button) on every keystroke inside
  // any input, and the user loses focus mid-type. The keydown listener
  // captures onClose via closure; an occasionally-stale onClose still
  // closes the modal correctly because close is idempotent.
  useEffect(() => {
    if (!open) return;
    restoreFocusRef.current = document.activeElement as HTMLElement | null;
    document.addEventListener('keydown', handleKeyDown);
    document.body.style.overflow = 'hidden';
    // Focus first focusable on open
    const t = setTimeout(() => {
      const focusable = containerRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE);
      focusable?.[0]?.focus();
    }, 50);
    return () => {
      clearTimeout(t);
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = '';
      restoreFocusRef.current?.focus?.();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  return (
    <AnimatePresence>
      {open && (
        <div
          className="fixed inset-0 z-[100] flex items-center justify-center"
          role="dialog"
          aria-modal="true"
          aria-label={title}
        >
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            onClick={onClose}
          />
          <motion.div
            ref={containerRef}
            initial={{ opacity: 0, scale: 0.95, y: 10 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 10 }}
            transition={{ duration: 0.15 }}
            className={`relative ${maxWidth} w-full mx-4 bg-surface border border-border/60 rounded-xl shadow-2xl overflow-hidden`}
          >
            {title && (
              <div className="flex items-center justify-between px-6 py-4 border-b border-border">
                <h2 className="text-lg font-semibold text-content">{title}</h2>
                <button
                  onClick={onClose}
                  aria-label="Close dialog"
                  className="p-1 text-content-subtle hover:text-content transition-colors rounded-md hover:bg-surface-overlay"
                >
                  <X size={18} />
                </button>
              </div>
            )}
            <div className="px-6 py-5">{children}</div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};

export default Modal;
