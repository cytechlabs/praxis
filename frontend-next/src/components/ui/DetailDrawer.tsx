import React, { useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X } from 'lucide-react';

interface DetailDrawerProps {
  open: boolean;
  onClose: () => void;
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  actions?: React.ReactNode;
  children: React.ReactNode;
  width?: string;
}

const FOCUSABLE = 'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Right-side inspection panel that slides in from the edge.
 * Use to show row detail without navigating away from a list/table.
 */
const DetailDrawer: React.FC<DetailDrawerProps> = ({
  open,
  onClose,
  title,
  subtitle,
  actions,
  children,
  width = 'max-w-xl',
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const restoreFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    restoreFocusRef.current = document.activeElement as HTMLElement | null;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    document.body.style.overflow = 'hidden';
    const t = setTimeout(() => {
      const focusable = containerRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE);
      focusable?.[0]?.focus();
    }, 80);
    return () => {
      clearTimeout(t);
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = '';
      restoreFocusRef.current?.focus?.();
    };
  }, [open, onClose]);

  return (
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-[90]" role="dialog" aria-modal="true">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="absolute inset-0 bg-black/50 backdrop-blur-[2px]"
            onClick={onClose}
          />
          <motion.aside
            ref={containerRef}
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ duration: 0.22, ease: [0.32, 0.72, 0, 1] }}
            className={`absolute top-0 right-0 h-full w-full ${width} bg-surface border-l border-border/60 shadow-2xl flex flex-col`}
          >
            <div className="flex items-start justify-between gap-4 px-6 py-4 border-b border-border">
              <div className="min-w-0 flex-1">
                {typeof title === 'string' ? (
                  <h2 className="text-lg font-semibold text-content tracking-tight truncate">{title}</h2>
                ) : (
                  title
                )}
                {subtitle && (
                  <div className="text-xs text-content-subtle mt-0.5">{subtitle}</div>
                )}
              </div>
              <button
                onClick={onClose}
                aria-label="Close panel"
                className="shrink-0 p-1.5 text-content-subtle hover:text-content hover:bg-surface-overlay rounded-md transition-colors"
              >
                <X size={18} />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto px-6 py-5">{children}</div>
            {actions && (
              <div className="px-6 py-4 border-t border-border flex items-center justify-end gap-2 bg-white/[0.01]">
                {actions}
              </div>
            )}
          </motion.aside>
        </div>
      )}
    </AnimatePresence>
  );
};

export default DetailDrawer;
