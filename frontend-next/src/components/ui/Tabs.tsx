import React from 'react';
import { motion } from 'framer-motion';

interface Tab {
  id: string;
  label: string;
  icon?: React.ReactNode;
}

interface TabsProps {
  tabs: Tab[];
  active: string;
  onChange: (id: string) => void;
  className?: string;
}

const Tabs: React.FC<TabsProps> = ({ tabs, active, onChange, className = '' }) => {
  return (
    // ``role="tablist"`` + per-button ``role="tab"`` + ``aria-selected``
    // give the component proper WAI-ARIA semantics so screen readers
    // (and Playwright's ``getByRole('tab', ...)``) can identify the
    // tabs. Pure additive - no behavioral or visual change for
    // existing consumers, which still pass ``tabs``, ``active``, and
    // ``onChange`` unchanged.
    <div role="tablist" className={`flex gap-1 border-b border-border ${className}`}>
      {tabs.map((tab) => {
        const isActive = tab.id === active;
        return (
          <button
            key={tab.id}
            role="tab"
            type="button"
            aria-selected={isActive}
            onClick={() => onChange(tab.id)}
            className={`
              relative flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors
              ${isActive ? 'text-brand' : 'text-content-subtle hover:text-content'}
            `}
          >
            {tab.icon}
            {tab.label}
            {isActive && (
              <motion.div
                layoutId="tab-underline"
                className="absolute bottom-0 left-0 right-0 h-0.5 bg-brand"
                transition={{ duration: 0.2 }}
              />
            )}
          </button>
        );
      })}
    </div>
  );
};

export default Tabs;
