import React from 'react';

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
  className?: string;
}

const PageHeader: React.FC<PageHeaderProps> = ({ title, subtitle, actions, className = '' }) => {
  return (
    <div className={`flex items-start justify-between mb-6 ${className}`}>
      <div>
        <h1 className="text-[28px] leading-tight font-bold text-content tracking-tight">{title}</h1>
        {subtitle && <p className="text-sm text-content-subtle mt-1.5">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2 flex-shrink-0">{actions}</div>}
    </div>
  );
};

export default PageHeader;
