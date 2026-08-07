import React from 'react';
import Link from 'next/link';
import { motion } from 'framer-motion';
import AnimatedNumber from './AnimatedNumber';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  hover?: boolean;
  onClick?: () => void;
}

interface CardHeaderProps {
  children: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}

interface CardBodyProps {
  children: React.ReactNode;
  className?: string;
}

export const Card: React.FC<CardProps> = ({ children, className = '', hover, onClick }) => {
  const Component = hover || onClick ? motion.div : 'div';
  const motionProps = hover || onClick ? {
    whileHover: { y: -1 },
    transition: { duration: 0.15 },
  } : {};

  return (
    <Component
      onClick={onClick}
      className={`
        bg-surface-raised border border-border rounded-lg overflow-hidden card-glow
        ${onClick ? 'cursor-pointer' : ''}
        ${className}
      `}
      {...motionProps}
    >
      {children}
    </Component>
  );
};

export const CardHeader: React.FC<CardHeaderProps> = ({ children, action, className = '' }) => {
  return (
    <div className={`flex items-center justify-between px-5 py-3.5 border-b border-border bg-surface-overlay/30 ${className}`}>
      <div className="text-base font-semibold text-content tracking-tight">{children}</div>
      {action && <div>{action}</div>}
    </div>
  );
};

export const CardBody: React.FC<CardBodyProps> = ({ children, className = '' }) => {
  return (
    <div className={`px-5 py-4 ${className}`}>
      {children}
    </div>
  );
};

export const StatCard: React.FC<{
  label: string;
  value: string | number;
  icon?: React.ReactNode;
  trend?: 'up' | 'down' | 'neutral';
  subtitle?: string;
  className?: string;
  href?: string;
}> = ({ label, value, icon, subtitle, className = '', href }) => {
  const inner = (
    <>
      <div className="flex items-center gap-2 text-content-subtle text-xs font-medium uppercase tracking-wider mb-2">
        {icon}
        {label}
      </div>
      <div className="text-2xl font-bold text-content tabular-nums">
        {typeof value === 'number' ? <AnimatedNumber value={value} /> : value}
      </div>
      {subtitle && <div className="text-xs text-content-subtle mt-1">{subtitle}</div>}
    </>
  );
  const baseClasses = `bg-surface-raised border border-border rounded-lg px-5 py-4 stat-accent ${className}`;
  if (href) {
    return (
      <Link
        href={href}
        className={`${baseClasses} block transition-colors duration-150 hover:border-border-strong focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring`}
      >
        {inner}
      </Link>
    );
  }
  return <div className={baseClasses}>{inner}</div>;
};
