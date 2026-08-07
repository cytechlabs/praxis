"use client";

import React, { ReactNode, useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { usePathname } from 'next/navigation';
import TopBar from './layout/TopBar';
import StatusBar from './layout/StatusBar';
import CommandPalette from './layout/CommandPalette';
import ActivitySidebar from './layout/ActivitySidebar';
import ContentGuard from '../ContentGuard';
import BrandedLoadingScreen from './layout/BrandedLoadingScreen';
import { useAuth } from '../context/AuthContext';

interface MainLayoutProps {
  children: ReactNode;
}

const MainLayout = ({ children }: MainLayoutProps) => {
  const [mounted, setMounted] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const { user, loading } = useAuth();
  const pathname = usePathname();
  const publicPaths = ['/login', '/register', '/forgot-password'];
  const isPublicPath = publicPaths.includes(pathname || '');

  useEffect(() => {
    setMounted(true);
    return () => setMounted(false);
  }, []);

  // Global Ctrl+K handler
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setPaletteOpen((prev) => !prev);
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleOpenPalette = useCallback(() => setPaletteOpen(true), []);
  const handleClosePalette = useCallback(() => setPaletteOpen(false), []);

  if (!mounted || loading) {
    // PRA-268/PRA-272: shared branded loading shell (official wordmark +
    // block-cursor motif, full-viewport geometry - no black flash / layout jump).
    return <BrandedLoadingScreen />;
  }

  if (isPublicPath || !user) {
    return <>{children}</>;
  }

  return (
    <div className="h-screen flex flex-col bg-surface overflow-hidden">
      <TopBar onOpenPalette={handleOpenPalette} />

      <main className="flex-1 overflow-y-auto">
        <AnimatePresence mode="wait">
          <motion.div
            key={pathname}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15, ease: 'easeOut' }}
            className="p-6 max-w-[1600px] mx-auto w-full"
          >
            <ContentGuard>{children}</ContentGuard>
          </motion.div>
        </AnimatePresence>
      </main>

      <StatusBar onOpenPalette={handleOpenPalette} />
      <CommandPalette open={paletteOpen} onClose={handleClosePalette} />
      <ActivitySidebar />
    </div>
  );
};

export default MainLayout;
