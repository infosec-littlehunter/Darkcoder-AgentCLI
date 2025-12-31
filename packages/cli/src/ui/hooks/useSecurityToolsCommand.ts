/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useCallback } from 'react';

interface UseSecurityToolsCommandReturn {
  isSecurityToolsDialogOpen: boolean;
  openSecurityToolsDialog: () => void;
  closeSecurityToolsDialog: () => void;
}

export const useSecurityToolsCommand = (): UseSecurityToolsCommandReturn => {
  const [isSecurityToolsDialogOpen, setIsSecurityToolsDialogOpen] =
    useState(false);

  const openSecurityToolsDialog = useCallback(() => {
    setIsSecurityToolsDialogOpen(true);
  }, []);

  const closeSecurityToolsDialog = useCallback(() => {
    setIsSecurityToolsDialogOpen(false);
  }, []);

  return {
    isSecurityToolsDialogOpen,
    openSecurityToolsDialog,
    closeSecurityToolsDialog,
  };
};
