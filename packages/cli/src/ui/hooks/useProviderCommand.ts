/**
 * @license
 * Copyright 2025 Qwen
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useCallback } from 'react';

interface UseProviderCommandReturn {
  isProviderDialogOpen: boolean;
  openProviderDialog: () => void;
  closeProviderDialog: () => void;
}

export const useProviderCommand = (): UseProviderCommandReturn => {
  const [isProviderDialogOpen, setIsProviderDialogOpen] = useState(false);

  const openProviderDialog = useCallback(() => {
    setIsProviderDialogOpen(true);
  }, []);

  const closeProviderDialog = useCallback(() => {
    setIsProviderDialogOpen(false);
  }, []);

  return {
    isProviderDialogOpen,
    openProviderDialog,
    closeProviderDialog,
  };
};
