/**
 * @license
 * Copyright 2025 Qwen
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useCallback } from 'react';

interface UseProviderKeysCommandReturn {
  isProviderKeysDialogOpen: boolean;
  openProviderKeysDialog: () => void;
  closeProviderKeysDialog: () => void;
}

export const useProviderKeysCommand = (): UseProviderKeysCommandReturn => {
  const [isProviderKeysDialogOpen, setIsProviderKeysDialogOpen] =
    useState(false);

  const openProviderKeysDialog = useCallback(() => {
    setIsProviderKeysDialogOpen(true);
  }, []);

  const closeProviderKeysDialog = useCallback(() => {
    setIsProviderKeysDialogOpen(false);
  }, []);

  return {
    isProviderKeysDialogOpen,
    openProviderKeysDialog,
    closeProviderKeysDialog,
  };
};
