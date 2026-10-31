import { useState, useEffect, useCallback } from 'react';
import { investigationsApi } from '../services/api';
import type { Investigation } from '../types';
import { STORAGE_KEYS } from '../utils/constants';

export function useInvestigations() {
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [activeInvestigationId, setActiveInvestigationId] = useState<string>(() => {
    return localStorage.getItem(STORAGE_KEYS.ACTIVE_INVESTIGATION_ID) || '';
  });
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchInvestigations = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await investigationsApi.list();
      const list = Array.isArray(res.data) ? res.data : [];
      setInvestigations(list);

      // If active ID is not set or not in list, select the first active investigation or first item
      if (list.length > 0) {
        const storedId = localStorage.getItem(STORAGE_KEYS.ACTIVE_INVESTIGATION_ID);
        const match = list.find((i) => i.id === storedId);
        if (!match) {
          const defaultItem = list.find((i) => i.status === 'ACTIVE') || list[0];
          setActiveInvestigationId(defaultItem.id);
          localStorage.setItem(STORAGE_KEYS.ACTIVE_INVESTIGATION_ID, defaultItem.id);
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to fetch investigations';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchInvestigations();
  }, [fetchInvestigations]);

  const selectActiveInvestigation = (id: string) => {
    setActiveInvestigationId(id);
    localStorage.setItem(STORAGE_KEYS.ACTIVE_INVESTIGATION_ID, id);
    window.dispatchEvent(new Event('vigilance_investigation_changed'));
  };

  useEffect(() => {
    const handleStorageChange = () => {
      const stored = localStorage.getItem(STORAGE_KEYS.ACTIVE_INVESTIGATION_ID) || '';
      setActiveInvestigationId(stored);
    };
    window.addEventListener('vigilance_investigation_changed', handleStorageChange);
    window.addEventListener('storage', handleStorageChange);
    return () => {
      window.removeEventListener('vigilance_investigation_changed', handleStorageChange);
      window.removeEventListener('storage', handleStorageChange);
    };
  }, []);

  const activeInvestigation = investigations.find((i) => i.id === activeInvestigationId);

  return {
    investigations,
    activeInvestigation,
    activeInvestigationId,
    selectActiveInvestigation,
    refetch: fetchInvestigations,
    loading,
    error,
  };
}
