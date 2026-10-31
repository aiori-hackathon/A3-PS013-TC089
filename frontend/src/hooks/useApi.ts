import { useState, useCallback, useEffect } from 'react';

interface UseApiOptions<T> {
  immediate?: boolean;
  initialData?: T;
  onSuccess?: (data: T) => void;
  onError?: (err: Error) => void;
}

export function useApi<T>(
  asyncFn: () => Promise<{ data: T }>,
  options: UseApiOptions<T> = { immediate: true }
) {
  const [data, setData] = useState<T | undefined>(options.initialData);
  const [loading, setLoading] = useState<boolean>(options.immediate ?? true);
  const [error, setError] = useState<string | null>(null);

  const execute = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await asyncFn();
      setData(response.data);
      options.onSuccess?.(response.data);
      return response.data;
    } catch (err: unknown) {
      const errorObj = err instanceof Error ? err : new Error(String(err));
      setError(errorObj.message);
      options.onError?.(errorObj);
      return undefined;
    } finally {
      setLoading(false);
    }
  }, [asyncFn, options]);

  useEffect(() => {
    if (options.immediate) {
      execute();
    }
  }, [execute, options.immediate]);

  return {
    data,
    loading,
    error,
    execute,
    setData,
  };
}
