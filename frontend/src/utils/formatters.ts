import { format, parseISO, isValid } from 'date-fns';

export function formatBytes(bytes: number, decimals = 2): string {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const safeIndex = Math.min(i, sizes.length - 1);
  return `${parseFloat((bytes / Math.pow(k, safeIndex)).toFixed(dm))} ${sizes[safeIndex]}`;
}

export function formatDate(dateStr?: string | null, pattern = 'yyyy-MM-dd HH:mm:ss'): string {
  if (!dateStr) return '—';
  try {
    const date = parseISO(dateStr);
    if (!isValid(date)) {
      const fallbackDate = new Date(dateStr);
      if (isValid(fallbackDate)) {
        return format(fallbackDate, pattern);
      }
      return dateStr;
    }
    return format(date, pattern);
  } catch {
    return dateStr;
  }
}

export function formatDuration(seconds?: number | null): string {
  if (seconds === undefined || seconds === null) return '—';
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const mins = Math.floor(seconds / 60);
  const remainingSecs = Math.round(seconds % 60);
  if (mins < 60) return `${mins}m ${remainingSecs}s`;
  const hours = Math.floor(mins / 60);
  const remainingMins = mins % 60;
  return `${hours}h ${remainingMins}m`;
}

export function truncateHash(hash?: string | null, startChars = 8, endChars = 8): string {
  if (!hash) return '—';
  if (hash.length <= startChars + endChars) return hash;
  return `${hash.slice(0, startChars)}...${hash.slice(-endChars)}`;
}

export function chunkHash(hash?: string | null, chunkSize = 8): string {
  if (!hash) return '—';
  const chunks: string[] = [];
  for (let i = 0; i < hash.length; i += chunkSize) {
    chunks.push(hash.slice(i, i + chunkSize));
  }
  return chunks.join(' ');
}
