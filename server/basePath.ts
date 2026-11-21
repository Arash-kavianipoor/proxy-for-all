export function normalizeBasePath(raw?: string | string[]): string {
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (!value) return '';
  const trimmed = String(value).trim();
  if (!trimmed || trimmed === '/') return '';
  const withLeading = trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
  const cleaned = withLeading.replace(/\/+$/, '');
  if (!/^\/[a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)*$/.test(cleaned)) {
    return '';
  }
  return cleaned;
}
