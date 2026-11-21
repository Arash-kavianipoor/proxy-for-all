import { redactSecrets } from '../crypto.ts';
import type {
  CloudflareRecordSummary,
  CloudflareWorkerDomainSummary,
  CloudflareWorkerRouteSummary,
} from '../../src/types/georoute.ts';

export interface CloudflareZoneSummary {
  id: string;
  name: string;
  status: string;
  nameServers: string[];
  accountId: string;
  accountName: string;
}

export interface CloudflareDiscoveryBundle {
  zone: CloudflareZoneSummary;
  records: CloudflareRecordSummary[];
  workerRoutes: CloudflareWorkerRouteSummary[];
  workerDomains: CloudflareWorkerDomainSummary[];
  sslMode: string;
  cacheLevel: string;
  requiresArchitectureReview: boolean;
  reviewNotes: string;
}

export class CloudflareReadOnlyClient {
  private readonly apiToken: string;
  private readonly baseUrl = 'https://api.cloudflare.com/client/v4';
  private readonly fetcher: typeof fetch;

  constructor(apiToken: string, fetcher: typeof fetch = fetch) {
    this.apiToken = apiToken.trim();
    this.fetcher = fetcher;
  }

  private async request<T>(path: string): Promise<T> {
    let response: Response;
    try {
      response = await this.fetcher(`${this.baseUrl}${path}`, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${this.apiToken}`,
          'Content-Type': 'application/json',
        },
        signal: AbortSignal.timeout(15000),
      });
    } catch (err) {
      const msg = err instanceof Error ? redactSecrets(err.message, [this.apiToken]) : 'Network error';
      throw new Error(`Cloudflare API request failed: ${msg}`);
    }

    const text = await response.text();
    let json: {
      success?: boolean;
      errors?: Array<{ code?: number; message?: string }>;
      result?: T;
    };
    try {
      json = JSON.parse(text);
    } catch {
      throw new Error(`Cloudflare API returned invalid JSON (HTTP ${response.status}).`);
    }

    if (!response.ok || json.success === false) {
      const errMsg =
        json.errors?.map((e) => e.message).filter(Boolean).join('; ') || `HTTP ${response.status}`;
      throw new Error(redactSecrets(`Cloudflare API error: ${errMsg}`, [this.apiToken]));
    }

    return json.result as T;
  }

  async verifyToken(): Promise<{ valid: boolean; status: string; message: string }> {
    try {
      const result = await this.request<{ id?: string; status?: string }>('/user/tokens/verify');
      return {
        valid: result?.status === 'active',
        status: result?.status || 'unknown',
        message: result?.status === 'active'
          ? 'Cloudflare API token is valid and active (read-only discovery ready).'
          : `Cloudflare token status: ${result?.status || 'unknown'}`,
      };
    } catch (err) {
      return {
        valid: false,
        status: 'invalid',
        message: err instanceof Error ? redactSecrets(err.message, [this.apiToken]) : 'Verification failed',
      };
    }
  }

  async listZones(): Promise<CloudflareZoneSummary[]> {
    const raw = await this.request<
      Array<{
        id: string;
        name: string;
        status: string;
        name_servers?: string[];
        account?: { id?: string; name?: string };
      }>
    >('/zones?per_page=50');

    return (raw || []).map((z) => ({
      id: z.id,
      name: z.name,
      status: z.status,
      nameServers: Array.isArray(z.name_servers) ? z.name_servers : [],
      accountId: z.account?.id || '',
      accountName: z.account?.name || '',
    }));
  }

  async discoverZone(zoneId: string): Promise<CloudflareDiscoveryBundle> {
    const zoneRaw = await this.request<{
      id: string;
      name: string;
      status: string;
      name_servers?: string[];
      account?: { id?: string; name?: string };
    }>(`/zones/${encodeURIComponent(zoneId)}`);

    const zone: CloudflareZoneSummary = {
      id: zoneRaw.id,
      name: zoneRaw.name,
      status: zoneRaw.status,
      nameServers: Array.isArray(zoneRaw.name_servers) ? zoneRaw.name_servers : [],
      accountId: zoneRaw.account?.id || '',
      accountName: zoneRaw.account?.name || '',
    };

    const recordsRaw = await this.request<
      Array<{
        id: string;
        type: string;
        name: string;
        content: string;
        proxied?: boolean;
        ttl: number;
      }>
    >(`/zones/${encodeURIComponent(zoneId)}/dns_records?per_page=100`).catch(() => []);

    const records: CloudflareRecordSummary[] = (recordsRaw || []).map((r) => ({
      id: r.id,
      type: r.type,
      name: r.name,
      content: r.content,
      proxied: Boolean(r.proxied),
      ttl: r.ttl,
    }));

    const workerRoutesRaw = await this.request<
      Array<{ id: string; pattern: string; script?: string }>
    >(`/zones/${encodeURIComponent(zoneId)}/workers/routes`).catch(() => []);

    const workerRoutes: CloudflareWorkerRouteSummary[] = (workerRoutesRaw || []).map((w) => ({
      id: w.id,
      pattern: w.pattern,
      script: w.script,
    }));

    let workerDomains: CloudflareWorkerDomainSummary[] = [];
    if (zone.accountId) {
      const domainsRaw = await this.request<
        Array<{
          id: string;
          hostname: string;
          service: string;
          environment?: string;
          zone_id?: string;
          zone_name?: string;
        }>
      >(`/accounts/${encodeURIComponent(zone.accountId)}/workers/domains`).catch(() => []);
      workerDomains = (domainsRaw || []).filter(
        (d) => d.zone_id === zoneId || d.hostname.endsWith(zone.name)
      );
    }

    const sslResult = await this.request<{ value?: string }>(
      `/zones/${encodeURIComponent(zoneId)}/settings/ssl`
    ).catch(() => ({ value: 'unknown (permission required)' }));

    const cacheResult = await this.request<{ value?: string }>(
      `/zones/${encodeURIComponent(zoneId)}/settings/cache_level`
    ).catch(() => ({ value: 'unknown (permission required)' }));

    const proxiedCount = records.filter((r) => r.proxied).length;
    const hasWorkers = workerRoutes.length > 0 || workerDomains.length > 0;

    let requiresArchitectureReview = false;
    const notes: string[] = [];

    if (hasWorkers) {
      requiresArchitectureReview = true;
      notes.push(
        'Zone uses Cloudflare Workers routes or Worker Custom Domains. Worker Custom Domains are bound to Cloudflare edge routing and cannot be treated as a bare origin IP.'
      );
    }
    if (proxiedCount > 0) {
      notes.push(
        `${proxiedCount} record(s) are Cloudflare-proxied (orange-clouded). External DNS returns Cloudflare anycast IPs rather than the origin server IP.`
      );
    }
    if (!hasWorkers && proxiedCount === 0) {
      notes.push('Zone records are DNS-only or no Workers bindings were detected (or token lacked Workers Read permission).');
    }

    return {
      zone,
      records,
      workerRoutes,
      workerDomains,
      sslMode: sslResult?.value || 'unknown',
      cacheLevel: cacheResult?.value || 'unknown',
      requiresArchitectureReview,
      reviewNotes: notes.join(' '),
    };
  }
}
