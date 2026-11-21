import { redactSecrets } from '../crypto.ts';
import { normalizeDomain } from '../security.ts';
import type { GeoDnsCapabilities, GeoDnsRecord, GeoDnsZone } from '../../src/types/georoute.ts';
import { PROVIDER_CAPABILITIES } from './capabilities.ts';
import { checkDnsDelegation } from './delegation.ts';
import {
  ProviderApiError,
  type DelegationStatus,
  type GeoDnsOperationResult,
  type GeoDnsProvider,
  type GeoDnsRecordInput,
  type ProviderValidationResult,
} from './types.ts';

export interface Ns1Credentials {
  apiKey: string;
}

interface Ns1ZoneResponse {
  zone: string;
  dns_servers?: string[];
  dnssec?: boolean;
  records?: Array<{
    id?: string;
    domain: string;
    type: string;
    ttl?: number;
    short_answers?: string[];
  }>;
}

interface Ns1RecordResponse {
  id?: string;
  zone?: string;
  domain: string;
  type: string;
  ttl: number;
  answers?: Array<{
    id?: string;
    answer: string[];
    meta?: {
      country?: string[] | string;
    };
  }>;
  filters?: Array<{
    filter: string;
    config?: Record<string, unknown>;
  }>;
}

export class Ns1GeoDnsProvider implements GeoDnsProvider {
  readonly providerType = 'ns1' as const;
  private readonly apiKey: string;
  private readonly baseUrl = 'https://api.nsone.net/v1';
  private readonly fetcher: typeof fetch;

  constructor(credentials: Ns1Credentials, fetcher: typeof fetch = fetch) {
    this.apiKey = credentials.apiKey.trim();
    this.fetcher = fetcher;
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers = new Headers(init.headers);
    headers.set('X-NSONE-Key', this.apiKey);
    headers.set('Content-Type', 'application/json');

    let response: Response;
    try {
      response = await this.fetcher(url, {
        ...init,
        headers,
        signal: AbortSignal.timeout(15000),
      });
    } catch (err) {
      const msg = err instanceof Error ? redactSecrets(err.message, [this.apiKey]) : 'Network request failed';
      throw new ProviderApiError('ns1', 'NETWORK_ERROR', `NS1 API request failed: ${msg}`, 502);
    }

    const rawText = await response.text();
    let parsed: unknown = null;
    try {
      parsed = rawText ? JSON.parse(rawText) : null;
    } catch {
      parsed = null;
    }

    if (!response.ok) {
      const apiMsg =
        parsed && typeof parsed === 'object' && 'message' in parsed
          ? String((parsed as { message: unknown }).message)
          : `HTTP ${response.status}`;
      const safeMsg = redactSecrets(apiMsg, [this.apiKey]);
      if (response.status === 401 || response.status === 403) {
        throw new ProviderApiError('ns1', 'AUTH_FAILED', `NS1 authentication failed: ${safeMsg}`, 401);
      }
      if (response.status === 404) {
        throw new ProviderApiError('ns1', 'NOT_FOUND', `NS1 resource not found: ${safeMsg}`, 404);
      }
      if (response.status === 429) {
        throw new ProviderApiError('ns1', 'RATE_LIMITED', `NS1 rate limit reached: ${safeMsg}`, 429);
      }
      throw new ProviderApiError('ns1', 'API_ERROR', `NS1 API error: ${safeMsg}`, response.status);
    }

    return parsed as T;
  }

  async validateCredentials(): Promise<ProviderValidationResult> {
    try {
      const zones = await this.listZones();
      return {
        valid: true,
        provider: 'ns1',
        message: `Connected to IBM NS1 Connect API (${zones.length} zone(s) accessible).`,
        accountInfo: { zoneCount: zones.length },
      };
    } catch (err) {
      const msg = err instanceof Error ? redactSecrets(err.message, [this.apiKey]) : 'Validation failed';
      return {
        valid: false,
        provider: 'ns1',
        message: msg,
      };
    }
  }

  async listZones(): Promise<GeoDnsZone[]> {
    const data = await this.request<Ns1ZoneResponse[]>('/zones');
    if (!Array.isArray(data)) {
      throw new ProviderApiError('ns1', 'INVALID_RESPONSE', 'Unexpected NS1 /zones response schema.', 502);
    }
    return data.map((z) => ({
      id: z.zone,
      name: z.zone,
      nameservers: Array.isArray(z.dns_servers) ? z.dns_servers : [],
      dnssecEnabled: Boolean(z.dnssec),
      geoDnsEnabled: true,
      recordCount: Array.isArray(z.records) ? z.records.length : undefined,
    }));
  }

  async getZone(zoneId: string): Promise<GeoDnsZone> {
    const cleanZone = normalizeDomain(zoneId);
    const data = await this.request<Ns1ZoneResponse>(`/zones/${encodeURIComponent(cleanZone)}`);
    if (!data || typeof data.zone !== 'string') {
      throw new ProviderApiError('ns1', 'INVALID_RESPONSE', 'Unexpected NS1 /zones/{zone} response schema.', 502);
    }
    return {
      id: data.zone,
      name: data.zone,
      nameservers: Array.isArray(data.dns_servers) ? data.dns_servers : [],
      dnssecEnabled: Boolean(data.dnssec),
      geoDnsEnabled: true,
      recordCount: Array.isArray(data.records) ? data.records.length : undefined,
    };
  }

  async getNameservers(zoneId: string): Promise<string[]> {
    const zone = await this.getZone(zoneId);
    return zone.nameservers;
  }

  async listRecords(zoneId: string): Promise<GeoDnsRecord[]> {
    const cleanZone = normalizeDomain(zoneId);
    const zoneData = await this.request<Ns1ZoneResponse>(`/zones/${encodeURIComponent(cleanZone)}`);
    const summaryRecords = Array.isArray(zoneData.records) ? zoneData.records : [];

    const results: GeoDnsRecord[] = [];
    for (const rec of summaryRecords) {
      if (rec.type === 'NS' || rec.type === 'SOA') {
        results.push({
          id: `${rec.domain}:${rec.type}`,
          zoneId: cleanZone,
          hostname: rec.domain,
          type: rec.type,
          value: (rec.short_answers || []).join(', '),
          ttl: rec.ttl ?? 3600,
          regionCode: 'DEFAULT',
        });
        continue;
      }

      try {
        const detail = await this.request<Ns1RecordResponse>(
          `/zones/${encodeURIComponent(cleanZone)}/${encodeURIComponent(rec.domain)}/${encodeURIComponent(rec.type)}`
        );
        const answers = Array.isArray(detail.answers) ? detail.answers : [];
        if (answers.length === 0) {
          results.push({
            id: `${rec.domain}:${rec.type}`,
            zoneId: cleanZone,
            hostname: rec.domain,
            type: rec.type,
            value: (rec.short_answers || []).join(', '),
            ttl: detail.ttl ?? rec.ttl ?? 300,
            regionCode: 'DEFAULT',
          });
          continue;
        }
        for (const ans of answers) {
          const countryMeta = ans.meta?.country;
          const countries = Array.isArray(countryMeta)
            ? countryMeta
            : typeof countryMeta === 'string'
              ? countryMeta.split(',').map((s) => s.trim())
              : [];
          const regionCode = countries.includes('IR') ? 'IR' : countries.length === 0 ? 'DEFAULT' : countries.join(',');
          results.push({
            id: `${rec.domain}:${rec.type}:${regionCode}`,
            zoneId: cleanZone,
            hostname: rec.domain,
            type: rec.type,
            value: (ans.answer || []).join(' '),
            ttl: detail.ttl ?? 300,
            regionCode,
            rawMeta: ans.meta as Record<string, unknown> | undefined,
          });
        }
      } catch {
        results.push({
          id: `${rec.domain}:${rec.type}`,
          zoneId: cleanZone,
          hostname: rec.domain,
          type: rec.type,
          value: (rec.short_answers || []).join(', '),
          ttl: rec.ttl ?? 300,
          regionCode: 'DEFAULT',
        });
      }
    }

    return results;
  }

  private buildNs1Payload(zoneId: string, input: GeoDnsRecordInput) {
    const cleanZone = normalizeDomain(zoneId);
    const fqdn =
      input.hostname === '@' || normalizeDomain(input.hostname) === cleanZone
        ? cleanZone
        : input.hostname.includes('.')
          ? normalizeDomain(input.hostname)
          : `${normalizeDomain(input.hostname)}.${cleanZone}`;

    const answers: Array<{ answer: string[]; meta: Record<string, unknown> }> = [];
    if (input.iranValue && input.defaultValue) {
      answers.push({ answer: [input.iranValue], meta: { country: ['IR'] } });
      answers.push({ answer: [input.defaultValue], meta: {} });
    } else if (input.regionCode === 'IR') {
      answers.push({ answer: [input.value], meta: { country: ['IR'] } });
    } else {
      answers.push({ answer: [input.value], meta: {} });
    }

    const payload: Record<string, unknown> = {
      zone: cleanZone,
      domain: fqdn,
      type: input.type,
      ttl: input.ttl,
      answers,
    };

    if (answers.length > 1 || input.regionCode === 'IR') {
      payload.filters = [
        { filter: 'up' },
        { filter: 'geofence_country', config: { labelfallback: true } },
        { filter: 'shuffle' },
      ];
    }

    return { fqdn, payload };
  }

  async createRecord(zoneId: string, input: GeoDnsRecordInput): Promise<GeoDnsOperationResult> {
    const cleanZone = normalizeDomain(zoneId);
    const { fqdn, payload } = this.buildNs1Payload(cleanZone, input);
    const res = await this.request<Ns1RecordResponse>(
      `/zones/${encodeURIComponent(cleanZone)}/${encodeURIComponent(fqdn)}/${encodeURIComponent(input.type)}`,
      {
        method: 'PUT',
        body: JSON.stringify(payload),
      }
    );
    return {
      success: true,
      operationId: res.id || `${fqdn}:${input.type}`,
      message: `Created NS1 ${input.type} record for ${fqdn}.`,
      record: {
        id: res.id || `${fqdn}:${input.type}`,
        zoneId: cleanZone,
        hostname: fqdn,
        type: input.type,
        value: input.value,
        ttl: res.ttl ?? input.ttl,
        regionCode: input.regionCode,
      },
    };
  }

  async updateRecord(zoneId: string, recordId: string, input: GeoDnsRecordInput): Promise<GeoDnsOperationResult> {
    const cleanZone = normalizeDomain(zoneId);
    const { fqdn, payload } = this.buildNs1Payload(cleanZone, input);
    const res = await this.request<Ns1RecordResponse>(
      `/zones/${encodeURIComponent(cleanZone)}/${encodeURIComponent(fqdn)}/${encodeURIComponent(input.type)}`,
      {
        method: 'POST',
        body: JSON.stringify(payload),
      }
    );
    return {
      success: true,
      operationId: res.id || recordId,
      message: `Updated NS1 ${input.type} record for ${fqdn}.`,
      record: {
        id: res.id || recordId,
        zoneId: cleanZone,
        hostname: fqdn,
        type: input.type,
        value: input.value,
        ttl: res.ttl ?? input.ttl,
        regionCode: input.regionCode,
      },
    };
  }

  async deleteRecord(zoneId: string, recordId: string): Promise<GeoDnsOperationResult> {
    const cleanZone = normalizeDomain(zoneId);
    const [fqdn, recType] = recordId.split(':');
    if (!fqdn || !recType) {
      throw new ProviderApiError('ns1', 'INVALID_RECORD_ID', 'Record ID must be formatted as fqdn:type.', 400);
    }
    await this.request(
      `/zones/${encodeURIComponent(cleanZone)}/${encodeURIComponent(fqdn)}/${encodeURIComponent(recType)}`,
      { method: 'DELETE' }
    );
    return {
      success: true,
      operationId: recordId,
      message: `Deleted NS1 ${recType} record for ${fqdn}.`,
    };
  }

  async checkDelegation(domain: string, expectedNameservers?: string[]): Promise<DelegationStatus> {
    const expected = expectedNameservers ?? (await this.getNameservers(domain).catch(() => []));
    return checkDnsDelegation(domain, expected);
  }

  async getCapabilities(): Promise<GeoDnsCapabilities> {
    return PROVIDER_CAPABILITIES.ns1;
  }
}
