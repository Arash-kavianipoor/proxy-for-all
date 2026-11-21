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

export interface ClouDnsCredentials {
  authId: string;
  authPassword: string;
  isSubUser?: boolean;
}

interface ClouDnsZoneRaw {
  name: string;
  type: string;
  zone?: string;
  status?: string;
}

interface ClouDnsRecordRaw {
  id: string | number;
  type: string;
  host: string;
  record: string;
  ttl: string | number;
  geodns_location?: string | number;
  geodns_code?: string;
}

export class ClouDnsGeoDnsProvider implements GeoDnsProvider {
  readonly providerType = 'cloudns' as const;
  private readonly authId: string;
  private readonly authPassword: string;
  private readonly isSubUser: boolean;
  private readonly baseUrl = 'https://api.cloudns.net';
  private readonly fetcher: typeof fetch;

  constructor(credentials: ClouDnsCredentials, fetcher: typeof fetch = fetch) {
    this.authId = credentials.authId.trim();
    this.authPassword = credentials.authPassword;
    this.isSubUser = Boolean(credentials.isSubUser);
    this.fetcher = fetcher;
  }

  private buildAuthParams(): Record<string, string> {
    if (this.isSubUser) {
      return {
        'sub-auth-id': this.authId,
        'auth-password': this.authPassword,
      };
    }
    return {
      'auth-id': this.authId,
      'auth-password': this.authPassword,
    };
  }

  private async request<T>(endpoint: string, params: Record<string, string | number> = {}): Promise<T> {
    const body = new URLSearchParams({
      ...this.buildAuthParams(),
      ...Object.fromEntries(Object.entries(params).map(([k, v]) => [k, String(v)])),
    });

    let response: Response;
    try {
      response = await this.fetcher(`${this.baseUrl}${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body.toString(),
        signal: AbortSignal.timeout(15000),
      });
    } catch (err) {
      const msg = err instanceof Error ? redactSecrets(err.message, [this.authPassword, this.authId]) : 'Network error';
      throw new ProviderApiError('cloudns', 'NETWORK_ERROR', `ClouDNS API request failed: ${msg}`, 502);
    }

    const rawText = await response.text();
    let parsed: unknown;
    try {
      parsed = JSON.parse(rawText);
    } catch {
      throw new ProviderApiError('cloudns', 'INVALID_RESPONSE', 'ClouDNS returned a non-JSON response.', 502);
    }

    if (
      parsed &&
      typeof parsed === 'object' &&
      !Array.isArray(parsed) &&
      'status' in parsed &&
      (parsed as { status: unknown }).status === 'Failed'
    ) {
      const desc =
        'statusDescription' in parsed
          ? redactSecrets(String((parsed as { statusDescription: unknown }).statusDescription), [this.authPassword, this.authId])
          : 'ClouDNS API returned status Failed';
      const isAuth = /auth|password|api/i.test(desc);
      throw new ProviderApiError(
        'cloudns',
        isAuth ? 'AUTH_FAILED' : 'API_ERROR',
        desc,
        isAuth ? 401 : 400
      );
    }

    if (!response.ok) {
      throw new ProviderApiError('cloudns', 'HTTP_ERROR', `ClouDNS HTTP ${response.status}`, response.status);
    }

    return parsed as T;
  }

  async validateCredentials(): Promise<ProviderValidationResult> {
    try {
      const zones = await this.listZones();
      return {
        valid: true,
        provider: 'cloudns',
        message: `Authenticated to ClouDNS HTTP API (${zones.length} zone(s) visible on page 1).`,
        accountInfo: { zoneCount: zones.length },
      };
    } catch (err) {
      const msg = err instanceof Error ? redactSecrets(err.message, [this.authPassword, this.authId]) : 'Validation failed';
      return {
        valid: false,
        provider: 'cloudns',
        message: msg,
      };
    }
  }

  async listZones(): Promise<GeoDnsZone[]> {
    const data = await this.request<ClouDnsZoneRaw[]>('/dns/list-zones.json', {
      page: 1,
      'rows-per-page': 100,
    });
    if (!Array.isArray(data)) {
      throw new ProviderApiError('cloudns', 'INVALID_RESPONSE', 'Expected array from ClouDNS list-zones.json.', 502);
    }
    return data.map((z) => ({
      id: z.name,
      name: z.name,
      nameservers: [],
      geoDnsEnabled: z.zone === 'geodns' || z.type === 'geodns',
    }));
  }

  async getZone(zoneId: string): Promise<GeoDnsZone> {
    const cleanZone = normalizeDomain(zoneId);
    const info = await this.request<Record<string, unknown>>('/dns/get-zone-info.json', {
      'domain-name': cleanZone,
    });
    const records = await this.listRecords(cleanZone).catch(() => []);
    const nsRecords = records
      .filter((r) => r.type === 'NS' && (r.hostname === cleanZone || r.hostname === '@'))
      .map((r) => normalizeDomain(r.value));

    return {
      id: cleanZone,
      name: cleanZone,
      nameservers: nsRecords,
      geoDnsEnabled: Boolean(info.zone === 'geodns' || info.type === 'geodns' || info.geodns === 1),
      recordCount: records.length,
    };
  }

  async getNameservers(zoneId: string): Promise<string[]> {
    const zone = await this.getZone(zoneId);
    return zone.nameservers;
  }

  async listRecords(zoneId: string): Promise<GeoDnsRecord[]> {
    const cleanZone = normalizeDomain(zoneId);
    const raw = await this.request<Record<string, ClouDnsRecordRaw>>('/dns/list-records.json', {
      'domain-name': cleanZone,
    });
    if (!raw || typeof raw !== 'object') {
      return [];
    }
    return Object.values(raw).map((r) => {
      const fqdn = !r.host || r.host === '@' ? cleanZone : `${r.host}.${cleanZone}`;
      const code = r.geodns_code || (String(r.geodns_location || '').toUpperCase() === 'IR' ? 'IR' : 'DEFAULT');
      return {
        id: String(r.id),
        zoneId: cleanZone,
        hostname: fqdn,
        type: r.type,
        value: r.record,
        ttl: Number(r.ttl) || 300,
        regionCode: code,
        rawMeta: {
          host: r.host,
          geodns_location: r.geodns_location,
          geodns_code: r.geodns_code,
        },
      };
    });
  }

  private toClouDnsHost(zoneId: string, hostname: string): string {
    const cleanZone = normalizeDomain(zoneId);
    const cleanHost = normalizeDomain(hostname);
    if (cleanHost === '@' || cleanHost === cleanZone) return '';
    if (cleanHost.endsWith(`.${cleanZone}`)) {
      return cleanHost.slice(0, -(cleanZone.length + 1));
    }
    return cleanHost;
  }

  async resolveGeoDnsLocationId(zoneId: string, regionCode: string): Promise<string | null> {
    if (regionCode === 'DEFAULT' || regionCode === 'FALLBACK') return 'DEFAULT';
    try {
      const locations = await this.request<Record<string, string>>('/dns/get-geodns-locations.json', {
        'domain-name': normalizeDomain(zoneId),
      });
      for (const [id, label] of Object.entries(locations)) {
        if (label.toLowerCase().includes('iran') || id.toUpperCase() === 'IR') {
          return id;
        }
      }
      return 'IR';
    } catch {
      return 'IR';
    }
  }

  async createRecord(zoneId: string, input: GeoDnsRecordInput): Promise<GeoDnsOperationResult> {
    const cleanZone = normalizeDomain(zoneId);
    const host = this.toClouDnsHost(cleanZone, input.hostname);
    const params: Record<string, string | number> = {
      'domain-name': cleanZone,
      'record-type': input.type,
      host,
      record: input.value,
      ttl: input.ttl,
    };
    if (input.regionCode === 'IR') {
      const loc = await this.resolveGeoDnsLocationId(cleanZone, 'IR');
      if (loc && /^\d+$/.test(loc)) {
        params['geodns-location'] = Number(loc);
      } else {
        params['geodns-code'] = 'IR';
      }
    } else {
      params['geodns-code'] = 'DEFAULT';
    }

    const res = await this.request<{ status?: string; data?: { id?: number | string } }>(
      '/dns/add-record.json',
      params
    );
    const recordId = res.data?.id ? String(res.data.id) : `${host || '@'}:${input.type}:${input.regionCode}`;
    return {
      success: true,
      operationId: recordId,
      message: `Created ClouDNS ${input.type} record (${input.regionCode}) for ${input.hostname}.`,
      record: {
        id: recordId,
        zoneId: cleanZone,
        hostname: input.hostname,
        type: input.type,
        value: input.value,
        ttl: input.ttl,
        regionCode: input.regionCode,
      },
    };
  }

  async updateRecord(zoneId: string, recordId: string, input: GeoDnsRecordInput): Promise<GeoDnsOperationResult> {
    const cleanZone = normalizeDomain(zoneId);
    const host = this.toClouDnsHost(cleanZone, input.hostname);
    const params: Record<string, string | number> = {
      'domain-name': cleanZone,
      'record-id': recordId,
      host,
      record: input.value,
      ttl: input.ttl,
    };
    if (input.regionCode === 'IR') {
      const loc = await this.resolveGeoDnsLocationId(cleanZone, 'IR');
      if (loc && /^\d+$/.test(loc)) {
        params['geodns-location'] = Number(loc);
      } else {
        params['geodns-code'] = 'IR';
      }
    } else {
      params['geodns-code'] = 'DEFAULT';
    }

    await this.request('/dns/mod-record.json', params);
    return {
      success: true,
      operationId: recordId,
      message: `Updated ClouDNS record ${recordId} for ${input.hostname}.`,
      record: {
        id: recordId,
        zoneId: cleanZone,
        hostname: input.hostname,
        type: input.type,
        value: input.value,
        ttl: input.ttl,
        regionCode: input.regionCode,
      },
    };
  }

  async deleteRecord(zoneId: string, recordId: string): Promise<GeoDnsOperationResult> {
    const cleanZone = normalizeDomain(zoneId);
    await this.request('/dns/delete-record.json', {
      'domain-name': cleanZone,
      'record-id': recordId,
    });
    return {
      success: true,
      operationId: recordId,
      message: `Deleted ClouDNS record ${recordId}.`,
    };
  }

  async checkDelegation(domain: string, expectedNameservers?: string[]): Promise<DelegationStatus> {
    const expected = expectedNameservers ?? (await this.getNameservers(domain).catch(() => []));
    return checkDnsDelegation(domain, expected);
  }

  async getCapabilities(): Promise<GeoDnsCapabilities> {
    return PROVIDER_CAPABILITIES.cloudns;
  }
}
