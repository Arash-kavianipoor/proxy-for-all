import type { GeoDnsCapabilities, GeoDnsRecord, GeoDnsZone } from '../../src/types/georoute.ts';
import { PROVIDER_CAPABILITIES } from './capabilities.ts';
import { checkDnsDelegation } from './delegation.ts';
import type {
  DelegationStatus,
  GeoDnsOperationResult,
  GeoDnsProvider,
  GeoDnsRecordInput,
  ProviderValidationResult,
} from './types.ts';

export class ManualGeoDnsProvider implements GeoDnsProvider {
  readonly providerType = 'manual' as const;

  async validateCredentials(): Promise<ProviderValidationResult> {
    return {
      valid: true,
      provider: 'manual',
      message: 'Manual Provider Setup active. No remote GeoDNS API is connected; configuration changes generate manual instructions only.',
    };
  }

  async listZones(): Promise<GeoDnsZone[]> {
    return [];
  }

  async getZone(zoneId: string): Promise<GeoDnsZone> {
    return {
      id: zoneId,
      name: zoneId,
      nameservers: [],
      geoDnsEnabled: false,
      recordCount: 0,
    };
  }

  async getNameservers(): Promise<string[]> {
    return [];
  }

  async listRecords(): Promise<GeoDnsRecord[]> {
    return [];
  }

  async createRecord(_zoneId: string, input: GeoDnsRecordInput): Promise<GeoDnsOperationResult> {
    return {
      success: false,
      manualMode: true,
      message: `Manual Mode: Apply ${input.type} (${input.regionCode}) for ${input.hostname} -> ${input.value} (TTL ${input.ttl}s) manually in your DNS provider console.`,
    };
  }

  async updateRecord(_zoneId: string, _recordId: string, input: GeoDnsRecordInput): Promise<GeoDnsOperationResult> {
    return {
      success: false,
      manualMode: true,
      message: `Manual Mode: Update ${input.type} (${input.regionCode}) for ${input.hostname} -> ${input.value} (TTL ${input.ttl}s) manually in your DNS provider console.`,
    };
  }

  async deleteRecord(_zoneId: string, recordId: string): Promise<GeoDnsOperationResult> {
    return {
      success: false,
      manualMode: true,
      message: `Manual Mode: Remove record ${recordId} manually in your DNS provider console.`,
    };
  }

  async checkDelegation(domain: string, expectedNameservers?: string[]): Promise<DelegationStatus> {
    return checkDnsDelegation(domain, expectedNameservers ?? []);
  }

  async getCapabilities(): Promise<GeoDnsCapabilities> {
    return PROVIDER_CAPABILITIES.manual;
  }
}
