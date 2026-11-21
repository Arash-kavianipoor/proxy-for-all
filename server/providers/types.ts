import type {
  DnsRecordType,
  GeoDnsCapabilities,
  GeoDnsRecord,
  GeoDnsZone,
  ProviderType,
  RegionCode,
} from '../../src/types/georoute.ts';

export interface ProviderValidationResult {
  valid: boolean;
  provider: ProviderType;
  message: string;
  accountInfo?: {
    zoneCount?: number;
    details?: string;
  };
}

export interface GeoDnsRecordInput {
  hostname: string;
  type: DnsRecordType;
  value: string;
  ttl: number;
  regionCode: RegionCode;
  iranValue?: string;
  defaultValue?: string;
}

export interface GeoDnsOperationResult {
  success: boolean;
  operationId?: string;
  message: string;
  record?: GeoDnsRecord;
  manualMode?: boolean;
}

export interface DelegationStatus {
  domain: string;
  status: 'verified' | 'waiting_delegation' | 'mismatch' | 'not_checked';
  expectedNameservers: string[];
  observedNameservers: string[];
  checkedAt: string;
  message: string;
}

export class ProviderApiError extends Error {
  readonly code: string;
  readonly statusCode: number;
  readonly provider: ProviderType;

  constructor(provider: ProviderType, code: string, message: string, statusCode = 502) {
    super(message);
    this.name = 'ProviderApiError';
    this.provider = provider;
    this.code = code;
    this.statusCode = statusCode;
  }
}

export interface GeoDnsProvider {
  readonly providerType: ProviderType;
  validateCredentials(): Promise<ProviderValidationResult>;
  listZones(): Promise<GeoDnsZone[]>;
  getZone(zoneId: string): Promise<GeoDnsZone>;
  getNameservers(zoneId: string): Promise<string[]>;
  listRecords(zoneId: string): Promise<GeoDnsRecord[]>;
  createRecord(zoneId: string, input: GeoDnsRecordInput): Promise<GeoDnsOperationResult>;
  updateRecord(zoneId: string, recordId: string, input: GeoDnsRecordInput): Promise<GeoDnsOperationResult>;
  deleteRecord(zoneId: string, recordId: string): Promise<GeoDnsOperationResult>;
  checkDelegation(domain: string, expectedNameservers?: string[]): Promise<DelegationStatus>;
  getCapabilities(): Promise<GeoDnsCapabilities>;
}
