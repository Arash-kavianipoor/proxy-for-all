export type ProjectStatus =
  | 'draft'
  | 'needs_infrastructure_verification'
  | 'geodns_not_configured'
  | 'dns_configured'
  | 'waiting_for_nameserver_delegation'
  | 'proxy_not_verified'
  | 'ssl_not_verified'
  | 'operational'
  | 'degraded'
  | 'failed';

export type ProviderType = 'ns1' | 'cloudns' | 'manual';

export type CapabilitySupportState =
  | 'supported'
  | 'not_supported'
  | 'not_documented'
  | 'requires_specific_plan'
  | 'requires_vendor_confirmation';

export type HostCapabilityStatus =
  | 'supported'
  | 'unsupported'
  | 'not_tested'
  | 'provider_confirmation_required';

export type DiagnosticStatus = 'passed' | 'failed' | 'warning' | 'not_tested';

export type RegionCode = 'IR' | 'DEFAULT' | 'FALLBACK';

export type DnsRecordType = 'A' | 'AAAA' | 'CNAME' | 'ALIAS' | 'TXT';

export type CacheBehavior =
  | 'cache_immutable'
  | 'cache_short'
  | 'revalidate'
  | 'bypass_always';

export interface UserSummary {
  id: string;
  username: string;
  role: 'admin' | 'operator' | 'viewer';
  createdAt: string;
}

export interface Project {
  id: string;
  ownerId: string;
  projectName: string;
  domain: string;
  description: string;
  status: ProjectStatus;
  iranProxyHostname: string;
  iranProxyIPv4: string;
  iranProxyIPv6: string;
  cloudflareTarget: string;
  cloudflareZoneId: string;
  geoDnsProvider: ProviderType;
  geoDnsZoneId: string;
  healthCheckUrl: string;
  notes: string;
  createdAt: string;
  updatedAt: string;
}

export interface HostingCapability {
  id: string;
  projectId: string;
  capabilityKey: string;
  capabilityLabel: string;
  category: string;
  status: HostCapabilityStatus;
  notes: string;
  verifiedAt: string;
  updatedAt: string;
}

export interface CachePolicy {
  id: string;
  projectId: string;
  pathPattern: string;
  resourceType: string;
  cacheBehavior: CacheBehavior;
  ttlSeconds: number;
  respectOriginHeaders: boolean;
  bypassOnCookie: boolean;
  enabled: boolean;
  updatedAt: string;
}

export interface GeoDnsCapabilities {
  provider: ProviderType;
  displayName: string;
  countryRouting: CapabilitySupportState;
  iranSpecificRule: CapabilitySupportState;
  defaultFallback: CapabilitySupportState;
  supportedRecordTypes: DnsRecordType[];
  apexHandling: string;
  minTtlSeconds: number;
  maxTtlSeconds: number;
  supportsEdnsClientSubnet: CapabilitySupportState;
  supportsHealthChecks: CapabilitySupportState;
  supportsFailover: CapabilitySupportState;
  supportsWeightedRouting: CapabilitySupportState;
  supportsIpv6: CapabilitySupportState;
  supportsDnssec: CapabilitySupportState;
  apiAuthMethod: string;
  pricingAndPlanNotes: string;
  sandboxNotes: string;
  rateLimitNotes: string;
  officialDocUrls: Array<{ label: string; url: string }>;
  verifiedDate: string;
  warnings: string[];
}

export interface DnsProviderAccountSummary {
  id: string;
  providerName: ProviderType;
  accountLabel: string;
  maskedHint: string;
  validationStatus: 'valid' | 'invalid' | 'not_validated' | 'manual';
  validationMessage: string;
  lastValidatedAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface GeoDnsZone {
  id: string;
  name: string;
  nameservers: string[];
  dnssecEnabled?: boolean;
  geoDnsEnabled?: boolean;
  recordCount?: number;
}

export interface GeoDnsRecord {
  id: string;
  zoneId: string;
  hostname: string;
  type: string;
  value: string;
  ttl: number;
  regionCode: RegionCode | string;
  rawMeta?: Record<string, unknown>;
}

export interface ProjectHostname {
  id: string;
  projectId: string;
  hostname: string;
  role: 'apex' | 'www' | 'static' | 'api' | 'custom';
  notes: string;
  createdAt: string;
  updatedAt: string;
}

export interface RoutingRule {
  id: string;
  projectId: string;
  hostname: string;
  regionCode: RegionCode;
  recordType: DnsRecordType;
  destination: string;
  ttl: number;
  enabled: boolean;
  updatedAt: string;
}

export interface DnsZoneBinding {
  id: string;
  projectId: string;
  providerAccountId: string | null;
  providerZoneId: string;
  domain: string;
  authoritativeNameservers: string[];
  delegationStatus: 'verified' | 'waiting_delegation' | 'mismatch' | 'not_checked';
  observedNameservers: string[];
  lastSyncedAt: string;
  updatedAt: string;
}

export interface DnsDiffItem {
  operation: 'create' | 'update' | 'delete' | 'unchanged' | 'conflict';
  hostname: string;
  regionCode: RegionCode;
  recordType: DnsRecordType;
  currentValue: string;
  proposedValue: string;
  ttl: number;
  conflictReason?: string;
  existingRecordId?: string;
}

export interface DeploymentPreview {
  previewHash: string;
  projectId: string;
  domain: string;
  providerName: ProviderType;
  providerAccountId: string | null;
  zoneId: string;
  authoritativeNameservers: string[];
  currentRecords: GeoDnsRecord[];
  changes: DnsDiffItem[];
  warnings: string[];
  conflicts: string[];
  canDeploy: boolean;
  manualMode: boolean;
  apexSupported: boolean;
  dnssecReminder: string;
  generatedAt: string;
}

export interface DnsDeploymentJob {
  id: string;
  projectId: string;
  providerAccountId: string | null;
  zoneId: string;
  previewHash: string;
  status: 'previewed' | 'deploying' | 'confirmed' | 'partial_failure' | 'failed' | 'manual_pending';
  summary: string;
  providerOperationId: string;
  confirmedBy: string | null;
  confirmedAt: string | null;
  createdAt: string;
  updatedAt: string;
  changes?: Array<{
    id: string;
    operation: string;
    hostname: string;
    regionCode: string;
    recordType: string;
    currentValue: string;
    proposedValue: string;
    ttl: number;
    resultStatus: string;
    errorMessage: string;
  }>;
}

export interface IrnicChecklistStep {
  id: string;
  projectId: string;
  stepKey: string;
  stepLabel: string;
  stepOrder: number;
  completed: boolean;
  updatedAt: string;
}

export interface CloudflareAccountSummary {
  id: string;
  accountLabel: string;
  maskedHint: string;
  validationStatus: 'valid' | 'invalid' | 'not_validated';
  validationMessage: string;
  lastValidatedAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface CloudflareRecordSummary {
  id: string;
  type: string;
  name: string;
  content: string;
  proxied: boolean;
  ttl: number;
}

export interface CloudflareWorkerRouteSummary {
  id: string;
  pattern: string;
  script?: string;
}

export interface CloudflareWorkerDomainSummary {
  id: string;
  hostname: string;
  service: string;
  environment?: string;
  zone_id?: string;
  zone_name?: string;
}

export interface ProjectCloudflareMapping {
  id: string;
  projectId: string;
  cloudflareAccountId: string;
  cloudflareZoneId: string;
  zoneName: string;
  zoneStatus: string;
  nameServers: string[];
  recordsSnapshot: CloudflareRecordSummary[];
  workerRoutes: CloudflareWorkerRouteSummary[];
  workerDomains: CloudflareWorkerDomainSummary[];
  sslMode: string;
  cacheLevel: string;
  requiresArchitectureReview: boolean;
  reviewNotes: string;
  discoveredAt: string;
  updatedAt: string;
}

export interface DiagnosticCheckRecord {
  id: string;
  projectId: string;
  checkCategory: string;
  target: string;
  status: DiagnosticStatus;
  testLocation: string;
  summary: string;
  technicalDetails: Record<string, unknown>;
  checkedAt: string;
}

export interface AuditLogEntry {
  id: string;
  actorId: string;
  actorUsername?: string;
  projectId: string | null;
  projectName?: string;
  action: string;
  result: 'success' | 'failure' | 'warning' | 'blocked';
  details: string;
  createdAt: string;
}
