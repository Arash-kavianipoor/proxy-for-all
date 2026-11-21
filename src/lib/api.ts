import type {
  AuditLogEntry,
  CachePolicy,
  CloudflareAccountSummary,
  DeploymentPreview,
  DiagnosticCheckRecord,
  DnsDeploymentJob,
  DnsProviderAccountSummary,
  DnsZoneBinding,
  GeoDnsCapabilities,
  GeoDnsRecord,
  GeoDnsZone,
  HostingCapability,
  IrnicChecklistStep,
  Project,
  ProjectCloudflareMapping,
  ProjectHostname,
  RoutingRule,
  UserSummary,
} from '../types/georoute';

let csrfTokenInMemory: string | null = null;
let sessionTokenInMemory: string | null = null;

export function setCsrfToken(token: string | null) {
  csrfTokenInMemory = token;
}

export function setSessionToken(token: string | null) {
  sessionTokenInMemory = token;
}

export class ApiError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

function getAppBasePath(): string {
  if (typeof document === 'undefined') return '';
  const meta = document.querySelector('meta[name="georoute-base"]')?.getAttribute('content') || '';
  const trimmed = meta.trim().replace(/\/+$/, '');
  if (!trimmed || trimmed === '/') return '';
  return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}

async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  if (sessionTokenInMemory && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${sessionTokenInMemory}`);
  }
  if (csrfTokenInMemory && ['POST', 'PUT', 'PATCH', 'DELETE'].includes((init.method || 'GET').toUpperCase())) {
    headers.set('X-CSRF-Token', csrfTokenInMemory);
  }

  const base = getAppBasePath();
  const targetUrl = path.startsWith('/') ? `${base}${path}` : path;

  const res = await fetch(targetUrl, {
    ...init,
    headers,
    credentials: 'same-origin',
  });

  const text = await res.text();
  let json: Record<string, unknown> = {};
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    json = { error: text || `HTTP ${res.status}` };
  }

  if (!res.ok) {
    throw new ApiError(String(json.error || `Request failed with HTTP ${res.status}`), res.status);
  }
  return json as T;
}

export interface AuthStatusResponse {
  initialized: boolean;
  authenticated: boolean;
  user: UserSummary | null;
  csrfToken: string | null;
  encryption: {
    source: 'environment' | 'local_dev_file';
    algorithm: string;
  };
  diagnosticsLocation: string;
}

export interface ProjectDetailResponse {
  project: Project;
  capabilities: HostingCapability[];
  cachePolicies: CachePolicy[];
  hostnames: ProjectHostname[];
  routingRules: RoutingRule[];
  dnsZone: DnsZoneBinding | null;
  irnicChecklist: IrnicChecklistStep[];
  cloudflareMapping: ProjectCloudflareMapping | null;
  diagnostics: DiagnosticCheckRecord[];
}

export const api = {
  authStatus: () => apiFetch<AuthStatusResponse>('/api/auth/status'),
  authSetup: (username: string, password: string) =>
    apiFetch<{ user: UserSummary; csrfToken: string; sessionToken?: string }>('/api/auth/setup', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  authLogin: (username: string, password: string) =>
    apiFetch<{ user: UserSummary; csrfToken: string; sessionToken?: string }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  authLogout: () => apiFetch<{ ok: boolean }>('/api/auth/logout', { method: 'POST' }),
  authChangePassword: (currentPassword: string, newPassword: string) =>
    apiFetch<{ ok: boolean }>('/api/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ currentPassword, newPassword }),
    }),

  listProviderCapabilities: () =>
    apiFetch<{ providers: GeoDnsCapabilities[] }>('/api/providers/capabilities'),

  listProjects: () => apiFetch<{ projects: Project[] }>('/api/projects'),
  createProject: (payload: {
    projectName: string;
    domain: string;
    description?: string;
    cloudflareTarget?: string;
    iranProxyHostname?: string;
    iranProxyIPv4?: string;
    geoDnsProvider?: string;
    notes?: string;
  }) =>
    apiFetch<{ project: Project }>('/api/projects', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  getProject: (projectId: string) => apiFetch<ProjectDetailResponse>(`/api/projects/${projectId}`),
  updateProject: (projectId: string, payload: Partial<Project>) =>
    apiFetch<{ project: Project }>(`/api/projects/${projectId}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),
  deleteProject: (projectId: string) =>
    apiFetch<{ ok: boolean }>(`/api/projects/${projectId}`, { method: 'DELETE' }),

  updateCapability: (projectId: string, capabilityKey: string, status: string, notes: string) =>
    apiFetch<{ ok: boolean }>(`/api/projects/${projectId}/capabilities/${capabilityKey}`, {
      method: 'PUT',
      body: JSON.stringify({ status, notes }),
    }),

  createCachePolicy: (
    projectId: string,
    payload: { pathPattern: string; resourceType: string; cacheBehavior: string; ttlSeconds: number }
  ) =>
    apiFetch<{ id: string }>(`/api/projects/${projectId}/cache-policies`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  updateCachePolicy: (
    projectId: string,
    policyId: string,
    payload: { cacheBehavior: string; ttlSeconds: number; enabled: boolean }
  ) =>
    apiFetch<{ ok: boolean }>(`/api/projects/${projectId}/cache-policies/${policyId}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  deleteCachePolicy: (projectId: string, policyId: string) =>
    apiFetch<{ ok: boolean }>(`/api/projects/${projectId}/cache-policies/${policyId}`, {
      method: 'DELETE',
    }),

  listDnsProviders: () => apiFetch<{ accounts: DnsProviderAccountSummary[] }>('/api/dns-providers'),
  createDnsProvider: (payload: {
    providerName: string;
    accountLabel: string;
    credentials: Record<string, unknown>;
  }) =>
    apiFetch<{ account: DnsProviderAccountSummary }>('/api/dns-providers', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  rotateDnsProvider: (id: string, credentials: Record<string, unknown>) =>
    apiFetch<{ ok: boolean; maskedHint: string }>(`/api/dns-providers/${id}/rotate`, {
      method: 'POST',
      body: JSON.stringify({ credentials }),
    }),
  validateDnsProvider: (id: string) =>
    apiFetch<{ validation: { valid: boolean; message: string } }>(`/api/dns-providers/${id}/validate`, {
      method: 'POST',
    }),
  listProviderZones: (id: string) =>
    apiFetch<{ zones: GeoDnsZone[] }>(`/api/dns-providers/${id}/zones`),
  deleteDnsProvider: (id: string) =>
    apiFetch<{ ok: boolean }>(`/api/dns-providers/${id}`, { method: 'DELETE' }),

  getProjectDns: (projectId: string) =>
    apiFetch<{
      provider: string;
      providerAccountId: string | null;
      zoneId: string;
      zoneBinding: DnsZoneBinding | null;
      routingRules: RoutingRule[];
      liveRecords: GeoDnsRecord[];
      liveError: string;
    }>(`/api/projects/${projectId}/dns`),

  bindProjectZone: (
    projectId: string,
    payload: { providerName: string; providerAccountId: string | null; providerZoneId: string }
  ) =>
    apiFetch<{ ok: boolean; nameservers: string[] }>(`/api/projects/${projectId}/dns/zone-binding`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  addProjectHostname: (
    projectId: string,
    payload: { hostname: string; role: string; notes?: string }
  ) =>
    apiFetch<{ id: string }>(`/api/projects/${projectId}/hostnames`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  deleteProjectHostname: (projectId: string, hostnameId: string) =>
    apiFetch<{ ok: boolean }>(`/api/projects/${projectId}/hostnames/${hostnameId}`, {
      method: 'DELETE',
    }),

  upsertRoutingRule: (
    projectId: string,
    payload: {
      hostname: string;
      regionCode: string;
      recordType: string;
      destination: string;
      ttl: number;
      enabled: boolean;
    }
  ) =>
    apiFetch<{ ok: boolean }>(`/api/projects/${projectId}/routing-rules`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  deleteRoutingRule: (projectId: string, ruleId: string) =>
    apiFetch<{ ok: boolean }>(`/api/projects/${projectId}/routing-rules/${ruleId}`, {
      method: 'DELETE',
    }),

  getDeploymentPreview: (projectId: string) =>
    apiFetch<{ preview: DeploymentPreview }>(`/api/projects/${projectId}/dns/preview`),
  deployDnsChanges: (
    projectId: string,
    payload: {
      previewHash: string;
      confirmProjectDomain: string;
      confirmProxyReady: boolean;
      confirmEmailRecordsPreserved: boolean;
      confirmDeployAction: boolean;
    }
  ) =>
    apiFetch<{
      deployment: { jobId: string; status: string; summary: string; operationIds: string[] };
    }>(`/api/projects/${projectId}/dns/deploy`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  listDeployments: (projectId: string) =>
    apiFetch<{ deployments: DnsDeploymentJob[] }>(`/api/projects/${projectId}/dns/deployments`),
  checkDelegation: (projectId: string) =>
    apiFetch<{
      delegation: {
        domain: string;
        status: string;
        expectedNameservers: string[];
        observedNameservers: string[];
        checkedAt: string;
        message: string;
      };
    }>(`/api/projects/${projectId}/dns/delegation`),

  updateIrnicStep: (projectId: string, stepKey: string, completed: boolean) =>
    apiFetch<{ ok: boolean }>(`/api/projects/${projectId}/irnic-checklist/${stepKey}`, {
      method: 'PUT',
      body: JSON.stringify({ completed }),
    }),

  listCloudflareAccounts: () =>
    apiFetch<{ accounts: CloudflareAccountSummary[] }>('/api/cloudflare/accounts'),
  createCloudflareAccount: (payload: { accountLabel: string; apiToken: string }) =>
    apiFetch<{ account: CloudflareAccountSummary }>('/api/cloudflare/accounts', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  validateCloudflareAccount: (id: string) =>
    apiFetch<{ validation: { valid: boolean; status: string; message: string } }>(
      `/api/cloudflare/accounts/${id}/validate`,
      { method: 'POST' }
    ),
  listCloudflareZones: (id: string) =>
    apiFetch<{
      zones: Array<{ id: string; name: string; status: string; nameServers: string[]; accountName: string }>;
    }>(`/api/cloudflare/accounts/${id}/zones`),
  deleteCloudflareAccount: (id: string) =>
    apiFetch<{ ok: boolean }>(`/api/cloudflare/accounts/${id}`, { method: 'DELETE' }),
  discoverCloudflare: (
    projectId: string,
    payload: { cloudflareAccountId: string; cloudflareZoneId: string }
  ) =>
    apiFetch<{ discovery: unknown }>(`/api/projects/${projectId}/cloudflare/discover`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  runDiagnostics: (projectId: string) =>
    apiFetch<{ checks: DiagnosticCheckRecord[] }>(`/api/projects/${projectId}/diagnostics`, {
      method: 'POST',
    }),
  getDiagnostics: (projectId: string) =>
    apiFetch<{ checks: DiagnosticCheckRecord[] }>(`/api/projects/${projectId}/diagnostics`),

  listAuditLogs: (projectId?: string) =>
    apiFetch<{ logs: AuditLogEntry[] }>(
      projectId ? `/api/audit-logs?projectId=${encodeURIComponent(projectId)}` : '/api/audit-logs'
    ),

  resolveCloudflareNs: (projectId: string, cloudflareTarget?: string) =>
    apiFetch<{
      resolution: {
        ok: boolean;
        domain: string;
        nameserversUsed: string[];
        resolvedNsIps: string[];
        ipv4Addresses: string[];
        ipv6Addresses: string[];
        message: string;
      };
    }>(`/api/projects/${projectId}/cloudflare/resolve-ns`, {
      method: 'POST',
      body: JSON.stringify(cloudflareTarget !== undefined ? { cloudflareTarget } : {}),
    }),

  testProxy: (projectId: string, payload: { path?: string; bypassCache?: boolean } = {}) =>
    apiFetch<{
      test: {
        ok: boolean;
        statusCode: number;
        cacheStatus: 'HIT' | 'MISS' | 'BYPASS';
        targetIp: string;
        cfRay: string;
        contentType: string;
        bytes: number;
        latencyMs: number;
        error: string;
      };
      cache: {
        entries: number;
        totalBytes: number;
        totalHits: number;
        items: Array<{ path: string; contentType: string; bytes: number; hits: number; expiresAt: string }>;
      };
    }>(`/api/projects/${projectId}/proxy/test`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getProxyCache: (projectId: string) =>
    apiFetch<{
      cache: {
        entries: number;
        totalBytes: number;
        totalHits: number;
        items: Array<{ path: string; contentType: string; bytes: number; hits: number; expiresAt: string }>;
      };
    }>(`/api/projects/${projectId}/proxy/cache`),

  clearProxyCache: (projectId: string) =>
    apiFetch<{
      ok: boolean;
      cleared: number;
      cache: {
        entries: number;
        totalBytes: number;
        totalHits: number;
        items: Array<{ path: string; contentType: string; bytes: number; hits: number; expiresAt: string }>;
      };
    }>(`/api/projects/${projectId}/proxy/cache`, { method: 'DELETE' }),

  exportBackup: () => apiFetch<Record<string, unknown>>('/api/settings/backup'),
};
