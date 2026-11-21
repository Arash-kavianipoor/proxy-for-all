import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import express, { type NextFunction, type Request, type Response } from 'express';
import {
  decryptSecret,
  encryptSecret,
  getEncryptionStatus,
  hashPassword,
  maskSecret,
  redactSecrets,
  signSessionId,
  verifyPassword,
  verifySignedSessionId,
} from './crypto.ts';
import { seedProjectDefaults, writeAuditLog } from './db.ts';
import { buildDeploymentPreview, executeDnsDeployment, validateRoutingRuleDestination } from './deployment.ts';
import { getDiagnosticsLocationLabel, runProjectDiagnostics } from './diagnostics.ts';
import { createGeoDnsProvider } from './providers/index.ts';
import { listProviderCapabilities } from './providers/capabilities.ts';
import { CloudflareReadOnlyClient } from './providers/cloudflare.ts';
import { checkDnsDelegation } from './providers/delegation.ts';
import { ManualGeoDnsProvider } from './providers/manual.ts';
import { normalizeBasePath } from './basePath.ts';
import {
  clearProjectCache,
  getProjectCacheStats,
  parseCloudflareInput,
  proxyFetchThroughCloudflare,
  resolveViaCloudflareNameservers,
} from './proxyCache.ts';
import { createRateLimiter, isValidDomain, isValidHostname, isValidIPv4, isValidIPv6, normalizeDomain } from './security.ts';
import type {
  DnsRecordType,
  Project,
  ProjectStatus,
  ProviderType,
  RegionCode,
  RoutingRule,
  UserSummary,
} from '../src/types/georoute.ts';

interface AuthenticatedRequest extends Request {
  authUser?: UserSummary;
  sessionCsrf?: string;
  sessionId?: string;
}

const SESSION_COOKIE_NAME = 'georoute_session';

function parseCookies(header?: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const val = decodeURIComponent(part.slice(idx + 1).trim());
    out[key] = val;
  }
  return out;
}

function mapProjectRow(row: Record<string, unknown>): Project {
  return {
    id: String(row.id),
    ownerId: String(row.owner_id),
    projectName: String(row.project_name),
    domain: String(row.domain),
    description: String(row.description || ''),
    status: String(row.status) as ProjectStatus,
    iranProxyHostname: String(row.iran_proxy_hostname || ''),
    iranProxyIPv4: String(row.iran_proxy_ipv4 || ''),
    iranProxyIPv6: String(row.iran_proxy_ipv6 || ''),
    cloudflareTarget: String(row.cloudflare_target || ''),
    cloudflareZoneId: String(row.cloudflare_zone_id || ''),
    geoDnsProvider: (String(row.geo_dns_provider || 'manual') as ProviderType),
    geoDnsZoneId: String(row.geo_dns_zone_id || ''),
    healthCheckUrl: String(row.health_check_url || ''),
    notes: String(row.notes || ''),
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
  };
}

export interface CreateAppOptions {
  fetcher?: typeof fetch;
  basePath?: string;
  hostProxyMiddleware?: express.RequestHandler;
}

export function createApp(db: DatabaseSync, options: CreateAppOptions = {}) {
  const app = express();
  const fetcher = options.fetcher || fetch;
  const configuredBasePath = normalizeBasePath(
    options.basePath ?? process.env.BASE_PATH ?? process.env.PASSENGER_BASE_URI
  );

  const trustProxyEnv = process.env.TRUST_PROXY?.trim();
  const trustProxy: boolean | number | string =
    trustProxyEnv === 'true'
      ? true
      : trustProxyEnv === 'false'
        ? false
        : trustProxyEnv && /^\d+$/.test(trustProxyEnv)
          ? Number(trustProxyEnv)
          : trustProxyEnv || 1;

  app.set('trust proxy', trustProxy);

  if (options.hostProxyMiddleware) {
    app.use(options.hostProxyMiddleware);
  }

  // Support running behind Apache VirtualHost subpath (e.g. /georoute alongside WordPress)
  app.use((req, res, next) => {
    const forwardedPrefix = normalizeBasePath(req.headers['x-forwarded-prefix']);
    const effectiveBase = configuredBasePath || forwardedPrefix;
    res.locals.georouteBasePath = effectiveBase;

    if (effectiveBase) {
      if (req.url === effectiveBase) {
        req.url = '/';
      } else if (req.url.startsWith(`${effectiveBase}/`)) {
        req.url = req.url.slice(effectiveBase.length) || '/';
      } else if (req.url.startsWith(`${effectiveBase}?`)) {
        req.url = `/${req.url.slice(effectiveBase.length)}`;
      }
    }
    next();
  });

  app.use('/api', express.json({ limit: '512kb' }));

  const authRateLimiter = createRateLimiter({ windowMs: 60_000, maxRequests: 20, name: 'auth' });
  const apiRateLimiter = createRateLimiter({ windowMs: 60_000, maxRequests: 180, name: 'api' });

  app.use('/api', apiRateLimiter);

  function isHttpsRequest(req: Request): boolean {
    const forwardedProto = String(req.headers['x-forwarded-proto'] || '').toLowerCase();
    return (
      req.secure ||
      forwardedProto
        .split(',')
        .some((proto) => proto.trim() === 'https')
    );
  }

  function setSessionCookie(req: Request, res: Response, sessionId: string): string {
    const signed = signSessionId(sessionId);
    const isSecure = isHttpsRequest(req);
    res.cookie(SESSION_COOKIE_NAME, signed, {
      httpOnly: true,
      sameSite: isSecure ? 'none' : 'lax',
      secure: Boolean(isSecure),
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return signed;
  }

  function createSession(userId: string): { sessionId: string; csrfToken: string } {
    const sessionId = crypto.randomUUID();
    const csrfToken = crypto.randomBytes(24).toString('hex');
    const now = new Date();
    const expires = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    db.prepare(`
      INSERT INTO sessions (id, user_id, csrf_token, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(sessionId, userId, csrfToken, expires.toISOString(), now.toISOString());
    return { sessionId, csrfToken };
  }

  function resolveSession(req: Request): { user: UserSummary; csrfToken: string; sessionId: string } | null {
    const cookies = parseCookies(req.headers.cookie);
    const authHeader = String(req.headers.authorization || '');
    const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const rawToken = cookies[SESSION_COOKIE_NAME] || bearerToken;
    if (!rawToken) return null;
    const sessionId = verifySignedSessionId(rawToken);
    if (!sessionId) return null;

    const row = db
      .prepare(`
        SELECT s.id AS sid, s.csrf_token, s.expires_at, u.id AS uid, u.username, u.role, u.created_at
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.id = ?
      `)
      .get(sessionId) as Record<string, unknown> | undefined;

    if (!row) return null;
    if (new Date(String(row.expires_at)).getTime() < Date.now()) {
      db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
      return null;
    }

    return {
      sessionId: String(row.sid),
      csrfToken: String(row.csrf_token),
      user: {
        id: String(row.uid),
        username: String(row.username),
        role: String(row.role) as UserSummary['role'],
        createdAt: String(row.created_at),
      },
    };
  }

  function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    const resolved = resolveSession(req);
    if (!resolved) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    req.authUser = resolved.user;
    req.sessionCsrf = resolved.csrfToken;
    req.sessionId = resolved.sessionId;

    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
      const headerCsrf = String(req.headers['x-csrf-token'] || '');
      if (!headerCsrf || headerCsrf !== resolved.csrfToken) {
        return res.status(403).json({ error: 'Invalid or missing CSRF token.' });
      }
    }
    return next();
  }

  function getOwnedProject(projectId: string, userId: string): Project | null {
    const row = db
      .prepare('SELECT * FROM projects WHERE id = ? AND owner_id = ?')
      .get(projectId, userId) as Record<string, unknown> | undefined;
    return row ? mapProjectRow(row) : null;
  }

  // -------------------- AUTH ROUTES --------------------

  app.get('/api/auth/status', (req, res) => {
    const countRow = db.prepare('SELECT COUNT(*) AS cnt FROM users').get() as { cnt: number };
    const resolved = resolveSession(req);
    res.json({
      initialized: countRow.cnt > 0,
      authenticated: Boolean(resolved),
      user: resolved?.user ?? null,
      csrfToken: resolved?.csrfToken ?? null,
      encryption: getEncryptionStatus(),
      diagnosticsLocation: getDiagnosticsLocationLabel(),
    });
  });

  app.post('/api/auth/setup', authRateLimiter, (req, res) => {
    const countRow = db.prepare('SELECT COUNT(*) AS cnt FROM users').get() as { cnt: number };
    if (countRow.cnt > 0) {
      return res.status(409).json({ error: 'Admin account is already initialized. Please sign in.' });
    }
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');

    if (!/^[a-zA-Z0-9._-]{3,32}$/.test(username)) {
      return res.status(400).json({ error: 'Username must be 3–32 characters (letters, numbers, ., _, -).' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }

    const userId = crypto.randomUUID();
    const now = new Date().toISOString();
    const { hash, salt } = hashPassword(password);

    db.prepare(`
      INSERT INTO users (id, username, role, password_hash, password_salt, created_at, updated_at)
      VALUES (?, ?, 'admin', ?, ?, ?, ?)
    `).run(userId, username, hash, salt, now, now);

    writeAuditLog(db, {
      actorId: userId,
      action: 'admin.setup',
      result: 'success',
      details: `Initialized primary admin account "${username}".`,
    });

    const { sessionId, csrfToken } = createSession(userId);
    const sessionToken = setSessionCookie(req, res, sessionId);

    res.status(201).json({
      user: { id: userId, username, role: 'admin', createdAt: now },
      csrfToken,
      sessionToken,
    });
  });

  app.post('/api/auth/login', authRateLimiter, (req, res) => {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');

    const row = db
      .prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)')
      .get(username) as Record<string, unknown> | undefined;

    if (!row || !verifyPassword(password, String(row.password_hash), String(row.password_salt))) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    const userId = String(row.id);
    const { sessionId, csrfToken } = createSession(userId);
    const sessionToken = setSessionCookie(req, res, sessionId);

    writeAuditLog(db, {
      actorId: userId,
      action: 'admin.login',
      result: 'success',
      details: `Signed in as "${username}".`,
    });

    res.json({
      user: {
        id: userId,
        username: String(row.username),
        role: String(row.role),
        createdAt: String(row.created_at),
      },
      csrfToken,
      sessionToken,
    });
  });

  app.post('/api/auth/logout', requireAuth, (req: AuthenticatedRequest, res) => {
    if (req.sessionId) {
      db.prepare('DELETE FROM sessions WHERE id = ?').run(req.sessionId);
    }
    const isSecure = isHttpsRequest(req);
    res.clearCookie(SESSION_COOKIE_NAME, {
      path: '/',
      sameSite: isSecure ? 'none' : 'lax',
      secure: Boolean(isSecure),
    });
    res.json({ ok: true });
  });

  app.post('/api/auth/change-password', requireAuth, (req: AuthenticatedRequest, res) => {
    const currentPassword = String(req.body?.currentPassword || '');
    const newPassword = String(req.body?.newPassword || '');
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters.' });
    }

    const row = db
      .prepare('SELECT password_hash, password_salt FROM users WHERE id = ?')
      .get(req.authUser!.id) as { password_hash: string; password_salt: string } | undefined;

    if (!row || !verifyPassword(currentPassword, row.password_hash, row.password_salt)) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }

    const { hash, salt } = hashPassword(newPassword);
    db.prepare('UPDATE users SET password_hash = ?, password_salt = ?, updated_at = ? WHERE id = ?').run(
      hash,
      salt,
      new Date().toISOString(),
      req.authUser!.id
    );

    writeAuditLog(db, {
      actorId: req.authUser!.id,
      action: 'admin.password_change',
      result: 'success',
      details: 'Administrator password updated and re-hashed with scrypt.',
    });

    res.json({ ok: true });
  });

  // -------------------- PROVIDER METADATA --------------------

  app.get('/api/providers/capabilities', requireAuth, (_req, res) => {
    res.json({ providers: listProviderCapabilities() });
  });

  // -------------------- PROJECTS CRUD --------------------

  app.get('/api/projects', requireAuth, (req: AuthenticatedRequest, res) => {
    const rows = db
      .prepare('SELECT * FROM projects WHERE owner_id = ? ORDER BY updated_at DESC')
      .all(req.authUser!.id) as Array<Record<string, unknown>>;
    res.json({ projects: rows.map(mapProjectRow) });
  });

  app.post('/api/projects', requireAuth, (req: AuthenticatedRequest, res) => {
    const projectName = String(req.body?.projectName || '').trim();
    const rawDomain = String(req.body?.domain || '');
    const domain = normalizeDomain(rawDomain);
    const description = String(req.body?.description || '').trim();
    const cloudflareTarget = String(req.body?.cloudflareTarget || '').trim();
    const iranProxyHostname = String(req.body?.iranProxyHostname || '').trim();
    const iranProxyIPv4 = String(req.body?.iranProxyIPv4 || '').trim();
    const geoDnsProvider = (String(req.body?.geoDnsProvider || 'manual') as ProviderType);
    const notes = String(req.body?.notes || '').trim();

    if (projectName.length < 2 || projectName.length > 80) {
      return res.status(400).json({ error: 'Project name must be 2–80 characters.' });
    }
    if (!isValidDomain(domain)) {
      return res.status(400).json({ error: 'Please enter a valid domain name (e.g. example.ir or example.com).' });
    }
    if (iranProxyIPv4 && !isValidIPv4(iranProxyIPv4)) {
      return res.status(400).json({ error: 'Iran proxy IPv4 is not a valid IPv4 address.' });
    }
    if (!['ns1', 'cloudns', 'manual'].includes(geoDnsProvider)) {
      return res.status(400).json({ error: 'Unsupported GeoDNS provider.' });
    }

    const projectId = crypto.randomUUID();
    const now = new Date().toISOString();
    const initialStatus: ProjectStatus =
      geoDnsProvider === 'manual' ? 'needs_infrastructure_verification' : 'geodns_not_configured';

    db.prepare(`
      INSERT INTO projects (
        id, owner_id, project_name, domain, description, status,
        iran_proxy_hostname, iran_proxy_ipv4, iran_proxy_ipv6,
        cloudflare_target, cloudflare_zone_id, geo_dns_provider, geo_dns_zone_id,
        health_check_url, notes, created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', ?, '', ?, '', ?, ?, ?, ?)
    `).run(
      projectId,
      req.authUser!.id,
      projectName,
      domain,
      description,
      initialStatus,
      iranProxyHostname,
      iranProxyIPv4,
      cloudflareTarget,
      geoDnsProvider,
      `https://${domain}`,
      notes,
      now,
      now
    );

    seedProjectDefaults(db, projectId, domain);

    // Normalize Cloudflare input (supports NS list like dane.ns.cloudflare.com, dolly.ns.cloudflare.com or direct IP/host)
    const parsedCf = parseCloudflareInput(cloudflareTarget);
    if (parsedCf.directTarget) {
      const recType: DnsRecordType = isValidIPv4(parsedCf.directTarget)
        ? 'A'
        : isValidIPv6(parsedCf.directTarget)
          ? 'AAAA'
          : 'ALIAS';
      db.prepare(`
        INSERT OR IGNORE INTO routing_rules
          (id, project_id, hostname, region_code, record_type, destination, ttl, enabled, updated_at)
        VALUES (?, ?, ?, 'DEFAULT', ?, ?, 300, 1, ?)
      `).run(crypto.randomUUID(), projectId, domain, recType, parsedCf.directTarget, now);
    }

    // If Iran proxy IP or hostname provided, seed IR routing rule immediately
    const iranDest = iranProxyIPv4 || iranProxyHostname;
    if (iranDest) {
      const irType: DnsRecordType = isValidIPv4(iranDest)
        ? 'A'
        : isValidIPv6(iranDest)
          ? 'AAAA'
          : 'ALIAS';
      db.prepare(`
        INSERT OR IGNORE INTO routing_rules
          (id, project_id, hostname, region_code, record_type, destination, ttl, enabled, updated_at)
        VALUES (?, ?, ?, 'IR', ?, ?, 300, 1, ?)
      `).run(crypto.randomUUID(), projectId, domain, irType, iranDest, now);
    }

    writeAuditLog(db, {
      actorId: req.authUser!.id,
      projectId,
      action: 'project.create',
      result: 'success',
      details: `Created project "${projectName}" (${domain}) in status "${initialStatus}".`,
    });

    const created = getOwnedProject(projectId, req.authUser!.id);
    res.status(201).json({ project: created });
  });

  app.get('/api/projects/:projectId', requireAuth, (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const capabilities = db
      .prepare('SELECT * FROM hosting_capabilities WHERE project_id = ? ORDER BY category, capability_label')
      .all(project.id) as Array<Record<string, unknown>>;
    const cachePolicies = db
      .prepare('SELECT * FROM cache_policies WHERE project_id = ? ORDER BY path_pattern')
      .all(project.id) as Array<Record<string, unknown>>;
    const hostnames = db
      .prepare('SELECT * FROM project_hostnames WHERE project_id = ? ORDER BY role, hostname')
      .all(project.id) as Array<Record<string, unknown>>;
    const routingRules = db
      .prepare('SELECT * FROM routing_rules WHERE project_id = ? ORDER BY hostname, region_code')
      .all(project.id) as Array<Record<string, unknown>>;
    const dnsZoneRow = db
      .prepare('SELECT * FROM dns_zones WHERE project_id = ?')
      .get(project.id) as Record<string, unknown> | undefined;
    const irnicChecklist = db
      .prepare('SELECT * FROM irnic_migration_checklists WHERE project_id = ? ORDER BY step_order')
      .all(project.id) as Array<Record<string, unknown>>;
    const cfMappingRow = db
      .prepare('SELECT * FROM project_cloudflare_mappings WHERE project_id = ?')
      .get(project.id) as Record<string, unknown> | undefined;
    const diagnostics = db
      .prepare('SELECT * FROM dns_health_checks WHERE project_id = ? ORDER BY checked_at DESC LIMIT 20')
      .all(project.id) as Array<Record<string, unknown>>;

    res.json({
      project,
      capabilities: capabilities.map((c) => ({
        id: String(c.id),
        projectId: String(c.project_id),
        capabilityKey: String(c.capability_key),
        capabilityLabel: String(c.capability_label),
        category: String(c.category),
        status: String(c.status),
        notes: String(c.notes || ''),
        verifiedAt: String(c.verified_at || ''),
        updatedAt: String(c.updated_at),
      })),
      cachePolicies: cachePolicies.map((p) => ({
        id: String(p.id),
        projectId: String(p.project_id),
        pathPattern: String(p.path_pattern),
        resourceType: String(p.resource_type),
        cacheBehavior: String(p.cache_behavior),
        ttlSeconds: Number(p.ttl_seconds),
        respectOriginHeaders: Boolean(p.respect_origin_headers),
        bypassOnCookie: Boolean(p.bypass_on_cookie),
        enabled: Boolean(p.enabled),
        updatedAt: String(p.updated_at),
      })),
      hostnames: hostnames.map((h) => ({
        id: String(h.id),
        projectId: String(h.project_id),
        hostname: String(h.hostname),
        role: String(h.role),
        notes: String(h.notes || ''),
        createdAt: String(h.created_at),
        updatedAt: String(h.updated_at),
      })),
      routingRules: routingRules.map((r) => ({
        id: String(r.id),
        projectId: String(r.project_id),
        hostname: String(r.hostname),
        regionCode: String(r.region_code),
        recordType: String(r.record_type),
        destination: String(r.destination),
        ttl: Number(r.ttl),
        enabled: Boolean(r.enabled),
        updatedAt: String(r.updated_at),
      })),
      dnsZone: dnsZoneRow
        ? {
            id: String(dnsZoneRow.id),
            projectId: String(dnsZoneRow.project_id),
            providerAccountId: dnsZoneRow.provider_account_id ? String(dnsZoneRow.provider_account_id) : null,
            providerZoneId: String(dnsZoneRow.provider_zone_id),
            domain: String(dnsZoneRow.domain),
            authoritativeNameservers: JSON.parse(String(dnsZoneRow.authoritative_nameservers_json || '[]')),
            delegationStatus: String(dnsZoneRow.delegation_status),
            observedNameservers: JSON.parse(String(dnsZoneRow.observed_nameservers_json || '[]')),
            lastSyncedAt: String(dnsZoneRow.last_synced_at || ''),
            updatedAt: String(dnsZoneRow.updated_at),
          }
        : null,
      irnicChecklist: irnicChecklist.map((s) => ({
        id: String(s.id),
        projectId: String(s.project_id),
        stepKey: String(s.step_key),
        stepLabel: String(s.step_label),
        stepOrder: Number(s.step_order),
        completed: Boolean(s.completed),
        updatedAt: String(s.updated_at),
      })),
      cloudflareMapping: cfMappingRow
        ? {
            id: String(cfMappingRow.id),
            projectId: String(cfMappingRow.project_id),
            cloudflareAccountId: String(cfMappingRow.cloudflare_account_id),
            cloudflareZoneId: String(cfMappingRow.cloudflare_zone_id),
            zoneName: String(cfMappingRow.zone_name),
            zoneStatus: String(cfMappingRow.zone_status || ''),
            nameServers: JSON.parse(String(cfMappingRow.name_servers_json || '[]')),
            recordsSnapshot: JSON.parse(String(cfMappingRow.records_snapshot_json || '[]')),
            workerRoutes: JSON.parse(String(cfMappingRow.worker_routes_json || '[]')),
            workerDomains: JSON.parse(String(cfMappingRow.worker_domains_json || '[]')),
            sslMode: String(cfMappingRow.ssl_mode || ''),
            cacheLevel: String(cfMappingRow.cache_level || ''),
            requiresArchitectureReview: Boolean(cfMappingRow.requires_architecture_review),
            reviewNotes: String(cfMappingRow.review_notes || ''),
            discoveredAt: String(cfMappingRow.discovered_at),
            updatedAt: String(cfMappingRow.updated_at),
          }
        : null,
      diagnostics: diagnostics.map((d) => ({
        id: String(d.id),
        projectId: String(d.project_id),
        checkCategory: String(d.check_category),
        target: String(d.target),
        status: String(d.status),
        testLocation: String(d.test_location),
        summary: String(d.summary),
        technicalDetails: JSON.parse(String(d.technical_details_json || '{}')),
        checkedAt: String(d.checked_at),
      })),
    });
  });

  app.patch('/api/projects/:projectId', requireAuth, (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const nextStatus = (req.body?.status ?? project.status) as ProjectStatus;
    const nextIranIPv4 = req.body?.iranProxyIPv4 !== undefined ? String(req.body.iranProxyIPv4).trim() : project.iranProxyIPv4;
    const nextIranIPv6 = req.body?.iranProxyIPv6 !== undefined ? String(req.body.iranProxyIPv6).trim() : project.iranProxyIPv6;
    const nextIranHost = req.body?.iranProxyHostname !== undefined ? String(req.body.iranProxyHostname).trim() : project.iranProxyHostname;

    if (nextIranIPv4 && !isValidIPv4(nextIranIPv4)) {
      return res.status(400).json({ error: 'Invalid Iran proxy IPv4 address.' });
    }
    if (nextIranIPv6 && !isValidIPv6(nextIranIPv6)) {
      return res.status(400).json({ error: 'Invalid Iran proxy IPv6 address.' });
    }
    if (nextIranHost && !isValidHostname(nextIranHost)) {
      return res.status(400).json({ error: 'Invalid Iran proxy hostname.' });
    }

    // Enforce: Operational status requires confirmed DNS deployment + verified delegation + passing diagnostics
    if (nextStatus === 'operational') {
      const confirmedJob = db
        .prepare("SELECT id FROM dns_deployment_jobs WHERE project_id = ? AND status = 'confirmed' LIMIT 1")
        .get(project.id);
      const passedDiag = db
        .prepare("SELECT id FROM dns_health_checks WHERE project_id = ? AND status = 'passed' LIMIT 1")
        .get(project.id);
      const zoneRow = db
        .prepare("SELECT delegation_status FROM dns_zones WHERE project_id = ?")
        .get(project.id) as { delegation_status?: string } | undefined;

      if (!confirmedJob || !passedDiag || zoneRow?.delegation_status !== 'verified') {
        return res.status(400).json({
          error:
            'Project cannot be marked Operational until a provider DNS deployment is confirmed, IRNIC nameserver delegation is verified, and health checks pass.',
        });
      }
    }

    const now = new Date().toISOString();
    db.prepare(`
      UPDATE projects
      SET project_name = ?, description = ?, status = ?,
          iran_proxy_hostname = ?, iran_proxy_ipv4 = ?, iran_proxy_ipv6 = ?,
          cloudflare_target = ?, geo_dns_provider = ?, health_check_url = ?, notes = ?, updated_at = ?
      WHERE id = ? AND owner_id = ?
    `).run(
      req.body?.projectName !== undefined ? String(req.body.projectName).trim() : project.projectName,
      req.body?.description !== undefined ? String(req.body.description).trim() : project.description,
      nextStatus,
      nextIranHost,
      nextIranIPv4,
      nextIranIPv6,
      req.body?.cloudflareTarget !== undefined ? String(req.body.cloudflareTarget).trim() : project.cloudflareTarget,
      req.body?.geoDnsProvider !== undefined ? String(req.body.geoDnsProvider) : project.geoDnsProvider,
      req.body?.healthCheckUrl !== undefined ? String(req.body.healthCheckUrl).trim() : project.healthCheckUrl,
      req.body?.notes !== undefined ? String(req.body.notes) : project.notes,
      now,
      project.id,
      req.authUser!.id
    );

    writeAuditLog(db, {
      actorId: req.authUser!.id,
      projectId: project.id,
      action: 'project.update',
      result: 'success',
      details: `Updated project settings (status: ${nextStatus}).`,
    });

    res.json({ project: getOwnedProject(project.id, req.authUser!.id) });
  });

  app.delete('/api/projects/:projectId', requireAuth, (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    db.prepare('DELETE FROM projects WHERE id = ? AND owner_id = ?').run(project.id, req.authUser!.id);
    writeAuditLog(db, {
      actorId: req.authUser!.id,
      projectId: null,
      action: 'project.delete',
      result: 'success',
      details: `Deleted project "${project.projectName}" (${project.domain}).`,
    });
    res.json({ ok: true });
  });

  // -------------------- HOSTING CAPABILITIES & CACHE POLICIES --------------------

  app.put('/api/projects/:projectId/capabilities/:capabilityKey', requireAuth, (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const status = String(req.body?.status || '');
    const notes = String(req.body?.notes || '').trim();
    if (!['supported', 'unsupported', 'not_tested', 'provider_confirmation_required'].includes(status)) {
      return res.status(400).json({ error: 'Invalid capability status.' });
    }

    const now = new Date().toISOString();
    const info = db
      .prepare(`
        UPDATE hosting_capabilities
        SET status = ?, notes = ?, verified_at = ?, updated_at = ?
        WHERE project_id = ? AND capability_key = ?
      `)
      .run(status, notes, status === 'not_tested' ? '' : now, now, project.id, String(req.params.capabilityKey));

    if (info.changes === 0) {
      return res.status(404).json({ error: 'Capability key not found for this project.' });
    }

    writeAuditLog(db, {
      actorId: req.authUser!.id,
      projectId: project.id,
      action: 'hosting_capability.update',
      result: 'success',
      details: `Set "${req.params.capabilityKey}" to "${status}".`,
    });

    res.json({ ok: true });
  });

  app.post('/api/projects/:projectId/cache-policies', requireAuth, (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const pathPattern = String(req.body?.pathPattern || '').trim();
    const resourceType = String(req.body?.resourceType || '').trim();
    const cacheBehavior = String(req.body?.cacheBehavior || 'bypass_always');
    const ttlSeconds = Number(req.body?.ttlSeconds ?? 0);

    if (!pathPattern || !resourceType) {
      return res.status(400).json({ error: 'Path pattern and resource type are required.' });
    }
    if (!['cache_immutable', 'cache_short', 'revalidate', 'bypass_always'].includes(cacheBehavior)) {
      return res.status(400).json({ error: 'Invalid cache behavior.' });
    }

    // Safety guard: never allow default caching on auth/api/admin paths
    if (
      cacheBehavior !== 'bypass_always' &&
      /\/(api|auth|login|admin|account|checkout|payment)/i.test(pathPattern)
    ) {
      return res.status(400).json({
        error: 'Safety policy blocks caching on API, authentication, admin, account, checkout, or payment paths.',
      });
    }

    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO cache_policies
        (id, project_id, path_pattern, resource_type, cache_behavior, ttl_seconds, respect_origin_headers, bypass_on_cookie, enabled, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, 1, 1, ?)
    `).run(id, project.id, pathPattern, resourceType, cacheBehavior, Math.max(0, ttlSeconds), now);

    writeAuditLog(db, {
      actorId: req.authUser!.id,
      projectId: project.id,
      action: 'cache_policy.create',
      result: 'success',
      details: `Added cache policy "${pathPattern}" (${cacheBehavior}, TTL ${ttlSeconds}s).`,
    });

    res.status(201).json({ id });
  });

  app.put('/api/projects/:projectId/cache-policies/:policyId', requireAuth, (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const enabled = req.body?.enabled !== undefined ? (req.body.enabled ? 1 : 0) : 1;
    const ttlSeconds = Number(req.body?.ttlSeconds ?? 0);
    const cacheBehavior = String(req.body?.cacheBehavior || 'bypass_always');

    const existing = db
      .prepare('SELECT path_pattern FROM cache_policies WHERE id = ? AND project_id = ?')
      .get(String(req.params.policyId), project.id) as { path_pattern: string } | undefined;
    if (!existing) return res.status(404).json({ error: 'Cache policy not found.' });

    if (
      cacheBehavior !== 'bypass_always' &&
      /\/(api|auth|login|admin|account|checkout|payment)/i.test(existing.path_pattern)
    ) {
      return res.status(400).json({
        error: 'Safety policy blocks caching on API, auth, admin, or private endpoints.',
      });
    }

    db.prepare(`
      UPDATE cache_policies
      SET cache_behavior = ?, ttl_seconds = ?, enabled = ?, updated_at = ?
      WHERE id = ? AND project_id = ?
    `).run(cacheBehavior, Math.max(0, ttlSeconds), enabled, new Date().toISOString(), String(req.params.policyId), project.id);

    res.json({ ok: true });
  });

  app.delete('/api/projects/:projectId/cache-policies/:policyId', requireAuth, (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });
    db.prepare('DELETE FROM cache_policies WHERE id = ? AND project_id = ?').run(
      String(req.params.policyId),
      project.id
    );
    res.json({ ok: true });
  });

  // -------------------- DNS PROVIDER ACCOUNTS --------------------

  app.get('/api/dns-providers', requireAuth, (req: AuthenticatedRequest, res) => {
    const rows = db
      .prepare('SELECT * FROM dns_provider_accounts WHERE owner_id = ? ORDER BY created_at DESC')
      .all(req.authUser!.id) as Array<Record<string, unknown>>;

    res.json({
      accounts: rows.map((r) => ({
        id: String(r.id),
        providerName: String(r.provider_name),
        accountLabel: String(r.account_label),
        maskedHint: String(r.masked_hint),
        validationStatus: String(r.validation_status),
        validationMessage: String(r.validation_message || ''),
        lastValidatedAt: String(r.last_validated_at || ''),
        createdAt: String(r.created_at),
        updatedAt: String(r.updated_at),
      })),
    });
  });

  app.post('/api/dns-providers', requireAuth, (req: AuthenticatedRequest, res) => {
    const providerName = String(req.body?.providerName || '') as ProviderType;
    const accountLabel = String(req.body?.accountLabel || '').trim();
    const credentials = req.body?.credentials || {};

    if (!['ns1', 'cloudns'].includes(providerName)) {
      return res.status(400).json({ error: 'Select a valid API-backed provider (ns1 or cloudns).' });
    }
    if (!accountLabel || accountLabel.length > 60) {
      return res.status(400).json({ error: 'Account label is required (max 60 characters).' });
    }

    let hint = '';
    if (providerName === 'ns1') {
      const apiKey = String(credentials.apiKey || '').trim();
      if (!apiKey) return res.status(400).json({ error: 'NS1 API Key is required.' });
      hint = maskSecret(apiKey);
    } else if (providerName === 'cloudns') {
      const authId = String(credentials.authId || '').trim();
      const authPassword = String(credentials.authPassword || '').trim();
      if (!authId || !authPassword) {
        return res.status(400).json({ error: 'ClouDNS auth-id and auth-password are required.' });
      }
      hint = `ID:${authId} / ${maskSecret(authPassword)}`;
    }

    const encrypted = encryptSecret(JSON.stringify(credentials));
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO dns_provider_accounts (
        id, owner_id, provider_name, account_label,
        encrypted_credentials_ciphertext, credentials_iv, credentials_tag,
        masked_hint, validation_status, validation_message, last_validated_at, created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'not_validated', 'Pending validation', '', ?, ?)
    `).run(
      id,
      req.authUser!.id,
      providerName,
      accountLabel,
      encrypted.ciphertext,
      encrypted.iv,
      encrypted.tag,
      hint,
      now,
      now
    );

    writeAuditLog(db, {
      actorId: req.authUser!.id,
      action: 'dns_provider.create',
      result: 'success',
      details: `Added ${providerName} provider account "${accountLabel}" (${hint}).`,
    });

    res.status(201).json({
      account: {
        id,
        providerName,
        accountLabel,
        maskedHint: hint,
        validationStatus: 'not_validated',
        validationMessage: 'Pending validation',
        lastValidatedAt: '',
        createdAt: now,
        updatedAt: now,
      },
    });
  });

  app.post('/api/dns-providers/:id/rotate', requireAuth, (req: AuthenticatedRequest, res) => {
    const row = db
      .prepare('SELECT * FROM dns_provider_accounts WHERE id = ? AND owner_id = ?')
      .get(String(req.params.id), req.authUser!.id) as Record<string, unknown> | undefined;
    if (!row) return res.status(404).json({ error: 'Provider account not found.' });

    const providerName = String(row.provider_name) as ProviderType;
    const credentials = req.body?.credentials || {};
    let hint = '';
    if (providerName === 'ns1') {
      const apiKey = String(credentials.apiKey || '').trim();
      if (!apiKey) return res.status(400).json({ error: 'New NS1 API Key is required.' });
      hint = maskSecret(apiKey);
    } else if (providerName === 'cloudns') {
      const authId = String(credentials.authId || '').trim();
      const authPassword = String(credentials.authPassword || '').trim();
      if (!authId || !authPassword) return res.status(400).json({ error: 'New ClouDNS credentials are required.' });
      hint = `ID:${authId} / ${maskSecret(authPassword)}`;
    }

    const encrypted = encryptSecret(JSON.stringify(credentials));
    const now = new Date().toISOString();
    db.prepare(`
      UPDATE dns_provider_accounts
      SET encrypted_credentials_ciphertext = ?, credentials_iv = ?, credentials_tag = ?,
          masked_hint = ?, validation_status = 'not_validated', validation_message = 'Credentials rotated — please re-validate', updated_at = ?
      WHERE id = ? AND owner_id = ?
    `).run(encrypted.ciphertext, encrypted.iv, encrypted.tag, hint, now, String(row.id), req.authUser!.id);

    writeAuditLog(db, {
      actorId: req.authUser!.id,
      action: 'dns_provider.rotate',
      result: 'success',
      details: `Rotated credentials for "${row.account_label}" (${hint}).`,
    });

    res.json({ ok: true, maskedHint: hint });
  });

  function resolveProviderInstance(accountId: string, ownerId: string) {
    const row = db
      .prepare('SELECT * FROM dns_provider_accounts WHERE id = ? AND owner_id = ?')
      .get(accountId, ownerId) as Record<string, unknown> | undefined;
    if (!row) return null;
    const plaintextJson = decryptSecret(
      String(row.encrypted_credentials_ciphertext),
      String(row.credentials_iv),
      String(row.credentials_tag)
    );
    const providerName = String(row.provider_name) as ProviderType;
    return {
      row,
      providerName,
      provider: createGeoDnsProvider(providerName, plaintextJson, fetcher),
    };
  }

  app.post('/api/dns-providers/:id/validate', requireAuth, async (req: AuthenticatedRequest, res) => {
    const resolved = resolveProviderInstance(String(req.params.id), req.authUser!.id);
    if (!resolved) return res.status(404).json({ error: 'Provider account not found.' });

    const result = await resolved.provider.validateCredentials();
    const now = new Date().toISOString();
    const status = result.valid ? 'valid' : 'invalid';

    db.prepare(`
      UPDATE dns_provider_accounts
      SET validation_status = ?, validation_message = ?, last_validated_at = ?, updated_at = ?
      WHERE id = ? AND owner_id = ?
    `).run(status, result.message, now, now, String(req.params.id), req.authUser!.id);

    writeAuditLog(db, {
      actorId: req.authUser!.id,
      action: 'dns_provider.validate',
      result: result.valid ? 'success' : 'failure',
      details: `Validated ${resolved.providerName} account "${resolved.row.account_label}": ${result.message}`,
    });

    res.json({ validation: result });
  });

  app.get('/api/dns-providers/:id/zones', requireAuth, async (req: AuthenticatedRequest, res) => {
    const resolved = resolveProviderInstance(String(req.params.id), req.authUser!.id);
    if (!resolved) return res.status(404).json({ error: 'Provider account not found.' });

    try {
      const zones = await resolved.provider.listZones();
      res.json({ zones });
    } catch (err) {
      res.status(502).json({
        error: err instanceof Error ? redactSecrets(err.message) : 'Failed to retrieve provider zones.',
      });
    }
  });

  app.get('/api/dns-providers/:id/zones/:zoneId/nameservers', requireAuth, async (req: AuthenticatedRequest, res) => {
    const resolved = resolveProviderInstance(String(req.params.id), req.authUser!.id);
    if (!resolved) return res.status(404).json({ error: 'Provider account not found.' });

    try {
      const nameservers = await resolved.provider.getNameservers(String(req.params.zoneId));
      res.json({ zoneId: req.params.zoneId, nameservers });
    } catch (err) {
      res.status(502).json({
        error: err instanceof Error ? redactSecrets(err.message) : 'Failed to retrieve nameservers.',
      });
    }
  });

  app.delete('/api/dns-providers/:id', requireAuth, (req: AuthenticatedRequest, res) => {
    const row = db
      .prepare('SELECT account_label FROM dns_provider_accounts WHERE id = ? AND owner_id = ?')
      .get(String(req.params.id), req.authUser!.id) as { account_label?: string } | undefined;
    if (!row) return res.status(404).json({ error: 'Provider account not found.' });

    db.prepare('DELETE FROM dns_provider_accounts WHERE id = ? AND owner_id = ?').run(
      String(req.params.id),
      req.authUser!.id
    );
    writeAuditLog(db, {
      actorId: req.authUser!.id,
      action: 'dns_provider.delete',
      result: 'success',
      details: `Disconnected provider account "${row.account_label}".`,
    });
    res.json({ ok: true });
  });

  // -------------------- PROJECT DNS, ROUTING, PREVIEW, DEPLOY & DELEGATION --------------------

  function getProjectRoutingRules(projectId: string): RoutingRule[] {
    const rows = db
      .prepare('SELECT * FROM routing_rules WHERE project_id = ? ORDER BY hostname, region_code')
      .all(projectId) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      id: String(r.id),
      projectId: String(r.project_id),
      hostname: String(r.hostname),
      regionCode: String(r.region_code) as RegionCode,
      recordType: String(r.record_type) as DnsRecordType,
      destination: String(r.destination),
      ttl: Number(r.ttl),
      enabled: Boolean(r.enabled),
      updatedAt: String(r.updated_at),
    }));
  }

  function resolveProjectProvider(project: Project, ownerId: string) {
    const zoneRow = db
      .prepare('SELECT * FROM dns_zones WHERE project_id = ?')
      .get(project.id) as Record<string, unknown> | undefined;
    const providerAccountId = zoneRow?.provider_account_id ? String(zoneRow.provider_account_id) : null;
    const zoneId = zoneRow?.provider_zone_id ? String(zoneRow.provider_zone_id) : project.geoDnsZoneId;

    if (providerAccountId && project.geoDnsProvider !== 'manual') {
      const resolved = resolveProviderInstance(providerAccountId, ownerId);
      if (resolved) {
        return {
          provider: resolved.provider,
          providerAccountId,
          zoneId: zoneId || project.domain,
          zoneRow,
        };
      }
    }

    return {
      provider: new ManualGeoDnsProvider(),
      providerAccountId: null,
      zoneId: zoneId || project.domain,
      zoneRow,
    };
  }

  app.get('/api/projects/:projectId/dns', requireAuth, async (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const { provider, providerAccountId, zoneId, zoneRow } = resolveProjectProvider(project, req.authUser!.id);
    const rules = getProjectRoutingRules(project.id);
    let liveRecords: unknown[] = [];
    let liveError = '';

    if (providerAccountId && project.geoDnsProvider !== 'manual' && zoneId) {
      try {
        liveRecords = await provider.listRecords(zoneId);
      } catch (err) {
        liveError = err instanceof Error ? err.message : 'Unable to fetch live records.';
      }
    }

    res.json({
      provider: project.geoDnsProvider,
      providerAccountId,
      zoneId,
      zoneBinding: zoneRow
        ? {
            id: String(zoneRow.id),
            providerAccountId,
            providerZoneId: String(zoneRow.provider_zone_id),
            domain: String(zoneRow.domain),
            authoritativeNameservers: JSON.parse(String(zoneRow.authoritative_nameservers_json || '[]')),
            delegationStatus: String(zoneRow.delegation_status),
            observedNameservers: JSON.parse(String(zoneRow.observed_nameservers_json || '[]')),
            lastSyncedAt: String(zoneRow.last_synced_at || ''),
          }
        : null,
      routingRules: rules,
      liveRecords,
      liveError,
    });
  });

  app.post('/api/projects/:projectId/dns/zone-binding', requireAuth, async (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const providerAccountId = req.body?.providerAccountId ? String(req.body.providerAccountId) : null;
    const providerZoneId = normalizeDomain(String(req.body?.providerZoneId || project.domain));
    const manualMode = req.body?.providerName === 'manual' || !providerAccountId;

    const now = new Date().toISOString();

    if (manualMode) {
      db.prepare(`UPDATE projects SET geo_dns_provider = 'manual', geo_dns_zone_id = ?, updated_at = ? WHERE id = ?`).run(
        providerZoneId,
        now,
        project.id
      );
      db.prepare(`
        INSERT INTO dns_zones (id, project_id, provider_account_id, provider_zone_id, domain, authoritative_nameservers_json, delegation_status, observed_nameservers_json, last_synced_at, updated_at)
        VALUES (?, ?, NULL, ?, ?, '[]', 'not_checked', '[]', ?, ?)
        ON CONFLICT(project_id) DO UPDATE SET
          provider_account_id = NULL,
          provider_zone_id = excluded.provider_zone_id,
          authoritative_nameservers_json = '[]',
          delegation_status = 'not_checked',
          updated_at = excluded.updated_at
      `).run(crypto.randomUUID(), project.id, providerZoneId, project.domain, now, now);

      writeAuditLog(db, {
        actorId: req.authUser!.id,
        projectId: project.id,
        action: 'project_dns.bind_manual',
        result: 'success',
        details: `Set project GeoDNS mode to Manual Setup (${providerZoneId}).`,
      });
      return res.json({ ok: true, nameservers: [] });
    }

    const resolved = resolveProviderInstance(providerAccountId!, req.authUser!.id);
    if (!resolved) return res.status(404).json({ error: 'Selected DNS provider account not found.' });

    let nameservers: string[] = [];
    try {
      const zone = await resolved.provider.getZone(providerZoneId);
      nameservers = zone.nameservers;
    } catch (err) {
      return res.status(502).json({
        error: `Could not load zone "${providerZoneId}" from ${resolved.providerName}: ${
          err instanceof Error ? err.message : 'API error'
        }`,
      });
    }

    const delegation = await checkDnsDelegation(project.domain, nameservers);

    db.prepare(`
      UPDATE projects
      SET geo_dns_provider = ?, geo_dns_zone_id = ?,
          status = CASE WHEN status IN ('draft', 'needs_infrastructure_verification') THEN 'geodns_not_configured' ELSE status END,
          updated_at = ?
      WHERE id = ?
    `).run(resolved.providerName, providerZoneId, now, project.id);

    db.prepare(`
      INSERT INTO dns_zones (id, project_id, provider_account_id, provider_zone_id, domain, authoritative_nameservers_json, delegation_status, observed_nameservers_json, last_synced_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(project_id) DO UPDATE SET
        provider_account_id = excluded.provider_account_id,
        provider_zone_id = excluded.provider_zone_id,
        authoritative_nameservers_json = excluded.authoritative_nameservers_json,
        delegation_status = excluded.delegation_status,
        observed_nameservers_json = excluded.observed_nameservers_json,
        last_synced_at = excluded.last_synced_at,
        updated_at = excluded.updated_at
    `).run(
      crypto.randomUUID(),
      project.id,
      providerAccountId,
      providerZoneId,
      project.domain,
      JSON.stringify(nameservers),
      delegation.status,
      JSON.stringify(delegation.observedNameservers),
      now,
      now
    );

    writeAuditLog(db, {
      actorId: req.authUser!.id,
      projectId: project.id,
      action: 'project_dns.bind_zone',
      result: 'success',
      details: `Bound zone "${providerZoneId}" via ${resolved.providerName} (${nameservers.length} authoritative NS retrieved).`,
    });

    res.json({ ok: true, nameservers, delegation });
  });

  app.post('/api/projects/:projectId/hostnames', requireAuth, (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const hostname = normalizeDomain(String(req.body?.hostname || ''));
    const role = String(req.body?.role || 'custom');
    const notes = String(req.body?.notes || '').trim();

    if (!isValidHostname(hostname) || (hostname !== project.domain && !hostname.endsWith(`.${project.domain}`))) {
      return res.status(400).json({
        error: `Hostname "${hostname}" must belong to project domain ${project.domain}.`,
      });
    }
    if (!['apex', 'www', 'static', 'api', 'custom'].includes(role)) {
      return res.status(400).json({ error: 'Invalid hostname role.' });
    }

    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    try {
      db.prepare(`
        INSERT INTO project_hostnames (id, project_id, hostname, role, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(id, project.id, hostname, role, notes, now, now);
    } catch {
      return res.status(409).json({ error: `Hostname ${hostname} is already configured on this project.` });
    }

    res.status(201).json({ id, hostname, role });
  });

  app.delete('/api/projects/:projectId/hostnames/:hostnameId', requireAuth, (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const row = db
      .prepare('SELECT hostname FROM project_hostnames WHERE id = ? AND project_id = ?')
      .get(String(req.params.hostnameId), project.id) as { hostname?: string } | undefined;
    if (!row) return res.status(404).json({ error: 'Hostname not found.' });

    db.prepare('DELETE FROM routing_rules WHERE project_id = ? AND hostname = ?').run(project.id, row.hostname!);
    db.prepare('DELETE FROM project_hostnames WHERE id = ? AND project_id = ?').run(
      String(req.params.hostnameId),
      project.id
    );
    res.json({ ok: true });
  });

  app.put('/api/projects/:projectId/routing-rules', requireAuth, (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const hostname = normalizeDomain(String(req.body?.hostname || project.domain));
    const regionCode = String(req.body?.regionCode || '') as RegionCode;
    const recordType = String(req.body?.recordType || '') as DnsRecordType;
    const destination = String(req.body?.destination || '').trim();
    const ttl = Number(req.body?.ttl ?? 300);
    const enabled = Boolean(req.body?.enabled);

    if (!['IR', 'DEFAULT', 'FALLBACK'].includes(regionCode)) {
      return res.status(400).json({ error: 'Region code must be IR, DEFAULT, or FALLBACK.' });
    }
    if (!['A', 'AAAA', 'CNAME', 'ALIAS', 'TXT'].includes(recordType)) {
      return res.status(400).json({ error: 'Unsupported DNS record type.' });
    }
    if (!Number.isFinite(ttl) || ttl < 10 || ttl > 2592000) {
      return res.status(400).json({ error: 'TTL must be between 10 and 2592000 seconds.' });
    }
    const destErr = validateRoutingRuleDestination(recordType, destination);
    if (destErr) {
      return res.status(400).json({ error: destErr });
    }

    const now = new Date().toISOString();
    const id = crypto.randomUUID();
    db.prepare(`
      INSERT INTO routing_rules (id, project_id, hostname, region_code, record_type, destination, ttl, enabled, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(project_id, hostname, region_code) DO UPDATE SET
        record_type = excluded.record_type,
        destination = excluded.destination,
        ttl = excluded.ttl,
        enabled = excluded.enabled,
        updated_at = excluded.updated_at
    `).run(id, project.id, hostname, regionCode, recordType, destination, ttl, enabled ? 1 : 0, now);

    writeAuditLog(db, {
      actorId: req.authUser!.id,
      projectId: project.id,
      action: 'routing_rule.upsert',
      result: 'success',
      details: `${enabled ? 'Enabled' : 'Disabled'} ${regionCode} rule for ${hostname}: ${recordType} -> ${destination} (TTL ${ttl}s).`,
    });

    res.json({ ok: true });
  });

  app.delete('/api/projects/:projectId/routing-rules/:ruleId', requireAuth, (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });
    db.prepare('DELETE FROM routing_rules WHERE id = ? AND project_id = ?').run(
      String(req.params.ruleId),
      project.id
    );
    res.json({ ok: true });
  });

  app.get('/api/projects/:projectId/dns/preview', requireAuth, async (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const { provider, providerAccountId, zoneId } = resolveProjectProvider(project, req.authUser!.id);
    const routingRules = getProjectRoutingRules(project.id);

    const preview = await buildDeploymentPreview({
      project,
      provider,
      providerAccountId,
      zoneId,
      routingRules,
    });

    res.json({ preview });
  });

  app.post('/api/projects/:projectId/dns/deploy', requireAuth, async (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const suppliedHash = String(req.body?.previewHash || '');
    const confirmDomain = normalizeDomain(String(req.body?.confirmProjectDomain || ''));
    const confirmProxyReady = Boolean(req.body?.confirmProxyReady);
    const confirmEmailRecords = Boolean(req.body?.confirmEmailRecordsPreserved);
    const confirmDeploy = Boolean(req.body?.confirmDeployAction);

    if (confirmDomain !== project.domain) {
      return res.status(400).json({ error: `Confirmation domain must match "${project.domain}".` });
    }
    if (!confirmProxyReady || !confirmEmailRecords || !confirmDeploy) {
      return res.status(400).json({
        error: 'All deployment safety confirmations (proxy readiness, email/TXT preservation, and explicit approval) are required.',
      });
    }

    const { provider, providerAccountId, zoneId } = resolveProjectProvider(project, req.authUser!.id);
    const routingRules = getProjectRoutingRules(project.id);

    const freshPreview = await buildDeploymentPreview({
      project,
      provider,
      providerAccountId,
      zoneId,
      routingRules,
    });

    if (freshPreview.previewHash !== suppliedHash) {
      return res.status(409).json({
        error: 'Routing configuration or live DNS state changed since preview was generated. Please generate a fresh preview.',
      });
    }
    if (!freshPreview.manualMode && freshPreview.conflicts.length > 0) {
      return res.status(400).json({
        error: `Cannot deploy while conflicts exist: ${freshPreview.conflicts.join(' ')}`,
      });
    }

    const result = await executeDnsDeployment({
      db,
      project,
      provider,
      providerAccountId,
      preview: freshPreview,
      actorId: req.authUser!.id,
    });

    const now = new Date().toISOString();
    if (result.status === 'confirmed') {
      const zoneRow = db.prepare('SELECT delegation_status FROM dns_zones WHERE project_id = ?').get(project.id) as
        | { delegation_status?: string }
        | undefined;
      const nextStatus: ProjectStatus =
        zoneRow?.delegation_status === 'verified' ? 'dns_configured' : 'waiting_for_nameserver_delegation';
      db.prepare('UPDATE projects SET status = ?, updated_at = ? WHERE id = ?').run(nextStatus, now, project.id);
    } else if (result.status === 'failed') {
      db.prepare('UPDATE projects SET status = ?, updated_at = ? WHERE id = ?').run('failed', now, project.id);
    } else if (result.status === 'partial_failure') {
      db.prepare('UPDATE projects SET status = ?, updated_at = ? WHERE id = ?').run('degraded', now, project.id);
    }

    writeAuditLog(db, {
      actorId: req.authUser!.id,
      projectId: project.id,
      action: 'project_dns.deploy',
      result: result.status === 'confirmed' ? 'success' : result.status === 'manual_pending' ? 'warning' : 'failure',
      details: `${result.summary} (Job ${result.jobId})`,
    });

    res.json({ deployment: result });
  });

  app.get('/api/projects/:projectId/dns/deployments', requireAuth, (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const jobs = db
      .prepare('SELECT * FROM dns_deployment_jobs WHERE project_id = ? ORDER BY created_at DESC LIMIT 25')
      .all(project.id) as Array<Record<string, unknown>>;

    const changesStmt = db.prepare('SELECT * FROM dns_deployment_changes WHERE job_id = ?');
    res.json({
      deployments: jobs.map((j) => {
        const changes = changesStmt.all(String(j.id)) as Array<Record<string, unknown>>;
        return {
          id: String(j.id),
          projectId: String(j.project_id),
          providerAccountId: j.provider_account_id ? String(j.provider_account_id) : null,
          zoneId: String(j.zone_id),
          previewHash: String(j.preview_hash),
          status: String(j.status),
          summary: String(j.summary),
          providerOperationId: String(j.provider_operation_id || ''),
          confirmedBy: j.confirmed_by ? String(j.confirmed_by) : null,
          confirmedAt: j.confirmed_at ? String(j.confirmed_at) : null,
          createdAt: String(j.created_at),
          updatedAt: String(j.updated_at),
          changes: changes.map((c) => ({
            id: String(c.id),
            operation: String(c.operation),
            hostname: String(c.hostname),
            regionCode: String(c.region_code),
            recordType: String(c.record_type),
            currentValue: String(c.current_value || ''),
            proposedValue: String(c.proposed_value || ''),
            ttl: Number(c.ttl),
            resultStatus: String(c.result_status),
            errorMessage: String(c.error_message || ''),
          })),
        };
      }),
    });
  });

  app.get('/api/projects/:projectId/dns/delegation', requireAuth, async (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const { provider, providerAccountId, zoneId, zoneRow } = resolveProjectProvider(project, req.authUser!.id);
    let expectedNs: string[] = zoneRow
      ? JSON.parse(String(zoneRow.authoritative_nameservers_json || '[]'))
      : [];

    if (providerAccountId && project.geoDnsProvider !== 'manual' && zoneId) {
      try {
        const freshNs = await provider.getNameservers(zoneId);
        if (freshNs.length > 0) expectedNs = freshNs;
      } catch {
        // fallback to cached nameservers if transient API error
      }
    }

    const delegation = await checkDnsDelegation(project.domain, expectedNs);
    const now = new Date().toISOString();

    if (zoneRow) {
      db.prepare(`
        UPDATE dns_zones
        SET authoritative_nameservers_json = ?, delegation_status = ?, observed_nameservers_json = ?, last_synced_at = ?, updated_at = ?
        WHERE project_id = ?
      `).run(
        JSON.stringify(expectedNs),
        delegation.status,
        JSON.stringify(delegation.observedNameservers),
        now,
        now,
        project.id
      );
    }

    writeAuditLog(db, {
      actorId: req.authUser!.id,
      projectId: project.id,
      action: 'project_dns.check_delegation',
      result: delegation.status === 'verified' ? 'success' : 'warning',
      details: delegation.message,
    });

    res.json({ delegation });
  });

  app.put('/api/projects/:projectId/irnic-checklist/:stepKey', requireAuth, (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const completed = req.body?.completed ? 1 : 0;
    const now = new Date().toISOString();
    const info = db
      .prepare(`
        UPDATE irnic_migration_checklists
        SET completed = ?, updated_at = ?
        WHERE project_id = ? AND step_key = ?
      `)
      .run(completed, now, project.id, String(req.params.stepKey));

    if (info.changes === 0) {
      return res.status(404).json({ error: 'Checklist step not found.' });
    }

    writeAuditLog(db, {
      actorId: req.authUser!.id,
      projectId: project.id,
      action: 'irnic_checklist.update',
      result: 'success',
      details: `Marked IRNIC step "${req.params.stepKey}" as ${completed ? 'completed' : 'incomplete'}.`,
    });

    res.json({ ok: true });
  });

  // -------------------- CLOUDFLARE READ-ONLY DISCOVERY --------------------

  app.get('/api/cloudflare/accounts', requireAuth, (req: AuthenticatedRequest, res) => {
    const rows = db
      .prepare('SELECT * FROM cloudflare_accounts WHERE owner_id = ? ORDER BY created_at DESC')
      .all(req.authUser!.id) as Array<Record<string, unknown>>;

    res.json({
      accounts: rows.map((r) => ({
        id: String(r.id),
        accountLabel: String(r.account_label),
        maskedHint: String(r.masked_hint),
        validationStatus: String(r.validation_status),
        validationMessage: String(r.validation_message || ''),
        lastValidatedAt: String(r.last_validated_at || ''),
        createdAt: String(r.created_at),
        updatedAt: String(r.updated_at),
      })),
    });
  });

  app.post('/api/cloudflare/accounts', requireAuth, (req: AuthenticatedRequest, res) => {
    const accountLabel = String(req.body?.accountLabel || '').trim();
    const apiToken = String(req.body?.apiToken || '').trim();

    if (!accountLabel || accountLabel.length > 60) {
      return res.status(400).json({ error: 'Cloudflare account label is required (max 60 characters).' });
    }
    if (apiToken.length < 16) {
      return res.status(400).json({ error: 'Please provide a valid least-privilege Cloudflare API token.' });
    }

    const encrypted = encryptSecret(apiToken);
    const hint = maskSecret(apiToken);
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO cloudflare_accounts (
        id, owner_id, account_label, encrypted_token_ciphertext, token_iv, token_tag,
        masked_hint, validation_status, validation_message, last_validated_at, created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, 'not_validated', 'Pending token verification', '', ?, ?)
    `).run(id, req.authUser!.id, accountLabel, encrypted.ciphertext, encrypted.iv, encrypted.tag, hint, now, now);

    writeAuditLog(db, {
      actorId: req.authUser!.id,
      action: 'cloudflare_account.create',
      result: 'success',
      details: `Added Cloudflare read-only account "${accountLabel}" (${hint}).`,
    });

    res.status(201).json({
      account: {
        id,
        accountLabel,
        maskedHint: hint,
        validationStatus: 'not_validated',
        validationMessage: 'Pending token verification',
        lastValidatedAt: '',
        createdAt: now,
        updatedAt: now,
      },
    });
  });

  function resolveCloudflareClient(accountId: string, ownerId: string) {
    const row = db
      .prepare('SELECT * FROM cloudflare_accounts WHERE id = ? AND owner_id = ?')
      .get(accountId, ownerId) as Record<string, unknown> | undefined;
    if (!row) return null;
    const token = decryptSecret(
      String(row.encrypted_token_ciphertext),
      String(row.token_iv),
      String(row.token_tag)
    );
    return {
      row,
      client: new CloudflareReadOnlyClient(token, fetcher),
    };
  }

  app.post('/api/cloudflare/accounts/:id/validate', requireAuth, async (req: AuthenticatedRequest, res) => {
    const resolved = resolveCloudflareClient(String(req.params.id), req.authUser!.id);
    if (!resolved) return res.status(404).json({ error: 'Cloudflare account not found.' });

    const check = await resolved.client.verifyToken();
    const now = new Date().toISOString();
    const status = check.valid ? 'valid' : 'invalid';

    db.prepare(`
      UPDATE cloudflare_accounts
      SET validation_status = ?, validation_message = ?, last_validated_at = ?, updated_at = ?
      WHERE id = ? AND owner_id = ?
    `).run(status, check.message, now, now, String(req.params.id), req.authUser!.id);

    writeAuditLog(db, {
      actorId: req.authUser!.id,
      action: 'cloudflare_account.validate',
      result: check.valid ? 'success' : 'failure',
      details: `Validated Cloudflare token "${resolved.row.account_label}": ${check.message}`,
    });

    res.json({ validation: check });
  });

  app.get('/api/cloudflare/accounts/:id/zones', requireAuth, async (req: AuthenticatedRequest, res) => {
    const resolved = resolveCloudflareClient(String(req.params.id), req.authUser!.id);
    if (!resolved) return res.status(404).json({ error: 'Cloudflare account not found.' });

    try {
      const zones = await resolved.client.listZones();
      res.json({ zones });
    } catch (err) {
      res.status(502).json({
        error: err instanceof Error ? redactSecrets(err.message) : 'Failed to list Cloudflare zones.',
      });
    }
  });

  app.delete('/api/cloudflare/accounts/:id', requireAuth, (req: AuthenticatedRequest, res) => {
    const row = db
      .prepare('SELECT account_label FROM cloudflare_accounts WHERE id = ? AND owner_id = ?')
      .get(String(req.params.id), req.authUser!.id) as { account_label?: string } | undefined;
    if (!row) return res.status(404).json({ error: 'Cloudflare account not found.' });

    db.prepare('DELETE FROM cloudflare_accounts WHERE id = ? AND owner_id = ?').run(
      String(req.params.id),
      req.authUser!.id
    );
    writeAuditLog(db, {
      actorId: req.authUser!.id,
      action: 'cloudflare_account.delete',
      result: 'success',
      details: `Removed Cloudflare account "${row.account_label}".`,
    });
    res.json({ ok: true });
  });

  app.post('/api/projects/:projectId/cloudflare/discover', requireAuth, async (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const cloudflareAccountId = String(req.body?.cloudflareAccountId || '');
    const cloudflareZoneId = String(req.body?.cloudflareZoneId || '');
    if (!cloudflareAccountId || !cloudflareZoneId) {
      return res.status(400).json({ error: 'Cloudflare account ID and zone ID are required.' });
    }

    const resolved = resolveCloudflareClient(cloudflareAccountId, req.authUser!.id);
    if (!resolved) return res.status(404).json({ error: 'Cloudflare account not found.' });

    try {
      const bundle = await resolved.client.discoverZone(cloudflareZoneId);
      const now = new Date().toISOString();

      db.prepare(`
        INSERT INTO project_cloudflare_mappings (
          id, project_id, cloudflare_account_id, cloudflare_zone_id, zone_name, zone_status,
          name_servers_json, records_snapshot_json, worker_routes_json, worker_domains_json,
          ssl_mode, cache_level, requires_architecture_review, review_notes, discovered_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(project_id) DO UPDATE SET
          cloudflare_account_id = excluded.cloudflare_account_id,
          cloudflare_zone_id = excluded.cloudflare_zone_id,
          zone_name = excluded.zone_name,
          zone_status = excluded.zone_status,
          name_servers_json = excluded.name_servers_json,
          records_snapshot_json = excluded.records_snapshot_json,
          worker_routes_json = excluded.worker_routes_json,
          worker_domains_json = excluded.worker_domains_json,
          ssl_mode = excluded.ssl_mode,
          cache_level = excluded.cache_level,
          requires_architecture_review = excluded.requires_architecture_review,
          review_notes = excluded.review_notes,
          discovered_at = excluded.discovered_at,
          updated_at = excluded.updated_at
      `).run(
        crypto.randomUUID(),
        project.id,
        cloudflareAccountId,
        bundle.zone.id,
        bundle.zone.name,
        bundle.zone.status,
        JSON.stringify(bundle.zone.nameServers),
        JSON.stringify(bundle.records),
        JSON.stringify(bundle.workerRoutes),
        JSON.stringify(bundle.workerDomains),
        bundle.sslMode,
        bundle.cacheLevel,
        bundle.requiresArchitectureReview ? 1 : 0,
        bundle.reviewNotes,
        now,
        now
      );

      db.prepare('UPDATE projects SET cloudflare_zone_id = ?, updated_at = ? WHERE id = ?').run(
        bundle.zone.id,
        now,
        project.id
      );

      writeAuditLog(db, {
        actorId: req.authUser!.id,
        projectId: project.id,
        action: 'cloudflare.discover',
        result: bundle.requiresArchitectureReview ? 'warning' : 'success',
        details: `Read-only discovery completed for Cloudflare zone "${bundle.zone.name}" (${bundle.records.length} DNS records, ${bundle.workerRoutes.length} Worker routes).`,
      });

      res.json({ discovery: bundle });
    } catch (err) {
      res.status(502).json({
        error: err instanceof Error ? redactSecrets(err.message) : 'Cloudflare discovery failed.',
      });
    }
  });

  app.get('/api/projects/:projectId/cloudflare/discovery', requireAuth, (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const row = db
      .prepare('SELECT * FROM project_cloudflare_mappings WHERE project_id = ?')
      .get(project.id) as Record<string, unknown> | undefined;

    if (!row) return res.json({ mapping: null });

    res.json({
      mapping: {
        id: String(row.id),
        projectId: String(row.project_id),
        cloudflareAccountId: String(row.cloudflare_account_id),
        cloudflareZoneId: String(row.cloudflare_zone_id),
        zoneName: String(row.zone_name),
        zoneStatus: String(row.zone_status || ''),
        nameServers: JSON.parse(String(row.name_servers_json || '[]')),
        recordsSnapshot: JSON.parse(String(row.records_snapshot_json || '[]')),
        workerRoutes: JSON.parse(String(row.worker_routes_json || '[]')),
        workerDomains: JSON.parse(String(row.worker_domains_json || '[]')),
        sslMode: String(row.ssl_mode || ''),
        cacheLevel: String(row.cache_level || ''),
        requiresArchitectureReview: Boolean(row.requires_architecture_review),
        reviewNotes: String(row.review_notes || ''),
        discoveredAt: String(row.discovered_at),
        updatedAt: String(row.updated_at),
      },
    });
  });

  // -------------------- DIAGNOSTICS --------------------

  app.post('/api/projects/:projectId/diagnostics', requireAuth, async (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const { provider, providerAccountId, zoneRow } = resolveProjectProvider(project, req.authUser!.id);
    const expectedNs: string[] = zoneRow
      ? JSON.parse(String(zoneRow.authoritative_nameservers_json || '[]'))
      : [];
    const routingRules = getProjectRoutingRules(project.id);

    const checks = await runProjectDiagnostics({
      project,
      routingRules,
      provider,
      expectedNameservers: expectedNs,
      hasProviderAccount: Boolean(providerAccountId),
    });

    const insertDiag = db.prepare(`
      INSERT INTO dns_health_checks
        (id, project_id, check_category, target, status, test_location, summary, technical_details_json, checked_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const c of checks) {
      insertDiag.run(
        c.id,
        c.projectId,
        c.checkCategory,
        c.target,
        c.status,
        c.testLocation,
        c.summary,
        JSON.stringify(c.technicalDetails),
        c.checkedAt
      );
    }

    writeAuditLog(db, {
      actorId: req.authUser!.id,
      projectId: project.id,
      action: 'diagnostics.run',
      result: checks.some((c) => c.status === 'failed') ? 'warning' : 'success',
      details: `Executed ${checks.length} read-only diagnostic checks from external backend.`,
    });

    res.json({ checks });
  });

  app.get('/api/projects/:projectId/diagnostics', requireAuth, (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const rows = db
      .prepare('SELECT * FROM dns_health_checks WHERE project_id = ? ORDER BY checked_at DESC LIMIT 40')
      .all(project.id) as Array<Record<string, unknown>>;

    res.json({
      checks: rows.map((d) => ({
        id: String(d.id),
        projectId: String(d.project_id),
        checkCategory: String(d.check_category),
        target: String(d.target),
        status: String(d.status),
        testLocation: String(d.test_location),
        summary: String(d.summary),
        technicalDetails: JSON.parse(String(d.technical_details_json || '{}')),
        checkedAt: String(d.checked_at),
      })),
    });
  });

  // -------------------- AUDIT LOGS & BACKUP --------------------

  app.get('/api/audit-logs', requireAuth, (req: AuthenticatedRequest, res) => {
    const projectId = req.query.projectId ? String(req.query.projectId) : null;
    const rows = projectId
      ? (db
          .prepare(`
            SELECT a.*, u.username AS actor_username, p.project_name
            FROM audit_logs a
            LEFT JOIN users u ON u.id = a.actor_id
            LEFT JOIN projects p ON p.id = a.project_id
            WHERE a.actor_id = ? AND a.project_id = ?
            ORDER BY a.created_at DESC
            LIMIT 100
          `)
          .all(req.authUser!.id, projectId) as Array<Record<string, unknown>>)
      : (db
          .prepare(`
            SELECT a.*, u.username AS actor_username, p.project_name
            FROM audit_logs a
            LEFT JOIN users u ON u.id = a.actor_id
            LEFT JOIN projects p ON p.id = a.project_id
            WHERE a.actor_id = ?
            ORDER BY a.created_at DESC
            LIMIT 150
          `)
          .all(req.authUser!.id) as Array<Record<string, unknown>>);

    res.json({
      logs: rows.map((r) => ({
        id: String(r.id),
        actorId: String(r.actor_id),
        actorUsername: String(r.actor_username || ''),
        projectId: r.project_id ? String(r.project_id) : null,
        projectName: r.project_name ? String(r.project_name) : undefined,
        action: String(r.action),
        result: String(r.result),
        details: String(r.details),
        createdAt: String(r.created_at),
      })),
    });
  });

  app.get('/api/settings/backup', requireAuth, (req: AuthenticatedRequest, res) => {
    const userId = req.authUser!.id;
    const projects = db.prepare('SELECT * FROM projects WHERE owner_id = ?').all(userId);
    const projectIds = (projects as Array<{ id: string }>).map((p) => p.id);

    const routingRules = projectIds.length
      ? db
          .prepare(`SELECT * FROM routing_rules WHERE project_id IN (${projectIds.map(() => '?').join(',')})`)
          .all(...projectIds)
      : [];
    const cachePolicies = projectIds.length
      ? db
          .prepare(`SELECT * FROM cache_policies WHERE project_id IN (${projectIds.map(() => '?').join(',')})`)
          .all(...projectIds)
      : [];
    const dnsZones = projectIds.length
      ? db
          .prepare(`SELECT * FROM dns_zones WHERE project_id IN (${projectIds.map(() => '?').join(',')})`)
          .all(...projectIds)
      : [];
    const dnsProviders = db
      .prepare('SELECT id, provider_name, account_label, masked_hint, validation_status, created_at FROM dns_provider_accounts WHERE owner_id = ?')
      .all(userId);
    const cloudflareAccounts = db
      .prepare('SELECT id, account_label, masked_hint, validation_status, created_at FROM cloudflare_accounts WHERE owner_id = ?')
      .all(userId);

    writeAuditLog(db, {
      actorId: userId,
      action: 'settings.backup_export',
      result: 'success',
      details: `Exported sanitized configuration backup (${projects.length} project(s); secrets excluded).`,
    });

    res.json({
      exportedAt: new Date().toISOString(),
      note: 'Sanitized GeoRoute Manager configuration backup. Password hashes and encrypted API credentials are excluded.',
      projects,
      routingRules,
      cachePolicies,
      dnsZones,
      dnsProviders,
      cloudflareAccounts,
    });
  });

  // -------------------- CLOUDFLARE NS RESOLVER & SAFE STATIC CACHE PROXY --------------------

  app.post('/api/projects/:projectId/cloudflare/resolve-ns', requireAuth, async (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const rawTarget = String(req.body?.cloudflareTarget ?? project.cloudflareTarget ?? '').trim();
    const resolution = await resolveViaCloudflareNameservers(project.domain, rawTarget);
    res.json({ resolution });
  });

  app.post('/api/projects/:projectId/proxy/test', requireAuth, async (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const testPath = String(req.body?.path || '/');
    const bypassCache = Boolean(req.body?.bypassCache);
    const result = await proxyFetchThroughCloudflare({
      projectId: project.id,
      domain: project.domain,
      cloudflareTarget: project.cloudflareTarget,
      reqPath: testPath,
      method: 'GET',
      bypassCache,
    });

    res.json({
      test: {
        ok: result.ok,
        statusCode: result.statusCode,
        cacheStatus: result.cacheStatus,
        targetIp: result.targetIp,
        cfRay: result.cfRay,
        contentType: result.contentType,
        bytes: result.bytes,
        latencyMs: result.latencyMs,
        error: result.error || '',
      },
      cache: getProjectCacheStats(project.id),
    });
  });

  app.get('/api/projects/:projectId/proxy/cache', requireAuth, (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });
    res.json({ cache: getProjectCacheStats(project.id) });
  });

  app.delete('/api/projects/:projectId/proxy/cache', requireAuth, (req: AuthenticatedRequest, res) => {
    const project = getOwnedProject(String(req.params.projectId), req.authUser!.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });
    const cleared = clearProjectCache(project.id);
    res.json({ ok: true, cleared, cache: getProjectCacheStats(project.id) });
  });

  // Global error handler — always redact any accidental secret substring
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const raw = err instanceof Error ? err.message : 'Internal server error';
    res.status(500).json({ error: redactSecrets(raw) });
  });

  return app;
}
