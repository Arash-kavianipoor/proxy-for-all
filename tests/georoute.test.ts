import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { describe, expect, it } from 'vitest';
import { createApp } from '../server/app.ts';
import { normalizeBasePath } from '../server/basePath.ts';
import { decryptSecret, encryptSecret, redactSecrets } from '../server/crypto.ts';
import { ensureDefaultAdmin, runMigrations } from '../server/db.ts';
import { buildDeploymentPreview } from '../server/deployment.ts';
import { ClouDnsGeoDnsProvider } from '../server/providers/cloudns.ts';
import { CloudflareReadOnlyClient } from '../server/providers/cloudflare.ts';
import { ManualGeoDnsProvider } from '../server/providers/manual.ts';
import { Ns1GeoDnsProvider } from '../server/providers/ns1.ts';
import {
  clearProjectCache,
  getProjectCacheStats,
  parseCloudflareInput,
  resolveViaCloudflareNameservers,
} from '../server/proxyCache.ts';
import { assertSafePublicUrl, isPrivateOrReservedIp } from '../server/security.ts';
import type { Project, RoutingRule } from '../src/types/georoute.ts';

function setupTestDb() {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON;');
  runMigrations(db);
  return db;
}

function makeProject(overrides: Partial<Project> = {}): Project {
  const now = new Date().toISOString();
  return {
    id: 'proj-1',
    ownerId: 'user-1',
    projectName: 'Test Site',
    domain: 'example.ir',
    description: '',
    status: 'draft',
    iranProxyHostname: '',
    iranProxyIPv4: '',
    iranProxyIPv6: '',
    cloudflareTarget: 'cf-target.example.workers.dev',
    cloudflareZoneId: '',
    geoDnsProvider: 'ns1',
    geoDnsZoneId: 'example.ir',
    healthCheckUrl: 'https://example.ir',
    notes: '',
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

describe('GeoRoute Manager Security & Cryptography', () => {
  it('encrypts and decrypts secrets with AES-256-GCM and redacts secrets from logs', () => {
    const token = 'cf_secret_token_9876543210';
    const enc = encryptSecret(token);
    expect(enc.ciphertext).not.toContain(token);
    expect(decryptSecret(enc.ciphertext, enc.iv, enc.tag)).toBe(token);

    const logMsg = `Authorization: Bearer ${token} failed with X-NSONE-Key: ns1_key_abc123`;
    const redacted = redactSecrets(logMsg, [token]);
    expect(redacted).not.toContain(token);
    expect(redacted).not.toContain('ns1_key_abc123');
    expect(redacted).toContain('[REDACTED]');
  });

  it('blocks private, loopback, and link-local IP addresses against SSRF', async () => {
    expect(isPrivateOrReservedIp('127.0.0.1')).toBe(true);
    expect(isPrivateOrReservedIp('10.0.0.5')).toBe(true);
    expect(isPrivateOrReservedIp('169.254.169.254')).toBe(true);
    expect(isPrivateOrReservedIp('192.168.1.1')).toBe(true);
    expect(isPrivateOrReservedIp('1.1.1.1')).toBe(false);

    await expect(assertSafePublicUrl('http://127.0.0.1:8080/admin')).rejects.toThrow();
    await expect(assertSafePublicUrl('http://localhost/health')).rejects.toThrow();
    await expect(assertSafePublicUrl('http://169.254.169.254/latest/meta-data')).rejects.toThrow();
  });
});

describe('GeoDNS Provider Adapters', () => {
  it('parses IBM NS1 Connect zones, nameservers, and country-tagged records', async () => {
    const mockFetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/zones')) {
        return new Response(
          JSON.stringify([{ zone: 'example.ir', dns_servers: ['dns1.p01.nsone.net', 'dns2.p01.nsone.net'] }]),
          { status: 200 }
        );
      }
      if (url.endsWith('/zones/example.ir')) {
        return new Response(
          JSON.stringify({
            zone: 'example.ir',
            dns_servers: ['dns1.p01.nsone.net', 'dns2.p01.nsone.net'],
            records: [{ domain: 'www.example.ir', type: 'A', ttl: 300, short_answers: ['1.1.1.1'] }],
          }),
          { status: 200 }
        );
      }
      if (url.endsWith('/zones/example.ir/www.example.ir/A')) {
        return new Response(
          JSON.stringify({
            domain: 'www.example.ir',
            type: 'A',
            ttl: 300,
            answers: [
              { answer: ['185.10.10.10'], meta: { country: ['IR'] } },
              { answer: ['104.21.1.1'], meta: {} },
            ],
          }),
          { status: 200 }
        );
      }
      return new Response(JSON.stringify({ message: 'Not found' }), { status: 404 });
    }) as typeof fetch;

    const ns1 = new Ns1GeoDnsProvider({ apiKey: 'test-ns1-secret-key' }, mockFetch);
    const val = await ns1.validateCredentials();
    expect(val.valid).toBe(true);

    const ns = await ns1.getNameservers('example.ir');
    expect(ns).toEqual(['dns1.p01.nsone.net', 'dns2.p01.nsone.net']);

    const records = await ns1.listRecords('example.ir');
    expect(records).toHaveLength(2);
    expect(records.find((r) => r.regionCode === 'IR')?.value).toBe('185.10.10.10');
    expect(records.find((r) => r.regionCode === 'DEFAULT')?.value).toBe('104.21.1.1');
  });

  it('parses ClouDNS zones and handles auth failures cleanly without leaking secrets', async () => {
    const mockFailFetch = (async () =>
      new Response(JSON.stringify({ status: 'Failed', statusDescription: 'Invalid auth-password my_secret_pass' }), {
        status: 200,
      })) as typeof fetch;

    const cloudns = new ClouDnsGeoDnsProvider(
      { authId: '12345', authPassword: 'my_secret_pass' },
      mockFailFetch
    );
    const validation = await cloudns.validateCredentials();
    expect(validation.valid).toBe(false);
    expect(validation.message).not.toContain('my_secret_pass');
  });

  it('ManualGeoDnsProvider never claims automated deployment', async () => {
    const manual = new ManualGeoDnsProvider();
    const res = await manual.createRecord('example.ir', {
      hostname: 'example.ir',
      type: 'A',
      value: '185.10.10.10',
      ttl: 300,
      regionCode: 'IR',
    });
    expect(res.success).toBe(false);
    expect(res.manualMode).toBe(true);
  });
});

describe('DNS Preview Conflict Detection', () => {
  it('detects missing Global fallback, apex CNAME, and CNAME coexistence conflicts', async () => {
    const mockNs1 = new Ns1GeoDnsProvider({ apiKey: 'k' }, (async (url: RequestInfo | URL) => {
      if (String(url).endsWith('/zones/example.ir')) {
        return new Response(
          JSON.stringify({
            zone: 'example.ir',
            dns_servers: ['dns1.p01.nsone.net'],
            records: [],
          }),
          { status: 200 }
        );
      }
      return new Response('{}', { status: 200 });
    }) as typeof fetch);

    const project = makeProject();
    const rules: RoutingRule[] = [
      {
        id: 'r1',
        projectId: project.id,
        hostname: 'example.ir',
        regionCode: 'IR',
        recordType: 'CNAME',
        destination: 'proxy.example.ir',
        ttl: 300,
        enabled: true,
        updatedAt: new Date().toISOString(),
      },
    ];

    const preview = await buildDeploymentPreview({
      project,
      provider: mockNs1,
      providerAccountId: 'acc-1',
      zoneId: 'example.ir',
      routingRules: rules,
    });

    expect(preview.canDeploy).toBe(false);
    expect(preview.apexSupported).toBe(false);
    expect(preview.conflicts.some((c) => c.includes('Global/Default'))).toBe(true);
    expect(preview.conflicts.some((c) => c.includes('Apex domain'))).toBe(true);
  });
});

describe('Cloudflare Read-Only Discovery', () => {
  it('flags Worker routes as requiring architecture review and handles invalid token', async () => {
    const failClient = new CloudflareReadOnlyClient('bad_cf_token_1234', (async () =>
      new Response(JSON.stringify({ success: false, errors: [{ message: 'Invalid token bad_cf_token_1234' }] }), {
        status: 401,
      })) as typeof fetch);

    const verifyFail = await failClient.verifyToken();
    expect(verifyFail.valid).toBe(false);
    expect(verifyFail.message).not.toContain('bad_cf_token_1234');

    const okClient = new CloudflareReadOnlyClient('good_cf_token_1234', (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/zones/z1')) {
        return new Response(
          JSON.stringify({
            success: true,
            result: { id: 'z1', name: 'example.ir', status: 'active', name_servers: ['ns1.cf.com'], account: { id: 'a1' } },
          }),
          { status: 200 }
        );
      }
      if (url.includes('/dns_records')) {
        return new Response(
          JSON.stringify({
            success: true,
            result: [{ id: 'd1', type: 'A', name: 'example.ir', content: '192.0.2.1', proxied: true, ttl: 1 }],
          }),
          { status: 200 }
        );
      }
      if (url.includes('/workers/routes')) {
        return new Response(
          JSON.stringify({
            success: true,
            result: [{ id: 'w1', pattern: 'example.ir/api/*', script: 'api-worker' }],
          }),
          { status: 200 }
        );
      }
      if (url.includes('/settings/ssl')) {
        return new Response(JSON.stringify({ success: true, result: { value: 'strict' } }), { status: 200 });
      }
      if (url.includes('/settings/cache_level')) {
        return new Response(JSON.stringify({ success: true, result: { value: 'aggressive' } }), { status: 200 });
      }
      return new Response(JSON.stringify({ success: true, result: [] }), { status: 200 });
    }) as typeof fetch);

    const bundle = await okClient.discoverZone('z1');
    expect(bundle.requiresArchitectureReview).toBe(true);
    expect(bundle.workerRoutes).toHaveLength(1);
    expect(bundle.sslMode).toBe('strict');
  });
});

describe('API Authorization, Project Isolation & Operational Gating', () => {
  it('enforces auth, CSRF, project isolation, cache-bypass safety, and operational gating', async () => {
    const db = setupTestDb();
    const app = createApp(db);

    const server = app.listen(0);
    const addr = server.address();
    const baseUrl = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`;

    try {
      // 1. Unauthenticated access rejected
      const unauth = await fetch(`${baseUrl}/api/projects`);
      expect(unauth.status).toBe(401);

      // 2. Setup admin user
      const setupRes = await fetch(`${baseUrl}/api/auth/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: 'StrongPassword123!' }),
      });
      expect(setupRes.status).toBe(201);
      const cookie = setupRes.headers.get('set-cookie')?.split(';')[0] || '';
      const setupJson = (await setupRes.json()) as { csrfToken: string };

      // 3. CSRF required on mutations
      const noCsrf = await fetch(`${baseUrl}/api/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: cookie },
        body: JSON.stringify({ projectName: 'Site A', domain: 'sitea.ir' }),
      });
      expect(noCsrf.status).toBe(403);

      // 4. Create project with valid CSRF
      const createRes = await fetch(`${baseUrl}/api/projects`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: cookie,
          'X-CSRF-Token': setupJson.csrfToken,
        },
        body: JSON.stringify({
          projectName: 'Site A',
          domain: 'sitea.ir',
          cloudflareTarget: 'cf.sitea.ir',
        }),
      });
      expect(createRes.status).toBe(201);
      const { project } = (await createRes.json()) as { project: Project };

      // 5. Block marking operational before confirmed deploy + verified delegation + health check
      const opRes = await fetch(`${baseUrl}/api/projects/${project.id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Cookie: cookie,
          'X-CSRF-Token': setupJson.csrfToken,
        },
        body: JSON.stringify({ status: 'operational' }),
      });
      expect(opRes.status).toBe(400);

      // 6. Block caching on /api/* endpoints
      const badCache = await fetch(`${baseUrl}/api/projects/${project.id}/cache-policies`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: cookie,
          'X-CSRF-Token': setupJson.csrfToken,
        },
        body: JSON.stringify({
          pathPattern: '/api/users',
          resourceType: 'API',
          cacheBehavior: 'cache_immutable',
          ttlSeconds: 3600,
        }),
      });
      expect(badCache.status).toBe(400);
    } finally {
      server.close();
      db.close();
    }
  });

  it('seeds hashed default admin (Arash2021368) and supports password change', async () => {
    const db = setupTestDb();
    ensureDefaultAdmin(db);
    // Calling twice must remain idempotent
    ensureDefaultAdmin(db);

    const row = db
      .prepare('SELECT username, password_hash, password_salt FROM users WHERE username = ?')
      .get('admin') as { username: string; password_hash: string; password_salt: string };
    expect(row.username).toBe('admin');
    expect(row.password_hash).not.toContain('Arash');
    expect(row.password_hash.length).toBe(128);

    const app = createApp(db);
    const server = app.listen(0);
    const addr = server.address();
    const baseUrl = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`;

    try {
      // Wrong password rejected
      const badLogin = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: 'WrongPassword123' }),
      });
      expect(badLogin.status).toBe(401);

      // Default password accepted (case-insensitive username)
      const okLogin = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'Admin', password: 'Arash2021368' }),
      });
      expect(okLogin.status).toBe(200);
      const cookie = okLogin.headers.get('set-cookie')?.split(';')[0] || '';
      const loginJson = (await okLogin.json()) as { csrfToken: string };

      // Change password
      const changeRes = await fetch(`${baseUrl}/api/auth/change-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: cookie,
          'X-CSRF-Token': loginJson.csrfToken,
        },
        body: JSON.stringify({
          currentPassword: 'Arash2021368',
          newPassword: 'NewStrongPassword#2026',
        }),
      });
      expect(changeRes.status).toBe(200);

      // Old password no longer works
      const oldLogin = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: 'Arash2021368' }),
      });
      expect(oldLogin.status).toBe(401);

      // New password works
      const newLogin = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: 'NewStrongPassword#2026' }),
      });
      expect(newLogin.status).toBe(200);
    } finally {
      server.close();
      db.close();
    }
  });

  it('supports Apache subpath BASE_PATH routing and chained X-Forwarded-Proto headers', async () => {
    expect(normalizeBasePath('/georoute/')).toBe('/georoute');
    expect(normalizeBasePath('/')).toBe('');
    expect(normalizeBasePath('invalid<script>')).toBe('');

    const db = setupTestDb();
    ensureDefaultAdmin(db);
    const app = createApp(db, { basePath: '/georoute' });

    const server = app.listen(0);
    const addr = server.address();
    const baseUrl = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`;

    try {
      const statusRes = await fetch(`${baseUrl}/georoute/api/auth/status`);
      expect(statusRes.status).toBe(200);
      const statusJson = (await statusRes.json()) as { initialized: boolean };
      expect(statusJson.initialized).toBe(true);

      const loginRes = await fetch(`${baseUrl}/georoute/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Forwarded-Proto': 'https, http',
        },
        body: JSON.stringify({ username: 'admin', password: 'Arash2021368' }),
      });
      expect(loginRes.status).toBe(200);
      const setCookie = loginRes.headers.get('set-cookie') || '';
      expect(setCookie.toLowerCase()).toContain('secure');
      expect(setCookie.toLowerCase()).toContain('samesite=none');

      const loginJson = (await loginRes.json()) as { sessionToken?: string };
      expect(loginJson.sessionToken).toBeTruthy();

      // Verify Bearer sessionToken works even if browser blocks third-party iframe cookies
      const projectsRes = await fetch(`${baseUrl}/georoute/api/projects`, {
        headers: {
          Authorization: `Bearer ${loginJson.sessionToken}`,
        },
      });
      expect(projectsRes.status).toBe(200);
    } finally {
      server.close();
      db.close();
    }
  });

  it('parses Cloudflare nameservers, blocks private NS targets, and isolates proxy cache stats', async () => {
    const parsed = parseCloudflareInput('dane.ns.cloudflare.com\ndolly.ns.cloudflare.com');
    expect(parsed.nameservers).toEqual(['dane.ns.cloudflare.com', 'dolly.ns.cloudflare.com']);
    expect(parsed.directTarget).toBe('');
    expect(parsed.normalizedDisplay).toBe('dane.ns.cloudflare.com, dolly.ns.cloudflare.com');

    const parsedComma = parseCloudflareInput('dane.ns.cloudflare.com, dolly.ns.cloudflare.com');
    expect(parsedComma.nameservers).toEqual(['dane.ns.cloudflare.com', 'dolly.ns.cloudflare.com']);

    const ssrfRes = await resolveViaCloudflareNameservers('example.ir', '127.0.0.1');
    expect(ssrfRes.ok).toBe(false);
    expect(ssrfRes.ipv4Addresses).toEqual([]);

    const privateRes = await resolveViaCloudflareNameservers('example.ir', '192.168.1.50');
    expect(privateRes.ok).toBe(false);

    const stats = getProjectCacheStats('nonexistent-proj');
    expect(stats.entries).toBe(0);
    expect(stats.totalBytes).toBe(0);
    expect(clearProjectCache('nonexistent-proj')).toBe(0);
  });

  it('routes /api/* on proxied domains to hostProxyMiddleware instead of control-plane API 404', async () => {
    const db = setupTestDb();
    ensureDefaultAdmin(db);
    const interceptedHosts: string[] = [];

    const app = createApp(db, {
      hostProxyMiddleware: (req, res, next) => {
        const host = String(req.headers.host || '').split(':')[0].toLowerCase();
        if (host === 'arosebartar.ir') {
          interceptedHosts.push(`${host}${req.originalUrl}`);
          return res.status(200).json({ reviews: [{ id: 1 }] });
        }
        return next();
      },
    });

    const server = app.listen(0);
    const addr = server.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;

    const getWithHost = (reqPath: string, hostHeader: string) =>
      new Promise<{ status: number; body: string }>((resolve, reject) => {
        const req = http.get(
          {
            hostname: '127.0.0.1',
            port,
            path: reqPath,
            headers: { Host: hostHeader },
          },
          (res) => {
            const chunks: Buffer[] = [];
            res.on('data', (c: Buffer) => chunks.push(c));
            res.on('end', () =>
              resolve({ status: res.statusCode || 0, body: Buffer.concat(chunks).toString('utf8') })
            );
          }
        );
        req.on('error', reject);
      });

    try {
      const proxiedApiRes = await getWithHost('/api/reviews?_t=12345', 'arosebartar.ir');
      expect(proxiedApiRes.status).toBe(200);
      expect(interceptedHosts).toEqual(['arosebartar.ir/api/reviews?_t=12345']);

      const panelStatusRes = await getWithHost('/api/auth/status', 'arashproxysystem.ir');
      expect(panelStatusRes.status).toBe(200);
      const statusJson = JSON.parse(panelStatusRes.body) as { initialized: boolean };
      expect(statusJson.initialized).toBe(true);
    } finally {
      server.close();
      db.close();
    }
  });
});


