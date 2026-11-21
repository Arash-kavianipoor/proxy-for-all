import dns from 'node:dns';
import https from 'node:https';
import type { DatabaseSync } from 'node:sqlite';
import type { NextFunction, Request, Response } from 'express';
import {
  isPrivateOrReservedIp,
  isValidDomain,
  isValidHostname,
  isValidIPv4,
  isValidIPv6,
  normalizeDomain,
} from './security.ts';

export interface ParsedCloudflareTarget {
  nameservers: string[];
  directTarget: string;
  normalizedDisplay: string;
}

export function parseCloudflareInput(raw: string): ParsedCloudflareTarget {
  const tokens = String(raw || '')
    .split(/[\s,;]+/)
    .map((t) => normalizeDomain(t))
    .filter(Boolean);

  const nameservers: string[] = [];
  let directTarget = '';

  for (const token of tokens) {
    if (token.endsWith('.ns.cloudflare.com') || (tokens.length > 1 && isValidHostname(token))) {
      if (!nameservers.includes(token)) nameservers.push(token);
    } else if (!directTarget) {
      directTarget = token;
    }
  }

  return {
    nameservers,
    directTarget,
    normalizedDisplay: nameservers.length > 0 ? nameservers.join(', ') : directTarget,
  };
}

export interface CloudflareNsResolutionResult {
  ok: boolean;
  domain: string;
  nameserversUsed: string[];
  resolvedNsIps: string[];
  ipv4Addresses: string[];
  ipv6Addresses: string[];
  message: string;
}

export async function resolveViaCloudflareNameservers(
  rawDomain: string,
  rawCloudflareTarget: string
): Promise<CloudflareNsResolutionResult> {
  const domain = normalizeDomain(rawDomain);
  if (!isValidDomain(domain)) {
    return {
      ok: false,
      domain,
      nameserversUsed: [],
      resolvedNsIps: [],
      ipv4Addresses: [],
      ipv6Addresses: [],
      message: 'Invalid domain name.',
    };
  }

  const parsed = parseCloudflareInput(rawCloudflareTarget);

  if (parsed.directTarget && isValidIPv4(parsed.directTarget)) {
    if (isPrivateOrReservedIp(parsed.directTarget)) {
      return {
        ok: false,
        domain,
        nameserversUsed: [],
        resolvedNsIps: [],
        ipv4Addresses: [],
        ipv6Addresses: [],
        message: 'Private or reserved IP targets are blocked.',
      };
    }
    return {
      ok: true,
      domain,
      nameserversUsed: [],
      resolvedNsIps: [],
      ipv4Addresses: [parsed.directTarget],
      ipv6Addresses: [],
      message: `Using direct Cloudflare IPv4 ${parsed.directTarget}.`,
    };
  }

  if (parsed.nameservers.length === 0 && parsed.directTarget) {
    try {
      const lookups = await dns.promises.lookup(parsed.directTarget, { all: true });
      const publicIps = lookups.map((l) => l.address).filter((ip) => !isPrivateOrReservedIp(ip));
      return {
        ok: publicIps.length > 0,
        domain,
        nameserversUsed: [parsed.directTarget],
        resolvedNsIps: [],
        ipv4Addresses: publicIps.filter((ip) => isValidIPv4(ip)),
        ipv6Addresses: publicIps.filter((ip) => isValidIPv6(ip)),
        message:
          publicIps.length > 0
            ? `Resolved ${parsed.directTarget} to ${publicIps.join(', ')}.`
            : `No public IPs returned for ${parsed.directTarget}.`,
      };
    } catch (err) {
      return {
        ok: false,
        domain,
        nameserversUsed: [],
        resolvedNsIps: [],
        ipv4Addresses: [],
        ipv6Addresses: [],
        message: err instanceof Error ? err.message : 'DNS lookup failed.',
      };
    }
  }

  if (parsed.nameservers.length === 0) {
    return {
      ok: false,
      domain,
      nameserversUsed: [],
      resolvedNsIps: [],
      ipv4Addresses: [],
      ipv6Addresses: [],
      message: 'No Cloudflare DNS nameservers configured.',
    };
  }

  const nsIps: string[] = [];
  for (const nsHost of parsed.nameservers) {
    if (!isValidHostname(nsHost)) continue;
    try {
      const res = await dns.promises.lookup(nsHost, { family: 4 });
      if (!isPrivateOrReservedIp(res.address) && !nsIps.includes(res.address)) {
        nsIps.push(res.address);
      }
    } catch {
      // Try remaining nameservers
    }
  }

  if (nsIps.length === 0) {
    return {
      ok: false,
      domain,
      nameserversUsed: parsed.nameservers,
      resolvedNsIps: [],
      ipv4Addresses: [],
      ipv6Addresses: [],
      message: `Could not resolve Cloudflare nameservers (${parsed.nameservers.join(', ')}).`,
    };
  }

  const resolver = new dns.promises.Resolver();
  resolver.setServers(nsIps);

  let ipv4Addresses: string[] = [];
  let ipv6Addresses: string[] = [];

  try {
    const v4 = await resolver.resolve4(domain);
    ipv4Addresses = v4.filter((ip) => !isPrivateOrReservedIp(ip));
  } catch {
    // Domain may only have AAAA or may not exist in that CF zone
  }

  try {
    const v6 = await resolver.resolve6(domain);
    ipv6Addresses = v6.filter((ip) => !isPrivateOrReservedIp(ip));
  } catch {
    // Ignore missing AAAA
  }

  const ok = ipv4Addresses.length > 0 || ipv6Addresses.length > 0;
  return {
    ok,
    domain,
    nameserversUsed: parsed.nameservers,
    resolvedNsIps: nsIps,
    ipv4Addresses,
    ipv6Addresses,
    message: ok
      ? `Resolved ${domain} via ${parsed.nameservers[0]} → ${[...ipv4Addresses, ...ipv6Addresses].join(', ')}`
      : `Cloudflare nameservers (${parsed.nameservers.join(', ')}) returned no A/AAAA records for ${domain}.`,
  };
}

interface CacheEntry {
  projectId: string;
  key: string;
  path: string;
  statusCode: number;
  contentType: string;
  headers: Record<string, string>;
  body: Buffer;
  storedAt: number;
  expiresAt: number;
  hits: number;
}

const MAX_CACHE_ENTRIES = 400;
const MAX_CACHE_ITEM_BYTES = 4 * 1024 * 1024;
const proxyCacheStore = new Map<string, CacheEntry>();

const STATIC_EXT_RE = /\.(?:js|mjs|css|png|jpg|jpeg|webp|avif|gif|svg|ico|woff|woff2|ttf|eot|map|json)$/i;
const SENSITIVE_PATH_RE = /^\/(?:api|auth|login|logout|admin|account|wp-admin|wp-login)(?:\/|$)/i;

function isCacheableResponse(reqPath: string, statusCode: number, headers: Record<string, string>): number | null {
  if (statusCode !== 200) return null;
  if (SENSITIVE_PATH_RE.test(reqPath)) return null;
  if (headers['set-cookie']) return null;

  const cc = (headers['cache-control'] || '').toLowerCase();
  if (cc.includes('no-store') || cc.includes('private') || cc.includes('no-cache')) {
    return null;
  }

  const maxAgeMatch = cc.match(/max-age=(\d+)/);
  if (maxAgeMatch) {
    const sec = Math.min(86400, Math.max(30, Number(maxAgeMatch[1])));
    return sec;
  }

  if (STATIC_EXT_RE.test(reqPath)) {
    return 3600;
  }

  return null;
}

function evictIfNeeded() {
  if (proxyCacheStore.size < MAX_CACHE_ENTRIES) return;
  const oldestKey = proxyCacheStore.keys().next().value;
  if (oldestKey) proxyCacheStore.delete(oldestKey);
}

export function getProjectCacheStats(projectId: string): {
  entries: number;
  totalBytes: number;
  totalHits: number;
  items: Array<{ path: string; contentType: string; bytes: number; hits: number; expiresAt: string }>;
} {
  const now = Date.now();
  let totalBytes = 0;
  let totalHits = 0;
  const items: Array<{ path: string; contentType: string; bytes: number; hits: number; expiresAt: string }> = [];

  for (const [k, entry] of proxyCacheStore.entries()) {
    if (entry.expiresAt <= now) {
      proxyCacheStore.delete(k);
      continue;
    }
    if (entry.projectId === projectId) {
      totalBytes += entry.body.length;
      totalHits += entry.hits;
      items.push({
        path: entry.path,
        contentType: entry.contentType,
        bytes: entry.body.length,
        hits: entry.hits,
        expiresAt: new Date(entry.expiresAt).toISOString(),
      });
    }
  }

  return {
    entries: items.length,
    totalBytes,
    totalHits,
    items,
  };
}

export function clearProjectCache(projectId: string): number {
  let removed = 0;
  for (const [key, entry] of proxyCacheStore.entries()) {
    if (entry.projectId === projectId) {
      proxyCacheStore.delete(key);
      removed += 1;
    }
  }
  return removed;
}

export interface ProxyFetchResult {
  ok: boolean;
  statusCode: number;
  cacheStatus: 'HIT' | 'MISS' | 'BYPASS';
  targetIp: string;
  cfRay: string;
  contentType: string;
  bytes: number;
  latencyMs: number;
  headers: Record<string, string>;
  setCookieHeaders: string[];
  body: Buffer;
  error?: string;
}

export async function proxyFetchThroughCloudflare(params: {
  projectId: string;
  domain: string;
  requestHost?: string;
  cloudflareTarget: string;
  reqPath?: string;
  method?: string;
  requestHeaders?: Record<string, string | string[] | undefined>;
  requestBody?: Buffer;
  bypassCache?: boolean;
}): Promise<ProxyFetchResult> {
  const start = Date.now();
  const domain = normalizeDomain(params.domain);
  const effectiveHost = normalizeDomain(params.requestHost || '') || domain;
  const reqPath = params.reqPath && params.reqPath.startsWith('/') ? params.reqPath : `/${params.reqPath || ''}`;
  const method = (params.method || 'GET').toUpperCase();
  const cacheKey = `${params.projectId}:${effectiveHost}:${reqPath}`;
  const hasCookies = Boolean(params.requestHeaders?.cookie || params.requestHeaders?.authorization);

  if (!params.bypassCache && !hasCookies && (method === 'GET' || method === 'HEAD')) {
    const cached = proxyCacheStore.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      cached.hits += 1;
      return {
        ok: true,
        statusCode: cached.statusCode,
        cacheStatus: 'HIT',
        targetIp: 'local-cache',
        cfRay: cached.headers['cf-ray'] || '',
        contentType: cached.contentType,
        bytes: cached.body.length,
        latencyMs: Date.now() - start,
        headers: cached.headers,
        setCookieHeaders: [],
        body: cached.body,
      };
    }
  }

  let resolution = await resolveViaCloudflareNameservers(effectiveHost, params.cloudflareTarget);
  if (!resolution.ok && effectiveHost !== domain) {
    resolution = await resolveViaCloudflareNameservers(domain, params.cloudflareTarget);
  }
  const targetIp = resolution.ipv4Addresses[0] || resolution.ipv6Addresses[0] || '';
  if (!targetIp || isPrivateOrReservedIp(targetIp)) {
    return {
      ok: false,
      statusCode: 502,
      cacheStatus: 'BYPASS',
      targetIp: '',
      cfRay: '',
      contentType: 'text/plain',
      bytes: 0,
      latencyMs: Date.now() - start,
      headers: {},
      setCookieHeaders: [],
      body: Buffer.alloc(0),
      error: resolution.message || 'Could not resolve public Cloudflare Edge IP.',
    };
  }

  const outboundHeaders: Record<string, string> = {
    Host: effectiveHost,
    'Accept-Encoding': 'identity',
    'x-forwarded-proto': 'https',
  };

  const hopByHopHeaders = new Set([
    'host',
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailers',
    'transfer-encoding',
    'upgrade',
    'accept-encoding',
    'content-length',
  ]);

  if (params.requestHeaders) {
    for (const [rawKey, val] of Object.entries(params.requestHeaders)) {
      const key = rawKey.toLowerCase();
      if (hopByHopHeaders.has(key) || !val) continue;
      outboundHeaders[key] = Array.isArray(val) ? val.join(', ') : String(val);
    }
  }

  if (!outboundHeaders['user-agent']) {
    outboundHeaders['user-agent'] = 'GeoRoute-Secure-Proxy/1.0';
  }
  if (!outboundHeaders.accept) {
    outboundHeaders.accept = '*/*';
  }

  if (params.requestBody && params.requestBody.length > 0) {
    outboundHeaders['content-length'] = String(params.requestBody.length);
  }

  return new Promise<ProxyFetchResult>((resolve) => {
    const req = https.request(
      {
        host: targetIp,
        port: 443,
        path: reqPath,
        method,
        servername: effectiveHost,
        timeout: 15000,
        headers: outboundHeaders,
      },
      (upstreamRes) => {
        const chunks: Buffer[] = [];
        let total = 0;

        upstreamRes.on('data', (chunk: Buffer) => {
          total += chunk.length;
          if (total <= MAX_CACHE_ITEM_BYTES * 4) {
            chunks.push(chunk);
          }
        });

        upstreamRes.on('end', () => {
          const body = Buffer.concat(chunks);
          const statusCode = upstreamRes.statusCode || 502;
          const cleanHeaders: Record<string, string> = {};
          const setCookieHeaders: string[] = [];

          for (const [k, v] of Object.entries(upstreamRes.headers)) {
            if (!v) continue;
            const lower = k.toLowerCase();
            if (lower === 'set-cookie') {
              if (Array.isArray(v)) setCookieHeaders.push(...v);
              else setCookieHeaders.push(String(v));
              continue;
            }
            cleanHeaders[lower] = Array.isArray(v) ? v.join(', ') : String(v);
          }

          const ttlSeconds =
            !hasCookies &&
            setCookieHeaders.length === 0 &&
            (method === 'GET' || method === 'HEAD') &&
            body.length <= MAX_CACHE_ITEM_BYTES
              ? isCacheableResponse(reqPath, statusCode, {
                  ...cleanHeaders,
                  ...(setCookieHeaders.length > 0 ? { 'set-cookie': '1' } : {}),
                })
              : null;

          let cacheStatus: 'HIT' | 'MISS' | 'BYPASS' = 'BYPASS';
          if (ttlSeconds !== null) {
            evictIfNeeded();
            proxyCacheStore.set(cacheKey, {
              projectId: params.projectId,
              key: cacheKey,
              path: reqPath,
              statusCode,
              contentType: cleanHeaders['content-type'] || 'application/octet-stream',
              headers: cleanHeaders,
              body,
              storedAt: Date.now(),
              expiresAt: Date.now() + ttlSeconds * 1000,
              hits: 0,
            });
            cacheStatus = 'MISS';
          }

          resolve({
            ok: statusCode < 500,
            statusCode,
            cacheStatus,
            targetIp,
            cfRay: cleanHeaders['cf-ray'] || '',
            contentType: cleanHeaders['content-type'] || '',
            bytes: body.length,
            latencyMs: Date.now() - start,
            headers: cleanHeaders,
            setCookieHeaders,
            body,
          });
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error('Upstream Cloudflare connection timed out.'));
    });

    req.on('error', (err) => {
      resolve({
        ok: false,
        statusCode: 502,
        cacheStatus: 'BYPASS',
        targetIp,
        cfRay: '',
        contentType: 'text/plain',
        bytes: 0,
        latencyMs: Date.now() - start,
        headers: {},
        setCookieHeaders: [],
        body: Buffer.alloc(0),
        error: err.message,
      });
    });

    if (params.requestBody && params.requestBody.length > 0) {
      req.write(params.requestBody);
    }
    req.end();
  });
}

function readRequestBody(req: Request): Promise<Buffer> {
  return new Promise((resolve) => {
    if (req.method === 'GET' || req.method === 'HEAD') {
      return resolve(Buffer.alloc(0));
    }
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size <= 10 * 1024 * 1024) {
        chunks.push(chunk);
      }
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', () => resolve(Buffer.alloc(0)));
  });
}

export function createHostProxyMiddleware(db: DatabaseSync) {
  const adminHost = normalizeDomain(process.env.PANEL_HOSTNAME || '');

  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith('/__georoute')) {
      return next();
    }

    const rawHostHeader = String(req.headers['x-forwarded-host'] || req.headers.host || '')
      .split(',')[0]
      .trim();
    const reqHost = normalizeDomain(rawHostHeader.split(':')[0] || '');
    if (!reqHost || (adminHost && reqHost === adminHost)) {
      return next();
    }

    const apexCandidate = reqHost.replace(/^www\./, '');
    const row = db
      .prepare('SELECT id, domain, cloudflare_target, notes FROM projects WHERE domain IN (?, ?) LIMIT 1')
      .get(reqHost, apexCandidate) as
      | { id: string; domain: string; cloudflare_target: string; notes: string }
      | undefined;

    if (!row || !row.cloudflare_target || !row.notes.includes('proxy_active=true')) {
      return next();
    }

    const requestBody = await readRequestBody(req);
    const result = await proxyFetchThroughCloudflare({
      projectId: row.id,
      domain: row.domain,
      requestHost: reqHost,
      cloudflareTarget: row.cloudflare_target,
      reqPath: req.originalUrl,
      method: req.method,
      requestHeaders: req.headers,
      requestBody,
    });

    if (!result.ok && result.body.length === 0) {
      return res.status(502).send(result.error || 'Upstream Cloudflare proxy error.');
    }

    const skipHeaders = new Set(['transfer-encoding', 'content-length', 'connection']);
    for (const [k, v] of Object.entries(result.headers)) {
      if (!skipHeaders.has(k)) {
        res.setHeader(k, v);
      }
    }
    if (result.setCookieHeaders.length > 0) {
      res.setHeader('set-cookie', result.setCookieHeaders);
    }
    res.setHeader('X-GeoRoute-Cache', result.cacheStatus);
    return res.status(result.statusCode).send(result.body);
  };
}
