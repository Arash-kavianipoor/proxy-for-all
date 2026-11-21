import dns from 'node:dns/promises';
import net from 'node:net';
import type { NextFunction, Request, Response } from 'express';

const DOMAIN_REGEX = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const HOSTNAME_REGEX = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

export function normalizeDomain(domain: string): string {
  return domain.trim().toLowerCase().replace(/\.$/, '');
}

export function isValidDomain(domain: string): boolean {
  const clean = normalizeDomain(domain);
  return DOMAIN_REGEX.test(clean);
}

export function isValidHostname(hostname: string): boolean {
  const clean = normalizeDomain(hostname);
  if (clean === '@') return true;
  return HOSTNAME_REGEX.test(clean);
}

export function isValidIPv4(ip: string): boolean {
  return net.isIPv4(ip.trim());
}

export function isValidIPv6(ip: string): boolean {
  return net.isIPv6(ip.trim());
}

export function isPrivateOrReservedIp(ip: string): boolean {
  const trimmed = ip.trim().toLowerCase();
  if (net.isIPv4(trimmed)) {
    const parts = trimmed.split('.').map(Number);
    const [a, b] = parts;
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 127) return true; // 127.0.0.0/8 loopback
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
    if (a >= 224) return true; // multicast / reserved
    return false;
  }

  if (net.isIPv6(trimmed)) {
    if (trimmed === '::' || trimmed === '::1') return true;
    if (trimmed.startsWith('fc') || trimmed.startsWith('fd')) return true; // ULA fc00::/7
    if (trimmed.startsWith('fe8') || trimmed.startsWith('fe9') || trimmed.startsWith('fea') || trimmed.startsWith('feb')) {
      return true; // link-local fe80::/10
    }
    if (trimmed.startsWith('::ffff:')) {
      const mapped = trimmed.replace('::ffff:', '');
      if (net.isIPv4(mapped)) return isPrivateOrReservedIp(mapped);
    }
    return false;
  }

  return true;
}

export async function assertSafePublicUrl(rawUrl: string): Promise<URL> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    throw new Error('Invalid URL syntax.');
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error('Only HTTP and HTTPS target URLs are permitted.');
  }

  const host = parsed.hostname.toLowerCase();
  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host === 'metadata.google.internal'
  ) {
    throw new Error('Localhost and internal hostnames are blocked for SSRF protection.');
  }

  if (net.isIP(host)) {
    if (isPrivateOrReservedIp(host)) {
      throw new Error('Private, loopback, or link-local IP addresses are blocked.');
    }
    return parsed;
  }

  if (!isValidDomain(host)) {
    throw new Error('Target URL must reference a valid public domain name.');
  }

  try {
    const [v4, v6] = await Promise.allSettled([dns.resolve4(host), dns.resolve6(host)]);
    const resolvedIps: string[] = [];
    if (v4.status === 'fulfilled') resolvedIps.push(...v4.value);
    if (v6.status === 'fulfilled') resolvedIps.push(...v6.value);
    for (const ip of resolvedIps) {
      if (isPrivateOrReservedIp(ip)) {
        throw new Error(`DNS resolution for ${host} returned a private/reserved address (${ip}), blocked for DNS-rebinding safety.`);
      }
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes('blocked')) {
      throw err;
    }
    // If DNS cannot resolve yet, the diagnostic check itself will report NXDOMAIN safely
  }

  return parsed;
}

interface RateBucket {
  count: number;
  resetAt: number;
}

export function createRateLimiter(options: { windowMs: number; maxRequests: number; name: string }) {
  const buckets = new Map<string, RateBucket>();

  return (req: Request, res: Response, next: NextFunction) => {
    const key = `${options.name}:${req.ip || 'unknown'}`;
    const now = Date.now();
    const existing = buckets.get(key);

    if (!existing || now > existing.resetAt) {
      buckets.set(key, { count: 1, resetAt: now + options.windowMs });
      return next();
    }

    if (existing.count >= options.maxRequests) {
      const retryAfter = Math.ceil((existing.resetAt - now) / 1000);
      res.setHeader('Retry-After', String(retryAfter));
      return res.status(429).json({
        error: 'Rate limit exceeded. Please wait before retrying.',
        retryAfterSeconds: retryAfter,
      });
    }

    existing.count += 1;
    return next();
  };
}
