import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import tls from 'node:tls';
import { checkDnsDelegation } from './providers/delegation.ts';
import type { GeoDnsProvider } from './providers/types.ts';
import { assertSafePublicUrl, normalizeDomain } from './security.ts';
import type {
  DiagnosticCheckRecord,
  DiagnosticStatus,
  Project,
  RoutingRule,
} from '../src/types/georoute.ts';

export function getDiagnosticsLocationLabel(): string {
  return (
    process.env.DIAGNOSTICS_LOCATION_LABEL?.trim() ||
    'Control Plane Backend (External / Outside Iran — does NOT validate Iran-local reachability)'
  );
}

async function inspectTlsCertificate(
  hostname: string,
  port = 443
): Promise<{
  status: DiagnosticStatus;
  summary: string;
  details: Record<string, unknown>;
}> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: true,
        timeout: 8000,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          const authorized = socket.authorized;
          socket.end();

          if (!cert || !cert.valid_to) {
            resolve({
              status: 'warning',
              summary: 'TLS handshake completed, but peer certificate metadata was unavailable.',
              details: { hostname, port, authorized },
            });
            return;
          }

          const expiresAt = new Date(cert.valid_to);
          const daysRemaining = Math.floor((expiresAt.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
          const status: DiagnosticStatus = !authorized
            ? 'failed'
            : daysRemaining < 14
              ? 'warning'
              : 'passed';

          resolve({
            status,
            summary: authorized
              ? `Valid TLS certificate for ${hostname} (expires in ${daysRemaining} day(s) on ${expiresAt.toISOString().slice(0, 10)}).`
              : `TLS certificate verification failed for ${hostname}.`,
            details: {
              hostname,
              port,
              authorized,
              subject: cert.subject,
              issuer: cert.issuer,
              validFrom: cert.valid_from,
              validTo: cert.valid_to,
              daysRemaining,
              subjectAltName: cert.subjectaltname,
            },
          });
        } catch (err) {
          socket.destroy();
          resolve({
            status: 'failed',
            summary: `TLS inspection error for ${hostname}: ${err instanceof Error ? err.message : 'Unknown'}`,
            details: { hostname, port },
          });
        }
      }
    );

    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        status: 'failed',
        summary: `TLS connection to ${hostname}:${port} timed out after 8000ms.`,
        details: { hostname, port, timeoutMs: 8000 },
      });
    });

    socket.on('error', (err) => {
      socket.destroy();
      resolve({
        status: 'failed',
        summary: `TLS connection to ${hostname}:${port} failed: ${err.message}`,
        details: { hostname, port, error: err.message },
      });
    });
  });
}

async function inspectHttpEndpoint(rawUrl: string): Promise<{
  status: DiagnosticStatus;
  summary: string;
  details: Record<string, unknown>;
}> {
  let safeUrl: URL;
  try {
    safeUrl = await assertSafePublicUrl(rawUrl);
  } catch (err) {
    return {
      status: 'failed',
      summary: `Blocked unsafe target URL: ${err instanceof Error ? err.message : 'Invalid URL'}`,
      details: { target: rawUrl },
    };
  }

  const redirects: string[] = [];
  let current = safeUrl.toString();
  let finalResponse: Response | null = null;
  const startedAt = Date.now();

  try {
    for (let hop = 0; hop < 5; hop += 1) {
      const checkedUrl = await assertSafePublicUrl(current);
      const res = await fetch(checkedUrl.toString(), {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(10000),
      });

      if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
        const nextUrl = new URL(res.headers.get('location')!, checkedUrl).toString();
        redirects.push(`${res.status} -> ${nextUrl}`);
        current = nextUrl;
        continue;
      }

      finalResponse = res;
      break;
    }

    const elapsedMs = Date.now() - startedAt;
    if (!finalResponse) {
      return {
        status: 'warning',
        summary: `Exceeded 5 redirect hops checking ${safeUrl.hostname}.`,
        details: { redirects, elapsedMsFromBackend: elapsedMs },
      };
    }

    const headersObj: Record<string, string> = {};
    for (const key of [
      'server',
      'cache-control',
      'cf-cache-status',
      'cf-ray',
      'etag',
      'last-modified',
      'vary',
      'content-type',
      'set-cookie',
      'strict-transport-security',
    ]) {
      const v = finalResponse.headers.get(key);
      if (v) headersObj[key] = key === 'set-cookie' ? '[PRESENT - redacted]' : v;
    }

    const statusOk = finalResponse.status >= 200 && finalResponse.status < 400;
    return {
      status: statusOk ? 'passed' : 'warning',
      summary: `HTTP ${finalResponse.status} from ${current} in ${elapsedMs}ms (measured from backend outside Iran).`,
      details: {
        finalUrl: current,
        httpStatus: finalResponse.status,
        redirects,
        elapsedMsFromBackend: elapsedMs,
        headers: headersObj,
      },
    };
  } catch (err) {
    return {
      status: 'failed',
      summary: `HTTP probe failed for ${safeUrl.toString()}: ${err instanceof Error ? err.message : 'Request failed'}`,
      details: { target: safeUrl.toString(), redirects },
    };
  }
}

export async function runProjectDiagnostics(params: {
  project: Project;
  routingRules: RoutingRule[];
  provider: GeoDnsProvider;
  expectedNameservers: string[];
  hasProviderAccount: boolean;
}): Promise<DiagnosticCheckRecord[]> {
  const { project, routingRules, provider, expectedNameservers, hasProviderAccount } = params;
  const location = getDiagnosticsLocationLabel();
  const checkedAt = new Date().toISOString();
  const checks: DiagnosticCheckRecord[] = [];
  const cleanDomain = normalizeDomain(project.domain);

  // 1. Provider credentials & zone
  if (!hasProviderAccount || project.geoDnsProvider === 'manual') {
    checks.push({
      id: crypto.randomUUID(),
      projectId: project.id,
      checkCategory: 'provider_credentials',
      target: project.geoDnsProvider,
      status: 'warning',
      testLocation: location,
      summary: 'Manual provider mode or no GeoDNS API account linked; automated provider checks skipped.',
      technicalDetails: { provider: project.geoDnsProvider },
      checkedAt,
    });
  } else {
    const val = await provider.validateCredentials();
    checks.push({
      id: crypto.randomUUID(),
      projectId: project.id,
      checkCategory: 'provider_credentials',
      target: project.geoDnsProvider,
      status: val.valid ? 'passed' : 'failed',
      testLocation: location,
      summary: val.message,
      technicalDetails: { provider: project.geoDnsProvider, accountInfo: val.accountInfo || null },
      checkedAt,
    });
  }

  // 2. Authoritative NS delegation
  const delegation = await checkDnsDelegation(cleanDomain, expectedNameservers);
  checks.push({
    id: crypto.randomUUID(),
    projectId: project.id,
    checkCategory: 'ns_delegation',
    target: cleanDomain,
    status:
      delegation.status === 'verified'
        ? 'passed'
        : delegation.status === 'not_checked'
          ? 'warning'
          : delegation.status === 'mismatch'
            ? 'failed'
            : 'warning',
    testLocation: location,
    summary: delegation.message,
    technicalDetails: {
      expectedNameservers: delegation.expectedNameservers,
      observedNameservers: delegation.observedNameservers,
      delegationStatus: delegation.status,
    },
    checkedAt,
  });

  // 3. Public DNS resolution (A / AAAA / CNAME) from backend resolver
  const [aRes, aaaaRes, cnameRes] = await Promise.allSettled([
    dns.resolve4(cleanDomain),
    dns.resolve6(cleanDomain),
    dns.resolveCname(cleanDomain),
  ]);
  const aRecords = aRes.status === 'fulfilled' ? aRes.value : [];
  const aaaaRecords = aaaaRes.status === 'fulfilled' ? aaaaRes.value : [];
  const cnameRecords = cnameRes.status === 'fulfilled' ? cnameRes.value : [];
  const hasAnyDns = aRecords.length > 0 || aaaaRecords.length > 0 || cnameRecords.length > 0;

  checks.push({
    id: crypto.randomUUID(),
    projectId: project.id,
    checkCategory: 'dns_resolution',
    target: cleanDomain,
    status: hasAnyDns ? 'passed' : 'warning',
    testLocation: location,
    summary: hasAnyDns
      ? `Resolved from external backend (${aRecords.length} A, ${aaaaRecords.length} AAAA, ${cnameRecords.length} CNAME). External lookup reflects non-Iran resolver view only.`
      : `No A/AAAA/CNAME records currently resolve for ${cleanDomain}.`,
    technicalDetails: { aRecords, aaaaRecords, cnameRecords },
    checkedAt,
  });

  // 4. Routing policy consistency (Iran rule + Global fallback)
  const enabledRules = routingRules.filter((r) => r.enabled);
  const irRules = enabledRules.filter((r) => r.regionCode === 'IR');
  const defaultRules = enabledRules.filter((r) => r.regionCode === 'DEFAULT' || r.regionCode === 'FALLBACK');

  checks.push({
    id: crypto.randomUUID(),
    projectId: project.id,
    checkCategory: 'routing_policy_iran',
    target: `${cleanDomain} (IR)`,
    status: irRules.length > 0 ? 'passed' : 'warning',
    testLocation: location,
    summary:
      irRules.length > 0
        ? `${irRules.length} Iran (IR) routing rule(s) configured. Note: real Iranian ISP/recursive-resolver behavior cannot be proven from outside Iran.`
        : 'No enabled Iran (IR) routing rule configured yet.',
    technicalDetails: { rules: irRules.map((r) => ({ hostname: r.hostname, type: r.recordType, destination: r.destination, ttl: r.ttl })) },
    checkedAt,
  });

  checks.push({
    id: crypto.randomUUID(),
    projectId: project.id,
    checkCategory: 'routing_policy_global',
    target: `${cleanDomain} (DEFAULT)`,
    status: defaultRules.length > 0 ? 'passed' : 'failed',
    testLocation: location,
    summary:
      defaultRules.length > 0
        ? `${defaultRules.length} Global/Default fallback rule(s) active.`
        : 'Missing active Global/Default fallback rule. International visitors and fallback queries require a Cloudflare default route.',
    technicalDetails: { rules: defaultRules.map((r) => ({ hostname: r.hostname, type: r.recordType, destination: r.destination, ttl: r.ttl })) },
    checkedAt,
  });

  // 5. Cloudflare destination HTTP & TLS reachability
  const cfProbeTarget =
    project.healthCheckUrl?.trim() ||
    (project.cloudflareTarget?.trim().startsWith('http')
      ? project.cloudflareTarget.trim()
      : `https://${cleanDomain}`);

  if (cfProbeTarget) {
    try {
      const parsed = await assertSafePublicUrl(cfProbeTarget);
      const [tlsRes, httpRes] = await Promise.all([
        inspectTlsCertificate(parsed.hostname, parsed.port ? Number(parsed.port) : 443),
        inspectHttpEndpoint(parsed.toString()),
      ]);

      checks.push({
        id: crypto.randomUUID(),
        projectId: project.id,
        checkCategory: 'tls_certificate',
        target: parsed.hostname,
        status: tlsRes.status,
        testLocation: location,
        summary: tlsRes.summary,
        technicalDetails: tlsRes.details,
        checkedAt,
      });

      checks.push({
        id: crypto.randomUUID(),
        projectId: project.id,
        checkCategory: 'cloudflare_http_reachability',
        target: parsed.toString(),
        status: httpRes.status,
        testLocation: location,
        summary: httpRes.summary,
        technicalDetails: httpRes.details,
        checkedAt,
      });
    } catch (err) {
      checks.push({
        id: crypto.randomUUID(),
        projectId: project.id,
        checkCategory: 'cloudflare_http_reachability',
        target: cfProbeTarget,
        status: 'failed',
        testLocation: location,
        summary: err instanceof Error ? err.message : 'Invalid target URL',
        technicalDetails: { target: cfProbeTarget },
        checkedAt,
      });
    }
  }

  // 6. Iran proxy reachability (only if configured; never fabricate Iran-internal perspective)
  const proxyTarget = project.iranProxyHostname?.trim() || project.iranProxyIPv4?.trim();
  if (!proxyTarget) {
    checks.push({
      id: crypto.randomUUID(),
      projectId: project.id,
      checkCategory: 'iran_proxy_reachability',
      target: 'Not configured',
      status: 'not_tested',
      testLocation: location,
      summary: 'Iran proxy hostname/IPv4 is not configured yet.',
      technicalDetails: {},
      checkedAt,
    });
  } else {
    const proxyUrl = proxyTarget.startsWith('http') ? proxyTarget : `https://${proxyTarget}`;
    const httpRes = await inspectHttpEndpoint(proxyUrl);
    checks.push({
      id: crypto.randomUUID(),
      projectId: project.id,
      checkCategory: 'iran_proxy_reachability',
      target: proxyUrl,
      status: httpRes.status,
      testLocation: location,
      summary: `${httpRes.summary} (Note: external probe only; verify from inside an Iranian ISP network before enabling IR DNS.)`,
      technicalDetails: httpRes.details,
      checkedAt,
    });
  }

  return checks;
}
