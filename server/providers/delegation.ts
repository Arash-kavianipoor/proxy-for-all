import dns from 'node:dns/promises';
import { normalizeDomain } from '../security.ts';
import type { DelegationStatus } from './types.ts';

export async function checkDnsDelegation(
  domain: string,
  expectedNameservers: string[] = []
): Promise<DelegationStatus> {
  const cleanDomain = normalizeDomain(domain);
  const normalizedExpected = expectedNameservers
    .map((ns) => normalizeDomain(ns))
    .filter(Boolean);
  const checkedAt = new Date().toISOString();

  try {
    const observedRaw = await dns.resolveNs(cleanDomain);
    const observed = observedRaw.map((ns) => normalizeDomain(ns)).sort();

    if (normalizedExpected.length === 0) {
      return {
        domain: cleanDomain,
        status: 'not_checked',
        expectedNameservers: [],
        observedNameservers: observed,
        checkedAt,
        message: observed.length
          ? `Observed ${observed.length} authoritative nameserver(s), but no target GeoDNS nameservers are assigned yet to compare against.`
          : 'No authoritative NS records resolved yet.',
      };
    }

    const expectedSet = new Set(normalizedExpected);
    const allMatch =
      observed.length > 0 &&
      normalizedExpected.every((ns) => observed.includes(ns)) &&
      observed.every((ns) => expectedSet.has(ns));

    if (allMatch) {
      return {
        domain: cleanDomain,
        status: 'verified',
        expectedNameservers: normalizedExpected,
        observedNameservers: observed,
        checkedAt,
        message: 'Authoritative NS records match the GeoDNS provider nameservers.',
      };
    }

    const partialOverlap = observed.some((ns) => expectedSet.has(ns));
    return {
      domain: cleanDomain,
      status: partialOverlap ? 'mismatch' : 'waiting_delegation',
      expectedNameservers: normalizedExpected,
      observedNameservers: observed,
      checkedAt,
      message: partialOverlap
        ? 'Partial nameserver match detected — delegation may still be propagating or misconfigured at IRNIC.'
        : `Domain currently delegates to [${observed.join(', ')}] instead of provider nameservers [${normalizedExpected.join(', ')}].`,
    };
  } catch (err) {
    const code = err && typeof err === 'object' && 'code' in err ? String(err.code) : 'DNS_ERROR';
    return {
      domain: cleanDomain,
      status: normalizedExpected.length > 0 ? 'waiting_delegation' : 'not_checked',
      expectedNameservers: normalizedExpected,
      observedNameservers: [],
      checkedAt,
      message: `NS lookup for ${cleanDomain} returned ${code}. Delegation is not active or domain has no public NS records yet.`,
    };
  }
}
