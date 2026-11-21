import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import { sha256Hex } from './crypto.ts';
import { PROVIDER_CAPABILITIES } from './providers/capabilities.ts';
import type { GeoDnsProvider } from './providers/types.ts';
import { isValidIPv4, isValidIPv6, normalizeDomain } from './security.ts';
import type {
  DeploymentPreview,
  DnsDiffItem,
  DnsRecordType,
  GeoDnsRecord,
  Project,
  RegionCode,
  RoutingRule,
} from '../src/types/georoute.ts';

function normalizeFqdn(domain: string, hostname: string): string {
  const cleanDomain = normalizeDomain(domain);
  const cleanHost = normalizeDomain(hostname);
  if (!cleanHost || cleanHost === '@' || cleanHost === cleanDomain) return cleanDomain;
  if (cleanHost.endsWith(`.${cleanDomain}`)) return cleanHost;
  return `${cleanHost}.${cleanDomain}`;
}

export function validateRoutingRuleDestination(
  recordType: DnsRecordType,
  destination: string
): string | null {
  const val = destination.trim();
  if (!val) return 'Destination cannot be empty.';
  if (recordType === 'A' && !isValidIPv4(val)) {
    return `A record destination "${val}" is not a valid IPv4 address.`;
  }
  if (recordType === 'AAAA' && !isValidIPv6(val)) {
    return `AAAA record destination "${val}" is not a valid IPv6 address.`;
  }
  return null;
}

export async function buildDeploymentPreview(params: {
  project: Project;
  provider: GeoDnsProvider;
  providerAccountId: string | null;
  zoneId: string;
  routingRules: RoutingRule[];
}): Promise<DeploymentPreview> {
  const { project, provider, providerAccountId, zoneId, routingRules } = params;
  const capabilities = await provider.getCapabilities();
  const manualMode = project.geoDnsProvider === 'manual' || !providerAccountId;

  let currentRecords: GeoDnsRecord[] = [];
  let authoritativeNameservers: string[] = [];
  const warnings: string[] = [];
  const conflicts: string[] = [];

  if (!manualMode && zoneId) {
    try {
      const zone = await provider.getZone(zoneId);
      authoritativeNameservers = zone.nameservers || [];
      currentRecords = await provider.listRecords(zoneId);
    } catch (err) {
      warnings.push(
        `Could not fetch live zone records from ${capabilities.displayName}: ${
          err instanceof Error ? err.message : 'Unknown error'
        }`
      );
    }
  } else {
    warnings.push(
      'Manual Provider Setup mode is active. This preview shows proposed records to configure manually; automated deployment is disabled.'
    );
  }

  const enabledRules = routingRules.filter((r) => r.enabled);
  const hasIranRule = enabledRules.some((r) => r.regionCode === 'IR');
  const hasDefaultRule = enabledRules.some((r) => r.regionCode === 'DEFAULT' || r.regionCode === 'FALLBACK');

  if (!hasDefaultRule) {
    conflicts.push(
      'Missing active Global/Default fallback routing rule. A safe global Cloudflare fallback route is mandatory before deployment.'
    );
  }
  if (!hasIranRule) {
    warnings.push(
      'No enabled Iran (IR) routing rule is active. Visitors in Iran will fall back to the Global/Default route until an Iran rule is enabled.'
    );
  }

  // Group rules by hostname to detect CNAME conflicts and apex CNAME issues
  const rulesByHost = new Map<string, RoutingRule[]>();
  for (const rule of enabledRules) {
    const fqdn = normalizeFqdn(project.domain, rule.hostname);
    const list = rulesByHost.get(fqdn) || [];
    list.push(rule);
    rulesByHost.set(fqdn, list);
  }

  let apexSupported = true;
  const changes: DnsDiffItem[] = [];

  for (const [fqdn, hostRules] of rulesByHost.entries()) {
    const isApex = fqdn === normalizeDomain(project.domain);
    const types = new Set(hostRules.map((r) => r.recordType));

    if (types.has('CNAME') && types.size > 1) {
      conflicts.push(
        `Conflicting record types on ${fqdn}: CNAME cannot coexist with other record types at the same hostname.`
      );
    }

    if (isApex && types.has('CNAME')) {
      apexSupported = false;
      conflicts.push(
        `Apex domain ${fqdn} cannot use a standard CNAME record. Use A/AAAA or an ALIAS record (if supported by ${capabilities.displayName}).`
      );
    }

    for (const rule of hostRules) {
      if (!capabilities.supportedRecordTypes.includes(rule.recordType)) {
        conflicts.push(
          `Provider ${capabilities.displayName} does not support ${rule.recordType} records for GeoDNS routing (${fqdn}).`
        );
      }

      if (rule.ttl < capabilities.minTtlSeconds || rule.ttl > capabilities.maxTtlSeconds) {
        warnings.push(
          `TTL ${rule.ttl}s on ${fqdn} (${rule.regionCode}) is outside ${capabilities.displayName} range (${capabilities.minTtlSeconds}s–${capabilities.maxTtlSeconds}s).`
        );
      }

      const destError = validateRoutingRuleDestination(rule.recordType, rule.destination);
      if (destError) {
        conflicts.push(`${fqdn} (${rule.regionCode}): ${destError}`);
      }

      const existing = currentRecords.find(
        (rec) =>
          normalizeDomain(rec.hostname) === fqdn &&
          rec.type === rule.recordType &&
          (rec.regionCode === rule.regionCode ||
            (rule.regionCode === 'FALLBACK' && rec.regionCode === 'DEFAULT'))
      );

      // Check existing CNAME conflicts in live zone
      const liveConflict = currentRecords.find(
        (rec) =>
          normalizeDomain(rec.hostname) === fqdn &&
          rec.type !== 'NS' &&
          rec.type !== 'SOA' &&
          ((rule.recordType === 'CNAME' && rec.type !== 'CNAME') ||
            (rule.recordType !== 'CNAME' && rec.type === 'CNAME'))
      );

      if (liveConflict) {
        changes.push({
          operation: 'conflict',
          hostname: fqdn,
          regionCode: rule.regionCode as RegionCode,
          recordType: rule.recordType,
          currentValue: `${liveConflict.type} -> ${liveConflict.value}`,
          proposedValue: rule.destination,
          ttl: rule.ttl,
          conflictReason: `Existing ${liveConflict.type} record on ${fqdn} conflicts with proposed ${rule.recordType} record.`,
          existingRecordId: liveConflict.id,
        });
        conflicts.push(`Live zone conflict on ${fqdn}: existing ${liveConflict.type} conflicts with ${rule.recordType}.`);
        continue;
      }

      if (!existing) {
        changes.push({
          operation: 'create',
          hostname: fqdn,
          regionCode: rule.regionCode as RegionCode,
          recordType: rule.recordType,
          currentValue: '',
          proposedValue: rule.destination,
          ttl: rule.ttl,
        });
      } else if (existing.value !== rule.destination || existing.ttl !== rule.ttl) {
        changes.push({
          operation: 'update',
          hostname: fqdn,
          regionCode: rule.regionCode as RegionCode,
          recordType: rule.recordType,
          currentValue: existing.value,
          proposedValue: rule.destination,
          ttl: rule.ttl,
          existingRecordId: existing.id,
        });
      } else {
        changes.push({
          operation: 'unchanged',
          hostname: fqdn,
          regionCode: rule.regionCode as RegionCode,
          recordType: rule.recordType,
          currentValue: existing.value,
          proposedValue: rule.destination,
          ttl: rule.ttl,
          existingRecordId: existing.id,
        });
      }
    }
  }

  if (changes.length === 0) {
    warnings.push('No enabled routing rules are configured yet.');
  }

  const canonicalPayload = JSON.stringify({
    projectId: project.id,
    domain: project.domain,
    provider: project.geoDnsProvider,
    zoneId,
    changes: changes.map((c) => ({
      operation: c.operation,
      hostname: c.hostname,
      regionCode: c.regionCode,
      recordType: c.recordType,
      proposedValue: c.proposedValue,
      ttl: c.ttl,
    })),
  });
  const previewHash = sha256Hex(canonicalPayload);

  const canDeploy =
    !manualMode &&
    Boolean(zoneId) &&
    conflicts.length === 0 &&
    changes.some((c) => c.operation === 'create' || c.operation === 'update');

  return {
    previewHash,
    projectId: project.id,
    domain: project.domain,
    providerName: project.geoDnsProvider,
    providerAccountId,
    zoneId,
    authoritativeNameservers,
    currentRecords,
    changes,
    warnings,
    conflicts,
    canDeploy,
    manualMode,
    apexSupported,
    dnssecReminder:
      'Before updating nameservers at IRNIC, verify DNSSEC/DS records. Leaving an old DS record at IRNIC after changing nameservers will break DNS resolution globally.',
    generatedAt: new Date().toISOString(),
  };
}

export async function executeDnsDeployment(params: {
  db: DatabaseSync;
  project: Project;
  provider: GeoDnsProvider;
  providerAccountId: string | null;
  preview: DeploymentPreview;
  actorId: string;
}): Promise<{
  jobId: string;
  status: 'confirmed' | 'partial_failure' | 'failed' | 'manual_pending';
  summary: string;
  operationIds: string[];
}> {
  const { db, project, provider, providerAccountId, preview, actorId } = params;
  const jobId = crypto.randomUUID();
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO dns_deployment_jobs
      (id, project_id, provider_account_id, zone_id, preview_hash, status, summary, provider_operation_id, confirmed_by, confirmed_at, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, 'deploying', '', '', ?, ?, ?, ?)
  `).run(
    jobId,
    project.id,
    providerAccountId,
    preview.zoneId || project.domain,
    preview.previewHash,
    actorId,
    now,
    now,
    now
  );

  const insertChange = db.prepare(`
    INSERT INTO dns_deployment_changes
      (id, job_id, operation, hostname, region_code, record_type, current_value, proposed_value, ttl, result_status, error_message)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  if (preview.manualMode) {
    for (const c of preview.changes) {
      insertChange.run(
        crypto.randomUUID(),
        jobId,
        c.operation,
        c.hostname,
        c.regionCode,
        c.recordType,
        c.currentValue,
        c.proposedValue,
        c.ttl,
        'skipped',
        'Manual mode: operator must apply changes in external DNS panel'
      );
    }
    const summary = 'Manual configuration plan recorded. No automated provider API writes were executed.';
    db.prepare(`UPDATE dns_deployment_jobs SET status = 'manual_pending', summary = ?, updated_at = ? WHERE id = ?`).run(
      summary,
      new Date().toISOString(),
      jobId
    );
    return { jobId, status: 'manual_pending', summary, operationIds: [] };
  }

  const actionable = preview.changes.filter((c) => c.operation === 'create' || c.operation === 'update');
  const operationIds: string[] = [];
  let succeeded = 0;
  let failed = 0;

  // For NS1, group IR + DEFAULT answers for the same (hostname, recordType) so Filter Chain carries both answers
  if (project.geoDnsProvider === 'ns1') {
    const grouped = new Map<string, DnsDiffItem[]>();
    for (const item of actionable) {
      const key = `${item.hostname}:${item.recordType}`;
      const arr = grouped.get(key) || [];
      arr.push(item);
      grouped.set(key, arr);
    }

    for (const [, items] of grouped.entries()) {
      const primary = items[0];
      const irItem = items.find((i) => i.regionCode === 'IR');
      const defItem = items.find((i) => i.regionCode === 'DEFAULT' || i.regionCode === 'FALLBACK');
      const isUpdate = items.some((i) => i.operation === 'update');

      try {
        const input = {
          hostname: primary.hostname,
          type: primary.recordType,
          value: defItem?.proposedValue || irItem?.proposedValue || primary.proposedValue,
          ttl: primary.ttl,
          regionCode: primary.regionCode,
          iranValue: irItem?.proposedValue,
          defaultValue: defItem?.proposedValue,
        };
        const res = isUpdate
          ? await provider.updateRecord(preview.zoneId, primary.existingRecordId || `${primary.hostname}:${primary.recordType}`, input)
          : await provider.createRecord(preview.zoneId, input);
        if (res.operationId) operationIds.push(res.operationId);
        for (const item of items) {
          succeeded += 1;
          insertChange.run(
            crypto.randomUUID(),
            jobId,
            item.operation,
            item.hostname,
            item.regionCode,
            item.recordType,
            item.currentValue,
            item.proposedValue,
            item.ttl,
            'applied',
            ''
          );
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Provider write failed';
        for (const item of items) {
          failed += 1;
          insertChange.run(
            crypto.randomUUID(),
            jobId,
            item.operation,
            item.hostname,
            item.regionCode,
            item.recordType,
            item.currentValue,
            item.proposedValue,
            item.ttl,
            'failed',
            msg
          );
        }
      }
    }
  } else {
    for (const item of actionable) {
      try {
        const input = {
          hostname: item.hostname,
          type: item.recordType,
          value: item.proposedValue,
          ttl: item.ttl,
          regionCode: item.regionCode,
        };
        const res =
          item.operation === 'update' && item.existingRecordId
            ? await provider.updateRecord(preview.zoneId, item.existingRecordId, input)
            : await provider.createRecord(preview.zoneId, input);
        if (res.operationId) operationIds.push(res.operationId);
        succeeded += 1;
        insertChange.run(
          crypto.randomUUID(),
          jobId,
          item.operation,
          item.hostname,
          item.regionCode,
          item.recordType,
          item.currentValue,
          item.proposedValue,
          item.ttl,
          'applied',
          ''
        );
      } catch (err) {
        failed += 1;
        insertChange.run(
          crypto.randomUUID(),
          jobId,
          item.operation,
          item.hostname,
          item.regionCode,
          item.recordType,
          item.currentValue,
          item.proposedValue,
          item.ttl,
          'failed',
          err instanceof Error ? err.message : 'Provider write failed'
        );
      }
    }
  }

  // Re-fetch from provider to verify actual saved state
  let verificationConfirmed = false;
  if (succeeded > 0) {
    try {
      const liveAfter = await provider.listRecords(preview.zoneId);
      const allFound = actionable.every((item) =>
        liveAfter.some(
          (rec) =>
            normalizeDomain(rec.hostname) === normalizeDomain(item.hostname) &&
            rec.type === item.recordType &&
            rec.value === item.proposedValue
        )
      );
      verificationConfirmed = allFound;
      if (allFound) {
        db.prepare(`UPDATE dns_deployment_changes SET result_status = 'verified' WHERE job_id = ? AND result_status = 'applied'`).run(
          jobId
        );
      }
    } catch {
      verificationConfirmed = false;
    }
  }

  let finalStatus: 'confirmed' | 'partial_failure' | 'failed';
  let summary: string;
  if (failed > 0 && succeeded > 0) {
    finalStatus = 'partial_failure';
    summary = `Partial failure: ${succeeded} record change(s) applied, ${failed} failed.`;
  } else if (failed > 0 && succeeded === 0) {
    finalStatus = 'failed';
    summary = `Deployment failed: all ${failed} record operation(s) failed.`;
  } else if (verificationConfirmed) {
    finalStatus = 'confirmed';
    summary = `Confirmed: ${succeeded} record change(s) applied and re-verified via live provider read.`;
  } else {
    finalStatus = 'partial_failure';
    summary = `Applied ${succeeded} change(s), but post-deploy provider read-back could not confirm every record.`;
  }

  db.prepare(`
    UPDATE dns_deployment_jobs
    SET status = ?, summary = ?, provider_operation_id = ?, updated_at = ?
    WHERE id = ?
  `).run(finalStatus, summary, operationIds.join(','), new Date().toISOString(), jobId);

  return { jobId, status: finalStatus, summary, operationIds };
}
