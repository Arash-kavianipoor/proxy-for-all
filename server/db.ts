import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

let dbInstance: DatabaseSync | null = null;

const EMBEDDED_MIGRATIONS: Array<{ name: string; sql: string }> = [
  {
    name: '0001_initial.sql',
    sql: `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')) DEFAULT 'admin',
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  csrf_token TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  project_name TEXT NOT NULL,
  domain TEXT NOT NULL,
  description TEXT DEFAULT '',
  status TEXT NOT NULL CHECK (
    status IN (
      'draft',
      'needs_infrastructure_verification',
      'geodns_not_configured',
      'dns_configured',
      'waiting_for_nameserver_delegation',
      'proxy_not_verified',
      'ssl_not_verified',
      'operational',
      'degraded',
      'failed'
    )
  ) DEFAULT 'draft',
  iran_proxy_hostname TEXT DEFAULT '',
  iran_proxy_ipv4 TEXT DEFAULT '',
  iran_proxy_ipv6 TEXT DEFAULT '',
  cloudflare_target TEXT DEFAULT '',
  cloudflare_zone_id TEXT DEFAULT '',
  geo_dns_provider TEXT DEFAULT 'manual',
  geo_dns_zone_id TEXT DEFAULT '',
  health_check_url TEXT DEFAULT '',
  notes TEXT DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_projects_owner_id ON projects(owner_id);
CREATE INDEX IF NOT EXISTS idx_projects_domain ON projects(domain);
CREATE INDEX IF NOT EXISTS idx_projects_status ON projects(status);
CREATE TABLE IF NOT EXISTS project_origins (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  origin_type TEXT NOT NULL CHECK (origin_type IN ('cloudflare_worker', 'cloudflare_pages', 'cloudflare_origin', 'iran_proxy', 'fallback')),
  origin_hostname TEXT NOT NULL,
  origin_ip TEXT DEFAULT '',
  origin_port INTEGER NOT NULL DEFAULT 443,
  tls_mode TEXT NOT NULL CHECK (tls_mode IN ('strict', 'full', 'flexible', 'unverified')) DEFAULT 'strict',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_project_origins_project_id ON project_origins(project_id);
CREATE TABLE IF NOT EXISTS hosting_capabilities (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  capability_key TEXT NOT NULL,
  capability_label TEXT NOT NULL,
  category TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('supported', 'unsupported', 'not_tested', 'provider_confirmation_required')) DEFAULT 'not_tested',
  notes TEXT DEFAULT '',
  verified_at TEXT DEFAULT '',
  updated_at TEXT NOT NULL,
  UNIQUE(project_id, capability_key),
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_hosting_capabilities_project_id ON hosting_capabilities(project_id);
CREATE TABLE IF NOT EXISTS cache_policies (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  path_pattern TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  cache_behavior TEXT NOT NULL CHECK (cache_behavior IN ('cache_immutable', 'cache_short', 'revalidate', 'bypass_always')),
  ttl_seconds INTEGER NOT NULL DEFAULT 0,
  respect_origin_headers INTEGER NOT NULL DEFAULT 1,
  bypass_on_cookie INTEGER NOT NULL DEFAULT 1,
  enabled INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_cache_policies_project_id ON cache_policies(project_id);
CREATE TABLE IF NOT EXISTS health_checks (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  check_type TEXT NOT NULL,
  target TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('passed', 'failed', 'warning', 'not_tested')),
  test_location TEXT NOT NULL,
  result_summary TEXT NOT NULL,
  details_json TEXT DEFAULT '{}',
  checked_at TEXT NOT NULL,
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_health_checks_project_id ON health_checks(project_id);
CREATE INDEX IF NOT EXISTS idx_health_checks_checked_at ON health_checks(checked_at);
CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  actor_id TEXT NOT NULL,
  project_id TEXT,
  action TEXT NOT NULL,
  result TEXT NOT NULL CHECK (result IN ('success', 'failure', 'warning', 'blocked')),
  details TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_id ON audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_project_id ON audit_logs(project_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
`,
  },
  {
    name: '0002_phase2_geodns_cloudflare.sql',
    sql: `
CREATE TABLE IF NOT EXISTS dns_provider_accounts (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  provider_name TEXT NOT NULL CHECK (provider_name IN ('ns1', 'cloudns', 'manual')),
  account_label TEXT NOT NULL,
  encrypted_credentials_ciphertext TEXT NOT NULL,
  credentials_iv TEXT NOT NULL,
  credentials_tag TEXT NOT NULL,
  masked_hint TEXT NOT NULL DEFAULT '',
  validation_status TEXT NOT NULL CHECK (validation_status IN ('valid', 'invalid', 'not_validated', 'manual')) DEFAULT 'not_validated',
  validation_message TEXT DEFAULT '',
  last_validated_at TEXT DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_dns_provider_accounts_owner_id ON dns_provider_accounts(owner_id);
CREATE INDEX IF NOT EXISTS idx_dns_provider_accounts_provider_name ON dns_provider_accounts(provider_name);
CREATE TABLE IF NOT EXISTS dns_zones (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  provider_account_id TEXT,
  provider_zone_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  authoritative_nameservers_json TEXT NOT NULL DEFAULT '[]',
  delegation_status TEXT NOT NULL CHECK (delegation_status IN ('verified', 'waiting_delegation', 'mismatch', 'not_checked')) DEFAULT 'not_checked',
  observed_nameservers_json TEXT NOT NULL DEFAULT '[]',
  last_synced_at TEXT DEFAULT '',
  updated_at TEXT NOT NULL,
  UNIQUE(project_id),
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
  FOREIGN KEY (provider_account_id) REFERENCES dns_provider_accounts(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_dns_zones_project_id ON dns_zones(project_id);
CREATE INDEX IF NOT EXISTS idx_dns_zones_domain ON dns_zones(domain);
CREATE TABLE IF NOT EXISTS project_hostnames (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  hostname TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('apex', 'www', 'static', 'api', 'custom')) DEFAULT 'custom',
  notes TEXT DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(project_id, hostname),
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_project_hostnames_project_id ON project_hostnames(project_id);
CREATE TABLE IF NOT EXISTS routing_rules (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  hostname TEXT NOT NULL,
  region_code TEXT NOT NULL CHECK (region_code IN ('IR', 'DEFAULT', 'FALLBACK')),
  record_type TEXT NOT NULL CHECK (record_type IN ('A', 'AAAA', 'CNAME', 'ALIAS', 'TXT')),
  destination TEXT NOT NULL,
  ttl INTEGER NOT NULL DEFAULT 300,
  enabled INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  UNIQUE(project_id, hostname, region_code),
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_routing_rules_project_id ON routing_rules(project_id);
CREATE INDEX IF NOT EXISTS idx_routing_rules_region ON routing_rules(region_code);
CREATE TABLE IF NOT EXISTS dns_deployment_jobs (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  provider_account_id TEXT,
  zone_id TEXT NOT NULL,
  preview_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('previewed', 'deploying', 'confirmed', 'partial_failure', 'failed', 'manual_pending')) DEFAULT 'previewed',
  summary TEXT NOT NULL DEFAULT '',
  provider_operation_id TEXT DEFAULT '',
  confirmed_by TEXT,
  confirmed_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
  FOREIGN KEY (provider_account_id) REFERENCES dns_provider_accounts(id) ON DELETE SET NULL,
  FOREIGN KEY (confirmed_by) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_dns_deployment_jobs_project_id ON dns_deployment_jobs(project_id);
CREATE INDEX IF NOT EXISTS idx_dns_deployment_jobs_created_at ON dns_deployment_jobs(created_at);
CREATE TABLE IF NOT EXISTS dns_deployment_changes (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  operation TEXT NOT NULL CHECK (operation IN ('create', 'update', 'delete', 'unchanged', 'conflict')),
  hostname TEXT NOT NULL,
  region_code TEXT NOT NULL,
  record_type TEXT NOT NULL,
  current_value TEXT DEFAULT '',
  proposed_value TEXT DEFAULT '',
  ttl INTEGER NOT NULL DEFAULT 300,
  result_status TEXT NOT NULL CHECK (result_status IN ('pending', 'applied', 'verified', 'failed', 'skipped')) DEFAULT 'pending',
  error_message TEXT DEFAULT '',
  FOREIGN KEY (job_id) REFERENCES dns_deployment_jobs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_dns_deployment_changes_job_id ON dns_deployment_changes(job_id);
CREATE TABLE IF NOT EXISTS irnic_migration_checklists (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  step_key TEXT NOT NULL,
  step_label TEXT NOT NULL,
  step_order INTEGER NOT NULL,
  completed INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  UNIQUE(project_id, step_key),
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_irnic_checklists_project_id ON irnic_migration_checklists(project_id);
CREATE TABLE IF NOT EXISTS cloudflare_accounts (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  account_label TEXT NOT NULL,
  encrypted_token_ciphertext TEXT NOT NULL,
  token_iv TEXT NOT NULL,
  token_tag TEXT NOT NULL,
  masked_hint TEXT NOT NULL DEFAULT '',
  validation_status TEXT NOT NULL CHECK (validation_status IN ('valid', 'invalid', 'not_validated')) DEFAULT 'not_validated',
  validation_message TEXT DEFAULT '',
  last_validated_at TEXT DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_cloudflare_accounts_owner_id ON cloudflare_accounts(owner_id);
CREATE TABLE IF NOT EXISTS project_cloudflare_mappings (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  cloudflare_account_id TEXT NOT NULL,
  cloudflare_zone_id TEXT NOT NULL,
  zone_name TEXT NOT NULL,
  zone_status TEXT DEFAULT '',
  name_servers_json TEXT NOT NULL DEFAULT '[]',
  records_snapshot_json TEXT NOT NULL DEFAULT '[]',
  worker_routes_json TEXT NOT NULL DEFAULT '[]',
  worker_domains_json TEXT NOT NULL DEFAULT '[]',
  ssl_mode TEXT DEFAULT '',
  cache_level TEXT DEFAULT '',
  requires_architecture_review INTEGER NOT NULL DEFAULT 0,
  review_notes TEXT DEFAULT '',
  discovered_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(project_id),
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
  FOREIGN KEY (cloudflare_account_id) REFERENCES cloudflare_accounts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_project_cf_mappings_project_id ON project_cloudflare_mappings(project_id);
CREATE TABLE IF NOT EXISTS dns_health_checks (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  check_category TEXT NOT NULL,
  target TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('passed', 'failed', 'warning', 'not_tested')),
  test_location TEXT NOT NULL,
  summary TEXT NOT NULL,
  technical_details_json TEXT DEFAULT '{}',
  checked_at TEXT NOT NULL,
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_dns_health_checks_project_id ON dns_health_checks(project_id);
CREATE INDEX IF NOT EXISTS idx_dns_health_checks_checked_at ON dns_health_checks(checked_at);
`,
  },
];

export function getDb(customPath?: string): DatabaseSync {
  if (dbInstance && !customPath) return dbInstance;

  const targetPath = customPath || process.env.DATABASE_PATH || './data/georoute.db';
  if (targetPath !== ':memory:') {
    const dir = path.dirname(path.resolve(process.cwd(), targetPath));
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  const db = new DatabaseSync(targetPath);
  db.exec('PRAGMA foreign_keys = ON;');
  if (targetPath !== ':memory:') {
    try {
      db.exec('PRAGMA journal_mode = WAL;');
    } catch {
      // Fallback safely on shared filesystems where WAL shm locks are disallowed
    }
  }
  runMigrations(db);

  if (!customPath) {
    dbInstance = db;
  }
  return db;
}

export function runMigrations(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS _migrations (
      name TEXT PRIMARY KEY,
      applied_at TEXT NOT NULL
    );
  `);

  const candidateDirs = [
    path.resolve(process.cwd(), 'migrations'),
    typeof __dirname !== 'undefined' ? path.resolve(__dirname, '../migrations') : '',
  ].filter(Boolean);

  const migrationsDir = candidateDirs.find((d) => fs.existsSync(d));
  const checkStmt = db.prepare('SELECT name FROM _migrations WHERE name = ?');
  const insertStmt = db.prepare('INSERT INTO _migrations (name, applied_at) VALUES (?, ?)');

  const items: Array<{ name: string; sql: string }> = migrationsDir
    ? fs
        .readdirSync(migrationsDir)
        .filter((f) => f.endsWith('.sql'))
        .sort()
        .map((file) => ({
          name: file,
          sql: fs.readFileSync(path.join(migrationsDir, file), 'utf8'),
        }))
    : EMBEDDED_MIGRATIONS;

  for (const item of items) {
    const alreadyApplied = checkStmt.get(item.name);
    if (alreadyApplied) continue;

    db.exec('BEGIN;');
    try {
      db.exec(item.sql);
      insertStmt.run(item.name, new Date().toISOString());
      db.exec('COMMIT;');
    } catch (err) {
      db.exec('ROLLBACK;');
      throw err;
    }
  }
}

export const DEFAULT_HOSTING_CAPABILITIES: Array<{
  key: string;
  label: string;
  category: string;
}> = [
  { key: 'nodejs_available', label: 'Node.js runtime available on shared host', category: 'Runtime' },
  { key: 'nodejs_version', label: 'Supported LTS Node.js version (v20+ / v22+)', category: 'Runtime' },
  { key: 'persistent_process', label: 'Persistent background process / Passenger / PM2 allowed', category: 'Process' },
  { key: 'panel_nodejs_feature', label: 'Control panel (cPanel/DirectAdmin) Node.js App Selector present', category: 'Control Panel' },
  { key: 'outbound_https_cf', label: 'Outbound HTTPS to Cloudflare origins permitted', category: 'Network' },
  { key: 'long_running_http', label: 'Long-running HTTP requests without premature 30s kill', category: 'Network' },
  { key: 'response_streaming', label: 'Chunked / streaming HTTP responses supported', category: 'Network' },
  { key: 'body_size_limits', label: 'Request & response body size limits verified', category: 'Limits' },
  { key: 'custom_rewrite_proxy', label: 'Custom reverse-proxy / mod_proxy / rewrite rules allowed', category: 'Proxy' },
  { key: 'valid_ssl_cert', label: 'Valid TLS/SSL certificate (Let\'s Encrypt / custom cert) configurable', category: 'Security' },
  { key: 'documented_cache', label: 'Documented disk/LiteSpeed/Varnish cache facility available', category: 'Cache' },
  { key: 'provider_proxy_support', label: 'Host support confirmed reverse-proxy rules on account', category: 'Support' },
];

export const DEFAULT_IRNIC_STEPS: Array<{ key: string; label: string; order: number }> = [
  { key: 'export_zone', label: 'Existing DNS zone exported or recorded', order: 1 },
  { key: 'recreate_web', label: 'Website records (A/AAAA/CNAME/ALIAS) recreated at GeoDNS provider', order: 2 },
  { key: 'recreate_mx', label: 'MX mail exchanger records recreated', order: 3 },
  { key: 'recreate_email_auth', label: 'SPF, DKIM, and DMARC TXT records recreated', order: 4 },
  { key: 'recreate_verification', label: 'Domain verification TXT records recreated', order: 5 },
  { key: 'recreate_subdomains', label: 'All required subdomains recreated', order: 6 },
  { key: 'check_dnssec_ds', label: 'DNSSEC / DS record status checked (avoid stale DS at IRNIC)', order: 7 },
  { key: 'test_new_zone', label: 'New provider zone queried directly and verified', order: 8 },
  { key: 'update_irnic_ns', label: 'Authoritative nameservers updated in IRNIC panel', order: 9 },
  { key: 'verify_delegation', label: 'Nameserver delegation verified after propagation', order: 10 },
  { key: 'test_web_and_email', label: 'Website routing and email delivery tested end-to-end', order: 11 },
];

export const DEFAULT_CACHE_POLICIES: Array<{
  pathPattern: string;
  resourceType: string;
  cacheBehavior: 'cache_immutable' | 'cache_short' | 'revalidate' | 'bypass_always';
  ttlSeconds: number;
  respectOriginHeaders: number;
  bypassOnCookie: number;
}> = [
  {
    pathPattern: '/assets/*-[a-zA-Z0-9]{8}.js',
    resourceType: 'Vite hashed JS bundles',
    cacheBehavior: 'cache_immutable',
    ttlSeconds: 31536000,
    respectOriginHeaders: 1,
    bypassOnCookie: 1,
  },
  {
    pathPattern: '/assets/*-[a-zA-Z0-9]{8}.css',
    resourceType: 'Vite hashed CSS bundles',
    cacheBehavior: 'cache_immutable',
    ttlSeconds: 31536000,
    respectOriginHeaders: 1,
    bypassOnCookie: 1,
  },
  {
    pathPattern: '/assets/*.(webp|avif|svg|woff2)',
    resourceType: 'Static public images & fonts',
    cacheBehavior: 'cache_immutable',
    ttlSeconds: 2592000,
    respectOriginHeaders: 1,
    bypassOnCookie: 1,
  },
  {
    pathPattern: '/index.html',
    resourceType: 'HTML entry document',
    cacheBehavior: 'revalidate',
    ttlSeconds: 60,
    respectOriginHeaders: 1,
    bypassOnCookie: 1,
  },
  {
    pathPattern: '/api/*',
    resourceType: 'API endpoints',
    cacheBehavior: 'bypass_always',
    ttlSeconds: 0,
    respectOriginHeaders: 1,
    bypassOnCookie: 1,
  },
  {
    pathPattern: '/auth/*,/login,/admin/*,/account/*',
    resourceType: 'Authentication, admin & user-specific routes',
    cacheBehavior: 'bypass_always',
    ttlSeconds: 0,
    respectOriginHeaders: 1,
    bypassOnCookie: 1,
  },
];

export function seedProjectDefaults(db: DatabaseSync, projectId: string, domain: string): void {
  const now = new Date().toISOString();

  const capStmt = db.prepare(`
    INSERT OR IGNORE INTO hosting_capabilities
      (id, project_id, capability_key, capability_label, category, status, notes, verified_at, updated_at)
    VALUES (?, ?, ?, ?, ?, 'not_tested', '', '', ?)
  `);
  for (const cap of DEFAULT_HOSTING_CAPABILITIES) {
    capStmt.run(crypto.randomUUID(), projectId, cap.key, cap.label, cap.category, now);
  }

  const irnicStmt = db.prepare(`
    INSERT OR IGNORE INTO irnic_migration_checklists
      (id, project_id, step_key, step_label, step_order, completed, updated_at)
    VALUES (?, ?, ?, ?, ?, 0, ?)
  `);
  for (const step of DEFAULT_IRNIC_STEPS) {
    irnicStmt.run(crypto.randomUUID(), projectId, step.key, step.label, step.order, now);
  }

  const cacheStmt = db.prepare(`
    INSERT INTO cache_policies
      (id, project_id, path_pattern, resource_type, cache_behavior, ttl_seconds, respect_origin_headers, bypass_on_cookie, enabled, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
  `);
  for (const policy of DEFAULT_CACHE_POLICIES) {
    cacheStmt.run(
      crypto.randomUUID(),
      projectId,
      policy.pathPattern,
      policy.resourceType,
      policy.cacheBehavior,
      policy.ttlSeconds,
      policy.respectOriginHeaders,
      policy.bypassOnCookie,
      now
    );
  }

  const hostStmt = db.prepare(`
    INSERT OR IGNORE INTO project_hostnames (id, project_id, hostname, role, notes, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  hostStmt.run(crypto.randomUUID(), projectId, domain, 'apex', 'Root apex domain', now, now);
  hostStmt.run(crypto.randomUUID(), projectId, `www.${domain}`, 'www', 'Standard www subdomain', now, now);
}

export function writeAuditLog(
  db: DatabaseSync,
  params: {
    actorId: string;
    projectId?: string | null;
    action: string;
    result: 'success' | 'failure' | 'warning' | 'blocked';
    details: string;
  }
): void {
  db.prepare(`
    INSERT INTO audit_logs (id, actor_id, project_id, action, result, details, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    crypto.randomUUID(),
    params.actorId,
    params.projectId ?? null,
    params.action,
    params.result,
    params.details,
    new Date().toISOString()
  );
}

// Pre-computed scrypt(N=16384,r=8,p=1,keylen=64) hash & salt — plaintext password is never stored in source code
const DEFAULT_ADMIN_SALT = '28dce2c52b992e5936245386bb4947b0';
const DEFAULT_ADMIN_HASH =
  '7201d1139ea65ec47681335d44963264556f8a527a5a79f896b5b4c7a746bfa5cbee7e54c90f2a3ce62b20b086d8404be65ab26f024c88eaff7f1efcb68b6c97';

export function ensureDefaultAdmin(db: DatabaseSync): void {
  const existingAdmin = db
    .prepare("SELECT id, password_hash FROM users WHERE LOWER(username) = 'admin'")
    .get() as { id: string; password_hash: string } | undefined;

  if (!existingAdmin) {
    const userId = crypto.randomUUID();
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO users (id, username, role, password_hash, password_salt, created_at, updated_at)
      VALUES (?, 'admin', 'admin', ?, ?, ?, ?)
    `).run(userId, DEFAULT_ADMIN_HASH, DEFAULT_ADMIN_SALT, now, now);

    writeAuditLog(db, {
      actorId: userId,
      action: 'admin.seed',
      result: 'success',
      details: 'Initialized primary admin account "admin" with hashed password.',
    });
    return;
  }

  // Sync admin to the current configured default hash unless the user explicitly changed their password in Settings
  const hasChangedPassword = db
    .prepare("SELECT id FROM audit_logs WHERE actor_id = ? AND action = 'admin.password_change' LIMIT 1")
    .get(existingAdmin.id);

  if (!hasChangedPassword && existingAdmin.password_hash !== DEFAULT_ADMIN_HASH) {
    const now = new Date().toISOString();
    db.prepare(`
      UPDATE users SET password_hash = ?, password_salt = ?, updated_at = ? WHERE id = ?
    `).run(DEFAULT_ADMIN_HASH, DEFAULT_ADMIN_SALT, now, existingAdmin.id);

    writeAuditLog(db, {
      actorId: existingAdmin.id,
      action: 'admin.seed',
      result: 'success',
      details: 'Synchronized admin account with updated default hashed password.',
    });
  }
}

