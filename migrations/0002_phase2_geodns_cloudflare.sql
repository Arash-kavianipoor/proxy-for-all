-- GeoRoute Manager Phase 2 Schema: GeoDNS Providers, Routing Rules, Deployments, IRNIC Checklist & Cloudflare Discovery

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
