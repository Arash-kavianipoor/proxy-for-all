-- GeoRoute Manager Phase 1 Initial Schema (SQLite & Cloudflare D1 compatible)

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
