# Phase 2 — Real GeoDNS Provider Integration and Cloudflare Discovery
## Implementation Prompt for the Existing GeoRoute Manager Project

You are continuing development of the existing **GeoRoute Manager** application.

This is Phase 2. Do not rebuild the application from scratch. First inspect the existing source code, architecture, database schema, authentication, project model, backend API, and README. Preserve working functionality and extend the existing implementation safely.

The objective is to add a real, provider-backed GeoDNS integration and a safe Cloudflare discovery integration for multiple projects.

The application manages multiple websites. For each project, the intended routing is:

- Visitors classified by the GeoDNS provider as being in Iran should receive the configured Iran proxy destination.
- Visitors outside Iran should receive the configured Cloudflare destination.
- The default/fallback route must remain configurable and should normally point to the existing Cloudflare route until the Iran proxy is proven operational.
- Static asset caching is a separate proxy capability. DNS integration alone does not create a reverse proxy or cache.

The owner uses:
- React + Vite + TypeScript.
- Cloudflare Workers and D1 for existing application infrastructure.
- An Iranian Linux shared-hosting account without root access.
- Domains registered through IRNIC.
- No confirmed Nginx installation, root access, authoritative DNS server, or persistent proxy process on the Iranian shared host.

Do not assume that the Iranian shared host can run the proxy. This phase is about DNS provider integration, Cloudflare discovery, and safe configuration management—not deploying a proxy daemon.

---

# 1. Start by Inspecting the Existing Project

Before changing code:

1. Inspect the complete existing project structure.
2. Identify the current frontend framework and build configuration.
3. Identify the backend runtime and deployment target.
4. Identify the existing database schema and migration approach.
5. Identify how authentication and admin authorization work.
6. Identify how secrets are currently stored.
7. Identify existing project CRUD and status handling.
8. Identify existing API routes and error-handling conventions.
9. Identify existing tests and build scripts.
10. Read the current README and preserve its useful documentation.

Produce a short implementation assessment:
- Existing features that can be reused.
- Missing components required for Phase 2.
- Security risks in the current implementation.
- Any schema migration required.
- Any infrastructure requirement that cannot be fulfilled by the current hosting setup.

Do not delete or replace working code merely to simplify implementation.

---

# 2. Provider Selection Must Be Evidence-Based

The application needs an authoritative DNS provider that supports geographic DNS routing, specifically the ability to return different answers for Iran and the default/global region.

Do not assume that a provider supports Iran-specific country routing. Verify the provider's current official documentation.

Research and compare suitable providers using their official documentation. Potential candidates may include managed DNS providers with geographic routing features, but do not assume any particular vendor has the required country-level feature.

Evaluate each candidate against:

- Country-level geographic routing.
- Ability to define an Iran-specific rule.
- Default/global fallback behavior.
- A, AAAA, and CNAME record support.
- Apex/root-domain handling.
- API availability.
- API authentication method.
- Zone discovery.
- Record creation and update.
- Nameserver retrieval.
- TTL limits.
- Health checks and failover.
- DNSSEC support and requirements.
- Pricing and plan limitations.
- Availability of a test/sandbox environment.
- API rate limits.
- Whether Iran is explicitly included in its geographic database or routing policy.

Use official vendor documentation as the primary source. Community posts may be supplementary but cannot establish API behavior or feature support.

For every provider capability, record:
- Supported
- Not supported
- Not documented
- Requires a specific plan
- Requires vendor confirmation

Do not fabricate API endpoints, headers, request bodies, response schemas, nameservers, or feature availability.

If live documentation access is unavailable, do not guess. Build the provider adapter interface and a clearly labeled manual integration placeholder, then ask for the official API documentation or the selected provider.

Do not silently select a paid provider or activate a paid service.

---

# 3. Provider Adapter Architecture

Implement a provider-independent interface in the backend.

Use strict TypeScript types. Adapt the exact method signatures to the current project conventions, but include functionality equivalent to:

```ts
interface GeoDnsProvider {
  validateCredentials(): Promise<ProviderValidationResult>;

  listZones(): Promise<GeoDnsZone[]>;

  getZone(zoneId: string): Promise<GeoDnsZone>;

  getNameservers(zoneId: string): Promise<string[]>;

  listRecords(zoneId: string): Promise<GeoDnsRecord[]>;

  createRecord(
    zoneId: string,
    input: GeoDnsRecordInput
  ): Promise<GeoDnsOperationResult>;

  updateRecord(
    zoneId: string,
    recordId: string,
    input: GeoDnsRecordInput
  ): Promise<GeoDnsOperationResult>;

  deleteRecord(
    zoneId: string,
    recordId: string
  ): Promise<GeoDnsOperationResult>;

  checkDelegation(domain: string): Promise<DelegationStatus>;

  getCapabilities(): Promise<GeoDnsCapabilities>;
}
```

Create:
- A shared provider interface.
- Provider-specific adapters.
- Runtime validation of provider responses.
- Typed error mapping.
- Provider capability metadata.
- Unit tests for each adapter.

Keep vendor-specific logic out of React components.

The UI must communicate with the application's backend API. The browser must never call a secret DNS-provider API directly.

---

# 4. Secure Provider Credential Management

Add a DNS Providers management page.

The admin should be able to:

- Add a provider account.
- Set a friendly account label.
- Enter credentials through a secure form.
- Validate credentials.
- View connection status.
- Select a provider account for a project.
- Disconnect an account.
- Rotate credentials.

Security requirements:

- Store credentials only in a server-side secret store.
- Prefer Cloudflare Worker Secrets or the secure secret facility of the selected backend.
- If the secret store cannot hold multiple provider accounts dynamically, design a secure encrypted credential storage mechanism using a managed encryption key that is not stored in the database.
- Never store plaintext tokens in D1 or another ordinary database table.
- Never expose tokens in API responses.
- Never return secret values after saving.
- Never put secrets in Vite `VITE_` environment variables.
- Never log request headers containing authorization credentials.
- Never include secrets in error messages.
- Restrict credential-management endpoints to authenticated administrators.
- Use least-privilege provider API credentials.
- Document exactly which provider permissions are required.

If the current deployment platform cannot safely support multiple encrypted provider credentials, stop and explain the limitation. Do not implement insecure storage as a workaround.

---

# 5. Multi-Project DNS Configuration

Extend the existing project model without breaking existing projects.

Each project should be able to select:

- DNS provider account.
- DNS zone.
- Domain.
- Iran route destination.
- Global/default route destination.
- Fallback destination.
- Routing policy status.
- DNS TTL.
- Record type.
- Hostname being routed.
- Whether the rule is enabled.

Support separate hostnames when necessary, for example:
- `example.com`
- `www.example.com`
- `static.example.com`
- `api.example.com`

Do not assume that the apex domain and `www` can use identical record types or targets.

Allow a project to have multiple hostnames and multiple routing rules.

Keep each project's configuration isolated. All backend queries must verify that the requested project belongs to the authenticated user or account.

---

# 6. Iran and Global Routing Policy

Implement a routing policy editor with two main geographic outcomes:

## Iran rule
- Region/country: Iran (use the provider's documented country code and syntax).
- Destination: the configured Iran proxy hostname or IP.
- Enabled only after the destination is verified.
- Do not enable by default if the proxy is not operational.

## Default/global rule
- Destination: the existing Cloudflare target or the provider-supported representation of that target.
- Keep this route active as the safe fallback.

The application must not assume that the Cloudflare target is always a fixed IP.

For Cloudflare-proxied DNS records, Cloudflare may return its anycast addresses rather than the origin IP. Inspect the actual Cloudflare zone configuration and provider requirements before designing the target record.

If the selected GeoDNS provider cannot represent the Cloudflare destination safely (for example, because it cannot use the required CNAME or apex flattening behavior), explain the limitation and propose a verified alternative. Do not invent a workaround.

## Resolver-location limitation

Explain in the UI and documentation:

- GeoDNS commonly makes decisions using the recursive DNS resolver's location.
- Public DNS resolvers, mobile networks, VPNs, and DNS forwarding can affect the answer.
- DNS caching and TTL delay routing changes.
- Country-based DNS routing is not a perfect user-location detector.

Add a warning that the owner must test from real Iranian networks and at least one non-Iranian network before production deployment.

---

# 7. DNS Change Preview and Safe Deployment

Implement a two-step deployment process.

## Step A: Preview

Before any write operation, show:

- Current DNS records.
- Proposed records.
- Records to be created.
- Records to be changed.
- Records to be deleted, if any.
- Iran routing target.
- Global routing target.
- Fallback target.
- TTL.
- Provider and zone.
- Provider capability warnings.
- Potential conflicts.
- Whether the apex domain is supported.
- Whether DNSSEC or DS-record action may be required.

The preview must be generated from actual provider data, not guessed local state.

## Step B: Explicit deployment

Require the administrator to:
- Review the complete diff.
- Confirm the exact project and domain.
- Confirm that the Iran proxy destination is ready.
- Confirm that required DNS records exist.
- Confirm that email and verification records are preserved.
- Explicitly approve the deployment.

Only then call the provider's write API.

After deployment:
- Fetch records again from the provider.
- Verify the actual saved state.
- Record the provider response and operation ID, where available.
- Write an audit log.
- Show success only after provider confirmation.
- If verification fails, show a failed or uncertain state. Do not report success.

Use idempotent operations where supported. Avoid duplicate records. Do not delete unrelated records.

Provide rollback guidance. If the provider supports rollback or record restoration, implement it using verified API behavior. Otherwise show the exact manual recovery instructions.

---

# 8. IRNIC Nameserver Delegation Workflow

The app must not pretend to control IRNIC unless a verified IRNIC API integration exists.

For every selected DNS zone:

1. Retrieve the authoritative nameservers directly from the DNS provider.
2. Display the exact nameserver values returned by the provider.
3. Display the current delegation state, if a reliable check is available.
4. Provide a copy action for each nameserver.
5. Provide manual instructions for updating nameservers in the IRNIC domain control panel.
6. Warn that all required DNS records must exist at the new provider before delegation changes.
7. Explain DNSSEC/DS-record implications.
8. Recheck delegation after the user reports making the change or after a scheduled check.

Never invent nameserver hostnames.

Never instruct the owner to replace nameservers until the zone has been populated and checked.

Add a checklist:
- [ ] Existing DNS zone exported or recorded.
- [ ] Website records recreated.
- [ ] MX records recreated.
- [ ] SPF, DKIM, and DMARC records recreated.
- [ ] TXT verification records recreated.
- [ ] Required subdomains recreated.
- [ ] DNSSEC/DS status checked.
- [ ] New provider zone tested.
- [ ] Nameservers updated at IRNIC.
- [ ] Delegation verified.
- [ ] Website and email tested.

If delegation is not yet changed, clearly label the project as **Waiting for nameserver delegation**.

---

# 9. Cloudflare Read-Only Discovery

Add a Cloudflare integration for project discovery and verification.

Use official Cloudflare API documentation. Do not invent endpoints or permissions.

The first implementation should be read-only.

Support, where documented and permitted:

- Validate API token.
- List accessible zones.
- Retrieve zone metadata.
- Retrieve current DNS records.
- Identify proxied versus DNS-only records.
- Inspect relevant Worker routes and custom-domain configuration.
- Inspect relevant SSL/TLS configuration.
- Read relevant cache settings.
- Identify likely application hostnames and static asset hostnames.

Do not:
- Modify existing DNS records.
- Change Worker routes.
- Change custom domains.
- Change SSL/TLS settings.
- Modify D1 databases.
- Purge caches.
- Disable Cloudflare proxying.

Those operations are outside this phase unless explicitly added later with a separate approval flow.

## Cloudflare credential safety

- Use a least-privilege API token.
- Keep the token server-side.
- Never expose it to the frontend.
- Never log it.
- Show only a masked account label and validation status.
- Explain the exact permissions required based on the actual API calls.

## Cloudflare project mapping

Allow the admin to map:
- GeoDNS project.
- Domain.
- Cloudflare zone.
- Cloudflare record(s).
- Worker custom domain or route, where applicable.
- Existing static asset hostnames.

Do not infer that a Worker route is equivalent to a conventional origin IP.

If the current Cloudflare configuration cannot be safely represented as a GeoDNS target, mark it as **Requires architecture review**.

---

# 10. Diagnostics and Verification

Add a diagnostics page for every project.

Run only safe, read-only checks.

Checks should include:

- Provider credential validation.
- Zone retrieval.
- Nameserver retrieval.
- Current authoritative DNS answers.
- Delegation status.
- Record consistency.
- Iran rule configuration.
- Default/global rule configuration.
- Cloudflare target verification.
- Proxy target verification.
- TLS reachability when a real target hostname exists.

Do not claim that a DNS rule works for Iranian visitors based only on a lookup from an outside server.

For each check, display:
- Result: Passed / Failed / Warning / Not tested.
- Test location.
- Timestamp.
- Target.
- Short explanation.
- Technical details in an expandable panel.

If the backend runs outside Iran, clearly state that the test does not validate Iranian network reachability.

Do not fabricate latency, country, IP, or cache metrics.

---

# 11. Database and Migration Work

Inspect the existing database before making schema changes.

Add only the tables/columns required by the current schema.

Potential entities:

- `dns_provider_accounts`
- `dns_zones`
- `project_hostnames`
- `routing_rules`
- `dns_deployment_jobs`
- `dns_deployment_changes`
- `cloudflare_accounts`
- `project_cloudflare_mappings`
- `dns_health_checks`
- `audit_logs`

Use foreign keys and indexes.

If Cloudflare D1 is used:
- Use D1-compatible SQL.
- Provide ordered migration files.
- Do not delete existing user/project data.
- Make migrations safe to run in the documented deployment process.
- Add indexes for project IDs, provider IDs, domains, and timestamps.
- Use transactions where supported and appropriate.

Do not store raw provider tokens in database columns.

Add a backup/export path before schema changes.

---

# 12. UI Requirements

Extend the existing UI. Do not redesign unrelated pages.

Add or improve these areas:

## DNS Providers
- Provider list.
- Add provider account.
- Secure credential entry.
- Validate connection.
- View capabilities.
- View zones.
- Disconnect account.

## Project > DNS
- Provider selector.
- Zone selector.
- Hostname management.
- Current records.
- Iran routing rule.
- Global fallback rule.
- TTL.
- Deployment preview.
- Deployment confirmation.
- Nameserver instructions.

## Project > Cloudflare
- Connect Cloudflare account.
- Validate token.
- Select zone.
- View records.
- View Worker routes/custom domains where supported.
- Show mapping status.

## Project > Diagnostics
- Check list.
- Test timestamps.
- Test location.
- Result details.
- Retry action.

Use clear status badges, but do not use success styling for unverified operations.

Add empty states, loading states, error states, and accessible confirmation dialogs.

Keep the app responsive.

---

# 13. API Design

Follow the existing backend conventions. Create endpoints equivalent to:

```text
POST   /api/dns-providers
GET    /api/dns-providers
POST   /api/dns-providers/:id/validate
GET    /api/dns-providers/:id/zones
GET    /api/dns-providers/:id/zones/:zoneId/nameservers

GET    /api/projects/:projectId/dns
GET    /api/projects/:projectId/dns/preview
POST   /api/projects/:projectId/dns/deploy
GET    /api/projects/:projectId/dns/deployments
GET    /api/projects/:projectId/dns/delegation

POST   /api/cloudflare/accounts
POST   /api/cloudflare/accounts/:id/validate
GET    /api/cloudflare/accounts/:id/zones
GET    /api/projects/:projectId/cloudflare/discovery

POST   /api/projects/:projectId/diagnostics
GET    /api/projects/:projectId/diagnostics
```

These are logical route suggestions, not permission to invent provider endpoints. Adapt them to the existing backend.

Every route must:
- Authenticate the user.
- Authorize access to the requested project.
- Validate input.
- Apply rate limits where appropriate.
- Avoid returning secrets.
- Log administrative changes.
- Return consistent typed errors.

For deployment endpoints, require an explicit confirmation token or confirmation payload tied to the preview so that the deployed change matches the reviewed diff.

---

# 14. Testing Requirements

Add automated tests for:

- Project isolation.
- Provider credential validation.
- Provider adapter response parsing.
- Unsupported provider capabilities.
- Missing Iran route.
- Missing global fallback.
- Duplicate records.
- Conflicting DNS records.
- Apex-domain limitations.
- Safe deployment preview.
- Deployment confirmation requirement.
- Provider API failure.
- Partial deployment failure.
- Delegation pending state.
- Cloudflare token failure.
- Secret redaction in logs and responses.
- Authorization failures.
- No accidental cache/proxy claims.

Mock provider APIs in unit tests. Do not use fake production credentials.

Integration tests should run only against a documented sandbox/test zone or an explicitly approved test environment.

---

# 15. Required Documentation

Update README.md with:

1. Phase 2 architecture.
2. Provider selection findings and official documentation links.
3. Provider feature comparison.
4. Required credentials and least-privilege permissions.
5. Environment variable names with placeholder values only.
6. Database migrations.
7. Local development instructions.
8. Deployment instructions.
9. Provider connection instructions.
10. DNS deployment workflow.
11. IRNIC nameserver migration checklist.
12. DNSSEC warnings.
13. Cloudflare discovery instructions.
14. Troubleshooting guide.
15. Limitations and unsupported capabilities.

Add a separate `docs/PHASE_2_PROVIDER_INTEGRATION.md`.

For every provider feature, cite the official documentation URL in the documentation and identify the date on which it was checked.

---

# 16. Scope Boundaries

This phase does NOT deploy the Iran reverse proxy.

This phase does NOT install Nginx.

This phase does NOT create a DNS server.

This phase does NOT guarantee that the current shared host can proxy traffic.

This phase does NOT implement static asset caching.

This phase does NOT change IRNIC nameservers automatically.

This phase does NOT modify existing Cloudflare production settings.

Those are separate operations requiring verified infrastructure and explicit approval.

The app must make these boundaries clear to the owner.

---

# 17. Final Execution Instructions

Work in this order:

1. Inspect the existing repository.
2. Report the current architecture and missing requirements.
3. Research provider capabilities using official documentation.
4. Present a concise provider comparison and recommendation.
5. Identify any decisions that require the owner's approval.
6. Implement the provider abstraction and secure credential handling.
7. Implement one real provider adapter only when its API is verified.
8. Implement read-only Cloudflare discovery.
9. Implement DNS preview and explicit deployment workflow.
10. Add delegation status and IRNIC instructions.
11. Add tests and documentation.
12. Run the project's build, type checks, and tests.
13. Fix all errors introduced by this phase.

Do not make production DNS changes during development.

Do not select a paid plan or trigger a purchase.

Do not ask the owner to paste API tokens into chat or source code. Provide a secure settings form for entering them directly into the deployed application.

If provider research cannot be completed, stop before implementing guessed API calls. Deliver the adapter interface, manual setup mode, and a precise list of missing documentation or decisions.

## Expected first response

Before making code changes, report:

- What you found in the existing repository.
- Which GeoDNS providers you verified.
- Whether any provider explicitly supports Iran-specific routing.
- Official documentation links.
- Pricing/plan limitations, if verified.
- The recommended provider and why.
- What Cloudflare information can be safely discovered.
- What still requires owner approval.

Then proceed with implementation only where the requirements and API behavior are verified.
