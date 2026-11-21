# Multi-Project GeoDNS & Iran Static-Asset Proxy Manager
## Product Requirements and Implementation Prompt for Google AI Studio

You are a senior software architect and full-stack engineer. Design and implement a production-minded web application named **GeoRoute Manager**.

The application will manage multiple websites and help route visitors in Iran through an Iran-based hosting environment, while visitors outside Iran continue to access each website through its existing Cloudflare infrastructure.

The application is a **management control panel**. It is not itself an authoritative DNS server, a registrar, or a guaranteed reverse-proxy service. It must integrate with real DNS/GeoDNS providers and must clearly distinguish configuration management from infrastructure that must be provisioned separately.

---

# 1. Existing Infrastructure and Non-Negotiable Constraints

The owner currently has:

- Websites hosted primarily on Cloudflare.
- Cloudflare Workers for application/API logic.
- Cloudflare D1 for database storage.
- Frontends built with React, Vite, and TypeScript.
- A Linux shared-hosting account in Iran.
- No root access on the Iranian Linux host.
- No permission to install or configure system-level Nginx, Apache modules, DNS daemons, or firewall rules.
- No confirmed ability to bind privileged ports such as TCP/UDP 53.
- No confirmed ability to run a persistent Node.js process, background worker, or long-running proxy service.
- Domains registered through IRNIC.
- Google AI Studio is the intended development environment.

Do not assume that the shared host can run a reverse proxy just because it is Linux hosting. Do not assume Node.js support, persistent processes, outbound network access, streaming support, custom rewrite rules, or the ability to configure TLS certificates. These capabilities must be checked and reported as unknown until verified.

The application must never claim that it has created a working GeoDNS configuration, proxy, cache, or DNS server unless the relevant provider/API has confirmed the operation and the infrastructure has passed a real health check.

## Critical architecture distinction

There are three separate systems:

1. **GeoDNS provider:** An authoritative DNS provider that can return different DNS answers based on the visitor's geographic region or resolver location. It supplies its own authoritative nameservers. The domain's nameservers at IRNIC must be changed to those provider-supplied nameservers only after configuration and validation.
2. **Iran proxy/cache origin:** A real server-side service in Iran that receives HTTP/HTTPS requests and fetches the correct origin content. A shared-hosting account can only serve this role if its actual hosting capabilities support the required proxy behavior.
3. **Management application:** This React application manages projects, provider credentials, DNS records, routing policies, health checks, cache policies, and deployment instructions. It does not replace systems 1 or 2.

Do not build a custom authoritative DNS server inside this web application. Do not attempt to bind port 53 from a normal shared-hosting web application.

---

# 2. Main Product Goal

Build a secure, multi-project dashboard that allows the owner to add and manage multiple websites.

For each website, the owner should be able to configure:

- Project name.
- Domain name.
- Existing Cloudflare origin/target configuration.
- Iran proxy hostname or IP address.
- GeoDNS provider and DNS zone.
- Iran routing destination.
- International routing destination.
- Static asset caching policy.
- Dynamic/API bypass policy.
- SSL/TLS configuration status.
- Health-check endpoints.
- DNS deployment status.
- Cache status and purge actions, where supported.

The desired routing behavior for every configured domain is:

- Visitors identified by the GeoDNS provider as being in Iran receive the configured Iran proxy destination.
- Visitors outside Iran receive the configured Cloudflare destination.
- Dynamic application/API requests must continue to reach the correct application origin and must not be accidentally cached.
- Static assets may be cached at the Iran proxy only when the proxy implementation supports safe caching and the asset is eligible.
- If GeoDNS classification is uncertain or unavailable, the system must use a configurable safe fallback, preferably the existing Cloudflare route.

The system must explain that GeoDNS often identifies the location of the recursive DNS resolver rather than the end user's exact physical location. VPNs, public DNS resolvers, mobile carrier DNS, and DNS caching can affect the result. Do not promise perfect country detection.

---

# 3. Recommended Application Stack

Build the management panel with:

- React
- TypeScript
- Vite
- Responsive design
- A clean component architecture
- Strict TypeScript types
- Environment-based configuration
- A backend API layer separated from the frontend

Preferred backend options, in order:

1. Use the existing Cloudflare Workers + D1 infrastructure for the management API and persistent configuration, if the owner chooses to host the management backend there.
2. If the owner explicitly confirms that the Iranian shared host supports Node.js applications, a small Node.js backend may be used for supported hosting tasks.
3. Do not make the frontend call DNS-provider secret APIs directly.

The frontend may be deployed independently. The management backend must be deployed in an environment capable of securely storing secrets and making outbound HTTPS API calls.

Do not put API tokens, DNS provider credentials, Cloudflare API tokens, or secret keys in Vite environment variables that are exposed to the browser. Do not store secrets in localStorage, sessionStorage, browser IndexedDB, or frontend source code.

Use server-side secrets (for example, Cloudflare Worker Secrets or the hosting provider's secure environment-variable facility).

---

# 4. Multi-Project Dashboard

Create a dashboard with a project selector and a list/grid of all managed websites.

Each project must have an isolated configuration. Editing one project must never alter another project's settings.

## Project fields

Required:

- `id`
- `projectName`
- `domain`
- `status`
- `createdAt`
- `updatedAt`

Optional:

- `description`
- `iranProxyHostname`
- `iranProxyIPv4`
- `iranProxyIPv6`
- `cloudflareTarget`
- `cloudflareZoneId`
- `geoDnsProvider`
- `geoDnsZoneId`
- `healthCheckUrl`
- `notes`

Do not require an Iran proxy IP before a project can be created. Allow projects to be saved in a `draft` or `not_configured` state.

## Project statuses

Use explicit statuses such as:

- Draft
- Needs infrastructure verification
- GeoDNS not configured
- DNS configured
- Waiting for nameserver delegation
- Proxy not verified
- SSL not verified
- Operational
- Degraded
- Failed

A project may only be marked **Operational** when the required provider operations and health checks have actually succeeded.

---

# 5. GeoDNS Provider Integration

Create a provider abstraction layer. Do not hard-code one vendor's API into the UI.

Define a TypeScript interface similar to:

```ts
interface GeoDnsProvider {
  validateCredentials(): Promise<ProviderValidationResult>;
  listZones(): Promise<GeoDnsZone[]>;
  getZone(zoneId: string): Promise<GeoDnsZone>;
  createOrUpdateRecord(
    zoneId: string,
    record: GeoDnsRecordInput
  ): Promise<GeoDnsOperationResult>;
  listRecords(zoneId: string): Promise<GeoDnsRecord[]>;
  deleteRecord(zoneId: string, recordId: string): Promise<GeoDnsOperationResult>;
  getNameservers(zoneId: string): Promise<string[]>;
  checkDelegation(domain: string): Promise<DelegationStatus>;
}
```

Adapt the interface to the selected provider's real API. Do not invent API endpoints, payloads, authentication schemes, response fields, or provider capabilities.

## Provider configuration

The application should allow:

- Selecting a supported provider.
- Entering credentials securely through the backend.
- Validating credentials.
- Selecting a DNS zone.
- Retrieving the provider's actual authoritative nameservers.
- Viewing supported geographic routing features.
- Viewing TTL limits and record-type limitations.
- Viewing whether health checks, failover, weighted routing, and IPv6 are supported.

The application must not assume that every DNS provider supports country-level routing or separate answers for Iran and the rest of the world.

If no verified provider integration is available, show a clearly labeled **Manual Provider Setup** mode. In this mode, the UI may display configuration instructions, but must not pretend that records were deployed.

## DNS record management

Support only record types confirmed by the selected provider.

Potential record types:

- A
- AAAA
- CNAME
- TXT, only when required for verification

Provide separate routing rules for:

- Iran
- Default / rest of world

Allow a configurable fallback route.

Important DNS limitations:

- A CNAME cannot coexist with other record types at the same hostname.
- The DNS provider may impose restrictions on apex/root-domain CNAME records.
- Some providers use ALIAS/ANAME or flattening for apex domains.
- A DNS answer does not itself perform HTTP reverse proxying.
- DNS TTL and recursive resolver caching mean routing changes are not instantly visible everywhere.
- The DNS provider's authoritative nameservers must be obtained from the provider. Never invent nameservers.

Before any nameserver change, display a migration checklist:
1. Export or record current DNS records.
2. Recreate all required records at the new authoritative provider.
3. Verify MX, TXT, SPF, DKIM, DMARC, verification records, subdomains, and application records.
4. Verify DNSSEC/DS-record requirements and avoid leaving an invalid DS record at the registrar.
5. Confirm the new zone answers correctly.
6. Only then instruct the owner to update nameservers at IRNIC.
7. Recheck delegation after propagation.

Do not automatically change IRNIC nameservers unless a verified IRNIC API integration exists and the owner explicitly confirms the action. Otherwise provide accurate manual instructions.

---

# 6. Iran Proxy and Static Asset Cache

The application must have a dedicated **Iran Proxy** configuration page for each project.

However, the application must first verify the hosting environment. A shared Linux host without root access may not support a reliable reverse proxy.

## Hosting capability verification

Create a checklist and test plan for the owner to verify:

- Is Node.js available?
- Which Node.js versions are supported?
- Can a Node.js app remain running persistently?
- Is there a hosting control-panel feature for Node.js applications?
- Can the app make outbound HTTPS requests to Cloudflare?
- Are long-running HTTP requests supported?
- Is response streaming supported?
- Are request/response body size limits documented?
- Are custom rewrite/proxy rules supported?
- Can the domain use a valid SSL certificate?
- Is there a documented cache facility?
- Can the hosting provider configure reverse proxy rules on the owner's behalf?

Do not run intrusive or unauthorized tests. Use safe, small HTTPS checks only.

Show each capability as:

- Supported
- Unsupported
- Not tested
- Provider confirmation required

If the host cannot reliably run a proxy, show a clear recommendation to use a small Iran-based VPS or a managed proxy/CDN service. Do not silently substitute a normal static website host for a reverse proxy.

## Proxy behavior requirements

When a compatible proxy service is available, its intended behavior is:

- Accept HTTPS requests for the project domain.
- Fetch eligible requests from the configured Cloudflare origin.
- Preserve the original Host header when required by the origin architecture.
- Use correct TLS SNI and certificate validation.
- Preserve relevant request headers.
- Avoid forwarding hop-by-hop headers.
- Correctly handle redirects.
- Correctly handle compressed responses.
- Support GET and HEAD for static assets.
- Avoid caching POST, PUT, PATCH, DELETE, authenticated, or private responses.
- Avoid caching requests with cookies unless explicitly proven safe.
- Avoid caching API, authentication, account, checkout, payment, admin, and personalized endpoints.
- Prevent open-proxy behavior: only allow explicitly configured domains and upstream origins.
- Prevent SSRF: reject arbitrary user-supplied upstream URLs, private IP ranges, link-local addresses, localhost, and unapproved destinations.
- Apply timeouts, size limits, rate limits, and logging.
- Never expose origin credentials or provider tokens to the browser.

Do not implement a generic public URL fetcher.

## Static asset cache policy

Default cache policy:

| Resource | Default behavior |
|---|---|
| Vite hashed JS assets | Cache long-term, ideally one year, immutable |
| Vite hashed CSS assets | Cache long-term, ideally one year, immutable |
| Versioned images | Cache long-term |
| WebP/AVIF/SVG images | Cache long-term if public |
| Fonts | Cache long-term if public |
| HTML entry document | Revalidate or use a short TTL |
| API endpoints | Bypass cache by default |
| Authentication/session endpoints | Never cache |
| Admin/dashboard endpoints | Never cache |
| User-specific/private responses | Never cache |
| POST/PUT/PATCH/DELETE | Never cache |

The actual cache TTL must respect the origin's `Cache-Control`, `ETag`, `Last-Modified`, and `Vary` behavior, unless an explicitly approved policy overrides it.

Do not cache a response containing `Set-Cookie`, `Cache-Control: private`, or `Cache-Control: no-store`.

For Vite builds, detect hashed assets where possible. Do not assume every `.js` or `.css` file is immutable.

Provide:
- Cache status
- Cache hit/miss where the proxy exposes it
- Cache TTL
- Last purge time
- Purge by project
- Purge by URL, if supported
- Purge-all warning and confirmation
- Clear explanation when cache metrics are unavailable

Never claim cache is active just because a cache policy was saved. Confirm it with real response headers or proxy telemetry.

---

# 7. Cloudflare Integration

Create an optional Cloudflare integration module.

Support only verified API operations and least-privilege tokens.

Potential features:

- Validate Cloudflare credentials.
- List zones accessible to the token.
- Retrieve zone IDs.
- Inspect DNS records.
- Inspect relevant Worker routes and custom domains where supported by the API.
- Read relevant configuration and status.
- Trigger cache purge only if explicitly configured and authorized.
- Perform safe health checks against configured public URLs.

Do not modify existing Cloudflare DNS records, Worker routes, custom domains, or D1 databases without an explicit user confirmation.

Do not assume that the Cloudflare origin is always a fixed IP. Workers custom domains and routes can have architecture-specific behavior. The integration must inspect and document the actual origin/target arrangement for each project.

Do not expose Cloudflare API tokens in frontend code or logs.

---

# 8. Project Routing Configuration UI

For each project, create a visual routing editor.

Show:

- Domain
- Iran route destination
- International route destination
- Default/fallback route
- GeoDNS provider
- DNS zone
- TTL
- Proxy health
- SSL status
- Cache policy
- Last DNS synchronization
- Last health check

Provide a simple diagram:

```text
                    Visitor
                       |
                    GeoDNS
                       |
             +---------+---------+
             |                   |
          Iran visitor       Other visitors
             |                   |
       Iran proxy/cache       Cloudflare
             |                   |
       Cloudflare origin      Workers / D1
             |                   |
             +---------+---------+
                       |
                 Application
```

The diagram is conceptual. The implementation must reflect the project's actual configured topology. Do not draw a connection that is not configured.

Add a **Validate Configuration** action that runs read-only checks first.

Add a separate **Deploy DNS Changes** action. Before deployment:
- Show a summary of all changes.
- Show current and proposed records.
- Warn about DNS propagation and email records.
- Require explicit confirmation.
- Record the operation in an audit log.

---

# 9. Health Checks and Diagnostics

Create a diagnostics page per project.

Possible checks:

- DNS resolution from configured test resolvers, if a reliable backend check is available.
- Authoritative nameserver delegation.
- A/AAAA/CNAME answers.
- Iran proxy URL reachability.
- Cloudflare destination reachability.
- TLS certificate validity and expiry.
- HTTP status code.
- Redirect chain.
- Response headers.
- Cache headers.
- API bypass behavior.
- Basic latency measurements from the backend's actual test location.

Important:
- A test performed from a server outside Iran cannot prove that the Iran route works from inside Iran.
- Label test locations accurately.
- Do not fabricate Iran-based test results.
- If an external monitoring agent is required inside Iran, explain that it must be deployed separately.
- Do not treat a successful DNS lookup as proof that the proxy works.

Use clear result states: Passed, Failed, Warning, Not tested.

---

# 10. Security Requirements

Security is mandatory.

Implement:

- Authenticated admin access.
- Secure session handling.
- Role-based access if multiple users are supported.
- CSRF protection where applicable.
- Rate limiting.
- Server-side input validation.
- Strict domain and hostname validation.
- Secret encryption at rest where supported.
- No secrets in frontend bundles.
- No secrets in logs.
- Audit logs for changes and deployments.
- Confirmation for destructive operations.
- Safe error messages that do not leak credentials or internal infrastructure.
- Protection against SSRF, open proxy abuse, DNS rebinding risks, and arbitrary upstream configuration.
- Restrict management API access.
- Use HTTPS everywhere.

Do not build public endpoints that allow unauthenticated users to create DNS records, change routing, purge caches, or choose arbitrary proxy origins.

---

# 11. Data Model

Design a database schema that supports multiple projects.

Suggested entities:

## projects
- id
- project_name
- domain
- description
- status
- created_at
- updated_at

## project_origins
- id
- project_id
- origin_type
- origin_hostname
- origin_ip
- origin_port
- tls_mode
- created_at
- updated_at

## dns_provider_accounts
- id
- provider_name
- account_label
- encrypted_credentials_reference
- created_at
- updated_at

Do not store raw API tokens in this table. Store a secure secret reference or use the platform's secret store.

## dns_zones
- id
- project_id
- provider_account_id
- provider_zone_id
- domain
- authoritative_nameservers_json
- delegation_status
- updated_at

## routing_rules
- id
- project_id
- region_code
- record_type
- hostname
- destination
- ttl
- enabled
- updated_at

## cache_policies
- id
- project_id
- path_pattern
- resource_type
- cache_behavior
- ttl_seconds
- enabled
- updated_at

## health_checks
- id
- project_id
- check_type
- target
- status
- checked_at
- result_summary

## audit_logs
- id
- actor_id
- project_id
- action
- result
- created_at

Add appropriate foreign keys, indexes, validation, and migration scripts.

If Cloudflare D1 is selected, use D1-compatible SQL and migrations.

---

# 12. User Interface and Design

Create a professional, modern, responsive infrastructure-management dashboard.

Design goals:

- Clean enterprise SaaS appearance.
- Desktop-first but fully responsive on mobile.
- Clear visual hierarchy.
- Dark and light theme support.
- Accessible color contrast.
- Clear status labels.
- No decorative charts with fabricated data.
- Empty states for new installations.
- Loading, success, warning, and error states.
- Confirmation dialogs for dangerous operations.
- Persian and English localization should be possible in the architecture, but implement English as the initial default language.
- Use consistent terminology: GeoDNS, authoritative nameservers, reverse proxy, origin, cache, TTL, delegation.

Main navigation:

1. Overview
2. Projects
3. DNS Providers
4. Proxy Infrastructure
5. Diagnostics
6. Activity Logs
7. Settings

Project detail tabs:

1. Overview
2. Routing
3. DNS Records
4. Proxy & Cache
5. Cloudflare
6. Health Checks
7. Audit Log

Do not display fake metrics. Use empty states or clearly marked demo data only when running in demo mode.

---

# 13. Setup Wizard

On first launch, provide a guided setup wizard:

### Step 1: Create first project
Ask for project name and domain.

### Step 2: Verify Iranian hosting
Ask the owner to confirm hosting capabilities. Explain that shared hosting without root access may not support reverse proxying.

### Step 3: Configure GeoDNS provider
Allow the owner to connect a supported provider or use manual setup.

### Step 4: Configure destinations
Ask for:
- Iran proxy hostname/IP, if available.
- Existing Cloudflare destination/target.
- Fallback destination.

### Step 5: Configure cache policy
Offer safe defaults for static assets and bypass rules for dynamic/private requests.

### Step 6: Validate
Run read-only checks and show missing requirements.

### Step 7: Deployment checklist
Provide provider-specific instructions for DNS records and IRNIC nameserver delegation. Do not make changes without explicit confirmation.

---

# 14. Implementation Strategy

Build the application in phases. Do not generate a huge unstructured code dump.

## Phase 1: Working management dashboard
- React/Vite/TypeScript UI.
- Multi-project CRUD.
- Project status and configuration.
- Persistent database integration.
- Secure backend API architecture.
- No fake provider deployment.

## Phase 2: Provider abstraction
- Implement one real GeoDNS provider only after its current official API documentation is available.
- Validate credentials.
- List zones and nameservers.
- Read and update supported DNS records.
- Add audit logs.

## Phase 3: Cloudflare integration
- Secure server-side credential handling.
- Read-only discovery first.
- Add explicitly confirmed operations only.

## Phase 4: Hosting capability checks
- Provide safe checks and a guided manual checklist.
- Determine whether the Iranian shared host can actually run a proxy.
- Do not deploy an unsupported proxy implementation.

## Phase 5: Proxy/cache integration
- Implement only when a compatible proxy runtime exists.
- Use an allowlisted origin per project.
- Implement static-only cache rules and dynamic bypass.
- Add real cache diagnostics and purge support.

## Phase 6: Production hardening
- Security review.
- Error handling.
- Database migrations.
- Backup/export.
- Rate limiting.
- Audit log review.
- Deployment documentation.

At the end of every phase:
- Summarize completed features.
- List missing infrastructure.
- List assumptions that still need verification.
- Provide exact deployment steps.
- Do not mark incomplete features as complete.

---

# 15. Required Deliverables

Generate:

1. Complete React + TypeScript + Vite application.
2. Clear folder structure.
3. Database schema and migrations.
4. Backend API implementation.
5. Provider adapter interfaces.
6. Secure environment variable example file with placeholders only.
7. Setup instructions.
8. Deployment instructions for the chosen backend.
9. GeoDNS provider integration documentation.
10. IRNIC nameserver migration checklist.
11. Shared-hosting capability verification guide.
12. Proxy/cache deployment guide for a compatible environment.
13. Security checklist.
14. Troubleshooting guide.

Include a `README.md` with architecture diagrams and setup steps.

Include `.env.example`, but never include real credentials.

---

# 16. Mandatory Engineering Rules

- Never invent DNS provider API endpoints.
- Never invent authoritative nameservers or IP addresses.
- Never claim that a DNS record is deployed unless the provider confirms it.
- Never claim that a proxy is running unless a real health check confirms it.
- Never claim that caching is working unless response headers or telemetry confirm it.
- Never assume root access on the Iranian shared host.
- Never attempt to run an authoritative DNS server on the shared host.
- Never expose API tokens in browser code.
- Never cache authenticated or personalized responses by default.
- Never route all traffic through Iran unless the project owner explicitly chooses that mode.
- Preserve the existing Cloudflare architecture for international visitors.
- Keep each project's configuration isolated.
- Use safe fallback behavior.
- Prefer reversible, read-only validation before deployment.
- Require explicit confirmation before DNS changes.
- Make unsupported infrastructure requirements visible in the UI.

## First response expected from you

Before writing the full application, respond with:

1. Your understanding of the architecture.
2. A clear diagram of the intended traffic flow.
3. A list of infrastructure facts that remain unknown.
4. A proposed folder structure.
5. A phased implementation plan.
6. A short list of decisions that genuinely block implementation.

Do not assume that the shared Linux hosting can act as a reverse proxy. The first technical task is to establish what that host can actually run. Then implement the management dashboard around verified capabilities.
