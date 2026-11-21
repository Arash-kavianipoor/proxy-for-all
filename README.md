# GeoRoute Manager

**GeoRoute Manager** is a full-stack infrastructure control plane for managing multiple websites that route visitors in Iran through a verified Iran-based reverse proxy/cache while keeping international visitors on existing Cloudflare infrastructure (Cloudflare Workers + D1 + React/Vite).

---

## 1. Architecture Separation

GeoRoute Manager explicitly separates three distinct systems:

```text
                    Visitor / Recursive Resolver
                                |
                       Authoritative GeoDNS
             (ClouDNS / IBM NS1 Connect / Manual Provider)
                                |
              +-----------------+-----------------+
              |                                   |
       Iran Resolver (IR)                International / Fallback
              |                                   |
    Verified Iran Proxy / Cache              Cloudflare Edge
    (Only when host verified)            (Workers / D1 / Origins)
              |                                   |
              +-----------------+-----------------+
                                |
                         Application Origin
```

1. **Authoritative GeoDNS Provider**: Managed via server-side provider adapters (`ClouDNS`, `IBM NS1 Connect`, or `Manual Provider Setup`). GeoRoute Manager never runs a port 53 DNS server.
2. **Iran Proxy / Cache Origin**: Separate server-side infrastructure inside Iran. GeoRoute Manager enforces a 12-item hosting capability checklist before enabling Iran routing because shared Linux hosting without root access cannot install system Nginx or guarantee persistent reverse-proxy workers.
3. **Management Control Plane (This App)**: React + Vite + TypeScript frontend backed by an Express + SQLite (D1-compatible schema) backend handling authenticated sessions, AES-256-GCM encrypted credentials, diff previews, read-only Cloudflare discovery, and live diagnostics.

---

## 2. Tech Stack & Folder Structure

- **Frontend**: React 19, Vite, TypeScript, Tailwind CSS v4 (`Plus Jakarta Sans`, `DM Sans`, `JetBrains Mono`)
- **Backend**: Node.js 22 (`tsx server.ts`), Express, `node:sqlite` (`DatabaseSync`), `node:crypto` (scrypt + AES-256-GCM + HMAC-SHA256)
- **Migrations**: `migrations/0001_initial.sql`, `migrations/0002_phase2_geodns_cloudflare.sql` (SQLite & Cloudflare D1 compatible)
- **Tests**: `vitest` (`tests/georoute.test.ts`)

```text
├── docs/
│   └── PHASE_2_PROVIDER_INTEGRATION.md
├── migrations/
│   ├── 0001_initial.sql
│   └── 0002_phase2_geodns_cloudflare.sql
├── server/
│   ├── app.ts                # Express API routes, auth, CSRF, rate limiting
│   ├── crypto.ts             # scrypt, AES-256-GCM, HMAC cookies, secret redaction
│   ├── db.ts                 # SQLite connection, migration runner, project defaults
│   ├── deployment.ts         # DNS diff preview, conflict detection, read-back verification
│   ├── diagnostics.ts        # Live DNS, TLS cert, HTTP header probes (SSRF-guarded)
│   ├── security.ts           # Domain/IP validation, SSRF & DNS-rebinding guard
│   └── providers/
│       ├── capabilities.ts   # Evidence-based provider comparison matrix
│       ├── cloudflare.ts     # Read-only Cloudflare API v4 discovery client
│       ├── cloudns.ts        # ClouDNS HTTP JSON API adapter
│       ├── delegation.ts     # Authoritative NS delegation checker
│       ├── index.ts          # Provider factory
│       ├── manual.ts         # Manual Setup fallback adapter
│       ├── ns1.ts            # IBM NS1 Connect REST v1 adapter
│       └── types.ts          # Strict GeoDnsProvider interface
├── src/
│   ├── components/           # UI pages, ProjectDetail 7-tab workspace, Setup Wizard
│   ├── lib/api.ts            # Typed frontend API client (in-memory CSRF only)
│   └── types/georoute.ts     # Shared TypeScript interfaces
├── tests/georoute.test.ts    # Automated security, adapter, and API tests
├── .env.example
└── server.ts
```

---

## 3. Local Development & Testing

```bash
# 1. Copy environment placeholders and set strong secrets
cp .env.example .env

# 2. Install dependencies
npm install

# 3. Start full-stack dev server on port 3000
npm run dev

# 4. Run type checks, tests, and production build
npm run lint
npm test
npm run build
```

On first launch, open `http://localhost:3000` and create the primary administrator account via the setup form.

---

## 4. Environment Variables (Placeholders Only)

| Variable | Purpose |
|---|---|
| `PORT` | HTTP port (`3000`) |
| `SESSION_SECRET` | 32+ char secret for HMAC-signed `HttpOnly` session cookies |
| `CREDENTIAL_ENCRYPTION_KEY` | 32+ char master secret for AES-256-GCM credential encryption at rest |
| `DATABASE_PATH` | SQLite file path (default `./data/georoute.db`) |
| `DIAGNOSTICS_LOCATION_LABEL` | Accurate label describing where backend diagnostics execute |

Never expose credentials in `VITE_*` variables or browser storage (`localStorage`/`sessionStorage`).

---

## 5. Security Checklist

- [x] Authenticated admin access (`scrypt` salted password hashing + HMAC-signed `HttpOnly` cookies)
- [x] Per-session `X-CSRF-Token` verification on all mutating API requests
- [x] Sliding-window rate limiting on auth and API endpoints
- [x] AES-256-GCM encryption at rest for DNS provider & Cloudflare credentials
- [x] Secret masking (`****1234`) and automatic redaction in logs and error responses
- [x] Strict project and account ownership isolation (`owner_id` enforced on every query)
- [x] SSRF and DNS-rebinding protection blocking localhost, RFC1918, and `169.254.0.0/16`
- [x] Two-step DNS deployment requiring live diff preview hash + explicit admin confirmation
- [x] Operational status gating (cannot mark `Operational` until deployment confirmed, delegation verified, and health checks pass)
- [x] Cache safety rules prohibiting default caching of `/api/*`, `/auth/*`, `/admin/*`, `Set-Cookie`, `private`, or `no-store` responses

---

## 6. IRNIC Nameserver Migration Checklist & DNSSEC Warning

1. Export or record your existing DNS zone records.
2. Recreate website (`A`/`AAAA`/`ALIAS`/`CNAME`), `MX`, `SPF`, `DKIM`, `DMARC`, verification `TXT`, and subdomain records at the new GeoDNS provider.
3. **DNSSEC Warning**: Inspect DNSSEC / `DS` records at IRNIC before changing nameservers. Leaving a stale `DS` record at IRNIC when moving to a new DNS provider will break domain resolution globally.
4. Query the new provider zone directly and verify answers.
5. Update authoritative nameservers manually in the IRNIC control panel using the exact nameservers retrieved from your provider.
6. Re-run **Check NS Delegation** in GeoRoute Manager after propagation.

---

## 7. Shared-Hosting Verification & Proxy Deployment Guide

Before routing Iranian visitors away from Cloudflare:
1. Complete the 12-item **Hosting Capability Verification Checklist** under `Project > Proxy & Cache`.
2. If the shared host lacks persistent Node.js, outbound HTTPS to Cloudflare, valid SSL, or reverse-proxy support, **do not deploy a workaround proxy**. Provision an Iran-based VPS (Nginx/Caddy reverse proxy with strict upstream allowlisting) or a managed Iranian CDN.
3. Confirm static-asset caching via actual response headers (`Cache-Control`, `ETag`, cache hit/miss) before treating caching as active.

---

## 8. Troubleshooting

- **Preview shows `Blocking Conflicts Detected`**: Check for missing `DEFAULT` fallback rules, CNAME at the zone apex (use `A`, `AAAA`, or provider `ALIAS`), or a CNAME coexisting with another record on the same hostname.
- **Diagnostics pass from backend, but Iran users report issues**: Remember that the control plane runs outside Iran. GeoDNS routes based on recursive resolver location; verify from an actual Iranian ISP network using `dig` / `nslookup` and HTTPS checks.
- **Cloudflare discovery flags `Requires Architecture Review`**: The zone uses Cloudflare Workers routes or Worker Custom Domains, which bind to Cloudflare edge routing rather than a conventional origin IP. Review how the Iran proxy will reach the Worker hostname before enabling `IR` GeoDNS.
