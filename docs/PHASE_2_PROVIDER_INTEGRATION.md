# Phase 2 — GeoDNS Provider Integration & Cloudflare Read-Only Discovery

**Verification Date:** `2026-11-15`

---

## 1. Evidence-Based GeoDNS Provider Comparison

All provider capabilities below were verified against official vendor documentation on `2026-11-15`. GeoRoute Manager never invents endpoints, headers, or nameservers, and never selects a paid plan automatically.

| Capability | ClouDNS (GeoDNS) | IBM NS1 Connect | Manual Provider Setup |
|---|---|---|---|
| **Country-Level GeoDNS** | Supported | Supported (`geofence_country` / `geotarget_country`) | Requires vendor confirmation |
| **Iran (`IR`) Specific Rule** | Supported (Country override under Middle East hierarchy) | Requires vendor confirmation (supports ISO country code `IR`, but confirm IBM regional/export compliance) | Requires vendor confirmation |
| **Global / Default Fallback** | Supported (`DEFAULT` location) | Supported (Answer with empty `meta: {}` + `labelfallback: true`) | Requires vendor confirmation |
| **Supported GeoDNS Record Types** | `A`, `AAAA`, `CNAME`, `ALIAS`, `SRV`, `NAPTR` | `A`, `AAAA`, `CNAME`, `ALIAS`, `TXT`, etc. via Filter Chains | Provider-dependent |
| **Apex / Root Domain Handling** | Native `ALIAS` record + `A`/`AAAA` | Native `ALIAS` record + `A`/`AAAA` | Provider-dependent |
| **API Auth Method** | `auth-id` (or `sub-auth-id`) + `auth-password` over HTTPS | `X-NSONE-Key: <API_KEY>` header (`https://api.nsone.net/v1`) | None |
| **EDNS Client Subnet (ECS)** | Supported | Supported (falls back to recursive resolver location) | Provider-dependent |
| **DNSSEC Support** | Supported | Supported | Provider-dependent |
| **Pricing & Free Tier Limits** | **Free Forever plan does NOT include HTTP API or GeoDNS.** GeoDNS plans start at **$9.95/month** (includes Anycast, ECS, DNSSEC, HTTP API). | 30-day trial transitions to Free Edition (5M queries/mo, 500 records, **1 Filter Chain total**). Multi-record GeoDNS requires Essentials ($99+/mo) or Standard ($152+/mo). | $0 (Control plane planning only) |

### Official Documentation References (Checked 2026-11-15)

- **ClouDNS**
  - GeoDNS Overview & Record Types: `https://www.cloudns.net/wiki/article/190/`
  - GeoDNS Locations API (`get-geodns-locations.json`): `https://www.cloudns.net/wiki/article/313/`
  - HTTP API Reference (`list-zones.json`, `get-zone-info.json`, `list-records.json`, `add-record.json`, `mod-record.json`, `delete-record.json`): `https://www.cloudns.net/wiki/article/42/`
  - GeoDNS Plans & Pricing: `https://www.cloudns.net/geodns/`
- **IBM NS1 Connect**
  - REST API v1 Introduction (`https://api.nsone.net/v1`, `X-NSONE-Key`): `https://developer.ibm.com/apis/catalog/ns1--ibm-ns1-connect-api/Introduction`
  - Geotargeting & Geofencing Filter Chains (`geofence_country`, `geotarget_country`, `up`): `https://www.ibm.com/docs/en/ns1-connect?topic=chains-geotargeting-filters`
  - Plans & Free Edition Limits: `https://www.ibm.com/products/ns1-connect/pricing`
- **Cloudflare API v4 (Read-Only Discovery)**
  - Verify Token (`GET /user/tokens/verify`): `https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/verify/`
  - Zones & Zone Settings (`GET /zones`, `GET /zones/{zone_id}/settings/ssl`, `cache_level`): `https://developers.cloudflare.com/api/resources/zones/`
  - DNS Records (`GET /zones/{zone_id}/dns_records`): `https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/`
  - Workers Routes (`GET /zones/{zone_id}/workers/routes`): `https://developers.cloudflare.com/api/resources/workers/subresources/routes/methods/list/`
  - Workers Custom Domains (`GET /accounts/{account_id}/workers/domains`): `https://developers.cloudflare.com/api/resources/workers/subresources/domains/methods/list/`

---

## 2. Recommended Provider & Decision Notes

1. **ClouDNS GeoDNS ($9.95+/mo)** is the most practical low-cost API-backed option for multi-project Iran (`IR`) + `DEFAULT` GeoDNS routing with `ALIAS` apex flattening and `A`/`AAAA`/`CNAME` support—provided your account has an active GeoDNS plan (since the Free plan disables HTTP API and GeoDNS).
2. **IBM NS1 Connect** offers a free tier with API access, but restricts the Free Edition to **1 Filter Chain** across the entire account and requires confirming IBM regional/export compliance for Iranian domains.
3. **Manual Provider Setup** remains available at all times if you prefer an Iranian DNS provider (or want to test zone records manually before committing to a paid API plan).

---

## 3. Least-Privilege Token Permissions

### Cloudflare Discovery Token (Read-Only)
Create an API Token in Cloudflare with **Read** permissions only:
- `Zone > Zone > Read`
- `Zone > DNS > Read`
- `Zone > Zone Settings > Read`
- `Zone > Workers Routes > Read`
- `Account > Workers Scripts > Read` (optional, required for Worker Custom Domains listing)

GeoRoute Manager performs **zero** write requests against Cloudflare in Phase 2.

---

## 4. Phase 2 Scope Boundaries

Phase 2 explicitly does **not**:
- Deploy an Iran reverse proxy or install Nginx on shared hosting
- Run an authoritative DNS server on port 53
- Enable static-asset caching
- Automatically modify IRNIC nameservers
- Modify existing Cloudflare production DNS records, Worker routes, SSL modes, or D1 databases
