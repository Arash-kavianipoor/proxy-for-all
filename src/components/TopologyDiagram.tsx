import { ArrowDown } from 'lucide-react';
import { useI18n } from '../i18n/I18nContext';
import type { DnsZoneBinding, Project } from '../types/georoute';

interface TopologyDiagramProps {
  project: Project;
  dnsZone: DnsZoneBinding | null;
  resolvedCloudflareIps?: string[];
  cacheEntriesCount?: number;
}

export function TopologyDiagram({
  project,
  dnsZone,
  resolvedCloudflareIps = [],
  cacheEntriesCount = 0,
}: TopologyDiagramProps) {
  const { lang } = useI18n();
  const isFa = lang === 'fa';
  const currentHost =
    project.iranProxyHostname ||
    project.iranProxyIPv4 ||
    (typeof window !== 'undefined' ? window.location.host : 'this-host');

  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 sm:p-6">
      <div className="flex flex-wrap items-center justify-between gap-2 mb-5">
        <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
          {isFa ? 'مسیر اتصال امن دامنه به کلودفلر' : 'Secure Caching Proxy Flow'}
        </h2>
        <span className="text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400">
          {isFa ? `آیتم‌های کش‌شده: ${cacheEntriesCount}` : `Cached items: ${cacheEntriesCount}`}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-center">
        {/* Node 1: IRNIC Domain */}
        <div className="border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 rounded-md p-4 text-center">
          <div className="text-[11px] text-slate-500 dark:text-slate-400">
            {isFa ? '۱. دامنه در ایرنیک (کاربر ایران)' : '1. IRNIC Domain (Iran Visitor)'}
          </div>
          <div className="text-sm font-mono font-semibold text-slate-900 dark:text-slate-100 mt-1" dir="ltr">
            {project.domain}
          </div>
          {dnsZone?.authoritativeNameservers.length ? (
            <div className="text-[11px] font-mono text-slate-500 mt-1 truncate" dir="ltr">
              {dnsZone.authoritativeNameservers.join(', ')}
            </div>
          ) : null}
        </div>

        {/* Node 2: This Host Proxy & Cache */}
        <div className="border border-emerald-300 dark:border-emerald-800 bg-emerald-50/30 dark:bg-emerald-950/20 rounded-md p-4 text-center">
          <div className="text-[11px] font-semibold text-emerald-800 dark:text-emerald-300">
            {isFa ? '۲. پروکسی و کش امن (همین هاست)' : '2. Secure Cache Proxy (This Host)'}
          </div>
          <div className="text-xs font-mono text-slate-900 dark:text-slate-100 mt-1" dir="ltr">
            {currentHost}
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
            {isFa ? 'دریافت از کلودفلر و کش استاتیک' : 'Fetches from Cloudflare & caches static assets'}
          </div>
        </div>

        {/* Node 3: Cloudflare DNS */}
        <div className="border border-blue-300 dark:border-blue-800 bg-blue-50/30 dark:bg-blue-950/20 rounded-md p-4 text-center">
          <div className="text-[11px] font-semibold text-blue-800 dark:text-blue-300">
            {isFa ? '۳. DNSهای کلودفلر (مقصد اصلی)' : '3. Cloudflare DNS (Upstream)'}
          </div>
          <div className="text-xs font-mono text-slate-900 dark:text-slate-100 mt-1 break-all" dir="ltr">
            {project.cloudflareTarget || '—'}
          </div>
          {resolvedCloudflareIps.length > 0 && (
            <div className="text-[11px] font-mono text-emerald-700 dark:text-emerald-400 mt-1" dir="ltr">
              Edge IP: {resolvedCloudflareIps.join(', ')}
            </div>
          )}
        </div>
      </div>

      <div className="md:hidden flex justify-center pt-2 text-slate-400">
        <ArrowDown className="w-4 h-4" />
      </div>
    </div>
  );
}
