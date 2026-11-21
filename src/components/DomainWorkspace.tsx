import { useEffect, useState, type FormEvent } from 'react';
import {
  CheckCircle2,
  Copy,
  Eye,
  Globe,
  HardDrive,
  Play,
  Plus,
  RefreshCw,
  Rocket,
  Save,
  Server,
  Trash2,
} from 'lucide-react';
import { useI18n } from '../i18n/I18nContext';
import { api, type ProjectDetailResponse } from '../lib/api';
import type {
  DeploymentPreview,
  DnsProviderAccountSummary,
  GeoDnsZone,
  Project,
} from '../types/georoute';
import { TopologyDiagram } from './TopologyDiagram';

interface DomainWorkspaceProps {
  projects: Project[];
  selectedProjectId: string | null;
  dnsAccounts: DnsProviderAccountSummary[];
  onSelectProject: (id: string | null) => void;
  onOpenAddDomain: () => void;
  onOpenAddProvider: () => void;
  onRefreshWorkspace: () => Promise<void>;
}

export function DomainWorkspace({
  projects,
  selectedProjectId,
  dnsAccounts,
  onSelectProject,
  onOpenAddDomain,
  onOpenAddProvider,
  onRefreshWorkspace,
}: DomainWorkspaceProps) {
  const { lang } = useI18n();
  const isFa = lang === 'fa';

  const activeId =
    selectedProjectId && projects.some((p) => p.id === selectedProjectId)
      ? selectedProjectId
      : projects[0]?.id || null;

  const [detail, setDetail] = useState<ProjectDetailResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Form state
  const [proxyHost, setProxyHost] = useState('');
  const [proxyActive, setProxyActive] = useState(false);
  const [cloudflareNsInput, setCloudflareNsInput] = useState('');

  // Live Cloudflare NS resolution + Cache Proxy state
  const [resolvedIps, setResolvedIps] = useState<string[]>([]);
  const [nsMessage, setNsMessage] = useState('');
  const [testPath, setTestPath] = useState('/');
  const [testResult, setTestResult] = useState<{
    ok: boolean;
    statusCode: number;
    cacheStatus: string;
    targetIp: string;
    cfRay: string;
    latencyMs: number;
    bytes: number;
    error: string;
  } | null>(null);
  const [cacheStats, setCacheStats] = useState<{
    entries: number;
    totalBytes: number;
    totalHits: number;
    items: Array<{ path: string; contentType: string; bytes: number; hits: number; expiresAt: string }>;
  }>({ entries: 0, totalBytes: 0, totalHits: 0, items: [] });

  // Optional GeoDNS / IRNIC state
  const [accountId, setAccountId] = useState('');
  const [zones, setZones] = useState<GeoDnsZone[]>([]);
  const [zoneId, setZoneId] = useState('');
  const [copiedNs, setCopiedNs] = useState('');
  const [preview, setPreview] = useState<DeploymentPreview | null>(null);
  const [confirmDomain, setConfirmDomain] = useState('');
  const [confirmDeploy, setConfirmDeploy] = useState(false);

  const [deleteConfirm, setDeleteConfirm] = useState(false);

  async function loadProject(id: string) {
    setLoading(true);
    setError('');
    try {
      const [res, cacheRes] = await Promise.all([
        api.getProject(id),
        api.getProxyCache(id),
      ]);
      setDetail(res);
      setCacheStats(cacheRes.cache);

      const defaultHost =
        res.project.iranProxyIPv4 ||
        res.project.iranProxyHostname ||
        (typeof window !== 'undefined' ? window.location.hostname : '');
      setProxyHost(defaultHost);
      setProxyActive(res.project.notes.includes('proxy_active=true'));

      const formattedCf = (res.project.cloudflareTarget || '')
        .split(/[\s,;]+/)
        .filter(Boolean)
        .join('\n');
      setCloudflareNsInput(formattedCf);

      setAccountId(res.dnsZone?.providerAccountId || '');
      setZoneId(res.dnsZone?.providerZoneId || res.project.domain);
      setZones([]);
      setPreview(null);
      setResolvedIps([]);
      setNsMessage('');
      setTestResult(null);
      setDeleteConfirm(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : isFa ? 'خطا در بارگذاری دامنه.' : 'Failed to load domain.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (activeId) {
      loadProject(activeId);
    } else {
      setDetail(null);
    }
  }, [activeId]);

  async function handleAccountChange(nextAccountId: string) {
    setAccountId(nextAccountId);
    setZones([]);
    if (!nextAccountId || !detail) return;
    try {
      const res = await api.listProviderZones(nextAccountId);
      setZones(res.zones);
      const match = res.zones.find((z) => z.name === detail.project.domain);
      if (match) setZoneId(match.id);
      else if (res.zones[0]) setZoneId(res.zones[0].id);
    } catch (err) {
      setError(err instanceof Error ? err.message : isFa ? 'دریافت Zoneها ناموفق بود.' : 'Failed to load zones.');
    }
  }

  async function handleSaveConnection(e: FormEvent) {
    e.preventDefault();
    if (!detail) return;

    setBusy(true);
    setError('');
    setSuccess('');

    try {
      const normalizedCf = cloudflareNsInput
        .split(/[\n,;]+/)
        .map((line) => line.trim().toLowerCase())
        .filter(Boolean)
        .join(', ');

      const trimmedHost = proxyHost.trim();
      const isIpv4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(trimmedHost);
      const notesVal = proxyActive ? 'proxy_active=true' : '';

      await api.updateProject(detail.project.id, {
        cloudflareTarget: normalizedCf,
        iranProxyIPv4: isIpv4 ? trimmedHost : '',
        iranProxyHostname: !isIpv4 ? trimmedHost : '',
        notes: notesVal,
      });

      // Bind GeoDNS provider if selected
      const selectedAccount = dnsAccounts.find((a) => a.id === accountId);
      await api.bindProjectZone(detail.project.id, {
        providerName: selectedAccount ? selectedAccount.providerName : 'manual',
        providerAccountId: selectedAccount ? selectedAccount.id : null,
        providerZoneId: zoneId.trim() || detail.project.domain,
      });

      // Also resolve Cloudflare nameservers right away to verify connectivity
      const nsRes = await api.resolveCloudflareNs(detail.project.id, normalizedCf);
      setResolvedIps(nsRes.resolution.ipv4Addresses);
      setNsMessage(nsRes.resolution.message);

      // Sync IR and DEFAULT rules when real IPs are available
      if (isIpv4) {
        await api.upsertRoutingRule(detail.project.id, {
          hostname: detail.project.domain,
          regionCode: 'IR',
          recordType: 'A',
          destination: trimmedHost,
          ttl: 60,
          enabled: true,
        });
      }
      if (nsRes.resolution.ipv4Addresses[0]) {
        await api.upsertRoutingRule(detail.project.id, {
          hostname: detail.project.domain,
          regionCode: 'DEFAULT',
          recordType: 'A',
          destination: nsRes.resolution.ipv4Addresses[0],
          ttl: 300,
          enabled: true,
        });
      }

      setSuccess(
        isFa
          ? 'تنظیمات پروکسی و DNSهای کلودفلر ذخیره و استعلام شد.'
          : 'Proxy & Cloudflare DNS settings saved and resolved.'
      );
      await onRefreshWorkspace();
    } catch (err) {
      setError(err instanceof Error ? err.message : isFa ? 'ذخیره تنظیمات ناموفق بود.' : 'Failed to save configuration.');
    } finally {
      setBusy(false);
    }
  }

  async function handleResolveCloudflare() {
    if (!detail) return;
    setBusy(true);
    setError('');
    try {
      const normalizedCf = cloudflareNsInput
        .split(/[\n,;]+/)
        .map((line) => line.trim().toLowerCase())
        .filter(Boolean)
        .join(', ');
      const res = await api.resolveCloudflareNs(detail.project.id, normalizedCf);
      setResolvedIps(res.resolution.ipv4Addresses);
      setNsMessage(res.resolution.message);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'DNS resolution failed.');
    } finally {
      setBusy(false);
    }
  }

  async function handleTestProxy() {
    if (!detail) return;
    setBusy(true);
    setError('');
    try {
      const res = await api.testProxy(detail.project.id, { path: testPath.trim() || '/' });
      setTestResult(res.test);
      setCacheStats(res.cache);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Proxy test failed.');
    } finally {
      setBusy(false);
    }
  }

  async function handleClearCache() {
    if (!detail) return;
    setBusy(true);
    try {
      const res = await api.clearProxyCache(detail.project.id);
      setCacheStats(res.cache);
      setSuccess(isFa ? 'کش محلی این دامنه پاک شد.' : 'Local cache cleared.');
    } finally {
      setBusy(false);
    }
  }

  async function handleCheckDelegation() {
    if (!detail) return;
    setBusy(true);
    setError('');
    setSuccess('');
    try {
      const res = await api.checkDelegation(detail.project.id);
      setSuccess(res.delegation.message);
      await loadProject(detail.project.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Delegation check failed.');
    } finally {
      setBusy(false);
    }
  }

  async function handlePreview() {
    if (!detail) return;
    setBusy(true);
    setError('');
    try {
      const res = await api.getDeploymentPreview(detail.project.id);
      setPreview(res.preview);
      setConfirmDomain('');
      setConfirmDeploy(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate preview.');
    } finally {
      setBusy(false);
    }
  }

  async function handleDeploy() {
    if (!detail || !preview) return;
    setBusy(true);
    setError('');
    setSuccess('');
    try {
      const res = await api.deployDnsChanges(detail.project.id, {
        previewHash: preview.previewHash,
        confirmProjectDomain: confirmDomain.trim(),
        confirmProxyReady: confirmDeploy,
        confirmEmailRecordsPreserved: confirmDeploy,
        confirmDeployAction: confirmDeploy,
      });
      setSuccess(res.deployment.summary);
      setPreview(null);
      await loadProject(detail.project.id);
      await onRefreshWorkspace();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Deployment failed.');
    } finally {
      setBusy(false);
    }
  }

  if (projects.length === 0) {
    return (
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-10 text-center space-y-5">
        <div className="w-11 h-11 rounded-lg bg-blue-600/10 text-blue-600 dark:text-blue-400 flex items-center justify-center mx-auto">
          <Globe className="w-5 h-5" />
        </div>
        <div className="max-w-md mx-auto space-y-1.5">
          <h1 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
            {isFa ? 'هنوز دامنه‌ای ثبت نشده است' : 'No domain configured yet'}
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
            {isFa
              ? 'دامنه ایرنیک و دو آدرس DNS کلودفلر را وارد کنید تا همین هاست به عنوان پروکسی امن و کش به کلودفلر متصل شود.'
              : 'Add your IRNIC domain and Cloudflare nameservers so this host acts as a secure caching proxy.'}
          </p>
        </div>
        <button
          type="button"
          onClick={onOpenAddDomain}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-md cursor-pointer"
        >
          <Plus className="w-4 h-4" />
          <span>{isFa ? 'افزودن اولین دامنه' : 'Add First Domain'}</span>
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Domain Selector */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-1.5">
          {projects.map((p) => {
            const active = p.id === activeId;
            return (
              <button
                key={p.id}
                type="button"
                dir="ltr"
                onClick={() => onSelectProject(p.id)}
                className={`px-3.5 py-2 text-xs font-mono rounded-md border transition-colors cursor-pointer whitespace-nowrap ${
                  active
                    ? 'bg-blue-600 text-white border-blue-600 font-medium'
                    : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:border-slate-400'
                }`}
              >
                {p.domain}
              </button>
            );
          })}
        </div>

        <button
          type="button"
          onClick={onOpenAddDomain}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-md cursor-pointer whitespace-nowrap shrink-0"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>{isFa ? 'دامنه جدید' : 'Add Domain'}</span>
        </button>
      </div>

      {error && (
        <div className="p-3 rounded-md border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/30 text-xs text-red-700 dark:text-red-300">
          {error}
        </div>
      )}
      {success && (
        <div className="p-3 rounded-md border border-emerald-200 dark:border-emerald-900 bg-emerald-50 dark:bg-emerald-950/30 text-xs text-emerald-700 dark:text-emerald-300">
          {success}
        </div>
      )}

      {loading || !detail ? (
        <div className="p-8 text-xs text-slate-500 dark:text-slate-400">
          {isFa ? 'در حال بارگذاری...' : 'Loading...'}
        </div>
      ) : (
        <>
          <TopologyDiagram
            project={detail.project}
            dnsZone={detail.dnsZone}
            resolvedCloudflareIps={resolvedIps}
            cacheEntriesCount={cacheStats.entries}
          />

          {/* Section 1: Proxy Host (This Server) <-> Cloudflare Nameservers */}
          <form
            onSubmit={handleSaveConnection}
            className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-5"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {isFa ? '۱. اتصال پروکسی همین هاست به DNS کلودفلر' : '1. Connect This Proxy Host to Cloudflare DNS'}
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  {isFa
                    ? 'همین هاست به جای اتصال مستقیم، درخواست کاربران ایران را می‌گیرد و با کش محلی به کلودفلر منتقل می‌کند.'
                    : 'This host receives Iranian visitor traffic and securely forwards/caches requests to Cloudflare.'}
                </p>
              </div>
              <button
                type="button"
                disabled={busy}
                onClick={handleResolveCloudflare}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-slate-300 dark:border-slate-700 rounded-md hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>{isFa ? 'استعلام IP از کلودفلر' : 'Resolve Cloudflare IPs'}</span>
              </button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs">
              {/* This Host (Iran Proxy + Cache) */}
              <div className="border border-emerald-200 dark:border-emerald-900/60 bg-emerald-50/20 dark:bg-emerald-950/10 rounded-md p-4 space-y-3">
                <div className="flex items-center gap-1.5 font-semibold text-emerald-800 dark:text-emerald-300">
                  <Server className="w-3.5 h-3.5" />
                  <span>{isFa ? 'سرور پروکسی و کش ایران (همین هاست)' : 'Iran Proxy & Cache Host (This Server)'}</span>
                </div>
                <div>
                  <label className="block text-slate-600 dark:text-slate-400 mb-1">
                    {isFa ? 'آدرس یا IP همین هاست' : 'This Host Address / IPv4'}
                  </label>
                  <input
                    type="text"
                    dir="ltr"
                    value={proxyHost}
                    onChange={(e) => setProxyHost(e.target.value)}
                    placeholder={typeof window !== 'undefined' ? window.location.hostname : '185.x.x.x'}
                    className="w-full px-3 py-2 font-mono bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md"
                  />
                </div>
                <label className="flex items-start gap-2 text-slate-700 dark:text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={proxyActive}
                    onChange={(e) => setProxyActive(e.target.checked)}
                  />
                  <span>
                    {isFa
                      ? `فعال‌سازی دریافت مستقیم ترافیک دامنه (${detail.project.domain}) روی همین سرور`
                      : `Enable live reverse-proxy & cache when ${detail.project.domain} hits this host`}
                  </span>
                </label>
                {!proxyActive && (
                  <p className="text-[11px] text-amber-700 dark:text-amber-300 leading-relaxed">
                    {isFa
                      ? `در صورت خاموش بودن این تیک، با باز کردن ${detail.project.domain} صفحه ورود خود پنل نمایش داده می‌شود. این تیک را بزنید و دکمه «ذخیره و اتصال به کلودفلر» را کلیک کنید.`
                      : `While unchecked, opening ${detail.project.domain} displays this control panel. Check this and click Save to proxy traffic to Cloudflare.`}
                  </p>
                )}
                {typeof window !== 'undefined' && window.location.hostname.toLowerCase() === detail.project.domain.toLowerCase() && (
                  <p className="text-[11px] text-amber-700 dark:text-amber-300 leading-relaxed">
                    {isFa
                      ? 'نکته: این پنل اکنون روی همین دامنه باز است؛ برای فعال‌سازی پروکسی روی صفحه اصلی سایت، پنل را روی یک ساب‌دامنه (مثلاً panel) بالا بیاورید یا متغیر PANEL_HOSTNAME را تنظیم کنید.'
                      : 'Note: The admin panel is currently open on this same domain. Host the panel on a separate subdomain or set PANEL_HOSTNAME before enabling live root proxying.'}
                  </p>
                )}
              </div>

              {/* Cloudflare Nameservers */}
              <div className="border border-blue-200 dark:border-blue-900/60 bg-blue-50/20 dark:bg-blue-950/10 rounded-md p-4 space-y-3">
                <div className="font-semibold text-blue-800 dark:text-blue-300">
                  {isFa ? 'DNSهای کلودفلر (نیم‌سرورهای کلودفلر)' : 'Cloudflare DNS Nameservers'}
                </div>
                <div>
                  <label className="block text-slate-600 dark:text-slate-400 mb-1">
                    {isFa ? 'دو آدرس NS کلودفلر را وارد کنید' : 'Enter Cloudflare NS (one per line)'}
                  </label>
                  <textarea
                    dir="ltr"
                    rows={2}
                    required
                    value={cloudflareNsInput}
                    onChange={(e) => setCloudflareNsInput(e.target.value)}
                    placeholder={'dane.ns.cloudflare.com\ndolly.ns.cloudflare.com'}
                    className="w-full px-3 py-2 font-mono leading-relaxed bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md resize-y"
                  />
                </div>
                {nsMessage && (
                  <div className="text-[11px] font-mono text-slate-700 dark:text-slate-300 break-all" dir="ltr">
                    {nsMessage}
                  </div>
                )}
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 pt-1 border-t border-slate-200 dark:border-slate-800">
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span className="text-slate-500 dark:text-slate-400">
                  {isFa ? 'GeoDNS میانی:' : 'GeoDNS:'}
                </span>
                <select
                  value={accountId}
                  onChange={(e) => handleAccountChange(e.target.value)}
                  className="px-2.5 py-1.5 bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md"
                >
                  <option value="">{isFa ? 'بدون API (پروکسی همین هاست)' : 'Direct Proxy (No API)'}</option>
                  {dnsAccounts.map((acc) => (
                    <option key={acc.id} value={acc.id}>
                      {acc.accountLabel} ({acc.providerName.toUpperCase()})
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  onClick={onOpenAddProvider}
                  className="text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
                >
                  {isFa ? '+ اتصال ClouDNS / NS1' : '+ Connect Provider'}
                </button>
              </div>

              <button
                type="submit"
                disabled={busy}
                className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded-md cursor-pointer"
              >
                <Save className="w-3.5 h-3.5" />
                <span>{busy ? (isFa ? 'در حال ذخیره...' : 'Saving...') : isFa ? 'ذخیره و اتصال به کلودفلر' : 'Save & Connect'}</span>
              </button>
            </div>
          </form>

          {/* Section 2: Proxy Test + Local Cache & Optional GeoDNS IRNIC Nameservers */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Proxy Test & Cache Panel */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <HardDrive className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                  <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                    {isFa ? '۲. تست اتصال پروکسی و کش محلی' : '2. Proxy Test & Local Cache'}
                  </h2>
                </div>
                <button
                  type="button"
                  disabled={busy || cacheStats.entries === 0}
                  onClick={handleClearCache}
                  className="text-xs text-red-600 dark:text-red-400 hover:underline disabled:opacity-40 cursor-pointer"
                >
                  {isFa ? 'پاک‌سازی کش' : 'Clear Cache'}
                </button>
              </div>

              <div className="flex items-center gap-2 text-xs">
                <input
                  type="text"
                  dir="ltr"
                  value={testPath}
                  onChange={(e) => setTestPath(e.target.value)}
                  placeholder="/assets/app.js or /"
                  className="flex-1 px-3 py-2 font-mono bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md"
                />
                <button
                  type="button"
                  disabled={busy}
                  onClick={handleTestProxy}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 font-medium text-white bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 rounded-md cursor-pointer shrink-0"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>{isFa ? 'تست دریافت' : 'Test Proxy'}</span>
                </button>
              </div>

              {testResult && (
                <div className="p-3 rounded-md border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-xs space-y-1 font-mono" dir="ltr">
                  <div className="flex items-center justify-between">
                    <span>HTTP {testResult.statusCode} · Cache: {testResult.cacheStatus}</span>
                    <span className="tabular-nums">{testResult.latencyMs}ms · {testResult.bytes} B</span>
                  </div>
                  <div className="text-slate-500">
                    Edge: {testResult.targetIp || '—'} {testResult.cfRay ? `· CF-Ray: ${testResult.cfRay}` : ''}
                  </div>
                  {testResult.error && <div className="text-red-500">{testResult.error}</div>}
                </div>
              )}

              <div className="grid grid-cols-3 gap-3 text-center text-xs pt-1">
                <div className="p-2.5 rounded-md border border-slate-200 dark:border-slate-800">
                  <div className="text-slate-500">{isFa ? 'فایل‌های کش‌شده' : 'Cached'}</div>
                  <div className="text-base font-bold tabular-nums mt-0.5">{cacheStats.entries}</div>
                </div>
                <div className="p-2.5 rounded-md border border-slate-200 dark:border-slate-800">
                  <div className="text-slate-500">{isFa ? 'دفعات استفاده از کش' : 'Cache Hits'}</div>
                  <div className="text-base font-bold tabular-nums mt-0.5">{cacheStats.totalHits}</div>
                </div>
                <div className="p-2.5 rounded-md border border-slate-200 dark:border-slate-800">
                  <div className="text-slate-500">{isFa ? 'حجم کش' : 'Cache Size'}</div>
                  <div className="text-base font-bold tabular-nums mt-0.5" dir="ltr">
                    {(cacheStats.totalBytes / 1024).toFixed(1)} KB
                  </div>
                </div>
              </div>
            </div>

            {/* IRNIC Delegation & Optional GeoDNS Deploy */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {isFa ? '۳. وضعیت دامنه در ایرنیک و اعمال GeoDNS' : '3. IRNIC Status & GeoDNS Apply'}
                </h2>
                <button
                  type="button"
                  disabled={busy}
                  onClick={handleCheckDelegation}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-slate-300 dark:border-slate-700 rounded-md hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>{isFa ? 'بررسی ایرنیک' : 'Check IRNIC'}</span>
                </button>
              </div>

              {detail.dnsZone?.authoritativeNameservers.length ? (
                <div className="space-y-1.5">
                  {detail.dnsZone.authoritativeNameservers.map((ns) => (
                    <div
                      key={ns}
                      dir="ltr"
                      className="flex items-center justify-between px-3 py-2 text-xs font-mono bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-md"
                    >
                      <span>{ns}</span>
                      <button
                        type="button"
                        onClick={() => {
                          navigator.clipboard.writeText(ns);
                          setCopiedNs(ns);
                          setTimeout(() => setCopiedNs(''), 1500);
                        }}
                        className="inline-flex items-center gap-1 text-blue-600 dark:text-blue-400 font-sans cursor-pointer"
                      >
                        <Copy className="w-3 h-3" />
                        <span>{copiedNs === ns ? (isFa ? 'کپی شد' : 'Copied') : isFa ? 'کپی' : 'Copy'}</span>
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-3 rounded-md border border-dashed border-slate-300 dark:border-slate-700 text-xs text-slate-500 dark:text-slate-400 leading-relaxed space-y-1">
                  <div>
                    {isFa
                      ? `برای دریافت ترافیک ${detail.project.domain} روی همین هاست cPanel:`
                      : `To route ${detail.project.domain} through this cPanel host:`}
                  </div>
                  <div>
                    {isFa
                      ? '۱) در cPanel بخش Domains این دامنه را با تیک «Share document root» (هم‌مسیر با public_html) اضافه و SSL آن را فعال کنید.'
                      : '1) Add this domain in cPanel -> Domains with "Share document root" checked and issue AutoSSL.'}
                  </div>
                  <div>
                    {isFa
                      ? '۲) تیک «فعال‌سازی دریافت مستقیم ترافیک دامنه روی همین سرور» را در بخش ۱ بزنید و ذخیره کنید.'
                      : '2) Enable live reverse-proxy in Section 1 and save.'}
                  </div>
                </div>
              )}

              <div className="text-xs space-y-1 pt-1 border-t border-slate-200 dark:border-slate-800">
                <div className="flex items-center justify-between">
                  <span className="text-slate-500">{isFa ? 'نیم‌سرور فعلی روی اینترنت:' : 'Observed NS:'}</span>
                  {detail.dnsZone?.delegationStatus === 'verified' && (
                    <span className="inline-flex items-center gap-1 text-emerald-700 dark:text-emerald-400 font-medium">
                      <CheckCircle2 className="w-3.5 h-3.5" /> {isFa ? 'متصل' : 'Verified'}
                    </span>
                  )}
                </div>
                <div className="font-mono text-slate-700 dark:text-slate-300 break-all" dir="ltr">
                  {detail.dnsZone?.observedNameservers.length
                    ? detail.dnsZone.observedNameservers.join(', ')
                    : '—'}
                </div>
              </div>

              {detail.project.geoDnsProvider !== 'manual' && (
                <div className="pt-2 border-t border-slate-200 dark:border-slate-800 space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-medium text-slate-700 dark:text-slate-300">
                      {zones.length > 0 ? zones.find((z) => z.id === zoneId)?.name : detail.project.domain}
                    </span>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={handlePreview}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-md cursor-pointer"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      <span>{isFa ? 'پیش‌نمایش DNS' : 'Preview DNS'}</span>
                    </button>
                  </div>

                  {preview && (
                    <div className="space-y-2.5 text-xs border border-slate-200 dark:border-slate-800 rounded-md p-3">
                      {preview.conflicts.map((c, idx) => (
                        <div key={idx} className="text-red-600 dark:text-red-400">{c}</div>
                      ))}
                      {preview.changes.map((c, idx) => (
                        <div key={idx} dir="ltr" className="font-mono text-slate-700 dark:text-slate-300">
                          {c.operation.toUpperCase()} {c.hostname} [{c.regionCode}] {c.recordType} → {c.proposedValue}
                        </div>
                      ))}
                      <input
                        type="text"
                        dir="ltr"
                        value={confirmDomain}
                        onChange={(e) => setConfirmDomain(e.target.value)}
                        placeholder={detail.project.domain}
                        className="w-full px-2.5 py-1.5 font-mono bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md"
                      />
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={confirmDeploy}
                          onChange={(e) => setConfirmDeploy(e.target.checked)}
                        />
                        <span>{isFa ? 'تأیید اعمال در DNS' : 'Confirm DNS deploy'}</span>
                      </label>
                      <button
                        type="button"
                        disabled={
                          busy ||
                          confirmDomain.trim().toLowerCase() !== detail.project.domain ||
                          !confirmDeploy ||
                          !preview.canDeploy
                        }
                        onClick={handleDeploy}
                        className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-white bg-emerald-600 hover:bg-emerald-700 disabled:opacity-40 rounded-md cursor-pointer"
                      >
                        <Rocket className="w-3.5 h-3.5" />
                        <span>{isFa ? 'اعمال نهایی' : 'Deploy'}</span>
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          <div className="flex justify-end">
            {!deleteConfirm ? (
              <button
                type="button"
                onClick={() => setDeleteConfirm(true)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs text-red-600 dark:text-red-400 border border-red-200 dark:border-red-900/60 rounded-md hover:bg-red-50 dark:hover:bg-red-950/30 cursor-pointer"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>{isFa ? 'حذف این دامنه' : 'Delete Domain'}</span>
              </button>
            ) : (
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={async () => {
                    await api.deleteProject(detail.project.id);
                    onSelectProject(null);
                    await onRefreshWorkspace();
                  }}
                  className="px-3 py-1.5 text-xs font-medium text-white bg-red-600 hover:bg-red-700 rounded-md cursor-pointer"
                >
                  {isFa ? 'تأیید حذف دامنه' : 'Confirm Delete'}
                </button>
                <button
                  type="button"
                  onClick={() => setDeleteConfirm(false)}
                  className="px-3 py-1.5 text-xs border border-slate-300 dark:border-slate-700 rounded-md text-slate-600 dark:text-slate-300 cursor-pointer"
                >
                  {isFa ? 'انصراف' : 'Cancel'}
                </button>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
