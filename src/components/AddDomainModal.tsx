import { useState, type FormEvent } from 'react';
import { Check, Server, X } from 'lucide-react';
import { useI18n } from '../i18n/I18nContext';
import { api } from '../lib/api';
import type { DnsProviderAccountSummary, Project, ProviderType } from '../types/georoute';

interface AddDomainModalProps {
  isOpen: boolean;
  dnsAccounts: DnsProviderAccountSummary[];
  onClose: () => void;
  onCreated: (project: Project) => Promise<void> | void;
}

export function AddDomainModal({ isOpen, dnsAccounts, onClose, onCreated }: AddDomainModalProps) {
  const { lang } = useI18n();
  const isFa = lang === 'fa';

  const [domain, setDomain] = useState('');
  const [iranProxyHost, setIranProxyHost] = useState(
    typeof window !== 'undefined' ? window.location.hostname : ''
  );
  const [cloudflareNsInput, setCloudflareNsInput] = useState('');
  const [selectedAccountId, setSelectedAccountId] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const domainValid = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(cleanDomain);
  const currentHostLabel = typeof window !== 'undefined' ? window.location.hostname : 'localhost';

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!domainValid) {
      setError(isFa ? 'لطفاً یک دامنه معتبر وارد کنید (مثال: example.ir).' : 'Please enter a valid domain name.');
      return;
    }

    setError('');
    setSubmitting(true);
    try {
      const account = dnsAccounts.find((a) => a.id === selectedAccountId);
      const provider: ProviderType = account ? account.providerName : 'manual';
      const normalizedCf = cloudflareNsInput
        .split(/[\n,;]+/)
        .map((line) => line.trim().toLowerCase())
        .filter(Boolean)
        .join(', ');

      const trimmedProxy = iranProxyHost.trim();
      const isIpv4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(trimmedProxy);

      const isSamePanelDomain = cleanDomain === currentHostLabel.toLowerCase();
      const res = await api.createProject({
        projectName: cleanDomain,
        domain: cleanDomain,
        cloudflareTarget: normalizedCf,
        iranProxyIPv4: isIpv4 ? trimmedProxy : '',
        iranProxyHostname: !isIpv4 ? trimmedProxy || currentHostLabel : '',
        geoDnsProvider: provider,
        notes: !isSamePanelDomain && normalizedCf ? 'proxy_active=true' : '',
      });

      if (account) {
        try {
          await api.bindProjectZone(res.project.id, {
            providerName: account.providerName,
            providerAccountId: account.id,
            providerZoneId: cleanDomain,
          });
        } catch {
          // Zone can be picked inside workspace
        }
      }

      await onCreated(res.project);
      setDomain('');
      setCloudflareNsInput('');
      setSelectedAccountId('');
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : isFa ? 'ایجاد دامنه ناموفق بود.' : 'Failed to create domain.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/70 flex items-center justify-center p-4">
      <div className="w-full max-w-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-200 dark:border-slate-800">
          <div>
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              {isFa ? 'افزودن دامنه به پروکسی امن' : 'Add Domain to Secure Proxy'}
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              {isFa
                ? 'این هاست به عنوان پروکسی کش‌دار به کلودفلر متصل می‌شود'
                : 'This host proxies & caches static content from Cloudflare'}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="p-1.5 text-slate-500 hover:text-slate-900 dark:hover:text-slate-100 cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4 text-xs">
          {error && (
            <div className="p-3 rounded-md border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-300">
              {error}
            </div>
          )}

          {/* div:nth-of-type(1): IRNIC Domain */}
          <div>
            <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
              {isFa ? 'دامنه شما در ایرنیک' : 'Domain Name (IRNIC)'}
            </label>
            <input
              type="text"
              dir="ltr"
              required
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.ir"
              className="w-full px-3 py-2 text-sm font-mono bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md"
            />
          </div>

          {/* div:nth-of-type(2): This host = Iran proxy/cache destination */}
          <div className="p-3 rounded-md border border-emerald-200 dark:border-emerald-900/60 bg-emerald-50/30 dark:bg-emerald-950/15 space-y-2">
            <div className="flex items-center justify-between gap-2">
              <span className="inline-flex items-center gap-1.5 font-medium text-emerald-800 dark:text-emerald-300">
                <Server className="w-3.5 h-3.5" />
                <span>{isFa ? 'پروکسی و کش ایران (همین هاست فعلی)' : 'Iran Proxy & Cache (This Host)'}</span>
              </span>
              <span className="font-mono text-[11px] text-slate-600 dark:text-slate-300" dir="ltr">
                {currentHostLabel}
              </span>
            </div>
            <input
              type="text"
              dir="ltr"
              value={iranProxyHost}
              onChange={(e) => setIranProxyHost(e.target.value)}
              placeholder={currentHostLabel}
              className="w-full px-3 py-1.5 text-xs font-mono bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md"
            />
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              {isFa
                ? 'کاربران داخل ایران به همین هاست می‌آیند و درخواست‌ها از اینجا به کلودفلر منتقل و کش می‌شوند.'
                : 'Iranian users connect to this host, which proxies and caches responses from Cloudflare.'}
            </p>
          </div>

          {/* div:nth-of-type(3): Focused element — Cloudflare DNS Nameservers */}
          <div>
            <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
              {isFa
                ? 'DNSهای کلودفلر (نام‌سرورهای کلودفلر)'
                : 'Cloudflare DNS Nameservers'}
            </label>
            <textarea
              dir="ltr"
              rows={2}
              required
              value={cloudflareNsInput}
              onChange={(e) => setCloudflareNsInput(e.target.value)}
              placeholder={'dane.ns.cloudflare.com\ndolly.ns.cloudflare.com'}
              className="w-full px-3 py-2 text-sm font-mono leading-relaxed bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 resize-y"
            />
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
              {isFa
                ? 'دو آدرس DNS کلودفلر را وارد کنید (هر کدام در یک خط یا با ویرگول).'
                : 'Enter your assigned Cloudflare nameservers (one per line or comma-separated).'}
            </p>
          </div>

          {/* div:nth-of-type(4): GeoDNS Middleware (optional) */}
          <div>
            <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
              {isFa ? 'سرویس GeoDNS میانی (اختیاری)' : 'Middleman GeoDNS Provider (Optional)'}
            </label>
            <select
              value={selectedAccountId}
              onChange={(e) => setSelectedAccountId(e.target.value)}
              className="w-full px-3 py-2 bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md"
            >
              <option value="">
                {isFa ? 'پروکسی مستقیم روی همین هاست (بدون API خارجی)' : 'Direct proxy on this host (Manual DNS)'}
              </option>
              {dnsAccounts.map((acc) => (
                <option key={acc.id} value={acc.id}>
                  {acc.accountLabel} ({acc.providerName.toUpperCase()})
                </option>
              ))}
            </select>
          </div>

          {/* div:nth-of-type(5): Actions */}
          <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-200 dark:border-slate-800">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded-md cursor-pointer"
            >
              {isFa ? 'انصراف' : 'Cancel'}
            </button>
            <button
              type="submit"
              disabled={submitting || !domainValid}
              className="inline-flex items-center gap-1.5 px-4 py-2 font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-40 rounded-md cursor-pointer"
            >
              <Check className="w-3.5 h-3.5" />
              <span>
                {submitting
                  ? isFa ? 'در حال ثبت...' : 'Creating...'
                  : isFa ? 'ثبت دامنه و اتصال به کلودفلر' : 'Add Domain & Connect'}
              </span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
