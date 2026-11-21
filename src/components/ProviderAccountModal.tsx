import { useState, type FormEvent } from 'react';
import { X } from 'lucide-react';
import { useI18n } from '../i18n/I18nContext';
import { api } from '../lib/api';
import type { DnsProviderAccountSummary, ProviderType } from '../types/georoute';

interface ProviderAccountModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCreated: (account: DnsProviderAccountSummary) => Promise<void> | void;
}

export function ProviderAccountModal({ isOpen, onClose, onCreated }: ProviderAccountModalProps) {
  const { lang } = useI18n();
  const isFa = lang === 'fa';

  const [providerName, setProviderName] = useState<Exclude<ProviderType, 'manual'>>('cloudns');
  const [accountLabel, setAccountLabel] = useState('');
  const [ns1Key, setNs1Key] = useState('');
  const [cloudnsAuthId, setCloudnsAuthId] = useState('');
  const [cloudnsPassword, setCloudnsPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const credentials =
        providerName === 'ns1'
          ? { apiKey: ns1Key.trim() }
          : { authId: cloudnsAuthId.trim(), authPassword: cloudnsPassword.trim() };

      const res = await api.createDnsProvider({
        providerName,
        accountLabel: accountLabel.trim() || `${providerName.toUpperCase()} Account`,
        credentials,
      });

      setAccountLabel('');
      setNs1Key('');
      setCloudnsAuthId('');
      setCloudnsPassword('');
      await onCreated(res.account);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : isFa ? 'ذخیره حساب ناموفق بود.' : 'Failed to save provider account.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/70 flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-200 dark:border-slate-800">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {isFa ? 'اتصال حساب سرویس GeoDNS میانی' : 'Connect GeoDNS Provider'}
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="p-1 text-slate-500 hover:text-slate-900 dark:hover:text-slate-100 cursor-pointer"
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

          <div>
            <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1.5">
              {isFa ? 'سرویس‌دهنده GeoDNS' : 'GeoDNS Service'}
            </label>
            <div className="grid grid-cols-2 gap-2">
              {(
                [
                  { id: 'cloudns', label: 'ClouDNS (GeoDNS)' },
                  { id: 'ns1', label: 'IBM NS1 Connect' },
                ] as const
              ).map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setProviderName(item.id)}
                  className={`py-2 px-3 rounded-md border font-medium cursor-pointer ${
                    providerName === item.id
                      ? 'border-blue-600 bg-blue-50 dark:bg-blue-950/40 text-blue-700 dark:text-blue-300'
                      : 'border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300'
                  }`}
                >
                  {item.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
              {isFa ? 'عنوان دلخواه' : 'Label'}
            </label>
            <input
              type="text"
              required
              value={accountLabel}
              onChange={(e) => setAccountLabel(e.target.value)}
              placeholder={providerName === 'cloudns' ? 'ClouDNS Main' : 'NS1 Main'}
              className="w-full px-3 py-2 bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md"
            />
          </div>

          {providerName === 'ns1' ? (
            <div>
              <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
                {isFa ? 'کلید API (X-NSONE-Key)' : 'NS1 API Key'}
              </label>
              <input
                type="password"
                dir="ltr"
                required
                value={ns1Key}
                onChange={(e) => setNs1Key(e.target.value)}
                className="w-full px-3 py-2 font-mono bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md"
              />
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Auth ID
                </label>
                <input
                  type="text"
                  dir="ltr"
                  required
                  value={cloudnsAuthId}
                  onChange={(e) => setCloudnsAuthId(e.target.value)}
                  className="w-full px-3 py-2 font-mono bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md"
                />
              </div>
              <div>
                <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Auth Password
                </label>
                <input
                  type="password"
                  dir="ltr"
                  required
                  value={cloudnsPassword}
                  onChange={(e) => setCloudnsPassword(e.target.value)}
                  className="w-full px-3 py-2 font-mono bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md"
                />
              </div>
            </div>
          )}

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-2 border border-slate-300 dark:border-slate-700 rounded-md text-slate-700 dark:text-slate-300 cursor-pointer"
            >
              {isFa ? 'انصراف' : 'Cancel'}
            </button>
            <button
              type="submit"
              disabled={busy}
              className="px-4 py-2 text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded-md font-medium cursor-pointer"
            >
              {busy ? (isFa ? 'در حال بررسی...' : 'Validating...') : isFa ? 'اتصال و ذخیره' : 'Connect & Save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
