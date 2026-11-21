import { useState, type FormEvent } from 'react';
import { CheckCircle2, KeyRound, Languages, Moon, Plus, Sun, Trash2 } from 'lucide-react';
import { useI18n } from '../i18n/I18nContext';
import { api } from '../lib/api';
import { useTheme } from '../theme/ThemeContext';
import type { DnsProviderAccountSummary } from '../types/georoute';

interface SettingsPageProps {
  username: string;
  dnsAccounts: DnsProviderAccountSummary[];
  onOpenAddProvider: () => void;
  onRefresh: () => Promise<void>;
}

export function SettingsPage({
  username,
  dnsAccounts,
  onOpenAddProvider,
  onRefresh,
}: SettingsPageProps) {
  const { lang, setLang, t } = useI18n();
  const { theme, setTheme } = useTheme();
  const isFa = lang === 'fa';

  const [busyId, setBusyId] = useState('');
  const [providerMsg, setProviderMsg] = useState('');

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');
  const [passBusy, setPassBusy] = useState(false);
  const [passError, setPassError] = useState('');
  const [passMessage, setPassMessage] = useState('');

  async function handleChangePassword(e: FormEvent) {
    e.preventDefault();
    setPassError('');
    setPassMessage('');
    if (newPassword !== confirmNewPassword) {
      setPassError(t.auth.passwordMismatch);
      return;
    }
    if (newPassword.length < 8) {
      setPassError(
        isFa ? 'رمز عبور جدید باید حداقل ۸ کاراکتر باشد.' : 'New password must be at least 8 characters.'
      );
      return;
    }
    setPassBusy(true);
    try {
      await api.authChangePassword(currentPassword, newPassword);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmNewPassword('');
      setPassMessage(
        isFa
          ? 'رمز عبور مدیر با موفقیت هش و ذخیره شد.'
          : 'Administrator password hashed and updated successfully.'
      );
    } catch (err) {
      setPassError(
        err instanceof Error
          ? err.message
          : isFa
            ? 'تغییر رمز عبور ناموفق بود.'
            : 'Failed to update password.'
      );
    } finally {
      setPassBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Connected GeoDNS Provider Accounts */}
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {isFa ? 'حساب‌های GeoDNS میانی' : 'GeoDNS Provider Accounts'}
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {isFa
                  ? 'حساب ClouDNS یا IBM NS1 برای تولید نیم‌سرور میانی'
                  : 'Connect ClouDNS or IBM NS1 credentials'}
              </p>
            </div>
            <button
              type="button"
              onClick={onOpenAddProvider}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-md cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>{isFa ? 'افزودن' : 'Add'}</span>
            </button>
          </div>

          {providerMsg && (
            <div className="p-2.5 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-xs text-slate-700 dark:text-slate-300">
              {providerMsg}
            </div>
          )}

          {dnsAccounts.length === 0 ? (
            <div className="p-4 rounded-md border border-dashed border-slate-300 dark:border-slate-700 text-xs text-slate-500 dark:text-slate-400">
              {isFa
                ? 'هنوز حساب ClouDNS یا NS1 متصل نشده است.'
                : 'No ClouDNS or NS1 account connected yet.'}
            </div>
          ) : (
            <div className="divide-y divide-slate-200 dark:divide-slate-800 border border-slate-200 dark:border-slate-800 rounded-md text-xs">
              {dnsAccounts.map((acc) => (
                <div key={acc.id} className="p-3 flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <div className="font-medium text-slate-900 dark:text-slate-100 truncate">
                      {acc.accountLabel}
                    </div>
                    <div className="font-mono text-slate-500 dark:text-slate-400" dir="ltr">
                      {acc.providerName.toUpperCase()} · {acc.maskedHint}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      disabled={busyId === acc.id}
                      onClick={async () => {
                        setBusyId(acc.id);
                        try {
                          const res = await api.validateDnsProvider(acc.id);
                          setProviderMsg(res.validation.message);
                          await onRefresh();
                        } finally {
                          setBusyId('');
                        }
                      }}
                      className="inline-flex items-center gap-1 px-2.5 py-1 border border-slate-300 dark:border-slate-700 rounded cursor-pointer"
                    >
                      <CheckCircle2 className="w-3 h-3" />
                      <span>{isFa ? 'تست' : 'Test'}</span>
                    </button>
                    <button
                      type="button"
                      onClick={async () => {
                        await api.deleteDnsProvider(acc.id);
                        await onRefresh();
                      }}
                      aria-label="Delete"
                      className="p-1 text-red-600 dark:text-red-400 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Appearance & Language */}
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {isFa ? 'ظاهر و زبان' : 'Appearance & Language'}
          </h2>

          <div className="flex items-center justify-between py-2 border-b border-slate-200 dark:border-slate-800 text-xs">
            <span className="font-medium text-slate-900 dark:text-slate-100">
              {isFa ? 'زبان برنامه' : 'Language'}
            </span>
            <div className="inline-flex rounded-md border border-slate-300 dark:border-slate-700 overflow-hidden shrink-0">
              <button
                type="button"
                onClick={() => setLang('fa')}
                className={`inline-flex items-center gap-1 px-3 py-1.5 cursor-pointer ${
                  lang === 'fa'
                    ? 'bg-blue-600 text-white'
                    : 'hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
                }`}
              >
                <Languages className="w-3.5 h-3.5" />
                <span>فارسی</span>
              </button>
              <button
                type="button"
                onClick={() => setLang('en')}
                className={`px-3 py-1.5 cursor-pointer ${
                  lang === 'en'
                    ? 'bg-blue-600 text-white'
                    : 'hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
                }`}
              >
                English
              </button>
            </div>
          </div>

          <div className="flex items-center justify-between py-2 text-xs">
            <span className="font-medium text-slate-900 dark:text-slate-100">
              {isFa ? 'تم پیش‌فرض' : 'Theme'}
            </span>
            <div className="inline-flex rounded-md border border-slate-300 dark:border-slate-700 overflow-hidden shrink-0">
              <button
                type="button"
                onClick={() => setTheme('dark')}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 cursor-pointer ${
                  theme === 'dark'
                    ? 'bg-blue-600 text-white'
                    : 'hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
                }`}
              >
                <Moon className="w-3.5 h-3.5" />
                <span>{isFa ? 'تاریک' : 'Dark'}</span>
              </button>
              <button
                type="button"
                onClick={() => setTheme('light')}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 cursor-pointer ${
                  theme === 'light'
                    ? 'bg-blue-600 text-white'
                    : 'hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
                }`}
              >
                <Sun className="w-3.5 h-3.5" />
                <span>{isFa ? 'روشن' : 'Light'}</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Change Admin Password */}
      <form
        onSubmit={handleChangePassword}
        className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4 max-w-2xl"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              {isFa ? 'تغییر رمز عبور مدیر' : 'Change Admin Password'}
            </h2>
          </div>
          <span className="text-xs font-mono text-slate-500" dir="ltr">{username}</span>
        </div>

        {passError && (
          <div className="p-3 rounded-md border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/30 text-xs text-red-700 dark:text-red-300">
            {passError}
          </div>
        )}
        {passMessage && (
          <div className="p-3 rounded-md border border-emerald-200 dark:border-emerald-900 bg-emerald-50 dark:bg-emerald-950/30 text-xs text-emerald-700 dark:text-emerald-300">
            {passMessage}
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div>
            <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
              {t.settings.currentPass}
            </label>
            <input
              type="password"
              dir="ltr"
              required
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
              {t.settings.newPass}
            </label>
            <input
              type="password"
              dir="ltr"
              required
              minLength={8}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
              {t.common.confirmPassword}
            </label>
            <input
              type="password"
              dir="ltr"
              required
              minLength={8}
              value={confirmNewPassword}
              onChange={(e) => setConfirmNewPassword(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md"
            />
          </div>
        </div>

        <button
          type="submit"
          disabled={passBusy}
          className="px-4 py-2 text-xs font-medium text-white bg-slate-800 dark:bg-slate-700 hover:bg-slate-900 rounded-md cursor-pointer"
        >
          {passBusy ? t.common.processing : t.settings.updatePassBtn}
        </button>
      </form>
    </div>
  );
}
