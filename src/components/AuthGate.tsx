import { useState, type FormEvent } from 'react';
import { Eye, EyeOff, Globe, Lock, Moon, ShieldCheck, Sun } from 'lucide-react';
import { useI18n } from '../i18n/I18nContext';
import { api, setCsrfToken, setSessionToken } from '../lib/api';
import { useTheme } from '../theme/ThemeContext';
import type { UserSummary } from '../types/georoute';

interface AuthGateProps {
  initialized: boolean;
  onAuthenticated: (user: UserSummary) => Promise<void> | void;
}

export function AuthGate({ initialized, onAuthenticated }: AuthGateProps) {
  const { lang, toggleLang, t } = useI18n();
  const { theme, toggleTheme } = useTheme();
  const [username, setUsername] = useState(initialized ? 'admin' : '');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  function localizeAuthError(rawMessage: string): string {
    if (lang !== 'fa') return rawMessage;
    if (rawMessage === 'Invalid username or password.') {
      return 'نام کاربری یا رمز عبور نادرست است. از انگلیسی بودن صفحه‌کلید و عدم وجود فاصله اضافه در رمز اطمینان حاصل کنید.';
    }
    return rawMessage;
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');
    if (!initialized && password !== confirmPassword) {
      setError(t.auth.passwordMismatch);
      return;
    }

    setLoading(true);
    try {
      const cleanUser = username.trim();
      const res = initialized
        ? await api.authLogin(cleanUser, password)
        : await api.authSetup(cleanUser, password);
      setCsrfToken(res.csrfToken);
      setSessionToken(res.sessionToken ?? null);
      await onAuthenticated(res.user);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Authentication failed.';
      setError(localizeAuthError(msg));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex items-center justify-center p-6">
      <div className="w-full max-w-md bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-8">
        <div className="flex items-center justify-between gap-2 mb-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-md bg-blue-600 text-white flex items-center justify-center shrink-0">
              <ShieldCheck className="w-4 h-4" aria-hidden="true" />
            </div>
            <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100" dir="ltr">
              {t.brand}
            </h1>
          </div>

          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={toggleTheme}
              aria-label={theme === 'dark' ? t.common.lightMode : t.common.darkMode}
              title={theme === 'dark' ? t.common.lightMode : t.common.darkMode}
              className="inline-flex items-center justify-center p-1.5 text-xs border border-slate-200 dark:border-slate-700 rounded-md text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
            >
              {theme === 'dark' ? <Sun className="w-3.5 h-3.5" aria-hidden="true" /> : <Moon className="w-3.5 h-3.5" aria-hidden="true" />}
            </button>
            <button
              type="button"
              onClick={toggleLang}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium border border-slate-200 dark:border-slate-700 rounded-md text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
            >
              <Globe className="w-3.5 h-3.5" aria-hidden="true" />
              <span>{lang === 'fa' ? 'English' : 'فارسی'}</span>
            </button>
          </div>
        </div>

        <p className="text-sm text-slate-600 dark:text-slate-400 mb-6 leading-relaxed">
          {initialized ? t.auth.subtitleLogin : t.auth.subtitleSetup}
        </p>

        {error && (
          <div
            role="alert"
            className="mb-4 p-3 rounded-md border border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/30 text-xs text-red-700 dark:text-red-300 leading-relaxed"
          >
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="auth-username" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
              {t.common.username}
            </label>
            <input
              id="auth-username"
              type="text"
              dir="ltr"
              required
              autoComplete="username"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="admin"
              className="w-full px-3 py-2 text-sm font-mono bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
            {initialized && (
              <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
                {t.auth.defaultAdminHint}
              </p>
            )}
          </div>

          <div>
            <label htmlFor="auth-password" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
              {t.common.password}
            </label>
            <div className="relative">
              <input
                id="auth-password"
                type={showPassword ? 'text' : 'password'}
                dir="ltr"
                required
                minLength={8}
                autoComplete={initialized ? 'current-password' : 'new-password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full px-3 py-2 pe-10 text-sm font-mono bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
              <button
                type="button"
                onClick={() => setShowPassword((prev) => !prev)}
                aria-label={
                  showPassword
                    ? lang === 'fa' ? 'مخفی کردن رمز عبور' : 'Hide password'
                    : lang === 'fa' ? 'نمایش رمز عبور' : 'Show password'
                }
                className="absolute inset-y-0 end-0 px-2.5 flex items-center text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 cursor-pointer"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {!initialized && (
            <div>
              <label htmlFor="auth-confirm" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                {t.common.confirmPassword}
              </label>
              <input
                id="auth-confirm"
                type={showPassword ? 'text' : 'password'}
                dir="ltr"
                required
                minLength={8}
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full px-3 py-2 text-sm font-mono bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 py-2.5 px-4 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded-md transition-colors cursor-pointer"
          >
            <Lock className="w-4 h-4" aria-hidden="true" />
            <span>{loading ? t.common.processing : initialized ? t.common.signIn : t.common.createAdmin}</span>
          </button>
        </form>

        <div className="mt-6 pt-5 border-t border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
          {t.auth.cookieNote}
        </div>
      </div>
    </div>
  );
}
