import { useEffect, useState } from 'react';
import { Languages, LogOut, Moon, Plus, ShieldCheck, Sun } from 'lucide-react';
import { AddDomainModal } from './components/AddDomainModal';
import { AuthGate } from './components/AuthGate';
import { DomainWorkspace } from './components/DomainWorkspace';
import { ProviderAccountModal } from './components/ProviderAccountModal';
import { SettingsPage } from './components/SettingsPage';
import { useI18n } from './i18n/I18nContext';
import { api, setCsrfToken, setSessionToken } from './lib/api';
import { useTheme } from './theme/ThemeContext';
import type { DnsProviderAccountSummary, Project, UserSummary } from './types/georoute';

type NavTab = 'domains' | 'settings';

export default function App() {
  const { lang, toggleLang, t } = useI18n();
  const { theme, toggleTheme } = useTheme();
  const isFa = lang === 'fa';

  const [booting, setBooting] = useState(true);
  const [initialized, setInitialized] = useState(false);
  const [user, setUser] = useState<UserSummary | null>(null);

  const [activeTab, setActiveTab] = useState<NavTab>('domains');
  const [addDomainOpen, setAddDomainOpen] = useState(false);
  const [addProviderOpen, setAddProviderOpen] = useState(false);

  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null);
  const [dnsAccounts, setDnsAccounts] = useState<DnsProviderAccountSummary[]>([]);

  async function loadWorkspaceData() {
    const [projRes, dnsRes] = await Promise.all([
      api.listProjects(),
      api.listDnsProviders(),
    ]);
    setProjects(projRes.projects);
    setDnsAccounts(dnsRes.accounts);
  }

  useEffect(() => {
    (async () => {
      try {
        const status = await api.authStatus();
        setInitialized(status.initialized);
        if (status.authenticated && status.user) {
          setCsrfToken(status.csrfToken);
          await loadWorkspaceData();
          setUser(status.user);
        }
      } catch {
        setCsrfToken(null);
        setSessionToken(null);
        setUser(null);
      } finally {
        setBooting(false);
      }
    })();
  }, []);

  if (booting) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex items-center justify-center text-sm text-slate-500">
        {t.initializing}
      </div>
    );
  }

  if (!user) {
    return (
      <AuthGate
        initialized={initialized}
        onAuthenticated={async (authenticatedUser) => {
          setInitialized(true);
          await loadWorkspaceData();
          setUser(authenticatedUser);
        }}
      />
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col">
      {/* Clean 3-Zone Top Bar */}
      <header className="h-14 px-4 sm:px-6 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-4 shrink-0">
        <div className="flex items-center gap-6 min-w-0">
          <div className="flex items-center gap-2 shrink-0">
            <div className="w-7 h-7 rounded-md bg-blue-600 text-white flex items-center justify-center shrink-0">
              <ShieldCheck className="w-4 h-4" aria-hidden="true" />
            </div>
            <span className="font-display font-bold text-sm tracking-tight whitespace-nowrap" dir="ltr">
              GeoRoute
            </span>
          </div>

          <nav className="flex items-center gap-4 text-xs font-medium">
            <button
              type="button"
              onClick={() => setActiveTab('domains')}
              className={`py-1.5 border-b-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                activeTab === 'domains'
                  ? 'border-blue-600 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              {isFa ? 'دامنه‌ها و مسیریابی' : 'Domains & Routing'}
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('settings')}
              className={`py-1.5 border-b-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                activeTab === 'settings'
                  ? 'border-blue-600 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              {isFa ? 'تنظیمات' : 'Settings'}
            </button>
          </nav>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={toggleTheme}
            aria-label={theme === 'dark' ? t.common.lightMode : t.common.darkMode}
            className="p-2 text-xs border border-slate-200 dark:border-slate-700 rounded-md hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
          >
            {theme === 'dark' ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
          </button>

          <button
            type="button"
            onClick={toggleLang}
            aria-label={t.common.language}
            className="hidden sm:inline-flex items-center gap-1 px-2.5 py-1.5 text-xs border border-slate-200 dark:border-slate-700 rounded-md hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
          >
            <Languages className="w-3.5 h-3.5" />
            <span>{isFa ? 'EN' : 'FA'}</span>
          </button>

          <button
            type="button"
            onClick={() => setAddDomainOpen(true)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-md whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{isFa ? 'دامنه جدید' : 'Add Domain'}</span>
          </button>

          <button
            type="button"
            onClick={async () => {
              try {
                await api.authLogout();
              } finally {
                setCsrfToken(null);
                setSessionToken(null);
                setUser(null);
              }
            }}
            aria-label={t.common.signOut}
            title={t.common.signOut}
            className="p-2 text-xs border border-slate-200 dark:border-slate-700 rounded-md text-slate-500 hover:text-red-600 dark:hover:text-red-400 cursor-pointer"
          >
            <LogOut className="w-3.5 h-3.5" />
          </button>
        </div>
      </header>

      <main className="flex-1 w-full max-w-[1160px] mx-auto p-4 sm:p-6 lg:p-8">
        {activeTab === 'domains' ? (
          <DomainWorkspace
            projects={projects}
            selectedProjectId={selectedProjectId}
            dnsAccounts={dnsAccounts}
            onSelectProject={setSelectedProjectId}
            onOpenAddDomain={() => setAddDomainOpen(true)}
            onOpenAddProvider={() => setAddProviderOpen(true)}
            onRefreshWorkspace={loadWorkspaceData}
          />
        ) : (
          <SettingsPage
            username={user.username}
            dnsAccounts={dnsAccounts}
            onOpenAddProvider={() => setAddProviderOpen(true)}
            onRefresh={loadWorkspaceData}
          />
        )}
      </main>

      <AddDomainModal
        isOpen={addDomainOpen}
        dnsAccounts={dnsAccounts}
        onClose={() => setAddDomainOpen(false)}
        onCreated={async (created) => {
          await loadWorkspaceData();
          setSelectedProjectId(created.id);
          setActiveTab('domains');
        }}
      />

      <ProviderAccountModal
        isOpen={addProviderOpen}
        onClose={() => setAddProviderOpen(false)}
        onCreated={async () => {
          await loadWorkspaceData();
        }}
      />
    </div>
  );
}
