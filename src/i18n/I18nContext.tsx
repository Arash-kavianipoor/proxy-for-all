import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import {
  CAPABILITY_LABELS_FA,
  IRNIC_STEPS_FA,
  STATUS_LABELS,
  TRANSLATIONS,
  type Lang,
} from './translations';

interface I18nContextValue {
  lang: Lang;
  isRtl: boolean;
  setLang: (lang: Lang) => void;
  toggleLang: () => void;
  t: (typeof TRANSLATIONS)[Lang];
  statusLabel: (status: string) => string;
  capabilityLabel: (key: string, fallbackLabel: string, fallbackCategory: string) => { label: string; category: string };
  irnicStepLabel: (key: string, fallbackLabel: string) => string;
  formatDate: (iso: string) => string;
}

const I18nContext = createContext<I18nContextValue | null>(null);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(() => {
    if (typeof window !== 'undefined') {
      const saved = window.localStorage.getItem('georoute_lang');
      if (saved === 'en' || saved === 'fa') return saved;
    }
    return 'fa';
  });

  useEffect(() => {
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === 'fa' ? 'rtl' : 'ltr';
    if (typeof window !== 'undefined') {
      window.localStorage.setItem('georoute_lang', lang);
    }
  }, [lang]);

  const setLang = (next: Lang) => setLangState(next);
  const toggleLang = () => setLangState((prev) => (prev === 'fa' ? 'en' : 'fa'));

  const value: I18nContextValue = {
    lang,
    isRtl: lang === 'fa',
    setLang,
    toggleLang,
    t: TRANSLATIONS[lang],
    statusLabel: (status: string) => STATUS_LABELS[lang][status] || status,
    capabilityLabel: (key: string, fallbackLabel: string, fallbackCategory: string) => {
      if (lang === 'fa' && CAPABILITY_LABELS_FA[key]) {
        return CAPABILITY_LABELS_FA[key];
      }
      return { label: fallbackLabel, category: fallbackCategory };
    },
    irnicStepLabel: (key: string, fallbackLabel: string) => {
      if (lang === 'fa' && IRNIC_STEPS_FA[key]) {
        return IRNIC_STEPS_FA[key];
      }
      return fallbackLabel;
    },
    formatDate: (iso: string) => {
      if (!iso) return '—';
      try {
        return new Date(iso).toLocaleString(lang === 'fa' ? 'fa-IR' : 'en-US');
      } catch {
        return iso;
      }
    },
  };

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (!ctx) {
    throw new Error('useI18n must be used within I18nProvider');
  }
  return ctx;
}
