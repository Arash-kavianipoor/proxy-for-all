import type { ProviderType } from '../../src/types/georoute.ts';
import { ClouDnsGeoDnsProvider, type ClouDnsCredentials } from './cloudns.ts';
import { ManualGeoDnsProvider } from './manual.ts';
import { Ns1GeoDnsProvider, type Ns1Credentials } from './ns1.ts';
import type { GeoDnsProvider } from './types.ts';

export function createGeoDnsProvider(
  providerType: ProviderType,
  rawCredentialsJson?: string,
  fetcher: typeof fetch = fetch
): GeoDnsProvider {
  if (providerType === 'ns1') {
    const parsed = JSON.parse(rawCredentialsJson || '{}') as Ns1Credentials;
    if (!parsed.apiKey) {
      throw new Error('NS1 provider requires an apiKey credential.');
    }
    return new Ns1GeoDnsProvider(parsed, fetcher);
  }

  if (providerType === 'cloudns') {
    const parsed = JSON.parse(rawCredentialsJson || '{}') as ClouDnsCredentials;
    if (!parsed.authId || !parsed.authPassword) {
      throw new Error('ClouDNS provider requires authId and authPassword credentials.');
    }
    return new ClouDnsGeoDnsProvider(parsed, fetcher);
  }

  return new ManualGeoDnsProvider();
}
