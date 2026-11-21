import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

let cachedMasterKey: Buffer | null = null;
let cachedSessionSecret: string | null = null;
let keySource: 'environment' | 'local_dev_file' = 'environment';

function ensureLocalKeyFile(filename: string, bytes: number): Buffer {
  const filePath = path.resolve(process.cwd(), filename);
  if (fs.existsSync(filePath)) {
    const raw = fs.readFileSync(filePath, 'utf8').trim();
    if (raw.length >= 32) {
      return crypto.createHash('sha256').update(raw).digest();
    }
  }
  const generated = crypto.randomBytes(bytes).toString('hex');
  fs.writeFileSync(filePath, generated, { mode: 0o600 });
  return crypto.createHash('sha256').update(generated).digest();
}

export function getMasterEncryptionKey(): Buffer {
  if (cachedMasterKey) return cachedMasterKey;
  const envKey = process.env.CREDENTIAL_ENCRYPTION_KEY?.trim();
  if (envKey && envKey.length >= 16 && !envKey.startsWith('CHANGE_ME')) {
    keySource = 'environment';
    cachedMasterKey = crypto.createHash('sha256').update(envKey).digest();
    return cachedMasterKey;
  }
  keySource = 'local_dev_file';
  cachedMasterKey = ensureLocalKeyFile('.georoute-local-key', 32);
  return cachedMasterKey;
}

export function getEncryptionStatus(): {
  source: 'environment' | 'local_dev_file';
  algorithm: string;
} {
  getMasterEncryptionKey();
  return {
    source: keySource,
    algorithm: 'AES-256-GCM',
  };
}

export function getSessionSecret(): string {
  if (cachedSessionSecret) return cachedSessionSecret;
  const envSecret = process.env.SESSION_SECRET?.trim();
  if (envSecret && envSecret.length >= 16 && !envSecret.startsWith('CHANGE_ME')) {
    cachedSessionSecret = envSecret;
    return cachedSessionSecret;
  }
  const filePath = path.resolve(process.cwd(), '.georoute-session-secret');
  if (fs.existsSync(filePath)) {
    const raw = fs.readFileSync(filePath, 'utf8').trim();
    if (raw.length >= 32) {
      cachedSessionSecret = raw;
      return cachedSessionSecret;
    }
  }
  const generated = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(filePath, generated, { mode: 0o600 });
  cachedSessionSecret = generated;
  return cachedSessionSecret;
}

export function hashPassword(password: string, existingSalt?: string): { hash: string; salt: string } {
  const salt = existingSalt || crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return { hash: derived, salt };
}

export function verifyPassword(password: string, storedHash: string, salt: string): boolean {
  const derived = crypto.scryptSync(password, salt, 64);
  const target = Buffer.from(storedHash, 'hex');
  if (derived.length !== target.length) return false;
  return crypto.timingSafeEqual(derived, target);
}

export function encryptSecret(plaintext: string): {
  ciphertext: string;
  iv: string;
  tag: string;
} {
  const key = getMasterEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
  };
}

export function decryptSecret(ciphertext: string, ivBase64: string, tagBase64: string): string {
  const key = getMasterEncryptionKey();
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(ivBase64, 'base64')
  );
  decipher.setAuthTag(Buffer.from(tagBase64, 'base64'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'base64')),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}

export function signSessionId(sessionId: string): string {
  const secret = getSessionSecret();
  const hmac = crypto.createHmac('sha256', secret).update(sessionId).digest('hex');
  return `${sessionId}.${hmac}`;
}

export function verifySignedSessionId(cookieValue: string): string | null {
  const parts = cookieValue.split('.');
  if (parts.length !== 2) return null;
  const [sessionId, signature] = parts;
  if (!sessionId || !signature) return null;
  const secret = getSessionSecret();
  const expected = crypto.createHmac('sha256', secret).update(sessionId).digest('hex');
  const sigBuf = Buffer.from(signature, 'hex');
  const expBuf = Buffer.from(expected, 'hex');
  if (sigBuf.length !== expBuf.length) return null;
  if (!crypto.timingSafeEqual(sigBuf, expBuf)) return null;
  return sessionId;
}

export function maskSecret(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return '****';
  if (trimmed.length <= 4) return '****';
  return `${'*'.repeat(Math.min(12, trimmed.length - 4))}${trimmed.slice(-4)}`;
}

export function redactSecrets(input: string, knownSecrets: string[] = []): string {
  let output = input;
  for (const secret of knownSecrets) {
    if (secret && secret.length >= 4) {
      output = output.split(secret).join('[REDACTED]');
    }
  }
  output = output
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, '$1[REDACTED]')
    .replace(/(X-NSONE-Key\s*[:=]\s*)\S+/gi, '$1[REDACTED]')
    .replace(/(auth-password\s*[=:]\s*)[^&\s"']+/gi, '$1[REDACTED]')
    .replace(/(api[_-]?key\s*[=:]\s*)[^&\s"']+/gi, '$1[REDACTED]');
  return output;
}

export function sha256Hex(input: string): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}
