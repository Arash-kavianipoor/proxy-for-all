import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import { createApp } from './server/app.ts';
import { ensureDefaultAdmin, getDb } from './server/db.ts';
import { createHostProxyMiddleware } from './server/proxyCache.ts';

function injectBaseMeta(html: string, basePath: string): string {
  const safeBase = basePath || '';
  const metaTag = `<meta name="georoute-base" content="${safeBase}" />`;
  const withMeta = html.includes('<meta name="georoute-base"')
    ? html.replace(/<meta\s+name="georoute-base"[^>]*>/i, metaTag)
    : html.replace('</head>', `    ${metaTag}\n  </head>`);

  if (!safeBase) return withMeta;
  const baseTag = `<base href="${safeBase}/" />`;
  return withMeta.replace('<head>', `<head>\n    ${baseTag}`);
}

function resolveDistDir(): string {
  const cwdDist = path.resolve(process.cwd(), 'dist');
  if (fs.existsSync(cwdDist)) return cwdDist;
  if (typeof __dirname !== 'undefined') {
    const relDist = path.resolve(__dirname, '../dist');
    if (fs.existsSync(relDist)) return relDist;
  }
  return cwdDist;
}

async function startServer() {
  const db = getDb();
  ensureDefaultAdmin(db);

  const isProd = process.env.NODE_ENV === 'production';
  const app = createApp(db, {
    hostProxyMiddleware: isProd ? createHostProxyMiddleware(db) : undefined,
  });
  const host = process.env.HOST || '0.0.0.0';
  const rawPort = process.env.PORT?.trim();
  const listenTarget: number | string =
    rawPort && !/^\d+$/.test(rawPort) ? rawPort : Number(rawPort || 3000);

  if (!isProd) {
    const viteModule = 'vite';
    const { createServer: createViteServer } = await import(viteModule);
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = resolveDistDir();
    const indexHtmlPath = path.join(distDir, 'index.html');
    const cachedTemplate = fs.existsSync(indexHtmlPath)
      ? fs.readFileSync(indexHtmlPath, 'utf8')
      : null;

    app.use(express.static(distDir, { index: false }));

    app.get('*', (req, res, next) => {
      if (req.path.startsWith('/api')) return next();

      const activeBase = String(res.locals.georouteBasePath || '');
      if (activeBase && req.originalUrl === activeBase) {
        return res.redirect(302, `${activeBase}/`);
      }

      if (cachedTemplate) {
        res.type('html').send(injectBaseMeta(cachedTemplate, activeBase));
      } else if (fs.existsSync(indexHtmlPath)) {
        const html = fs.readFileSync(indexHtmlPath, 'utf8');
        res.type('html').send(injectBaseMeta(html, activeBase));
      } else {
        res.status(404).send('Build output missing. Run npm run build.');
      }
    });
  }

  if (typeof listenTarget === 'string') {
    app.listen(listenTarget, () => {
      console.log(`GeoRoute Manager control plane listening on socket ${listenTarget}`);
    });
  } else {
    app.listen(listenTarget, host, () => {
      console.log(`GeoRoute Manager control plane listening on http://${host}:${listenTarget}`);
    });
  }
}

startServer().catch((err) => {
  const msg = err instanceof Error ? err.stack || err.message : String(err);
  console.error('Failed to start GeoRoute Manager server:', msg);
  try {
    fs.writeFileSync(path.resolve(process.cwd(), 'startup-error.log'), `${new Date().toISOString()}\n${msg}\n`);
  } catch {
    // Ignore file write errors
  }
  process.exit(1);
});
