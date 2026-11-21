// CommonJS entry wrapper for cPanel CloudLinux Passenger ("Setup Node.js App")
const fs = require('node:fs');
const path = require('node:path');

process.env.NODE_ENV = process.env.NODE_ENV || 'production';

// Ensure cwd matches the application root even if Passenger spawns from another directory
try {
  if (process.cwd() !== __dirname) {
    process.chdir(__dirname);
  }
} catch {
  // Ignore chdir errors
}

const cjsServerPath = path.join(__dirname, 'dist-server', 'server.cjs');
const mjsServerPath = path.join(__dirname, 'dist-server', 'server.mjs');

function recordStartupError(err) {
  const message = err && err.stack ? err.stack : String(err);
  console.error('Failed to start GeoRoute Manager server:', message);
  try {
    fs.writeFileSync(path.join(__dirname, 'startup-error.log'), `${new Date().toISOString()}\n${message}\n`);
  } catch {
    // Ignore logging errors
  }
}

try {
  if (fs.existsSync(cjsServerPath)) {
    require(cjsServerPath);
  } else if (fs.existsSync(mjsServerPath)) {
    import('./dist-server/server.mjs').catch((err) => {
      recordStartupError(err);
      process.exit(1);
    });
  } else {
    throw new Error(
      'Missing dist-server/server.cjs. Run "npm run build" locally or on the server and upload dist/ + dist-server/.'
    );
  }
} catch (err) {
  recordStartupError(err);
  process.exit(1);
}
