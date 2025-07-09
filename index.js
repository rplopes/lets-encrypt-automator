import http from 'node:http';
import fs from 'fs/promises';
import { createReadStream, statSync, renameSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import acme from 'acme-client';

/* --------------------------------------------------------------------- */
/* 1. Environment                                                        */
/* --------------------------------------------------------------------- */
const {
  DOMAIN, EMAIL, CPANEL_HOST, CPANEL_USER, CPANEL_TOKEN,
  RENEW_SECRET,
  LOG_FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), 'renewer.log'),
  HOME = process.env.HOME,
  PORT = 3000,
  MAX_LOG_BYTES = 1_000_000
} = process.env;

const REQUIRED = { DOMAIN, EMAIL, CPANEL_USER, CPANEL_TOKEN, RENEW_SECRET };
for (const [k, v] of Object.entries(REQUIRED)) {
  if (!v) { console.error(`Missing env var ${k}`); process.exit(1); }
}

/* --------------------------------------------------------------------- */
/* 2. Utility: poor‑man's log with size‑based rotation                   */
/* --------------------------------------------------------------------- */
async function log(event, detail = {}) {
  try {
    if (statSync(LOG_FILE, { throwIfNoEntry: false })?.size > MAX_LOG_BYTES) {
      renameSync(LOG_FILE, LOG_FILE + '.1');
    }
  } catch { /* ignore */ }

  const line = JSON.stringify({ ts: new Date().toISOString(), event, ...detail }) + '\n';
  await fs.appendFile(LOG_FILE, line);
}

/* --------------------------------------------------------------------- */
/* 3. Paths for ACME challenge & key store                               */
/* --------------------------------------------------------------------- */
const CHAL_DIR = path.join(HOME, 'public_html', '.well-known', 'acme-challenge');
const STORE    = path.join(path.dirname(fileURLToPath(import.meta.url)), 'data');
await fs.mkdir(CHAL_DIR, { recursive: true });
await fs.mkdir(STORE,    { recursive: true });

/* --------------------------------------------------------------------- */
/* 4. Challenge helpers (local FS)                                       */
/* --------------------------------------------------------------------- */
async function challengeCreate(_, ch, keyAuth) {
  await fs.writeFile(path.join(CHAL_DIR, ch.token), keyAuth, 'utf8');
  await log('challenge-create', { token: ch.token });
}
async function challengeRemove(_, ch) {
  await fs.rm(path.join(CHAL_DIR, ch.token), { force: true });
  await log('challenge-remove', { token: ch.token });
}

/* --------------------------------------------------------------------- */
/* 5. Main renewal routine                                               */
/* --------------------------------------------------------------------- */
async function renew() {
  await log('renew-start');

  /* account key ------------------------------------------------------- */
  const accPath   = path.join(STORE, 'account.key');
  let accountKey  = await fs.readFile(accPath, 'utf8').catch(() => null);
  if (!accountKey) {
    accountKey = await acme.crypto.createPrivateKey();
    await fs.writeFile(accPath, accountKey);
    await log('account-key-generated');
  }

  /* client ------------------------------------------------------------ */
  const client = new acme.Client({
    directoryUrl: acme.directory.letsencrypt.production,
    accountKey
  });

  /* domain key -------------------------------------------------------- */
  const keyPath   = path.join(STORE, `${DOMAIN}.key`);
  let domainKey   = await fs.readFile(keyPath, 'utf8').catch(() => null);
  if (!domainKey) {
    domainKey = await acme.crypto.createPrivateKey();
    await fs.writeFile(keyPath, domainKey);
    await log('domain-key-generated');
  }

  /* CSR --------------------------------------------------------------- */
  const [, csr] = await acme.crypto.createCsr(
    { commonName: DOMAIN, altNames: [DOMAIN, `www.${DOMAIN}`] },
    domainKey
  );

  /* Order & challenge ------------------------------------------------- */
  const fullchain = await client.auto({
    csr,
    email: EMAIL,
    termsOfServiceAgreed: true,
    challengeCreateFn : challengeCreate,
    challengeRemoveFn : challengeRemove
  });
  await log('certificate-issued');

  /* Split PEM parts --------------------------------------------------- */
  const parts   = fullchain.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/gs);
  const certPem = parts.shift();
  const cabundle = parts.join('\n');

  /* Install via cPanel UAPI ------------------------------------------- */
  const qs = new URLSearchParams({
    domain: DOMAIN, cert: certPem, key: domainKey, cabundle
  }).toString();

  const resp  = await fetch(`https://${CPANEL_HOST || DOMAIN}:2083/execute/SSL/install_ssl?${qs}`, {
    headers: { Authorization: `cpanel ${CPANEL_USER}:${CPANEL_TOKEN}` }
  });
  const data  = await resp.json();
  if (data.status !== 1) {
    await log('cpanel-install-failed', { errors: data.errors });
    throw new Error('cPanel rejected the certificate');
  }
  await log('cpanel-install-success');
  return data;
}

/* --------------------------------------------------------------------- */
/* 6. Minimal HTTP server                                                */
/* --------------------------------------------------------------------- */
const server = http.createServer(async (req, res) => {
  try {
    /* health‑check ---------------------------------------------------- */
    if (req.method === 'GET' && req.url === '/health') {
      const lastLine = await fs.readFile(LOG_FILE, 'utf8').catch(() => '');
      const lastTS   = lastLine.trim().split('\n').pop()?.match(/"ts":"([^"]+)"/)?.[1] || null;

      res.writeHead(200, { 'Content-Type': 'application/json' })
         .end(JSON.stringify({ ok: true, lastLog: lastTS }));
      return;
    }

    /* renew ----------------------------------------------------------- */
    if (req.method === 'POST' && req.url === '/certificate/renew') {
      if (req.headers.authorization !== `Bearer ${RENEW_SECRET}`) {
        res.writeHead(401).end('unauthorized');
        return;
      }
      const result = await renew();
      res.writeHead(200, { 'Content-Type': 'application/json' })
         .end(JSON.stringify({ ok: true, result }));
      return;
    }

    /* not found ------------------------------------------------------- */
    res.writeHead(404).end('not found');
  } catch (err) {
    await log('server-error', { message: err.message });
    res.writeHead(500).end('internal error');
  }
});

server.listen(PORT, () => log('server-start', { port: PORT }));
