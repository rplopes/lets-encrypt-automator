import http from 'node:http';
import fs from 'fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import acme from 'acme-client';

const {
  DOMAIN, EMAIL, CPANEL_HOST, CPANEL_USER, CPANEL_TOKEN,
  RENEW_SECRET, HOME = process.env.HOME
} = process.env;

if (!DOMAIN || !EMAIL || !CPANEL_USER || !CPANEL_TOKEN || !RENEW_SECRET) {
  console.error('Missing required environment variables');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------
const CHAL_DIR = path.join(HOME, 'public_html', '.well-known', 'acme-challenge');
const STORE    = path.join(path.dirname(fileURLToPath(import.meta.url)), 'data');
await fs.mkdir(CHAL_DIR, { recursive: true });
await fs.mkdir(STORE,    { recursive: true });

// ---------------------------------------------------------------------------
// Helpers for ACME HTTP‑01 challenge
// ---------------------------------------------------------------------------
async function challengeCreate(_, ch, keyAuth) {
  await fs.writeFile(path.join(CHAL_DIR, ch.token), keyAuth, 'utf8');
}
async function challengeRemove(_, ch) {
  await fs.rm(path.join(CHAL_DIR, ch.token), { force: true });
}

// ---------------------------------------------------------------------------
// Core renewal function – can be called from cron or the mini‑server
// ---------------------------------------------------------------------------
export async function renew() {
  // 1. account key
  const accPath = path.join(STORE, 'account.key');
  let accountKey = await fs.readFile(accPath, 'utf8').catch(() => null);
  if (!accountKey) {
    accountKey = await acme.crypto.createPrivateKey();
    await fs.writeFile(accPath, accountKey);
  }

  // 2. ACME client
  const client = new acme.Client({
    directoryUrl: acme.directory.letsencrypt.production,
    accountKey
  });

  // 3. domain key
  const keyPath = path.join(STORE, `${DOMAIN}.key`);
  let domainKey = await fs.readFile(keyPath, 'utf8').catch(() => null);
  if (!domainKey) {
    domainKey = await acme.crypto.createPrivateKey();
    await fs.writeFile(keyPath, domainKey);
  }

  // 4. CSR
  const [, csr] = await acme.crypto.createCsr(
    { commonName: DOMAIN, altNames: [DOMAIN, `www.${DOMAIN}`] },
    domainKey
  );

  // 5. Obtain certificate
  const fullchain = await client.auto({
    csr,
    email: EMAIL,
    termsOfServiceAgreed: true,
    challengeCreateFn: challengeCreate,
    challengeRemoveFn: challengeRemove
  });

  // Split leaf / chain
  const parts = fullchain.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/gs);
  const certPem  = parts.shift();
  const cabundle = parts.join('\n');

  // 6. Install via cPanel UAPI (HTTPS GET + basic header)
  const qs = new URLSearchParams({
    domain : DOMAIN,
    cert   : certPem,
    key    : domainKey,
    cabundle
  }).toString();

  const resp = await fetch(`https://${CPANEL_HOST || DOMAIN}:2083/execute/SSL/install_ssl?${qs}`, {
    headers: { Authorization: `cpanel ${CPANEL_USER}:${CPANEL_TOKEN}` },
    // shared hosts usually have a valid cert; if not, uncomment next line:
    // insecureHTTPParser: true
  });
  const data = await resp.json();
  if (data.status !== 1) throw new Error('cPanel refused the certificate: ' + JSON.stringify(data));
  return data;
}

// ---------------------------------------------------------------------------
// Tiny HTTP server using the Node stdlib
// ---------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === 'health') {
    res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true }));
  }
  if (req.method === 'POST' && req.url === '/certificate/renew') {
    if (req.headers.authorization !== `Bearer ${RENEW_SECRET}`) {
      res.writeHead(401).end('unauthorized');
      return;
    }
    try {
      const out = await renew();
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true, out }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: false, error: e.message }));
    }
  } else {
    res.writeHead(404).end('not found');
  }
});

server.listen(process.env.PORT || 3000, () =>
  console.log(`Renewer listening on port ${process.env.PORT || 3000}`));

