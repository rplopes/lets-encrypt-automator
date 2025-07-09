#!/usr/bin/env node
/**
 * renew.js – Run from cron or manually.
 *   --staging   → use Let's Encrypt STAGING (no rate limit, not trusted)
 *   --dry-run   → walk through everything EXCEPT the cPanel install step
 * Log file: renewer.log (JSON‑per‑line, auto‑rotates at 1 MB)
 */
import fs from 'fs/promises';
import { renameSync, statSync } from 'node:fs';
import path from 'node:path';
import acme from 'acme-client';

/* ------------------ 1. CLI options ------------------------------------- */
const argv = new Set(process.argv.slice(2));
const STAGING = argv.has('--staging');
const DRY     = argv.has('--dry-run');

/* ------------------ 2. Required env vars ------------------------------- */
const {
  DOMAIN, EMAIL, CPANEL_USER, CPANEL_TOKEN,
  CPANEL_HOST = DOMAIN,
  HOME = process.env.HOME,
  LOG_FILE = path.join(path.dirname(new URL(import.meta.url).pathname), 'renewer.log'),
  MAX_LOG_BYTES = 1_000_000
} = process.env;

for (const [k, v] of Object.entries({ DOMAIN, EMAIL, CPANEL_USER, CPANEL_TOKEN })) {
  if (!v) { console.error(`ENV ${k} is required`); process.exit(1); }
}

/* ------------------ 3. Poor‑man's logger ------------------------------- */
async function log(event, detail = {}) {
  try {
    if (statSync(LOG_FILE, { throwIfNoEntry: false })?.size > MAX_LOG_BYTES) {
      renameSync(LOG_FILE, LOG_FILE + '.1');
    }
  } catch {}
  await fs.appendFile(LOG_FILE,
    JSON.stringify({ ts: new Date().toISOString(), event, ...detail }) + '\n');
}

/* ------------------ 4. Paths ------------------------------------------ */
const STORE = path.join(path.dirname(new URL(import.meta.url).pathname), 'data');
const CHAL  = path.join(HOME, 'public_html', '.well-known', 'acme-challenge');
await fs.mkdir(STORE, { recursive: true });
await fs.mkdir(CHAL,  { recursive: true });

/* ------------------ 5. Challenge helpers ------------------------------ */
const challengeCreate = async (_, c, ka) => {
  await fs.writeFile(path.join(CHAL, c.token), ka, 'utf8');
  await log('challenge-create', { token: c.token });
};
const challengeRemove = async (_, c) => {
  await fs.rm(path.join(CHAL, c.token), { force: true });
  await log('challenge-remove', { token: c.token });
};

/* ------------------ 6. Main routine ----------------------------------- */
(async () => {
  try {
    await log('renew-start', { staging: STAGING, dry: DRY });

    /* account key */
    const accPath = path.join(STORE, 'account.key');
    let accountKey = await fs.readFile(accPath, 'utf8').catch(() => null);
    if (!accountKey) {
      accountKey = await acme.crypto.createPrivateKey();
      await fs.writeFile(accPath, accountKey);
      await log('account-key-generated');
    }

    /* client */
    const client = new acme.Client({
      directoryUrl: STAGING
        ? acme.directory.letsencrypt.staging
        : acme.directory.letsencrypt.production,
      accountKey
    });

    /* domain key */
    const keyPath = path.join(STORE, `${DOMAIN}.key`);
    let domainKey = await fs.readFile(keyPath, 'utf8').catch(() => null);
    if (!domainKey) {
      domainKey = await acme.crypto.createPrivateKey();
      await fs.writeFile(keyPath, domainKey);
      await log('domain-key-generated');
    }

    /* CSR */
    const [, csr] = await acme.crypto.createCsr(
      { commonName: DOMAIN, altNames: [DOMAIN, `www.${DOMAIN}`] },
      domainKey
    );

    /* order cert */
    const fullchain = await client.auto({
      csr,
      email: EMAIL,
      termsOfServiceAgreed: true,
      challengeCreateFn : challengeCreate,
      challengeRemoveFn : challengeRemove
    });
    await log('certificate-issued');

    if (DRY) {
      await log('dry-run-complete');
      console.log('Dry‑run OK – certificate obtained but not installed.');
      return;
    }

    /* split PEM parts */
    const [certPem, ...rest] =
      fullchain.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/gs);
    const cabundle = rest.join('\n');

    /* install via cPanel UAPI */
    const qs = new URLSearchParams({
      domain: DOMAIN, cert: certPem, key: domainKey, cabundle
    }).toString();

    const resp = await fetch(`https://${CPANEL_HOST}:2083/execute/SSL/install_ssl?${qs}`, {
      headers: { Authorization: `cpanel ${CPANEL_USER}:${CPANEL_TOKEN}` }
    });
    const data = await resp.json();
    if (data.status !== 1) {
      await log('cpanel-install-failed', { errors: data.errors });
      throw new Error('cPanel rejected the certificate');
    }
    await log('cpanel-install-success');
    console.log('Certificate installed.');
  } catch (e) {
    await log('renew-error', { message: e.message });
    console.error(e);
    process.exit(1);
  }
})();

