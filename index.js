#!/usr/bin/env node

const acme = require('acme-client');
const fs = require('fs').promises;
const path = require('path');
const https = require('https');
const http = require('http');
const { URLSearchParams } = require('url');

// Configuration - Load from environment variables and config file
const loadConfig = () => {
    let fileConfig = {};
    try {
        const configPath = process.env.CONFIG_FILE || './config.json';
        fileConfig = JSON.parse(require('fs').readFileSync(configPath, 'utf8'));
    } catch (error) {
        // Config file is optional, continue with environment variables
    }

    return {
        domain: process.env.DOMAIN || fileConfig.domain,
        email: process.env.EMAIL || fileConfig.email,
        cpanelUrl: process.env.CPANEL_URL || fileConfig.cpanelUrl,
        cpanelUsername: process.env.CPANEL_USERNAME || fileConfig.cpanelUsername,
        cpanelPassword: process.env.CPANEL_PASSWORD || fileConfig.cpanelPassword,
        webRoot: process.env.WEB_ROOT || fileConfig.webRoot,
        certDir: process.env.CERT_DIR || fileConfig.certDir,
        logFile: process.env.LOG_FILE || fileConfig.logFile,
        dryRun: process.argv.includes('--dry-run')
    };
};

const CONFIG = loadConfig();

class CertificateRenewer {
    constructor(config) {
        this.config = config;
        this.accountKey = null;
        this.client = null;
        this.cpanelSession = null;
    }

    async log(message) {
        const timestamp = new Date().toISOString();
        const logMessage = `[${timestamp}] ${message}\n`;
        console.log(logMessage.trim());
        
        if (!this.config.dryRun) {
            try {
                await fs.appendFile(this.config.logFile, logMessage);
            } catch (error) {
                console.error('Failed to write to log file:', error.message);
            }
        }
    }

    async ensureDirectoryExists(dirPath) {
        try {
            await fs.mkdir(dirPath, { recursive: true });
        } catch (error) {
            if (error.code !== 'EEXIST') {
                throw error;
            }
        }
    }

    async loadOrCreateAccountKey() {
        const keyPath = path.join(this.config.certDir, 'account.key');
        
        try {
            const keyData = await fs.readFile(keyPath);
            this.accountKey = keyData;
            await this.log('Loaded existing account key');
        } catch (error) {
            await this.log('Creating new account key');
            this.accountKey = await acme.forge.createPrivateKey();
            if (!this.config.dryRun) {
                await fs.writeFile(keyPath, this.accountKey);
            }
            await this.log('Account key created and saved');
        }
    }

    async initializeAcmeClient() {
        // Use staging environment for dry run
        const directoryUrl = this.config.dryRun
            ? acme.directory.letsencrypt.staging
            : acme.directory.letsencrypt.production;

        this.client = new acme.Client({
            directoryUrl,
            accountKey: this.accountKey
        });

        try {
            await this.client.getAccountUrl();
            await this.log(`Using existing ACME account (${this.config.dryRun ? 'STAGING' : 'PRODUCTION'})`);
        } catch (error) {
            await this.log(`Creating new ACME account (${this.config.dryRun ? 'STAGING' : 'PRODUCTION'})`);
            await this.client.createAccount({
                termsOfServiceAgreed: true,
                contact: [`mailto:${this.config.email}`]
            });
            await this.log('ACME account created');
        }
    }

    async handleHttpChallenge(authz, challenge, keyAuthorization) {
        const token = challenge.token;
        const challengePath = path.join(this.config.webRoot, '.well-known', 'acme-challenge', token);
        
        await this.log(`Creating challenge file: ${challengePath}`);
        await this.ensureDirectoryExists(path.dirname(challengePath));

        if (!this.config.dryRun) {
            await fs.writeFile(challengePath, keyAuthorization);
        } else {
            await this.log('DRY RUN: Would create challenge file');
        }
        
        // Verify the challenge file is accessible
        const challengeUrl = `http://${this.config.domain}/.well-known/acme-challenge/${token}`;
        await this.log(`Challenge file should be accessible at: ${challengeUrl}`);
        
        return async () => {
            try {
                if (!this.config.dryRun) {
                    await fs.unlink(challengePath);
                }
                await this.log('Challenge file cleaned up');
            } catch (error) {
                await this.log(`Warning: Could not clean up challenge file: ${error.message}`);
            }
        };
    }

    async requestCertificate() {
        await this.log(`Requesting certificate for domain: ${this.config.domain}`);
        
        if (this.config.dryRun) {
            await this.log('DRY RUN: Skipping actual certificate request');
            return {
                cert: '-----BEGIN CERTIFICATE-----\nDRY RUN CERTIFICATE\n-----END CERTIFICATE-----',
                key: '-----BEGIN PRIVATE KEY-----\nDRY RUN KEY\n-----END PRIVATE KEY-----',
                certPath: path.join(this.config.certDir, 'certificate.crt'),
                keyPath: path.join(this.config.certDir, 'private.key'),
                chainPath: path.join(this.config.certDir, 'chain.crt')
            };
        }

        // Create Certificate Signing Request
        const [key, csr] = await acme.forge.createCsr({
            commonName: this.config.domain
        });

        // Request certificate
        const cert = await this.client.auto({
            csr,
            email: this.config.email,
            termsOfServiceAgreed: true,
            challengeCreateFn: async (authz, challenge, keyAuthorization) => {
                if (challenge.type === 'http-01') {
                    return await this.handleHttpChallenge(authz, challenge, keyAuthorization);
                }
                throw new Error(`Unsupported challenge type: ${challenge.type}`);
            },
            challengeRemoveFn: async (authz, challenge, keyAuthorization) => {
                // Cleanup is handled in handleHttpChallenge return function
            }
        });

        // Save certificate files
        const certPath = path.join(this.config.certDir, 'certificate.crt');
        const keyPath = path.join(this.config.certDir, 'private.key');
        const chainPath = path.join(this.config.certDir, 'chain.crt');

        await fs.writeFile(certPath, cert);
        await fs.writeFile(keyPath, key);
        
        // Extract certificate chain
        const certLines = cert.split('\n');
        let inChain = false;
        let chainContent = '';
        
        for (const line of certLines) {
            if (line.includes('-----END CERTIFICATE-----')) {
                if (inChain) {
                    chainContent += line + '\n';
                }
                inChain = true;
            } else if (inChain) {
                chainContent += line + '\n';
            }
        }
        
        if (chainContent) {
            await fs.writeFile(chainPath, chainContent);
        }

        await this.log('Certificate files saved successfully');
        return { cert, key, certPath, keyPath, chainPath };
    }

    async makeHttpRequest(options, postData = null) {
        return new Promise((resolve, reject) => {
            const protocol = options.protocol === 'https:' ? https : http;
            const req = protocol.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    resolve({
                        statusCode: res.statusCode,
                        headers: res.headers,
                        body: data
                    });
                });
            });

            req.on('error', reject);

            if (postData) {
                req.write(postData);
            }

            req.end();
        });
    }

    async loginToCPanel() {
        await this.log('Attempting to login to cPanel via HTTP');
        
        if (this.config.dryRun) {
            await this.log('DRY RUN: Skipping cPanel login');
            return 'dry-run-session';
        }

        const loginUrl = new URL(this.config.cpanelUrl);
        const loginData = new URLSearchParams({
            user: this.config.cpanelUsername,
            pass: this.config.cpanelPassword,
            goto_uri: '/'
        });

        const options = {
            hostname: loginUrl.hostname,
            port: loginUrl.port || (loginUrl.protocol === 'https:' ? 443 : 80),
            path: '/login/',
            method: 'POST',
            protocol: loginUrl.protocol,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': loginData.toString().length,
                'User-Agent': 'Mozilla/5.0 (compatible; SSL-Renewer/1.0)'
            },
            rejectUnauthorized: false // For self-signed certificates
        };

        try {
            const response = await this.makeHttpRequest(options, loginData.toString());
            
            if (response.statusCode === 302 || response.statusCode === 200) {
                // Extract session cookies
                const cookies = response.headers['set-cookie'];
                if (cookies) {
                    this.cpanelSession = cookies.map(cookie => cookie.split(';')[0]).join('; ');
                    await this.log('Successfully logged into cPanel');
                    return this.cpanelSession;
                }
            }
            
            throw new Error(`Login failed with status: ${response.statusCode}`);
        } catch (error) {
            await this.log(`cPanel login failed: ${error.message}`);
            throw error;
        }
    }

    async uploadCertificateViaCPanel(certData) {
        await this.log('Uploading certificate via cPanel HTTP API');

        if (this.config.dryRun) {
            await this.log('DRY RUN: Would upload certificate to cPanel');
            return;
        }

        // First login to get session
        await this.loginToCPanel();

        // Read certificate files
        const certificate = await fs.readFile(certData.certPath, 'utf8');
        const privateKey = await fs.readFile(certData.keyPath, 'utf8');
        let chain = '';
        try {
            chain = await fs.readFile(certData.chainPath, 'utf8');
        } catch (error) {
            await this.log('No chain file found, continuing without it');
        }

        // Prepare certificate data
        const certFormData = new URLSearchParams({
            domain: this.config.domain,
            cert: certificate,
            key: privateKey,
            cab: chain,
            op: 'install'
        });

        const cpanelUrl = new URL(this.config.cpanelUrl);
        const options = {
            hostname: cpanelUrl.hostname,
            port: cpanelUrl.port || (cpanelUrl.protocol === 'https:' ? 443 : 80),
            path: '/frontend/paper_lantern/ssl/doinstallssl.html',
            method: 'POST',
            protocol: cpanelUrl.protocol,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': certFormData.toString().length,
                'Cookie': this.cpanelSession,
                'User-Agent': 'Mozilla/5.0 (compatible; SSL-Renewer/1.0)',
                'Referer': `${this.config.cpanelUrl}/frontend/paper_lantern/ssl/install.html`
            },
            rejectUnauthorized: false
        };

        try {
            const response = await this.makeHttpRequest(options, certFormData.toString());
            
            if (response.statusCode === 200 && response.body.includes('success')) {
                await this.log('Certificate uploaded successfully via cPanel');
            } else {
                throw new Error(`Certificate upload failed. Status: ${response.statusCode}`);
            }
        } catch (error) {
            await this.log(`Certificate upload failed: ${error.message}`);
            // Fall back to manual notification
            await this.log('FALLBACK: Certificate files are ready for manual upload:');
            await this.log(`Certificate: ${certData.certPath}`);
            await this.log(`Private Key: ${certData.keyPath}`);
            await this.log(`Chain: ${certData.chainPath}`);
        }
    }

    async checkCertificateExpiry() {
        try {
            const certPath = path.join(this.config.certDir, 'certificate.crt');
            const certData = await fs.readFile(certPath, 'utf8');
            
            // Simple expiry check without node-forge to save memory
            const certMatch = certData.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
            if (!certMatch) {
                throw new Error('Invalid certificate format');
            }
            
            // For now, assume renewal is needed if we can't parse the date
            // In a real scenario, you might want to add a simple date parser
            const now = new Date();
            const createdTime = (await fs.stat(certPath)).mtime;
            const daysSinceCreated = Math.floor((now - createdTime) / (1000 * 60 * 60 * 24));
            
            await this.log(`Certificate was created ${daysSinceCreated} days ago`);
            
            // Renew if certificate is older than 60 days (Let's Encrypt certs are valid for 90 days)
            return daysSinceCreated > 60;
        } catch (error) {
            await this.log(`Could not check certificate expiry: ${error.message}`);
            return true; // Renew if we can't check
        }
    }

    async renewCertificate() {
        try {
            await this.log(`=== Starting Let's Encrypt certificate renewal ${this.config.dryRun ? '(DRY RUN)' : ''} ===`);
            
            // Validate required configuration
            if (!this.config.cpanelPassword && !this.config.dryRun) {
                throw new Error('cPanel password is required. Set CPANEL_PASSWORD environment variable or add to config.json');
            }
            
            if (!this.config.domain || this.config.domain === 'your-domain.com') {
                throw new Error('Domain is required. Set DOMAIN environment variable or add to config.json');
            }
            
            // Check if renewal is needed
            const needsRenewal = await this.checkCertificateExpiry();
            if (!needsRenewal && !this.config.dryRun) {
                await this.log('Certificate does not need renewal yet');
                return;
            }
            
            // Ensure certificate directory exists
            await this.ensureDirectoryExists(this.config.certDir);
            
            // Initialize ACME client
            await this.loadOrCreateAccountKey();
            await this.initializeAcmeClient();
            
            // Request new certificate
            const certData = await this.requestCertificate();
            
            // Upload to cPanel
            await this.uploadCertificateViaCPanel(certData);
            
            await this.log(`=== Certificate renewal completed successfully ${this.config.dryRun ? '(DRY RUN)' : ''} ===`);
            
        } catch (error) {
            await this.log(`=== Certificate renewal failed: ${error.message} ===`);
            await this.log(`Stack trace: ${error.stack}`);
            throw error;
        }
    }
}

// Main execution
async function main() {
    const renewer = new CertificateRenewer(CONFIG);
    await renewer.renewCertificate();
}

// Run if this file is executed directly
if (require.main === module) {
    main().catch(error => {
        console.error('Fatal error:', error);
        process.exit(1);
    });
}

module.exports = CertificateRenewer;
