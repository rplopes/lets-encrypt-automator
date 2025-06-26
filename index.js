#!/usr/bin/env node

const acme = require('acme-client');
const puppeteer = require('puppeteer');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

// Configuration - Load from environment variables and config file
const loadConfig = () => {
    // Try to load from config file first
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
        logFile: process.env.LOG_FILE || fileConfig.logFile
    };
};

const CONFIG = loadConfig();

class LetsCertificateRenewer {
    constructor(config) {
        this.config = config;
        this.accountKey = null;
        this.client = null;
    }

    async log(message) {
        const timestamp = new Date().toISOString();
        const logMessage = `[${timestamp}] ${message}\n`;
        console.log(logMessage.trim());
        
        try {
            await fs.appendFile(this.config.logFile, logMessage);
        } catch (error) {
            console.error('Failed to write to log file:', error.message);
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
            await fs.writeFile(keyPath, this.accountKey);
            await this.log('Account key created and saved');
        }
    }

    async initializeAcmeClient() {
        this.client = new acme.Client({
            directoryUrl: acme.directory.letsencrypt.production,
            accountKey: this.accountKey
        });

        try {
            await this.client.getAccountUrl();
            await this.log('Using existing ACME account');
        } catch (error) {
            await this.log('Creating new ACME account');
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
        await fs.writeFile(challengePath, keyAuthorization);
        
        // Verify the challenge file is accessible
        const challengeUrl = `http://${this.config.domain}/.well-known/acme-challenge/${token}`;
        await this.log(`Challenge file should be accessible at: ${challengeUrl}`);
        
        return async () => {
            try {
                await fs.unlink(challengePath);
                await this.log('Challenge file cleaned up');
            } catch (error) {
                await this.log(`Warning: Could not clean up challenge file: ${error.message}`);
            }
        };
    }

    async requestCertificate() {
        await this.log(`Requesting certificate for domain: ${this.config.domain}`);
        
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
        
        // Extract certificate chain (intermediate certificates)
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

    async uploadToCPanel(certData) {
        await this.log('Starting cPanel certificate upload process');
        
        const browser = await puppeteer.launch({ 
            headless: true,
            args: ['--no-sandbox', '--disable-setuid-sandbox']
        });
        
        try {
            const page = await browser.newPage();
            
            // Set a longer timeout for slow connections
            page.setDefaultTimeout(30000);
            
            // Navigate to cPanel login
            await this.log('Navigating to cPanel login');
            await page.goto(this.config.cpanelUrl);
            
            // Login
            await this.log('Logging into cPanel');
            await page.waitForSelector('input[name="user"]', { timeout: 10000 });
            await page.type('input[name="user"]', this.config.cpanelUsername);
            await page.type('input[name="pass"]', this.config.cpanelPassword);
            await page.click('input[type="submit"]');
            
            // Wait for dashboard to load
            await page.waitForNavigation({ waitUntil: 'networkidle0' });
            await this.log('Successfully logged into cPanel');
            
            // Navigate to SSL/TLS section
            await this.log('Navigating to SSL/TLS section');
            await page.goto(`${this.config.cpanelUrl}/frontend/paper_lantern/ssl/index.html`);
            
            // Wait for SSL page to load
            await page.waitForSelector('a[href*="ssl_install"]', { timeout: 10000 });
            
            // Click on "Install and Manage SSL for your site"
            await page.click('a[href*="ssl_install"]');
            await page.waitForNavigation({ waitUntil: 'networkidle0' });
            
            await this.log('Uploading certificate data');
            
            // Read certificate files
            const certificate = await fs.readFile(certData.certPath, 'utf8');
            const privateKey = await fs.readFile(certData.keyPath, 'utf8');
            let chain = '';
            try {
                chain = await fs.readFile(certData.chainPath, 'utf8');
            } catch (error) {
                await this.log('No chain file found, continuing without it');
            }
            
            // Fill in the certificate form
            await page.waitForSelector('textarea[name="cert"]', { timeout: 10000 });
            
            // Clear existing content and fill new certificate
            await page.evaluate(() => {
                const certField = document.querySelector('textarea[name="cert"]');
                const keyField = document.querySelector('textarea[name="key"]');
                const chainField = document.querySelector('textarea[name="cab"]');
                
                if (certField) certField.value = '';
                if (keyField) keyField.value = '';
                if (chainField) chainField.value = '';
            });
            
            await page.type('textarea[name="cert"]', certificate);
            await page.type('textarea[name="key"]', privateKey);
            
            if (chain) {
                await page.type('textarea[name="cab"]', chain);
            }
            
            // Submit the form
            await this.log('Installing certificate');
            await page.click('input[value="Install Certificate"]');
            
            // Wait for success message
            await page.waitForSelector('.success, .alert-success, [class*="success"]', { timeout: 15000 });
            
            await this.log('Certificate installed successfully in cPanel');
            
        } catch (error) {
            await this.log(`Error during cPanel upload: ${error.message}`);
            throw error;
        } finally {
            await browser.close();
        }
    }

    async checkCertificateExpiry() {
        try {
            const certPath = path.join(this.config.certDir, 'certificate.crt');
            const certData = await fs.readFile(certPath, 'utf8');
            
            // Extract expiry date from certificate
            const forge = require('node-forge');
            const cert = forge.pki.certificateFromPem(certData);
            const expiryDate = cert.validity.notAfter;
            const now = new Date();
            const daysUntilExpiry = Math.floor((expiryDate - now) / (1000 * 60 * 60 * 24));
            
            await this.log(`Certificate expires in ${daysUntilExpiry} days (${expiryDate.toISOString()})`);
            
            // Renew if less than 30 days remaining
            return daysUntilExpiry < 30;
        } catch (error) {
            await this.log(`Could not check certificate expiry: ${error.message}`);
            return true; // Renew if we can't check
        }
    }

    async renewCertificate() {
        try {
            await this.log('=== Starting Let\'s Encrypt certificate renewal ===');
            
            // Validate required configuration
            if (!this.config.cpanelPassword) {
                throw new Error('cPanel password is required. Set CPANEL_PASSWORD environment variable or add to config.json');
            }
            
            if (!this.config.domain || this.config.domain === 'your-domain.com') {
                throw new Error('Domain is required. Set DOMAIN environment variable or add to config.json');
            }
            
            // Check if renewal is needed
            const needsRenewal = await this.checkCertificateExpiry();
            if (!needsRenewal) {
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
            await this.uploadToCPanel(certData);
            
            await this.log('=== Certificate renewal completed successfully ===');
            
        } catch (error) {
            await this.log(`=== Certificate renewal failed: ${error.message} ===`);
            await this.log(`Stack trace: ${error.stack}`);
            throw error;
        }
    }
}

// Main execution
async function main() {
    const renewer = new LetsCertificateRenewer(CONFIG);
    await renewer.renewCertificate();
}

// Run if this file is executed directly
if (require.main === module) {
    main().catch(error => {
        console.error('Fatal error:', error);
        process.exit(1);
    });
}

module.exports = LetsCertificateRenewer;
