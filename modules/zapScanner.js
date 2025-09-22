import ZAP from 'zaproxy';

export class ZAPScanner {
    constructor() {
        this.zapClient = null;
        this.zapConfig = {
            proxy: 'http://127.0.0.1:8080'
        };
    }

    // Helper method to check if ZAP Docker container is running
    static getZAPDockerInstructions() {
        return {
            quickStart: `docker run -d --name devxploit-zap -p 8080:8080 zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true`,
            checkStatus: `docker ps | grep zap`,
            stopZAP: `docker stop devxploit-zap && docker rm devxploit-zap`,
            testConnection: `curl http://localhost:8080/JSON/core/view/version/`,
            troubleshoot: `If ZAP won't start, kill any existing containers first: docker stop devxploit-zap 2>/dev/null || true && docker rm devxploit-zap 2>/dev/null || true`
        };
    }

    async initializeZAP() {
        try {
            // Initialize ZAP client with proper configuration
            this.zapClient = new ZAP({
                proxy: 'http://127.0.0.1:8080'
            });
            
            // Test ZAP connection
            const version = await this.zapClient.core.version();
            console.log(`✅ ZAP Docker container connected - Version: ${version}`);
            return true;
        } catch (error) {
            console.log('❌ ZAP Docker container not available:', error.message);
            
            // For now, let's disable ZAP and focus on the core functionality
            console.log('🎯 Continuing with passive scanning (ZAP integration disabled)');
            return false;
        }
    }

    async performActiveScan(targetUrl) {
        const zapAvailable = await this.initializeZAP();
        
        if (!zapAvailable) {
            const instructions = ZAPScanner.getZAPDockerInstructions();
            return {
                error: 'ZAP Docker container not available',
                message: 'OWASP ZAP is not running in Docker. Start it with the command below.',
                instructions: instructions,
                vulnerabilities: [],
                fallbackUsed: true
            };
        }

        try {
            const results = await this.runZAPScan(targetUrl);
            return {
                zapAvailable: true,
                vulnerabilities: results.vulnerabilities,
                scanSummary: results.summary,
                zapVersion: results.version
            };
        } catch (error) {
            console.error('ZAP scan failed:', error);
            return {
                error: 'ZAP scan failed',
                message: error.message,
                vulnerabilities: [],
                fallbackUsed: true
            };
        }
    }

    async runZAPScan(targetUrl) {
        console.log(`🔍 Starting OWASP ZAP scan for: ${targetUrl}`);
        
        // Get ZAP version
        const version = await this.zapClient.core.version();
        
        // Step 1: Spider the target (passive discovery)
        console.log('🕷️ Starting ZAP spider...');
        const spiderScanId = await this.zapClient.spider.scan(targetUrl);
        await this.waitForSpiderCompletion(spiderScanId);
        
        // Step 2: Passive scan (analyze spidered content)
        console.log('🔍 Running passive scan...');
        await this.waitForPassiveScanCompletion();
        
        // Step 3: Active scan (vulnerability detection)
        console.log('⚡ Starting active vulnerability scan...');
        const activeScanId = await this.zapClient.ascan.scan(targetUrl);
        await this.waitForActiveScanCompletion(activeScanId);
        
        // Step 4: Get results
        const alerts = await this.zapClient.core.alerts('High,Medium,Low');
        const summary = await this.zapClient.core.alertsSummary();
        
        console.log(`✅ ZAP scan completed. Found ${alerts.length} alerts`);
        
        return {
            version: version,
            vulnerabilities: this.processZAPAlerts(alerts),
            summary: this.processSummary(summary)
        };
    }

    async waitForSpiderCompletion(spiderScanId) {
        let progress = 0;
        while (progress < 100) {
            await this.sleep(2000); // Wait 2 seconds
            const status = await this.zapClient.spider.status(spiderScanId);
            progress = parseInt(status);
            console.log(`🕷️ Spider progress: ${progress}%`);
        }
    }

    async waitForPassiveScanCompletion() {
        let recordsToScan = 1;
        while (recordsToScan > 0) {
            await this.sleep(2000);
            const recordsLeft = await this.zapClient.pscan.recordsToScan();
            recordsToScan = parseInt(recordsLeft);
            if (recordsToScan > 0) {
                console.log(`🔍 Passive scan: ${recordsToScan} records remaining`);
            }
        }
    }

    async waitForActiveScanCompletion(activeScanId) {
        let progress = 0;
        while (progress < 100) {
            await this.sleep(3000); // Wait 3 seconds
            const status = await this.zapClient.ascan.status(activeScanId);
            progress = parseInt(status);
            console.log(`⚡ Active scan progress: ${progress}%`);
        }
    }

    processZAPAlerts(alerts) {
        return alerts.map(alert => ({
            type: alert.alert || 'Unknown Vulnerability',
            severity: this.mapZAPRisk(alert.risk),
            confidence: alert.confidence,
            location: alert.url,
            description: alert.description || 'No description available',
            solution: alert.solution || 'No solution provided',
            reference: alert.reference || '',
            evidence: alert.evidence || alert.attack || '',
            cweid: alert.cweid || '',
            wascid: alert.wascid || '',
            pluginId: alert.pluginId || '',
            source: 'OWASP ZAP',
            remediation: this.generateZAPRemediation(alert)
        }));
    }

    mapZAPRisk(zapRisk) {
        const riskMapping = {
            'High': 'High',
            'Medium': 'Medium', 
            'Low': 'Low',
            'Informational': 'Info'
        };
        return riskMapping[zapRisk] || 'Unknown';
    }

    generateZAPRemediation(alert) {
        if (alert.solution) {
            return alert.solution;
        }

        // Generate basic remediation based on vulnerability type
        const remediationMap = {
            'SQL Injection': 'Use parameterized queries and input validation',
            'Cross Site Scripting': 'Implement output encoding and Content Security Policy',
            'Cross-Site Request Forgery': 'Implement CSRF tokens and SameSite cookies',
            'Missing Anti-clickjacking Header': 'Add X-Frame-Options header',
            'Missing Anti-MIME-Sniffing Header': 'Add X-Content-Type-Options: nosniff header'
        };

        return remediationMap[alert.alert] || 'Review ZAP documentation for specific remediation steps';
    }

    processSummary(summary) {
        return {
            high: parseInt(summary.High || 0),
            medium: parseInt(summary.Medium || 0),
            low: parseInt(summary.Low || 0),
            informational: parseInt(summary.Informational || 0),
            total: parseInt(summary.High || 0) + parseInt(summary.Medium || 0) + 
                   parseInt(summary.Low || 0) + parseInt(summary.Informational || 0)
        };
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // Method to check if ZAP is running
    static async isZAPAvailable() {
        try {
            const testClient = new ZAP({
                proxy: 'http://127.0.0.1:8080'
            });
            await testClient.core.version();
            return true;
        } catch (error) {
            return false;
        }
    }

    // Method to start ZAP if needed (informational)
    static getZAPInstructions() {
        return {
            message: 'OWASP ZAP is required for active scanning',
            instructions: [
                '1. Download OWASP ZAP from https://www.zaproxy.org/download/',
                '2. Start ZAP in daemon mode: zap.sh -daemon -host 127.0.0.1 -port 8080',
                '3. Or start ZAP GUI and ensure API is enabled on port 8080',
                '4. Restart your scan with active mode enabled'
            ],
            alternative: 'DevXploit will use basic vulnerability checks if ZAP is not available'
        };
    }
}