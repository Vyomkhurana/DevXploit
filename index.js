const express = require('express');
const path = require('path');
const fs = require('fs');
const puppeteer = require('puppeteer');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = 3000;

// ZAP Configuration
const ZAP_BASE_URL = 'http://localhost:8080';
let zapAvailable = false;

// Check ZAP availability on startup
async function checkZAPAvailability() {
    try {
        const response = await axios.get(`${ZAP_BASE_URL}/JSON/core/view/version/`);
        if (response.data && response.data.version) {
            zapAvailable = true;
            console.log(`🔥 OWASP ZAP connected - Version: ${response.data.version}`);
            return true;
        }
    } catch (error) {
        zapAvailable = false;
        console.log('⚠️ OWASP ZAP not available - continuing with passive scanning only');
        return false;
    }
}

// ZAP Active Scanning Functions
async function performZAPActiveScan(targetUrl) {
    if (!zapAvailable) {
        return { error: 'ZAP not available' };
    }

    try {
        console.log(`🔥 Starting ZAP active scan for: ${targetUrl}`);
        
        // Spider the target first
        console.log('🕷️ ZAP Spider scanning...');
        const spiderResponse = await axios.get(`${ZAP_BASE_URL}/JSON/spider/action/scan/`, {
            params: { url: targetUrl }
        });
        
        const spiderScanId = spiderResponse.data.scan;
        
        // Wait for spider to complete
        let spiderComplete = false;
        let spiderProgress = 0;
        while (!spiderComplete && spiderProgress < 100) {
            await new Promise(resolve => setTimeout(resolve, 2000));
            const statusResponse = await axios.get(`${ZAP_BASE_URL}/JSON/spider/view/status/`, {
                params: { scanId: spiderScanId }
            });
            spiderProgress = parseInt(statusResponse.data.status);
            console.log(`🕷️ Spider progress: ${spiderProgress}%`);
            if (spiderProgress >= 100) spiderComplete = true;
        }
        
        // Start active scan
        console.log('⚡ ZAP Active scanning...');
        const activeScanResponse = await axios.get(`${ZAP_BASE_URL}/JSON/ascan/action/scan/`, {
            params: { url: targetUrl }
        });
        
        const activeScanId = activeScanResponse.data.scan;
        
        // Wait for active scan to complete (with timeout for better UX)
        let scanComplete = false;
        let scanProgress = 0;
        let scanTimeout = 0;
        const MAX_SCAN_TIME = 60; // 3 minutes maximum (60 * 3 seconds = 180 seconds)
        
        while (!scanComplete && scanProgress < 100 && scanTimeout < MAX_SCAN_TIME) {
            await new Promise(resolve => setTimeout(resolve, 3000));
            const statusResponse = await axios.get(`${ZAP_BASE_URL}/JSON/ascan/view/status/`, {
                params: { scanId: activeScanId }
            });
            scanProgress = parseInt(statusResponse.data.status);
            console.log(`⚡ Active scan progress: ${scanProgress}%`);
            
            // Return early results at 10% to improve UX
            if (scanProgress >= 10 && scanTimeout > 20) {
                console.log('🚀 Returning early ZAP results for better UX');
                break;
            }
            
            if (scanProgress >= 100) scanComplete = true;
            scanTimeout++;
        }
        
        if (scanTimeout >= MAX_SCAN_TIME) {
            console.log('⏱️ ZAP scan timeout - returning partial results');
        }
        
        // Get alerts/vulnerabilities
        const alertsResponse = await axios.get(`${ZAP_BASE_URL}/JSON/core/view/alerts/`, {
            params: { baseurl: targetUrl }
        });
        
        const zapVulns = alertsResponse.data.alerts.map(alert => ({
            type: `${alert.name} (ZAP)`,
            severity: mapZAPRiskToSeverity(alert.risk),
            description: alert.description || 'ZAP detected security issue',
            evidence: `Instance: ${alert.instances?.[0]?.uri || targetUrl}`,
            recommendation: alert.solution || 'Review and fix according to security best practices',
            cve: alert.cweid ? `CWE-${alert.cweid}` : 'N/A',
            impact: alert.description || 'Security vulnerability detected by professional scanner'
        }));
        
        console.log(`🔥 ZAP found ${zapVulns.length} vulnerabilities`);
        
        return {
            vulnerabilities: zapVulns,
            scanDetails: {
                spiderUrls: spiderProgress,
                activeScanId: activeScanId,
                totalAlerts: zapVulns.length
            }
        };
        
    } catch (error) {
        console.error('❌ ZAP scan failed:', error.message);
        return { error: error.message };
    }
}

function mapZAPRiskToSeverity(risk) {
    const riskMap = {
        'High': 'Critical',
        'Medium': 'High', 
        'Low': 'Medium',
        'Informational': 'Low'
    };
    return riskMap[risk] || 'Medium';
}

// File-based storage for scan results
const SCAN_RESULTS_FILE = path.join(__dirname, 'scan-results.json');
let scanResults = new Map();

function loadScanResults() {
    try {
        if (fs.existsSync(SCAN_RESULTS_FILE)) {
            const data = fs.readFileSync(SCAN_RESULTS_FILE, 'utf8');
            const results = JSON.parse(data);
            scanResults = new Map(Object.entries(results));
            console.log(`📁 Loaded ${scanResults.size} existing scan results`);
        }
    } catch (error) {
        console.error('❌ Error loading scan results:', error.message);
        scanResults = new Map();
    }
}

function saveScanResults() {
    try {
        const resultsObj = Object.fromEntries(scanResults);
        fs.writeFileSync(SCAN_RESULTS_FILE, JSON.stringify(resultsObj, null, 2));
        console.log('💾 Scan results saved to file');
    } catch (error) {
        console.error('❌ Error saving scan results:', error.message);
    }
}

// Load results on startup
loadScanResults();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

console.log('🚀 DevXploit Dashboard running on http://localhost:3000');
console.log('🔥 Advanced Security Intelligence Platform');
console.log('🎯 Think Like a Hacker, Build Like a Developer');

app.get('/', (req, res) => {
    try {
        res.render('home', { 
            title: 'DevXploit Security Platform',
            scanResults: Array.from(scanResults.values()).slice(-5)
        });
    } catch (error) {
        console.error("Error rendering home page:", error);
        res.status(500).send("Error loading dashboard");
    }
});

// Enhanced vulnerability scanning function
async function performComprehensiveVulnerabilityScanning(url) {
    const results = {
        url,
        timestamp: new Date().toISOString(),
        vulnerabilities: [],
        securityHeaders: {},
        technicalInfo: {}
    };

    try {
        console.log(`🔍 Starting comprehensive scan for: ${url}`);
        
        const response = await axios.get(url, { 
            timeout: 10000,
            validateStatus: false
        });
        
        const headers = response.headers;
        results.securityHeaders = {
            'strict-transport-security': headers['strict-transport-security'] || 'Missing',
            'content-security-policy': headers['content-security-policy'] || 'Missing',
            'x-frame-options': headers['x-frame-options'] || 'Missing',
            'x-content-type-options': headers['x-content-type-options'] || 'Missing',
            'x-xss-protection': headers['x-xss-protection'] || 'Missing'
        };

        console.log('🌐 Launching browser for dynamic analysis...');
        const browser = await puppeteer.launch({ 
            headless: true,
            args: [
                '--no-sandbox', 
                '--disable-setuid-sandbox',
                '--disable-web-security',
                '--disable-features=VizDisplayCompositor',
                '--disable-extensions',
                '--disable-plugins',
                '--disable-images',
                '--disable-javascript',
                '--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            ]
        });
        const page = await browser.newPage();
        
        // Set additional headers to bypass blocking
        await page.setExtraHTTPHeaders({
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        });
        
        try {
            await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 });
        } catch (gotoError) {
            console.log(`⚠️ Browser navigation blocked, falling back to HTTP analysis only: ${gotoError.message}`);
            // Continue with HTTP-only analysis
            await browser.close();
            
            // Perform HTTP-based vulnerability detection
            const responseText = response.data || '';
            
            // Enhanced XSS Detection
            const xssPatterns = [
                /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
                /javascript:/gi,
                /onload\s*=/gi,
                /onerror\s*=/gi,
                /onclick\s*=/gi,
                /onmouseover\s*=/gi,
                /eval\s*\(/gi,
                /document\.write/gi,
                /innerHTML/gi,
                /<iframe/gi,
                /<object/gi,
                /<embed/gi
            ];
            
            const xssMatches = xssPatterns.filter(pattern => pattern.test(responseText));
            if (xssMatches.length > 0) {
                results.vulnerabilities.push({
                    type: 'XSS (Cross-Site Scripting)',
                    severity: 'High',
                    description: 'Multiple XSS vectors detected in HTTP response',
                    evidence: `Found ${xssMatches.length} potential XSS patterns including script tags, event handlers, and dangerous functions`,
                    recommendation: 'Implement Content Security Policy, proper input validation and output encoding',
                    cve: 'CWE-79',
                    impact: 'Attackers could execute malicious scripts, steal cookies, or hijack sessions'
                });
            }
            
            // Enhanced SQL Injection Detection
            const sqlErrors = [
                'mysql_fetch_array', 'mysql_num_rows', 'mysql_error', 'mysql_result',
                'ORA-[0-9]+', 'Microsoft OLE DB', 'SQLServer JDBC Driver',
                'PostgreSQL.*ERROR', 'SQLite.*error', 'syntax error.*query',
                'Warning.*mysql_', 'valid MySQL result', 'MySqlClient',
                'Error Occurred While Processing Request', 'Server Error.*SQL',
                'ODBC.*SQL.*Driver', 'Invalid SQL statement', 'SQL syntax.*error',
                'Error.*in.*query', 'Database.*error', 'You have an error in your SQL syntax'
            ];
            
            const hasSqlError = sqlErrors.some(error => {
                const regex = new RegExp(error, 'i');
                return regex.test(responseText);
            });
            
            if (hasSqlError) {
                results.vulnerabilities.push({
                    type: 'SQL Injection - Error Based',
                    severity: 'Critical',
                    description: 'SQL database error messages detected in response',
                    evidence: 'Database error messages found in HTTP response indicating potential SQL injection',
                    recommendation: 'Remove error messages, implement proper error handling, and use parameterized queries',
                    cve: 'CWE-89',
                    impact: 'May reveal database structure and enable SQL injection attacks leading to data breach'
                });
            }
            
            // Advanced Form Analysis
            const formPattern = /<form[\s\S]*?<\/form>/gi;
            const forms = responseText.match(formPattern) || [];
            const inputPattern = /<input[^>]*>/gi;
            const textareaPattern = /<textarea[\s\S]*?<\/textarea>/gi;
            
            if (forms.length > 0) {
                let totalInputs = 0;
                let hasPasswordField = false;
                let hasFileUpload = false;
                let hasGetMethod = false;
                
                forms.forEach(form => {
                    const inputs = form.match(inputPattern) || [];
                    const textareas = form.match(textareaPattern) || [];
                    totalInputs += inputs.length + textareas.length;
                    
                    if (form.includes('type="password"') || form.includes("type='password'")) {
                        hasPasswordField = true;
                    }
                    if (form.includes('type="file"') || form.includes("type='file'")) {
                        hasFileUpload = true;
                    }
                    if (form.includes('method="get"') || form.includes("method='get'")) {
                        hasGetMethod = true;
                    }
                });
                
                results.vulnerabilities.push({
                    type: 'Form Security Risk',
                    severity: hasPasswordField ? 'High' : 'Medium',
                    description: `${forms.length} forms with ${totalInputs} input fields detected`,
                    evidence: `Forms analysis: ${hasPasswordField ? 'password fields, ' : ''}${hasFileUpload ? 'file uploads, ' : ''}${hasGetMethod ? 'GET method usage, ' : ''}${totalInputs} total inputs`,
                    recommendation: 'Implement CSRF protection, input validation, secure transmission (HTTPS), and proper authentication',
                    cve: 'CWE-20',
                    impact: hasPasswordField ? 'Credential theft and account compromise possible' : 'Various injection attacks and data manipulation possible'
                });
            }
            
            // Check for information disclosure
            const infoDisclosurePatterns = [
                /\/\*.*?\*\//gs, // SQL comments
                /<!--.*?-->/gs, // HTML comments
                /password/gi,
                /username/gi,
                /admin/gi,
                /root/gi,
                /config/gi,
                /database/gi,
                /mysqli/gi,
                /pdo/gi,
                /connection/gi
            ];
            
            const hasInfoDisclosure = infoDisclosurePatterns.some(pattern => pattern.test(responseText));
            if (hasInfoDisclosure) {
                results.vulnerabilities.push({
                    type: 'Information Disclosure',
                    severity: 'Medium',
                    description: 'Sensitive information detected in HTTP response',
                    evidence: 'Comments, configuration details, or sensitive keywords found in response',
                    recommendation: 'Remove debug information, comments, and sensitive data from public responses',
                    cve: 'CWE-200',
                    impact: 'Information leakage may aid attackers in further exploitation'
                });
            }
            
            // Add security header vulnerabilities since we can't do browser analysis
            Object.entries(results.securityHeaders).forEach(([header, value]) => {
                if (value === 'Missing') {
                    const severity = header === 'strict-transport-security' ? 'High' : 'Medium';
                    results.vulnerabilities.push({
                        type: 'Missing Security Header',
                        severity,
                        description: `Missing ${header} header`,
                        evidence: `Header '${header}' not found in response`,
                        recommendation: `Implement ${header} header for enhanced security`,
                        cve: 'CWE-693',
                        impact: 'Reduced protection against various web attacks'
                    });
                }
            });
            
            results.technicalInfo = {
                responseTime: Date.now(),
                statusCode: response.status,
                server: headers.server || 'Unknown',
                contentType: headers['content-type'] || 'Unknown',
                pageTitle: 'Browser analysis blocked',
                note: 'HTTP-only analysis performed due to client-side blocking'
            };
            
            console.log(`✅ HTTP-only scan completed for ${url} - Found ${results.vulnerabilities.length} issues`);
            return results;
        }
        
        // Check for potential XSS vulnerabilities
        const pageContent = await page.content();
        if (pageContent.includes('<script>') || pageContent.includes('javascript:')) {
            results.vulnerabilities.push({
                type: 'XSS (Cross-Site Scripting)',
                severity: 'High',
                description: 'Potential XSS vulnerability detected in page content',
                evidence: 'Script tags or javascript: URLs found in HTML',
                recommendation: 'Implement proper input validation and output encoding',
                cve: 'CWE-79',
                impact: 'Attackers could execute malicious scripts in user browsers'
            });
        }

        // Check for SQL injection indicators
        const forms = await page.$$('form');
        if (forms.length > 0) {
            const formInputs = await page.$$('input[type="text"], input[name*="user"], input[name*="pass"], textarea');
            if (formInputs.length > 0) {
                results.vulnerabilities.push({
                    type: 'SQL Injection Risk',
                    severity: 'Critical',
                    description: 'Forms detected that may be vulnerable to SQL injection',
                    evidence: `Found ${forms.length} forms with ${formInputs.length} input fields`,
                    recommendation: 'Use parameterized queries and input validation',
                    cve: 'CWE-89',
                    impact: 'Attackers could access, modify, or delete database contents'
                });
            }
        }

        // Check for missing security headers
        Object.entries(results.securityHeaders).forEach(([header, value]) => {
            if (value === 'Missing') {
                const severity = header === 'strict-transport-security' ? 'High' : 'Medium';
                results.vulnerabilities.push({
                    type: 'Missing Security Header',
                    severity,
                    description: `Missing ${header} header`,
                    evidence: `Header '${header}' not found in response`,
                    recommendation: `Implement ${header} header for enhanced security`,
                    cve: 'CWE-693',
                    impact: 'Reduced protection against various web attacks'
                });
            }
        });

        results.technicalInfo = {
            responseTime: Date.now(),
            statusCode: response.status,
            server: headers.server || 'Unknown',
            contentType: headers['content-type'] || 'Unknown',
            pageTitle: await page.title()
        };

        await browser.close();
        console.log(`✅ Scan completed for ${url} - Found ${results.vulnerabilities.length} issues`);
        
    } catch (error) {
        console.error(`❌ Error during scan:`, error.message);
        results.error = error.message;
    }

    return results;
}

// API route to start scan
app.post('/api/scan', async (req, res) => {
    try {
        const { url, scanType } = req.body;
        
        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        const scanId = `scan_${Math.random().toString(36).substr(2, 9)}_${Date.now()}`;
        
        console.log(`🚀 Starting ${scanType || 'basic'} scan for: ${url}`);
        console.log(`📋 Scan ID: ${scanId}`);

        const scanResult = {
            id: scanId,
            url,
            scanType: scanType || 'basic',
            status: 'running',
            startTime: new Date().toISOString(),
            progress: 0
        };

        scanResults.set(scanId, scanResult);
        saveScanResults();

        // Start scan asynchronously
        (async () => {
            try {
                scanResult.progress = 20;
                scanResult.currentStep = 'Analyzing target URL';
                scanResults.set(scanId, scanResult);
                saveScanResults();

                const vulnerabilityResults = await performComprehensiveVulnerabilityScanning(url);
                
                scanResult.progress = 50;
                scanResult.currentStep = zapAvailable ? 'Starting ZAP professional scan (may take 2-3 minutes)' : 'Generating AI analysis';
                scanResults.set(scanId, scanResult);
                saveScanResults();

                // Add ZAP active scanning if available
                let zapResults = null;
                if (zapAvailable && scanType === 'comprehensive') {
                    try {
                        console.log('🔥 Initiating ZAP active scan...');
                        scanResult.progress = 60;
                        scanResult.currentStep = 'ZAP scanning for SQL injection, XSS and other vulnerabilities...';
                        scanResults.set(scanId, scanResult);
                        saveScanResults();
                        
                        zapResults = await performZAPActiveScan(url);
                        
                        if (zapResults && zapResults.vulnerabilities) {
                            // Merge ZAP vulnerabilities with our existing results
                            vulnerabilityResults.vulnerabilities = [
                                ...vulnerabilityResults.vulnerabilities,
                                ...zapResults.vulnerabilities
                            ];
                            console.log(`🔥 ZAP added ${zapResults.vulnerabilities.length} vulnerabilities`);
                        }
                        
                        scanResult.progress = 75;
                        scanResult.currentStep = 'ZAP scan completed, generating AI analysis';
                        scanResults.set(scanId, scanResult);
                        saveScanResults();
                        
                    } catch (zapError) {
                        console.error('❌ ZAP scan failed:', zapError.message);
                        zapResults = { error: zapError.message };
                    }
                } else {
                    scanResult.progress = 75;
                    scanResult.currentStep = 'Generating AI analysis';
                    scanResults.set(scanId, scanResult);
                    saveScanResults();
                }

                // Provide default AI analysis
                const aiAnalysis = {
                    redTeam: {
                        attackNarrative: "Analyze the identified vulnerabilities to understand potential attack vectors. XSS vulnerabilities can be exploited for session hijacking, while SQL injection can lead to data breaches.",
                        exploitChain: ["Identify input vectors", "Test for injection points", "Escalate privileges", "Extract sensitive data"],
                        criticalPaths: ["Review all user input fields", "Check authentication mechanisms"]
                    },
                    blueTeam: {
                        defenseStrategy: "Implement comprehensive input validation, use parameterized queries, and deploy security headers across all endpoints.",
                        prioritizedFixes: ["Fix SQL injection vulnerabilities", "Implement XSS protection", "Add security headers", "Enable HTTPS"],
                        monitoringRecommendations: ["Monitor for suspicious input patterns", "Log authentication attempts", "Track unusual database queries"]
                    }
                };

                // Transform vulnerability data to match frontend expectations
                const structuredResults = {
                    ...vulnerabilityResults,
                    vulnerabilities: {
                        vulnerabilities: vulnerabilityResults.vulnerabilities,
                        totalFound: vulnerabilityResults.vulnerabilities.length,
                        severity: {
                            criticalCount: vulnerabilityResults.vulnerabilities.filter(v => v.severity === 'Critical').length,
                            highCount: vulnerabilityResults.vulnerabilities.filter(v => v.severity === 'High').length,
                            mediumCount: vulnerabilityResults.vulnerabilities.filter(v => v.severity === 'Medium').length,
                            lowCount: vulnerabilityResults.vulnerabilities.filter(v => v.severity === 'Low').length
                        }
                    }
                };

                scanResult.status = 'completed';
                scanResult.progress = 100;
                scanResult.endTime = new Date().toISOString();
                scanResult.results = structuredResults;
                scanResult.aiAnalysis = aiAnalysis;
                delete scanResult.currentStep;

                scanResults.set(scanId, scanResult);
                saveScanResults();

                console.log(`✅ Scan ${scanId} completed for ${url}`);
                console.log(`🚨 Total vulnerabilities found: ${vulnerabilityResults.vulnerabilities.length}`);

            } catch (error) {
                console.error(`❌ Scan ${scanId} failed:`, error);
                scanResult.status = 'failed';
                scanResult.error = error.message;
                scanResult.endTime = new Date().toISOString();
                scanResults.set(scanId, scanResult);
                saveScanResults();
            }
        })();

        res.json({
            success: true,
            scanId,
            message: 'Scan started successfully',
            statusUrl: `/api/scan/${scanId}`
        });

    } catch (error) {
        console.error('❌ Error starting scan:', error);
        res.status(500).json({ error: 'Failed to start scan' });
    }
});

// API route to get scan status
app.get('/api/scan/:scanId', (req, res) => {
    const { scanId } = req.params;
    const scanResult = scanResults.get(scanId);
    
    if (!scanResult) {
        console.log(`❌ Scan not found: ${scanId}`);
        console.log(`📊 Available scans: ${Array.from(scanResults.keys()).join(', ')}`);
        return res.status(404).json({ error: 'Scan not found' });
    }
    
    console.log(`✅ Returning scan result for: ${scanId}`);
    res.json(scanResult);
});

// API route to get all scans
app.get('/api/scans', (req, res) => {
    const allScans = Array.from(scanResults.values())
        .sort((a, b) => new Date(b.startTime) - new Date(a.startTime))
        .slice(0, 10);
    
    res.json(allScans);
});

// API route to check ZAP status
app.get('/api/zap-status', async (req, res) => {
    try {
        const available = await checkZAPAvailability();
        res.json({
            available: available,
            message: available ? 'OWASP ZAP Docker container ready for active scanning' : 'OWASP ZAP Docker container not available',
            zapUrl: available ? ZAP_BASE_URL : null,
            version: available ? 'Connected' : 'Not connected'
        });
    } catch (error) {
        res.json({
            available: false,
            message: 'Error checking ZAP status',
            error: error.message
        });
    }
});

app.listen(PORT, async () => {
    console.log(`\n🌟 Server running on port ${PORT}`);
    console.log(`🔗 Open: http://localhost:${PORT}`);
    console.log(`📊 Total stored scans: ${scanResults.size}`);
    
    // Check ZAP availability on startup
    await checkZAPAvailability();
});
