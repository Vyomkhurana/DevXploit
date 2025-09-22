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
        
        // Update security score
        this.updateSecurityScore(results.vulnerabilities?.severity);
        
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

        const vulnHTML = vulnList.map((vuln, index) => {
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

            return `
                <div class="p-5 hover:bg-zinc-900/30 transition-colors">
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
                                <span class="inline-flex items-center px-3 py-1 text-xs font-medium rounded-md border ${config.color} ml-3">
                                    ${vuln.severity}
                                </span>
                            </div>
                            
                            <p class="text-sm text-zinc-400 mb-4 leading-relaxed">${vuln.description}</p>
                            
                            <!-- Expandable Details -->
                            <div class="space-y-3">
                                <div class="rounded-lg bg-zinc-950/50 border border-zinc-800 p-3">
                                    <div class="grid md:grid-cols-2 gap-3 text-sm">
                                        <div>
                                            <span class="text-zinc-500 font-medium">Location:</span>
                                            <div class="mt-1 text-zinc-300 font-mono text-xs bg-zinc-900/50 px-2 py-1 rounded border break-all">
                                                ${vuln.location}
                                            </div>
                                        </div>
                                        <div>
                                            <span class="text-zinc-500 font-medium">Evidence:</span>
                                            <div class="mt-1 text-zinc-400 text-xs">
                                                ${vuln.evidence}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                
                                <!-- Remediation -->
                                <div class="rounded-lg bg-emerald-500/5 border border-emerald-500/20 p-3">
                                    <div class="flex items-start gap-2">
                                        <i data-lucide="wrench" class="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" style="stroke-width:1.5"></i>
                                        <div>
                                            <span class="text-emerald-400 font-medium text-sm">Remediation:</span>
                                            <div class="mt-1 text-zinc-300 text-sm leading-relaxed">
                                                ${vuln.remediation}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        findingsList.innerHTML = vulnHTML;
        lucide.createIcons();
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

        const scoreElement = document.getElementById('securityScore');
        const scoreBar = document.getElementById('securityScoreBar');
        
        if (scoreElement) {
            scoreElement.textContent = severity.score;
        }
        
        if (scoreBar) {
            scoreBar.style.width = `${severity.score}%`;
            
            // Color based on score
            if (severity.score >= 80) {
                scoreBar.className = scoreBar.className.replace(/bg-\w+-\d+/, 'bg-emerald-500');
            } else if (severity.score >= 60) {
                scoreBar.className = scoreBar.className.replace(/bg-\w+-\d+/, 'bg-yellow-500');
            } else {
                scoreBar.className = scoreBar.className.replace(/bg-\w+-\d+/, 'bg-red-500');
            }
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