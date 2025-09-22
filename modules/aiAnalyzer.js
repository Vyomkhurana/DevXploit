import OpenAI from 'openai';

export class AIAnalyzer {
  constructor() {
    this.openai = new OpenAI({
      apiKey: process.env.OPENAI_API_KEY
    });
  }

  async generateAttackerNarrative(scanResults) {
    try {
      const prompt = this.buildAttackerPrompt(scanResults);
      
      const completion = await this.openai.chat.completions.create({
        model: "gpt-3.5-turbo",
        messages: [
          {
            role: "system",
            content: "You are a cybersecurity expert explaining how an attacker would exploit vulnerabilities. Write from an attacker's perspective, explaining the step-by-step process they would follow. Be technical but accessible. Focus on the attack chain and methodology."
          },
          {
            role: "user",
            content: prompt
          }
        ],
        max_tokens: 800,
        temperature: 0.7
      });

      return completion.choices[0].message.content;
    } catch (error) {
      console.error('OpenAI API error:', error);
      return this.generateFallbackAttackerNarrative(scanResults);
    }
  }

  async generateDeveloperRemediation(scanResults) {
    try {
      const prompt = this.buildDeveloperPrompt(scanResults);
      
      const completion = await this.openai.chat.completions.create({
        model: "gpt-3.5-turbo",
        messages: [
          {
            role: "system",
            content: "You are a senior security engineer providing actionable remediation steps to developers. Focus on practical, implementable solutions with code examples where appropriate. Prioritize fixes by impact and ease of implementation."
          },
          {
            role: "user",
            content: prompt
          }
        ],
        max_tokens: 1000,
        temperature: 0.3
      });

      return completion.choices[0].message.content;
    } catch (error) {
      console.error('OpenAI API error:', error);
      return this.generateFallbackDeveloperRemediation(scanResults);
    }
  }

  buildAttackerPrompt(scanResults) {
    const { headerAnalysis, techStack, vulnerabilities } = scanResults;
    
    let prompt = `I found the following information about a web application:\n\n`;
    
    // Technology stack
    if (techStack.technologies.length > 0) {
      prompt += `Technology Stack:\n`;
      techStack.technologies.forEach(tech => {
        prompt += `- ${tech.name} (${tech.type})\n`;
      });
      prompt += `\n`;
    }

    // Security headers
    if (headerAnalysis.missingHeaders.length > 0) {
      prompt += `Missing Security Headers:\n`;
      headerAnalysis.missingHeaders.forEach(header => {
        prompt += `- ${header.header}: ${header.description}\n`;
      });
      prompt += `\n`;
    }

    // Vulnerabilities
    if (vulnerabilities.vulnerabilities.length > 0) {
      prompt += `Potential Vulnerabilities:\n`;
      vulnerabilities.vulnerabilities.forEach(vuln => {
        prompt += `- ${vuln.type} (${vuln.severity}): ${vuln.description}\n`;
      });
      prompt += `\n`;
    }

    prompt += `As an attacker, explain how you would exploit this application step by step. Focus on the most effective attack path that combines these findings.`;

    return prompt;
  }

  buildDeveloperPrompt(scanResults) {
    const { headerAnalysis, techStack, vulnerabilities } = scanResults;
    
    let prompt = `I need to secure a web application with the following issues:\n\n`;
    
    // Missing security headers
    if (headerAnalysis.missingHeaders.length > 0) {
      prompt += `Missing Security Headers:\n`;
      headerAnalysis.missingHeaders.forEach(header => {
        prompt += `- ${header.header}: ${header.description}\n`;
      });
      prompt += `\n`;
    }

    // Vulnerabilities
    if (vulnerabilities.vulnerabilities.length > 0) {
      prompt += `Identified Vulnerabilities:\n`;
      vulnerabilities.vulnerabilities.forEach(vuln => {
        prompt += `- ${vuln.type} (${vuln.severity}): ${vuln.description}\n`;
      });
      prompt += `\n`;
    }

    // Technology context
    if (techStack.technologies.length > 0) {
      const frameworks = techStack.technologies.filter(t => t.type === 'Framework');
      if (frameworks.length > 0) {
        prompt += `Application Framework: ${frameworks[0].name}\n\n`;
      }
    }

    prompt += `Provide specific, actionable remediation steps prioritized by risk level. Include code examples and configuration changes where applicable.`;

    return prompt;
  }

  generateFallbackAttackerNarrative(scanResults) {
    const { vulnerabilities } = scanResults;
    
    if (vulnerabilities.vulnerabilities.length === 0) {
      return `**Phase 1: Reconnaissance**
The target appears to have basic security measures in place. I would begin with passive reconnaissance, analyzing the application's technology stack and looking for information disclosure.

**Phase 2: Enumeration**
I would probe for hidden directories, backup files, and administrative interfaces. Social engineering and OSINT gathering would help identify potential entry points.

**Phase 3: Exploitation**
With limited obvious vulnerabilities, I would focus on business logic flaws, session management issues, or attempt credential stuffing attacks against login forms.`;
    }

    const highSeverityVulns = vulnerabilities.vulnerabilities.filter(v => v.severity === 'High');
    
    let narrative = `**Phase 1: Initial Reconnaissance**
I've identified several attack vectors in this application. `;

    if (highSeverityVulns.length > 0) {
      narrative += `The most promising entry points are the ${highSeverityVulns.length} high-severity vulnerabilities.

**Phase 2: Exploitation**
I would prioritize the ${highSeverityVulns[0].type} vulnerability, which could allow me to ${this.getAttackImpact(highSeverityVulns[0].type)}.

**Phase 3: Post-Exploitation**
Once initial access is gained, I would escalate privileges and establish persistence to maintain access to the system.`;
    }

    return narrative;
  }

  generateFallbackDeveloperRemediation(scanResults) {
    const { headerAnalysis, vulnerabilities } = scanResults;
    
    let remediation = `## Security Remediation Plan\n\n`;
    
    if (headerAnalysis.missingHeaders.length > 0) {
      remediation += `### 1. Implement Security Headers (Priority: High)\n`;
      headerAnalysis.missingHeaders.forEach(header => {
        remediation += `- **${header.header}**: ${header.description}\n`;
      });
      remediation += `\n`;
    }

    if (vulnerabilities.vulnerabilities.length > 0) {
      remediation += `### 2. Address Vulnerabilities\n`;
      const groupedVulns = this.groupVulnerabilitiesBySeverity(vulnerabilities.vulnerabilities);
      
      Object.entries(groupedVulns).forEach(([severity, vulns]) => {
        if (vulns.length > 0) {
          remediation += `\n**${severity} Priority:**\n`;
          vulns.forEach(vuln => {
            remediation += `- ${vuln.type}: ${vuln.remediation}\n`;
          });
        }
      });
    }

    remediation += `\n### 3. Additional Security Measures\n`;
    remediation += `- Implement Web Application Firewall (WAF)\n`;
    remediation += `- Regular security testing and code reviews\n`;
    remediation += `- Keep all dependencies updated\n`;

    return remediation;
  }

  groupVulnerabilitiesBySeverity(vulnerabilities) {
    return vulnerabilities.reduce((groups, vuln) => {
      const severity = vuln.severity;
      if (!groups[severity]) groups[severity] = [];
      groups[severity].push(vuln);
      return groups;
    }, {});
  }

  getAttackImpact(vulnType) {
    const impacts = {
      'Cross-Site Scripting (XSS)': 'steal user sessions and execute malicious JavaScript',
      'Potential SQL Injection': 'access and manipulate the database',
      'Potential Directory Traversal': 'read sensitive files from the server',
      'Potential Open Redirect': 'redirect users to malicious sites for phishing',
      'Sensitive File Exposure': 'gather configuration details and credentials'
    };
    
    return impacts[vulnType] || 'compromise the application';
  }

  async generateKillChainSteps(scanResults) {
    const { vulnerabilities } = scanResults;
    
    const steps = [
      {
        phase: 'recon',
        title: 'Reconnaissance',
        status: 'completed',
        findings: `Identified ${scanResults.techStack.technologies.length} technologies`,
        description: 'Gathered information about target technologies and infrastructure'
      },
      {
        phase: 'enum',
        title: 'Enumeration',
        status: 'completed',
        findings: `Found ${scanResults.headerAnalysis.missingHeaders.length} security issues`,
        description: 'Analyzed security headers and configuration weaknesses'
      }
    ];

    if (vulnerabilities.vulnerabilities.length > 0) {
      steps.push({
        phase: 'vuln',
        title: 'Vulnerability Discovery',
        status: 'completed',
        findings: `${vulnerabilities.vulnerabilities.length} potential vulnerabilities`,
        description: 'Identified exploitable security weaknesses'
      });

      const highVulns = vulnerabilities.vulnerabilities.filter(v => v.severity === 'High');
      if (highVulns.length > 0) {
        steps.push({
          phase: 'exploit',
          title: 'Exploitation',
          status: 'possible',
          findings: `${highVulns.length} high-risk attack vectors`,
          description: 'High-severity vulnerabilities enable system compromise'
        });

        steps.push({
          phase: 'post',
          title: 'Post-Exploitation',
          status: 'possible',
          findings: 'Privilege escalation opportunities',
          description: 'Potential for lateral movement and data exfiltration'
        });
      }
    }

    return steps;
  }
}