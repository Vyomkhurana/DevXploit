import axios from 'axios';
import { parse } from 'url';

export class PassiveRecon {
  constructor() {
    this.userAgent = 'DevXploit-Security-Scanner/1.0';
  }

  async analyzeHeaders(url) {
    try {
      const response = await axios.get(url, {
        headers: { 'User-Agent': this.userAgent },
        timeout: 5000, // Reduced from 10000 to 5000ms
        maxRedirects: 3, // Reduced from 5 to 3
        validateStatus: () => true
      });

      const securityHeaders = {
        'strict-transport-security': response.headers['strict-transport-security'],
        'content-security-policy': response.headers['content-security-policy'],
        'x-frame-options': response.headers['x-frame-options'],
        'x-content-type-options': response.headers['x-content-type-options'],
        'x-xss-protection': response.headers['x-xss-protection'],
        'referrer-policy': response.headers['referrer-policy'],
        'permissions-policy': response.headers['permissions-policy']
      };

      const missingHeaders = [];
      const weakHeaders = [];

      // Check for missing security headers
      if (!securityHeaders['strict-transport-security']) {
        missingHeaders.push({
          header: 'Strict-Transport-Security',
          risk: 'Medium',
          description: 'Missing HSTS header allows downgrade attacks'
        });
      }

      if (!securityHeaders['content-security-policy']) {
        missingHeaders.push({
          header: 'Content-Security-Policy',
          risk: 'High',
          description: 'Missing CSP allows XSS and injection attacks'
        });
      }

      if (!securityHeaders['x-frame-options']) {
        missingHeaders.push({
          header: 'X-Frame-Options',
          risk: 'Medium',
          description: 'Missing X-Frame-Options allows clickjacking attacks'
        });
      }

      // Check for weak configurations
      if (securityHeaders['x-xss-protection'] === '0') {
        weakHeaders.push({
          header: 'X-XSS-Protection',
          risk: 'Low',
          description: 'XSS protection is disabled'
        });
      }

      return {
        statusCode: response.status,
        headers: response.headers,
        securityHeaders,
        missingHeaders,
        weakHeaders,
        serverInfo: {
          server: response.headers.server || 'Unknown',
          powered: response.headers['x-powered-by'] || 'Unknown',
          technology: this.detectTechnology(response.headers)
        }
      };
    } catch (error) {
      console.error(`Header analysis error for ${url}:`, error.message);
      // Return minimal data instead of throwing
      return {
        statusCode: 0,
        headers: {},
        securityHeaders: {},
        missingHeaders: [
          {
            header: 'Connection Failed',
            risk: 'Info',
            description: `Unable to connect to target: ${error.message}`
          }
        ],
        weakHeaders: [],
        serverInfo: {
          server: 'Unknown',
          powered: 'Unknown',
          technology: []
        }
      };
    }
  }

  detectTechnology(headers) {
    const tech = [];
    
    if (headers.server) {
      if (headers.server.includes('nginx')) tech.push('Nginx');
      if (headers.server.includes('Apache')) tech.push('Apache');
      if (headers.server.includes('cloudflare')) tech.push('Cloudflare');
    }
    
    if (headers['x-powered-by']) {
      if (headers['x-powered-by'].includes('Express')) tech.push('Express.js');
      if (headers['x-powered-by'].includes('PHP')) tech.push('PHP');
      if (headers['x-powered-by'].includes('ASP.NET')) tech.push('ASP.NET');
    }

    return tech;
  }

  async analyzeSubdomains(domain) {
    try {
      const subdomains = [];
      const commonSubs = ['www', 'mail', 'ftp', 'admin', 'api']; // Reduced list for faster scanning
      
      for (const sub of commonSubs) {
        try {
          const subdomain = `${sub}.${domain}`;
          const response = await axios.get(`http://${subdomain}`, {
            timeout: 2000, // Very short timeout for subdomain checks
            validateStatus: () => true
          });
          
          if (response.status < 400) {
            subdomains.push({
              subdomain,
              status: response.status,
              title: this.extractTitle(response.data)
            });
          }
        } catch (error) {
          // Subdomain doesn't exist or is unreachable - continue
        }
      }

      return subdomains;
    } catch (error) {
      console.error(`Subdomain analysis error for ${domain}:`, error.message);
      return []; // Return empty array instead of throwing
    }
  }

  extractTitle(html) {
    const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    return titleMatch ? titleMatch[1].trim() : 'No title';
  }

  async analyzeTechStack(url) {
    try {
      const response = await axios.get(url, {
        headers: { 'User-Agent': this.userAgent },
        timeout: 5000 // Reduced timeout
      });

      const technologies = [];
      const html = response.data;

      // Detect JavaScript libraries
      const jsLibraries = this.detectJSLibraries(html);
      technologies.push(...jsLibraries);

      // Detect CMS
      const cms = this.detectCMS(html, response.headers);
      if (cms) technologies.push(cms);

      // Detect frameworks
      const frameworks = this.detectFrameworks(html, response.headers);
      technologies.push(...frameworks);

      return {
        technologies,
        jsLibraries: jsLibraries.length,
        totalTech: technologies.length
      };
    } catch (error) {
      console.error(`Tech stack analysis error for ${url}:`, error.message);
      // Return empty results instead of throwing
      return {
        technologies: [],
        jsLibraries: 0,
        totalTech: 0
      };
    }
  }

  detectJSLibraries(html) {
    const libraries = [];
    const patterns = {
      'jQuery': /jquery[.-]?(\d+\.?\d*\.?\d*)/i,
      'React': /react[.-]?(\d+\.?\d*\.?\d*)/i,
      'Vue.js': /vue[.-]?(\d+\.?\d*\.?\d*)/i,
      'Angular': /angular[.-]?(\d+\.?\d*\.?\d*)/i,
      'Bootstrap': /bootstrap[.-]?(\d+\.?\d*\.?\d*)/i,
      'Lodash': /lodash[.-]?(\d+\.?\d*\.?\d*)/i,
      'D3.js': /d3[.-]?(\d+\.?\d*\.?\d*)/i
    };

    for (const [name, pattern] of Object.entries(patterns)) {
      const match = html.match(pattern);
      if (match) {
        libraries.push({
          name,
          version: match[1] || 'Unknown',
          type: 'JavaScript Library'
        });
      }
    }

    return libraries;
  }

  detectCMS(html, headers) {
    // WordPress detection
    if (html.includes('wp-content') || html.includes('wordpress')) {
      return { name: 'WordPress', type: 'CMS' };
    }

    // Drupal detection
    if (html.includes('Drupal.settings') || headers['x-drupal-cache']) {
      return { name: 'Drupal', type: 'CMS' };
    }

    // Joomla detection
    if (html.includes('joomla') || html.includes('/media/system/js/')) {
      return { name: 'Joomla', type: 'CMS' };
    }

    return null;
  }

  detectFrameworks(html, headers) {
    const frameworks = [];

    // Next.js detection
    if (html.includes('__NEXT_DATA__') || headers['x-powered-by']?.includes('Next.js')) {
      frameworks.push({ name: 'Next.js', type: 'Framework' });
    }

    // Laravel detection
    if (headers['x-powered-by']?.includes('Laravel') || html.includes('laravel_session')) {
      frameworks.push({ name: 'Laravel', type: 'Framework' });
    }

    // Django detection
    if (headers['x-powered-by']?.includes('Django') || html.includes('csrfmiddlewaretoken')) {
      frameworks.push({ name: 'Django', type: 'Framework' });
    }

    return frameworks;
  }
}