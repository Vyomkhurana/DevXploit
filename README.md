# DevXploit - Security Analysis Platform

A comprehensive web application security scanner built with Node.js and integrated with OWASP ZAP for professional vulnerability assessment.

## 🔍 Features

### Core Functionality
- **Real-time Vulnerability Scanning** - Dynamic analysis of web applications
- **OWASP ZAP Integration** - Professional-grade security testing
- **Comprehensive Reporting** - Detailed vulnerability analysis with severity ratings
- **Red Team & Blue Team Perspectives** - Attack vectors and defense strategies
- **Security Headers Analysis** - Missing security headers detection
- **Form Security Assessment** - Input validation and CSRF protection analysis

### Technical Capabilities
- **SQL Injection Detection** - Database vulnerability assessment
- **XSS (Cross-Site Scripting) Analysis** - Client-side security testing
- **Information Disclosure Detection** - Sensitive data exposure identification
- **Security Score Calculation** - Risk assessment with grading system
- **Real-time Progress Tracking** - Live scan status updates
- **Historical Scan Data** - Previous scan results storage and analysis

## 🛠️ Technology Stack

- **Backend**: Node.js, Express.js
- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **UI Framework**: Tailwind CSS
- **Security Scanner**: OWASP ZAP 2.16.1
- **Browser Automation**: Puppeteer
- **Charts**: Chart.js
- **Icons**: Lucide Icons

## 📋 Prerequisites

Before running DevXploit, ensure you have:

1. **Node.js** (v14.0.0 or higher)
2. **npm** (Node Package Manager)
3. **OWASP ZAP** installed and accessible
   - Download from: https://www.zaproxy.org/download/
   - Install in default location: `C:\Program Files\ZAP\Zed Attack Proxy\`

## 🚀 Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/Vyomkhurana/DevXploit.git
cd DevXploit
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Environment Configuration
Create a `.env` file in the root directory:
```env
PORT=3000
ZAP_PORT=8081
NODE_ENV=development
```

### 4. Start OWASP ZAP
Start ZAP in daemon mode on port 8081:
```bash
# Windows
cd "C:\Program Files\ZAP\Zed Attack Proxy"
.\ZAP.exe -daemon -host 0.0.0.0 -port 8081 -config api.disablekey=true

# Linux/Mac
zap.sh -daemon -host 0.0.0.0 -port 8081 -config api.disablekey=true
```

### 5. Start DevXploit
```bash
node index.js
```

### 6. Access the Application
Open your browser and navigate to: `http://localhost:3000`

## 🎯 Quick Start Guide

### Running a Basic Scan
1. Open DevXploit in your browser
2. Enter a target URL (e.g., `https://example.com`)
3. Select scan type:
   - **Basic**: HTTP analysis and security headers
   - **Comprehensive**: Full ZAP active scanning (requires ZAP)
4. Click "Start Security Scan"
5. Monitor real-time progress
6. Review detailed vulnerability report

### Understanding Results
- **Critical**: Immediate security risks requiring urgent attention
- **High**: Significant vulnerabilities that should be addressed quickly
- **Medium**: Moderate security issues for timely remediation
- **Low**: Minor security improvements and best practices

## 📁 Project Structure

```
DevXploit/
├── index.js                 # Main server file
├── package.json            # Node.js dependencies
├── public/                 # Static assets
│   └── dashboard.js        # Frontend JavaScript
├── views/                  # EJS templates
│   └── home.ejs           # Main UI template
├── scan-results.json      # Scan history storage
├── .env                   # Environment variables
├── .gitignore            # Git ignore rules
└── README.md             # This file
```

## 🔧 Configuration

### ZAP Configuration
- **Port**: 8081 (configurable in `.env`)
- **Mode**: Daemon (headless)
- **API**: Enabled without key for local development

### Application Settings
- **Server Port**: 3000
- **Scan Timeout**: 10 seconds per request
- **Browser**: Headless Puppeteer
- **Storage**: File-based JSON storage

## 🛡️ Security Considerations

### Development Environment
- ZAP API runs without authentication (local development only)
- Browser automation disabled security features for testing
- File-based storage for scan results

### Production Deployment
- Enable ZAP API authentication
- Implement proper authentication and authorization
- Use database storage for scan results
- Enable HTTPS and security headers
- Rate limiting and input validation

## 🚦 API Endpoints

### Scan Management
- `POST /api/scan` - Start new vulnerability scan
- `GET /api/scan/:scanId` - Get scan status and results
- `GET /api/scans` - List recent scans
- `GET /api/zap-status` - Check ZAP connectivity

### Response Format
```json
{
  "id": "scan_abc123_1234567890",
  "url": "https://example.com",
  "status": "completed",
  "vulnerabilities": {
    "totalFound": 5,
    "severity": {
      "score": 75,
      "grade": "Good"
    }
  }
}
```

## 🐛 Troubleshooting

### Common Issues

**ZAP Connection Failed**
- Ensure ZAP is running on port 8081
- Check firewall settings
- Verify ZAP daemon mode is enabled

**Scan Timeouts**
- Increase timeout values in code
- Check target website accessibility
- Verify network connectivity

**Browser Navigation Blocked**
- Normal behavior for protected sites
- Application falls back to HTTP-only analysis
- Review console logs for details

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -m 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **OWASP ZAP** - Professional security scanning engine
- **Node.js Community** - Excellent runtime and packages
- **Tailwind CSS** - Modern CSS framework
- **Chart.js** - Beautiful data visualization

## 📞 Support

For support and questions:
- Create an issue on GitHub
- Check existing documentation
- Review troubleshooting section

---

**DevXploit** - Professional Security Analysis Platform
Built with ❤️ for the cybersecurity community