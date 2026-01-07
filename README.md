# 🛡️ SecureNet Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/theepreacher-ai/securenet-toolkit/graphs/commit-activity)

**A comprehensive network security automation toolkit for penetration testers and security professionals.**

SecureNet Toolkit combines multiple security reconnaissance and analysis tools into a single, easy-to-use command-line interface. Perfect for security audits, network assessments, and educational purposes.

---

## ✨ Features

- **Port Scanner**: Fast TCP/UDP port scanning with service detection
- **Network Mapper**: Discover active hosts on local networks
- **DNS Enumeration**: Subdomain discovery and DNS record analysis
- **SSL/TLS Analyzer**: Certificate validation and cipher suite testing
- **HTTP Security Headers**: Analyze security headers on web applications
- **WiFi Analyzer**: Scan and analyze wireless networks (requires wireless adapter)
- **Report Generation**: Export findings in JSON, CSV, or HTML format
- **Modular Architecture**: Easy to extend with custom modules

---

## 🚀 Quick Start

### Prerequisites

```bash
# System requirements
- Python 3.8 or higher
- pip package manager
- Linux/Unix-based OS (Kali Linux recommended)
- Root/sudo privileges for certain features
```

### Installation

```bash
# Clone the repository
git clone https://github.com/theepreacher-ai/securenet-toolkit.git
cd securenet-toolkit

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run setup script (for additional tools)
sudo ./setup.sh
```

### Basic Usage

```bash
# Activate virtual environment
source venv/bin/activate

# Run the toolkit
python3 securenet.py

# Or use specific modules directly
python3 securenet.py --scan-ports 192.168.1.1
python3 securenet.py --dns-enum example.com
python3 securenet.py --http-headers https://example.com
```

---

## 📖 Usage Examples

### 1. Port Scanning

```bash
# Scan common ports
python3 securenet.py --scan-ports 192.168.1.100

# Scan specific port range
python3 securenet.py --scan-ports 192.168.1.100 --port-range 1-1000

# Scan with service detection
python3 securenet.py --scan-ports 192.168.1.100 --detect-services
```

### 2. Network Discovery

```bash
# Discover hosts on local network
python3 securenet.py --discover-hosts 192.168.1.0/24

# Ping sweep
python3 securenet.py --ping-sweep 10.0.0.0/24
```

### 3. DNS Enumeration

```bash
# Enumerate subdomains
python3 securenet.py --dns-enum example.com

# With custom wordlist
python3 securenet.py --dns-enum example.com --wordlist custom-subdomains.txt
```

### 4. SSL/TLS Analysis

```bash
# Analyze SSL/TLS configuration
python3 securenet.py --ssl-check example.com

# Check certificate expiry
python3 securenet.py --cert-expiry example.com
```

### 5. HTTP Security Headers

```bash
# Check security headers
python3 securenet.py --http-headers https://example.com

# Generate detailed report
python3 securenet.py --http-headers https://example.com --report html
```

---

## 🏗️ Project Structure

```
securenet-toolkit/
├── securenet.py              # Main entry point
├── requirements.txt          # Python dependencies
├── setup.sh                  # Setup script
├── config/
│   ├── config.yaml          # Configuration file
│   └── wordlists/           # Custom wordlists
├── modules/
│   ├── __init__.py
│   ├── port_scanner.py      # Port scanning module
│   ├── network_mapper.py    # Network discovery
│   ├── dns_enum.py          # DNS enumeration
│   ├── ssl_analyzer.py      # SSL/TLS analysis
│   ├── http_analyzer.py     # HTTP security headers
│   └── wifi_scanner.py      # WiFi analysis
├── utils/
│   ├── __init__.py
│   ├── logger.py            # Logging utilities
│   ├── reporter.py          # Report generation
│   └── helpers.py           # Helper functions
├── reports/                 # Generated reports
├── tests/
│   ├── test_port_scanner.py
│   ├── test_dns_enum.py
│   └── test_ssl_analyzer.py
├── docs/
│   ├── installation.md
│   ├── usage.md
│   └── contributing.md
├── LICENSE
└── README.md
```

---

## 🔧 Configuration

Edit `config/config.yaml` to customize toolkit behavior:

```yaml
general:
  timeout: 5
  threads: 10
  verbose: true

port_scanner:
  default_ports: [21, 22, 23, 25, 80, 443, 3306, 3389, 8080]
  scan_timeout: 1
  max_threads: 50

dns_enum:
  default_wordlist: "config/wordlists/subdomains.txt"
  timeout: 3
  threads: 20

reports:
  output_dir: "reports"
  format: "json"  # Options: json, csv, html
  timestamp: true
```

---

## 🛠️ Development

### Setting Up Development Environment

```bash
# Clone repository
git clone https://github.com/theepreacher-ai/securenet-toolkit.git
cd securenet-toolkit

# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=modules tests/

# Run specific test file
pytest tests/test_port_scanner.py -v
```

### Code Style

This project follows PEP 8 guidelines. Use the following tools:

```bash
# Format code
black securenet.py modules/ utils/

# Check style
flake8 securenet.py modules/ utils/

# Type checking
mypy securenet.py modules/ utils/
```

---

## 📚 Documentation

Comprehensive documentation is available in the `docs/` directory:

- [Installation Guide](docs/installation.md)
- [Usage Guide](docs/usage.md)
- [Module Documentation](docs/modules.md)
- [API Reference](docs/api.md)
- [Contributing Guidelines](docs/contributing.md)

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please read [CONTRIBUTING.md](docs/contributing.md) for details on our code of conduct and development process.

---

## 🔐 Security & Legal Disclaimer

**⚠️ IMPORTANT:** This toolkit is designed for authorized security testing and educational purposes only.

**Usage Guidelines:**
- Only test systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal
- Always comply with local laws and regulations
- The authors assume no liability for misuse of this tool

**Responsible Disclosure:**
If you discover vulnerabilities using this toolkit, follow responsible disclosure practices and notify system owners immediately.

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Inspired by tools like Nmap, Metasploit, and Burp Suite
- Built with Python and open-source libraries
- Special thanks to the cybersecurity community

---

## 📞 Contact & Support

**Author:** Francis (theepreacher-ai)
- **Email:** kuriaf791@gmail.com
- **GitHub:** [@theepreacher-ai](https://github.com/theepreacher-ai)
- **Twitter:** [@insightsphere7](https://twitter.com/insightsphere7)

### Getting Help

- **Issues:** [GitHub Issues](https://github.com/theepreacher-ai/securenet-toolkit/issues)
- **Discussions:** [GitHub Discussions](https://github.com/theepreacher-ai/securenet-toolkit/discussions)
- **Documentation:** [Wiki](https://github.com/theepreacher-ai/securenet-toolkit/wiki)

---

## 🗺️ Roadmap

### Current Version: 1.0.0

**Upcoming Features:**
- [ ] Web application vulnerability scanner
- [ ] Automated exploit suggestions
- [ ] Integration with CVE databases
- [ ] Real-time packet capture and analysis
- [ ] Machine learning-based anomaly detection
- [ ] Cloud security assessment tools
- [ ] Docker containerization
- [ ] Web-based dashboard

---

## 📊 Project Stats

![GitHub stars](https://img.shields.io/github/stars/theepreacher-ai/securenet-toolkit?style=social)
![GitHub forks](https://img.shields.io/github/forks/theepreacher-ai/securenet-toolkit?style=social)
![GitHub issues](https://img.shields.io/github/issues/theepreacher-ai/securenet-toolkit)
![GitHub pull requests](https://img.shields.io/github/issues-pr/theepreacher-ai/securenet-toolkit)

---

**⭐ If you find this project useful, please consider giving it a star!**

---

## 📸 Screenshots

### Main Menu
```
╔══════════════════════════════════════════════════════════════╗
║              SecureNet Toolkit v1.0.0                        ║
║        Network Security Automation Suite                     ║
╚══════════════════════════════════════════════════════════════╝

[1] Port Scanner
[2] Network Discovery
[3] DNS Enumeration
[4] SSL/TLS Analyzer
[5] HTTP Security Headers
[6] WiFi Scanner
[7] Generate Report
[8] Settings
[0] Exit

Select an option:
```

### Sample Output - Port Scan
```
[+] Starting port scan on 192.168.1.100
[+] Scanning ports 1-1000...

[✓] Port 22 (SSH) - OPEN - OpenSSH 8.2
[✓] Port 80 (HTTP) - OPEN - Apache 2.4.41
[✓] Port 443 (HTTPS) - OPEN - Apache 2.4.41
[✗] Port 3306 (MySQL) - FILTERED

[+] Scan completed in 12.34 seconds
[+] Found 3 open ports
[+] Report saved to: reports/scan_192.168.1.100_20260106_143022.json
```

---

**Made with ❤️ by theepreacher-ai | Empowering Security Professionals**
