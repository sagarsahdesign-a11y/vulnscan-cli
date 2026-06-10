<div align="center">

<img src="https://raw.githubusercontent.com/sagarsahdesign-a11y/vulnscan-cli/main/docs/assets/logo.png" alt="cvemap logo" width="120" />

# cvemap

**CVE-powered network vulnerability scanner**  
*Scan. Enumerate. Correlate. Report.*

[![PyPI version](https://img.shields.io/pypi/v/cvemap?color=brightgreen&logo=pypi&logoColor=white)](https://pypi.org/project/cvemap/)
[![Python](https://img.shields.io/pypi/pyversions/cvemap?logo=python&logoColor=white)](https://pypi.org/project/cvemap/)
[![CI](https://github.com/sagarsahdesign-a11y/vulnscan-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/sagarsahdesign-a11y/vulnscan-cli/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/sagarsahdesign-a11y/vulnscan-cli/branch/main/graph/badge.svg)](https://codecov.io/gh/sagarsahdesign-a11y/vulnscan-cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/sagarsahdesign-a11y/vulnscan-cli?style=social)](https://github.com/sagarsahdesign-a11y/vulnscan-cli/stargazers)

---

**cvemap** combines Nmap's port scanning power with the NIST NVD CVE database to give you a one-command vulnerability assessment of any network — with beautiful color-coded output and exportable reports.

> **Tested against Metasploitable2 — detected 12 exploitable services with full CVE details in under 90 seconds.**

</div>

---

## ✨ Demo

<!-- Record with: asciinema rec cvemap-demo.cast -->
<!-- Upload to: https://asciinema.org/ and paste embed link below -->

```
📌 Demo GIF coming soon — record your own with:

   pip install asciinema
   asciinema rec cvemap-demo.cast
   cvemap scan -t 192.168.1.1 -p 1-1000
   # Then upload to asciinema.org and embed here
```

---

## 🚀 Features

| Feature | Details |
|---------|---------|
| **Automated port scanning** | TCP/SYN scanning across single IPs, ranges, or `/24` subnets |
| **Service enumeration** | Identifies product names, versions, and CPE identifiers |
| **OS fingerprinting** | Best-guess OS detection with confidence score |
| **CVE correlation** | Real-time lookup against NIST NVD API v2.0 per service |
| **CVSS scoring** | v3.1 / v3.0 / v2.0 scores with severity labels |
| **Rich terminal UI** | Color-coded output, progress bars, severity badges |
| **HTML reports** | Dark-mode dashboard with Chart.js graphs, filterable CVE tables |
| **JSON export** | Machine-readable output for SIEM/pipeline integration |
| **Rate limiting** | Respects NVD API limits; supports API key for 10× throughput |
| **Config via `.env`** | Store API keys securely, no hardcoding |
| **CI-friendly exit codes** | Exit 2 on CRITICAL, 3 on HIGH findings |
| **Cross-platform** | Linux, macOS, Windows |

---

## ⚡ Quick Start

### Prerequisites

- Python 3.9+
- [nmap](https://nmap.org/download.html) installed on your system
- (Optional) [NIST NVD API key](https://nvd.nist.gov/developers/request-an-api-key) for higher rate limits

### Install

```bash
pip install cvemap
```

Or install from source:

```bash
git clone https://github.com/sagarsahdesign-a11y/vulnscan-cli.git
cd vulnscan-cli
pip install -e ".[dev]"
```

---

## 🔍 Usage

### Basic scan

```bash
# Scan a single host, top 1000 ports
cvemap scan -t 192.168.1.1

# Scan a /24 subnet
cvemap scan -t 192.168.1.0/24

# Scan specific ports
cvemap scan -t 10.10.10.5 -p 22,80,443,8080,3306
```

### Advanced options

```bash
# Full port scan with stealth mode (requires root/Administrator)
sudo cvemap scan -t 192.168.1.1 -p 1-65535 --stealth

# Faster scan with aggressive timing
cvemap scan -t 192.168.1.0/24 --timing 4

# Run NSE vulnerability scripts
sudo cvemap scan -t 10.0.0.1 --scripts vuln,auth

# Export HTML + JSON reports to a specific directory
cvemap scan -t 192.168.1.1 -o my_scan --output-dir ./reports

# Use API key for 10× faster CVE lookups
cvemap scan -t 192.168.1.1 --api-key YOUR_NVD_KEY

# Skip CVE lookup (scan-only mode)
cvemap scan -t 192.168.1.0/24 --no-cve
```

### CLI Reference

```
cvemap scan --help

Options:
  -t, --target     TARGET   IP, hostname, or CIDR (required)
  -p, --ports      PORTS    Port range (default: 1-1000)
  -o, --output     PATH     Output file stem
  --format         FMT      Output format: html json (default: both)
  --output-dir     DIR      Report output directory
  --timing         0-5      Nmap timing template (default: 3)
  --stealth                 SYN scan (requires root)
  --no-os                   Disable OS fingerprinting
  --no-cve                  Skip CVE lookup
  --max-cves       N        Max CVEs per service (default: 10)
  --scripts        SCRIPTS  NSE scripts (e.g., vuln,auth)
  --api-key        KEY      NIST NVD API key
  --env-file       FILE     Path to .env config file
  --timeout        SECS     Per-host timeout (default: 300)
  --verbose                 Verbose CVE lookup output
  --no-report               Print to terminal only
  --no-banner               Suppress banner
```

### Exit Codes (CI/CD integration)

| Code | Meaning |
|------|---------|
| `0`  | Success, no findings or only Low/None severity |
| `1`  | Scan error (invalid target, nmap failure) |
| `2`  | CRITICAL severity CVEs found |
| `3`  | HIGH severity CVEs found |

```bash
# Use in CI pipeline
cvemap scan -t $TARGET --no-report
if [ $? -eq 2 ]; then
  echo "CRITICAL vulnerabilities found — blocking deployment!"
  exit 1
fi
```

---

## ⚙️ Configuration

Create a `.env` file in your working directory (or at `~/.cvemap/.env`):

```bash
# ~/.cvemap/.env

# Get your free API key: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=your_api_key_here

# Default output directory for reports
CVEMAP_OUTPUT_DIR=./reports

# Nmap timing template (0-5, default: 3)
CVEMAP_TIMING=3

# Max CVEs to fetch per service (default: 10)
CVEMAP_MAX_CVES=10
```

Copy the example:

```bash
cp .env.example .env
# Then edit with your API key
```

---

## 📊 Sample Output

### Terminal

```
  _____ _   ______ __  __          _____
 / ____| | / / __ \  \/  |   /\   |  __ \
| |    | |/ / |  | | \  / |  /  \  | |__) |
...

▶  Target   : 192.168.1.1
   Ports    : 1-1000

╭──────┬───────┬───────┬──────────────┬────────────────────────────────────────╮
│ Port │ Proto │ State │ Service      │ Version / Product                      │
├──────┼───────┼───────┼──────────────┼────────────────────────────────────────┤
│   22 │ TCP   │ open  │ ssh          │ OpenSSH 7.4 (protocol 2.0)             │
│   80 │ TCP   │ open  │ http         │ Apache httpd 2.4.49                    │
│  443 │ TCP   │ open  │ https        │ Apache httpd 2.4.49                    │
│ 3306 │ TCP   │ open  │ mysql        │ MySQL 5.5.62                           │
╰──────┴───────┴───────┴──────────────┴────────────────────────────────────────╯

✔  CVE enrichment complete — 18 CVE(s) found across 4 service(s)

╔══ SCAN SUMMARY ════════════════════════════════════╗
  Target      : 192.168.1.1
  Hosts found : 1
  Open ports  : 4
  CVEs found  : 18
  Risk score  : 8.4 / 10
╚═════════════════════════════════════════════════════╝

  Severity    Count
  ──────────  ─────
  CRITICAL    3
  HIGH        7
  MEDIUM      6
  LOW         2
```

### HTML Report

The HTML report includes:
- 📊 Executive dashboard with severity donut chart
- 🖥️ Per-host collapsible port tables with CVE details
- 🔴 Filterable CVE table (by severity + search)
- 📋 Scan metadata and full command audit trail

---

## 🧪 Testing

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest

# Run with coverage
pytest --cov=cvemap --cov-report=html

# Run specific test module
pytest tests/test_cve_lookup.py -v
```

Tests use mocked HTTP and nmap — **no network or nmap installation required** to run the test suite.

---

## 📦 PyPI Publishing

cvemap is published to PyPI on every GitHub Release. To release a new version:

1. Update `version` in `pyproject.toml` and `cvemap/__init__.py`
2. Commit: `git commit -am "chore: bump version to X.Y.Z"`
3. Tag: `git tag vX.Y.Z && git push --tags`
4. Create a GitHub Release — CI automatically publishes to PyPI

---

## 🤝 Contributing

Contributions are warmly welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a PR.

**Ways to contribute:**
- 🐛 [Report bugs](https://github.com/sagarsahdesign-a11y/vulnscan-cli/issues/new?template=bug_report.yml)
- ✨ [Request features](https://github.com/sagarsahdesign-a11y/vulnscan-cli/issues/new?template=feature_request.yml)
- 🔧 Submit a pull request
- ⭐ Star the project if you find it useful!

---

## 🗺️ Roadmap

- [ ] `--format sarif` — GitHub Code Scanning integration
- [ ] `--format csv` — Spreadsheet-friendly export
- [ ] Exploit-DB cross-reference
- [ ] Docker image (`docker run ghcr.io/sagarsahdesign-a11y/vulnscan-cli scan -t ...`)
- [ ] Interactive TUI with Textual
- [ ] `cvemap update` — self-update command
- [ ] Shodan/Censys API integration
- [ ] PDF report export

---

## ⚠️ Legal Disclaimer

**Only scan systems you own or have explicit written permission to scan.**  
Unauthorized scanning may violate laws including the Computer Fraud and Abuse Act (CFAA) and similar legislation in your jurisdiction.  
The authors assume no liability for misuse of this tool.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for full text.

---

<div align="center">

Made with ❤️ by [sagarsahdesign-a11y](https://github.com/sagarsahdesign-a11y)

If cvemap helped you find a real vulnerability, please ⭐ the repo!

</div>
