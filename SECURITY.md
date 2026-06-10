# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes    |
| < 1.0   | ❌ No     |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities as public GitHub issues.**

If you discover a security vulnerability in cvemap itself (e.g., a dependency with a known CVE, an injection flaw in the HTML report template, insecure API key handling), please report it privately:

**Email:** `security@[your-domain].com` *(replace with your actual contact)*  
**Subject:** `[cvemap] Security Vulnerability Report`

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Your suggested fix (if any)

We will acknowledge your report within 48 hours and aim to release a patch within 14 days for confirmed vulnerabilities.

## Responsible Disclosure

We follow coordinated disclosure. We ask that you:
- Give us reasonable time to patch before public disclosure
- Not exploit the vulnerability beyond what is needed to demonstrate it
- Not access user data (cvemap does not collect data, but related infra might)

We will credit reporters in the release notes unless anonymity is requested.

## Scope

**In scope:**
- The cvemap Python package code
- The HTML report template (XSS, injection)
- Dependency vulnerabilities

**Out of scope:**
- Issues in nmap itself — report those to https://nmap.org/
- Issues in the NIST NVD API — report those to nvd@nist.gov
- Vulnerabilities in *targets* that cvemap scans (that's what cvemap is for!)
