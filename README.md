# CVE-2025-55182 Scanner (React2Shell)

A community tool to detect and remediate the critical React Server Components RCE vulnerability.

[![CVSS Score](https://img.shields.io/badge/CVSS-10.0%20CRITICAL-red)](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

**CVE-2025-55182** (also known as "React2Shell") is a critical unauthenticated remote code execution vulnerability in React Server Components (RSC). With a CVSS score of 10.0, this vulnerability allows attackers to execute arbitrary code on servers through specially crafted HTTP requests.

This tool helps you:
- Scan your projects for vulnerable versions of React and Next.js
- Identify affected packages and their versions
- Generate fix commands for easy remediation
- Integrate vulnerability scanning into CI/CD pipelines

## Vulnerability Details

| Property | Value |
|----------|-------|
| **CVE ID** | CVE-2025-55182 |
| **Name** | React2Shell |
| **CVSS Score** | 10.0 (CRITICAL) |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H |
| **Attack Vector** | Network |
| **Authentication** | None required |
| **Impact** | Complete system compromise |

### Affected Versions

**React:**
- `19.0.0`, `19.1.0`, `19.1.1`, `19.2.0`

**React Server DOM Packages:**
- `react-server-dom-webpack` 19.0.0 - 19.2.0
- `react-server-dom-parcel` 19.0.0 - 19.2.0
- `react-server-dom-turbopack` 19.0.0 - 19.2.0

**Next.js:**
- `14.3.0-canary.0` to `14.3.0-canary.87`
- `15.0.0` to `15.0.4`
- `15.1.0` to `15.1.8`
- `15.2.0` to `15.2.5`
- `15.3.0` to `15.3.5`
- `15.4.0` to `15.4.7`
- `15.5.0` to `15.5.6`
- `16.0.0` to `16.0.6`

### Patched Versions

**React:** `19.2.1` or later

**Next.js:**
- `14.3.0-canary.88+`
- `15.0.5+`, `15.1.9+`, `15.2.6+`, `15.3.6+`, `15.4.8+`, `15.5.7+`
- `16.0.7+`

## Installation

### Prerequisites

**For Bash script:**
- bash 4.0+
- jq (JSON processor)

```bash
# Install jq
# macOS
brew install jq

# Ubuntu/Debian
sudo apt-get install jq

# RHEL/CentOS
sudo yum install jq
```

**For Node.js script:**
- Node.js 12+

### Download

```bash
# Clone the repository
git clone https://github.com/nxgn-kd01/cve-2025-55182-scanner.git
cd cve-2025-55182-scanner

# Make scripts executable
chmod +x scan.sh scan.js
```

Or download individual scripts:
```bash
# Bash version
curl -O https://raw.githubusercontent.com/nxgn-kd01/cve-2025-55182-scanner/main/scan.sh
chmod +x scan.sh

# Node.js version
curl -O https://raw.githubusercontent.com/nxgn-kd01/cve-2025-55182-scanner/main/scan.js
chmod +x scan.js
```

## Usage

### Basic Scanning

**Scan current directory:**
```bash
# Using Node.js
node scan.js

# Using Bash
./scan.sh
```

**Scan specific project:**
```bash
node scan.js /path/to/project
./scan.sh /path/to/project
```

**Recursive scan (all subdirectories):**
```bash
node scan.js -r
./scan.sh -r
```

### Advanced Options

**JSON output (for automation):**
```bash
node scan.js --json
./scan.sh --json
```

**CI/CD mode (exits with code 1 if vulnerable):**
```bash
node scan.js --ci
./scan.sh --ci
```

**Verbose output:**
```bash
node scan.js -v
./scan.sh -v
```

**Combine options:**
```bash
node scan.js /path/to/projects -r --json --ci
./scan.sh /path/to/projects -r --json --ci
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-r`, `--recursive` | Scan all subdirectories for Node.js projects |
| `-v`, `--verbose` | Show detailed output |
| `--json` | Output results as JSON |
| `--ci` | Exit with code 1 if vulnerabilities found (for CI/CD) |
| `-h`, `--help` | Show help message |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found |
| 1 | Vulnerabilities found (when using `--ci` flag) |
| 2 | Scan error occurred |

## Examples

### Example 1: Scan a single project

```bash
$ node scan.js ~/my-react-app

╔════════════════════════════════════════════════════════════╗
║  CVE-2025-55182 Scanner (React2Shell)                      ║
╚════════════════════════════════════════════════════════════╝

Severity: CRITICAL (CVSS 10.0)
Description: Unauthenticated RCE in React Server Components

Scan Summary:
  Total projects: 1
  Vulnerable: 1
  Safe: 0

⚠ VULNERABLE PROJECTS FOUND:

1. /Users/user/my-react-app
   └─ react 19.0.0 → 19.2.1
   └─ next 15.0.3 → 15.0.5

   Fix command:
   $ cd /Users/user/my-react-app
   $ npm install react@19.2.1 next@15.0.5
```

### Example 2: Recursive scan with JSON output

```bash
$ node scan.js ~/projects -r --json > results.json
```

```json
{
  "vulnerability": "CVE-2025-55182",
  "severity": "CRITICAL",
  "cvss": 10.0,
  "scanned": 5,
  "vulnerable": 2,
  "results": [
    {
      "path": "/Users/user/projects/app1",
      "vulnerable": true,
      "packages": [
        {
          "name": "react",
          "version": "19.0.0",
          "fixVersion": "19.2.1"
        }
      ],
      "packageManager": "npm",
      "fixCommands": [
        "cd /Users/user/projects/app1",
        "npm install react@19.2.1"
      ]
    }
  ]
}
```

### Example 3: CI/CD integration

**.github/workflows/security-scan.yml**
```yaml
name: CVE-2025-55182 Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Download CVE-2025-55182 Scanner
        run: |
          curl -O https://raw.githubusercontent.com/nxgn-kd01/cve-2025-55182-scanner/main/scan.js
          chmod +x scan.js

      - name: Scan for vulnerabilities
        run: node scan.js --ci
```

**GitLab CI (.gitlab-ci.yml)**
```yaml
security-scan:
  stage: test
  image: node:18
  script:
    - curl -O https://raw.githubusercontent.com/nxgn-kd01/cve-2025-55182-scanner/main/scan.js
    - chmod +x scan.js
    - node scan.js --ci
  allow_failure: false
```

## How It Works

The scanner performs the following checks:

1. **Locates Node.js projects** by finding `package.json` files
2. **Parses dependencies** from both `dependencies` and `devDependencies`
3. **Checks versions** against known vulnerable versions:
   - React 19.0.0, 19.1.0, 19.1.1, 19.2.0
   - React Server DOM packages (same versions)
   - Next.js version ranges (14.3.x, 15.x, 16.x)
4. **Detects package manager** (npm, yarn, or pnpm)
5. **Generates fix commands** with appropriate upgrade syntax
6. **Reports findings** in human-readable or JSON format

## Remediation

### Step 1: Run the scanner

```bash
node scan.js -r
```

### Step 2: Apply the fix commands

For each vulnerable project, run the suggested fix command:

```bash
cd /path/to/project
npm install react@19.2.1 next@15.0.5  # Example
```

Or with yarn:
```bash
yarn upgrade react@19.2.1 next@15.0.5
```

Or with pnpm:
```bash
pnpm update react@19.2.1 next@15.0.5
```

### Step 3: Test your application

```bash
npm test
npm run build
```

### Step 4: Verify the fix

```bash
node scan.js --ci
```

## Frequently Asked Questions

### Q: Does this scan transitive dependencies?

A: Currently, the scanner checks direct dependencies in `package.json`. For deep dependency scanning, use `npm audit` or `yarn audit` in combination with this tool.

### Q: I'm on React 18, am I affected?

A: No, only React 19.x versions are affected. However, if you use Next.js 15.x or 16.x, you may have React 19 as a transitive dependency.

### Q: Can I use this in my automated build pipeline?

A: Yes! Use the `--ci` flag to make the scanner exit with code 1 if vulnerabilities are found, which will fail your pipeline.

### Q: What if I can't upgrade immediately?

A: If you cannot upgrade immediately:
1. Disable Server Components in your application
2. Add WAF rules to block suspicious RSC payloads
3. Monitor your logs for exploitation attempts
4. Plan an emergency upgrade window

**Note:** Upgrading is the only definitive mitigation.

### Q: How accurate is this scanner?

A: The scanner checks exact version matches against the official CVE advisory. False positives are unlikely, but always verify with your package manager's lock files.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

### Running tests

```bash
# Test on sample projects
./test-scanner.sh
```

### Adding support for more frameworks

If you're using other RSC-enabled frameworks (Remix, Waku, etc.), please open an issue or submit a PR with detection logic.

## References

- [NVD CVE-2025-55182](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
- [React Security Advisory](https://react.dev/blog/2025/12/03/security-update)
- [Wiz Research: React2Shell Analysis](https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182)
- [Tenable: CVE-2025-55182 FAQ](https://www.tenable.com/blog/react2shell-cve-2025-55182-react-server-components-rce)
- [Vercel Advisory](https://vercel.com/changelog/cve-2025-55182)

## License

MIT License - see [LICENSE](LICENSE) file for details

## Disclaimer

This tool is provided as-is for the community to help identify vulnerable projects. Always verify scanner results and test updates in a safe environment before deploying to production.

## Support

If you find this tool helpful, please:
- ⭐ Star this repository
- 🐛 Report issues
- 🔄 Share with your team
- 🤝 Contribute improvements

---

**Stay safe and keep your dependencies updated!**
