# 🚨 React2Shell Scanner

**CVSS 10.0 RCE in React Server Components. Is your React 19 app vulnerable?**

Fast, accurate scanner for CVE-2025-55182 (React2Shell) - a critical remote code execution vulnerability exploited in the wild. Zero false positives with intelligent Server Components detection.

[![CVSS Score](https://img.shields.io/badge/CVSS-10.0%20CRITICAL-red)](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub Issues](https://img.shields.io/github/issues/nxgn-kd01/react2shell-scanner)](https://github.com/nxgn-kd01/react2shell-scanner/issues)
[![GitHub Stars](https://img.shields.io/github/stars/nxgn-kd01/react2shell-scanner?style=social)](https://github.com/nxgn-kd01/react2shell-scanner/stargazers)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/nxgn-kd01/react2shell-scanner/blob/main/CONTRIBUTING.md)

## 🚨 About React2Shell (CVE-2025-55182)

React2Shell is a **maximum severity (10.0 CVSS)** vulnerability in React Server Components that allows unauthenticated remote code execution. Attackers can exploit this through specially crafted HTTP requests to Server Function endpoints.

**Key Facts:**
- **Affected:** React 19.x, Next.js 14-16.x, react-router, waku, @parcel/rsc, expo
- **Attack Vector:** Network (no authentication required)
- **Impact:** Complete server compromise (RCE)
- **Disclosure:** December 3, 2025
- **Exploitation:** Near 100% success rate in default configurations
- **Related CVEs:** CVE-2025-55184 (DoS), CVE-2025-55183 (Source Exposure), CVE-2025-67779

**⚠️ Critical Note:** Only React 19.x is vulnerable. React 18.x and earlier are NOT affected.

## ⚡ Quick Start (30 seconds)

```bash
# Option A: Node.js scanner (recommended - cross-platform, no dependencies)
npx react2shell-scanner /path/to/your/project

# Option B: Direct download and run
curl -sSL https://raw.githubusercontent.com/nxgn-kd01/react2shell-scanner/main/scan.js > scan.js
node scan.js /path/to/your/project

# Option C: Clone and run
git clone https://github.com/nxgn-kd01/react2shell-scanner.git
cd react2shell-scanner
node scan.js /path/to/your/project
```

**Results in seconds:** 🚨 Vulnerable | ⚠️ Warnings | ✅ Safe

## 📋 What This Scanner Checks

This tool performs intelligent vulnerability detection:

### 1. **React Version Analysis** 🔴 Critical
- Detects vulnerable React 19.0.0, 19.1.0, 19.1.1, 19.2.0
- Confirms React 18.x apps are safe (prevents false positives)
- Identifies react-server-dom-* packages

### 2. **Framework Configuration Check** 🟡 Warning
- Scans Next.js 14.x-canary through 16.x versions
- Detects react-router, waku, @parcel/rsc, @vitejs/plugin-rsc, rwsdk, expo
- Validates React 19 dependency where required
- Detects static export mode (Server Components disabled = safe)

### 3. **Server Function Detection** 🔍 Deep Analysis
- Scans source files for `'use server'` directives
- Identifies files containing Server Functions
- Only flags projects that actually use Server Components
- **Note:** Dynamically imported Server Functions require manual review

### 4. **Smart False Positive Prevention** ✅ Accuracy
- Only flags apps with React 19 + Server Components + 'use server' directives
- Provides context for edge cases
- Explains why projects are/aren't vulnerable

### 5. **Multi-Project Scanning** 📁 Scale
- Recursive directory scanning
- Detects npm, yarn, and pnpm projects
- Generates project-specific fix commands

## 🎯 Scanner Features

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
- `14.0.0` to `14.2.34`
- `14.3.0-canary.0` to `14.3.0-canary.87`
- `15.0.0` to `15.0.6`
- `15.1.0` to `15.1.8`
- `15.2.0` to `15.2.5`
- `15.3.0` to `15.3.5`
- `15.4.0` to `15.4.7`
- `15.5.0` to `15.5.6`
- `16.0.0` to `16.0.9`

**Additional Affected Frameworks (per React official advisory):**
- `react-router` 7.0.0 - 7.1.3
- `waku` 0.21.0 - 0.21.5
- `@parcel/rsc` 2.12.0 - 2.13.2
- `@vitejs/plugin-rsc` 0.1.0 - 0.2.0
- `rwsdk` (Redwood SDK) 0.1.0 - 0.4.0
- `expo` 52.0.0 - 52.0.9

### Patched Versions

**React:** `19.2.1` or later

**Next.js:**
- `14.2.35+`, `14.3.0-canary.88+`
- `15.0.7+`, `15.1.9+`, `15.2.6+`, `15.3.6+`, `15.4.8+`, `15.5.7+`
- `16.0.10+`

**Other Frameworks:**
- `react-router`: `7.1.4+`
- `waku`: `0.21.6+`
- `@parcel/rsc`: `2.13.3+`
- `@vitejs/plugin-rsc`: `0.2.1+`
- `rwsdk`: `0.4.1+`
- `expo`: `52.0.10+`

## 🚀 Getting Started

### Prerequisites

**Node.js Scanner (Recommended):**
- Node.js 12+ (cross-platform, no dependencies)

**Bash Scanner:**
- Bash 3.2+ (macOS/Linux)
- jq (JSON processor)

```bash
# Install jq (if using Bash scanner)
# macOS
brew install jq

# Ubuntu/Debian
sudo apt-get install jq

# RHEL/CentOS
sudo yum install jq
```

### Step 1: Get the Scanner

**Option A: Clone (Recommended for users)**

```bash
# Clone the repository
git clone https://github.com/nxgn-kd01/react2shell-scanner.git
cd react2shell-scanner

# Make scripts executable
chmod +x scan.sh scan.js
```

**Option B: Fork (Recommended for contributors)**

```bash
# Fork on GitHub (click "Fork" button on repository page)
# Then clone your fork
git clone https://github.com/YOUR_USERNAME/react2shell-scanner.git
cd react2shell-scanner

# Make scripts executable
chmod +x scan.sh scan.js

# Add upstream remote to stay updated
git remote add upstream https://github.com/nxgn-kd01/react2shell-scanner.git
```

**Option C: Direct Download**

```bash
# Node.js version (recommended - cross-platform)
curl -O https://raw.githubusercontent.com/nxgn-kd01/react2shell-scanner/main/scan.js
chmod +x scan.js

# Bash version (Unix/Linux/macOS only)
curl -O https://raw.githubusercontent.com/nxgn-kd01/react2shell-scanner/main/scan.sh
chmod +x scan.sh
```

## 💻 Usage

### Step 2: Run the Scanner

**🔍 Scan current directory:**
```bash
# Using Node.js (recommended)
node scan.js

# Using Bash
./scan.sh
```

**📁 Scan specific project:**
```bash
node scan.js /path/to/project
./scan.sh /path/to/project
```

**🗂️ Recursive scan (all subdirectories):**
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
4. **Scans for Server Functions** by looking for `'use server'` directives in source files
5. **Validates actual vulnerability** by checking:
   - React version (only React 19 is affected - React 18 is safe)
   - Configuration (static exports don't use Server Components)
   - Presence of `'use server'` directives (indicates Server Functions in use)
6. **Detects package manager** (npm, yarn, or pnpm)
7. **Generates fix commands** with appropriate upgrade syntax
8. **Reports findings** in human-readable or JSON format

### Accuracy Features

The scanner includes intelligent detection to prevent false positives:

- **React Version Check**: Next.js apps are only flagged if React 19 is present (React 18 is safe)
- **Static Export Detection**: Projects using `output: 'export'` are marked as likely safe
- **Server Function Detection**: Scans source files for `'use server'` directives to confirm actual Server Component usage
- **Contextual Warnings**: Provides explanations for why projects are or aren't vulnerable
- **Conservative Approach**: Warns about edge cases that may need manual review (e.g., dynamically imported Server Functions)

**Example Output:**
```
✓ No vulnerable projects found

ℹ Projects with analysis notes:

1. /path/to/project
   ℹ Next.js ^15.1.3 is in vulnerable range, but using React 18 (safe - only React 19 affected)

2. /path/to/another-project
   ℹ Next.js 16.0.5 with React 19 detected, but no 'use server' directives found (likely safe).
     Note: dynamically imported Server Functions require manual review.
```

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

## ❓ Frequently Asked Questions

### Q: Does this scan transitive dependencies?

A: Currently, the scanner checks direct dependencies in `package.json`. For deep dependency scanning, use `npm audit` or `yarn audit` in combination with this tool.

### Q: I'm on React 18, am I affected?

A: **No, React 18 is NOT affected** ✅

CVE-2025-55182 only affects React 19.x Server Components. The scanner will correctly identify React 18 apps as safe, even if using Next.js 15.x or 16.x versions that are in the vulnerable range.

### Q: Can I use this in my automated build pipeline?

A: **Yes!** Use the `--ci` flag to make the scanner exit with code 1 if vulnerabilities are found, which will fail your pipeline. See CI/CD integration examples above.

### Q: What if I can't upgrade immediately?

A: **Temporary mitigations** (upgrading is the only definitive fix):
1. ⛔ Disable Server Components in your application
2. 🛡️ Add WAF rules to block suspicious RSC payloads
3. 📊 Monitor logs for exploitation attempts
4. ⏰ Plan an emergency upgrade window

**⚠️ Critical:** These are temporary measures only. Upgrade to patched versions ASAP.

### Q: How accurate is this scanner?

A: **Very accurate** with intelligent false positive prevention:
- ✅ Checks exact version matches against official CVE advisory
- ✅ Validates React 19 dependency (prevents React 18 false positives)
- ✅ Detects static export configuration
- ✅ Scans for `'use server'` directives to confirm actual vulnerability
- ✅ Provides contextual warnings for edge cases

### Q: What about dynamically imported Server Functions?

A: The scanner detects `'use server'` directives in your source files. However, **dynamically imported Server Functions** (loaded at runtime via `import()`) may not be detected statically. If the scanner reports "no 'use server' directives found" but you use dynamic imports for Server Functions, you should manually review those files. The scanner will include a note reminding you of this.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

### Running tests

```bash
# Test on sample projects
./test-scanner.sh
```

### Supported Frameworks

This scanner now detects all major RSC-enabled frameworks per the React official advisory:
- ✅ React / react-server-dom-*
- ✅ Next.js
- ✅ react-router (with RSC APIs)
- ✅ waku
- ✅ @parcel/rsc
- ✅ @vitejs/plugin-rsc
- ✅ rwsdk (Redwood SDK)
- ✅ expo

For additional frameworks, please open an issue or submit a PR.

## References

- [React Official Blog: Critical Security Vulnerability](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [NVD CVE-2025-55182](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
- [Wiz Research: React2Shell Analysis](https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182)
- [Microsoft: Defending Against CVE-2025-55182](https://www.microsoft.com/en-us/security/blog/2025/12/15/defending-against-the-cve-2025-55182-react2shell-vulnerability-in-react-server-components/)
- [AWS: China-nexus Groups Exploit React2Shell](https://aws.amazon.com/blogs/security/china-nexus-cyber-threat-groups-rapidly-exploit-react2shell-vulnerability-cve-2025-55182/)
- [Datadog Security Labs: CVE-2025-55182 RCE Analysis](https://securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components/)
- [Tenable: CVE-2025-55182 FAQ](https://www.tenable.com/blog/react2shell-cve-2025-55182-react-server-components-rce)

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
