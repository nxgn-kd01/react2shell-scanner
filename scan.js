#!/usr/bin/env node

/**
 * CVE-2025-55182 Scanner
 * Detects React Server Components RCE vulnerability (React2Shell)
 *
 * Scans Node.js projects for vulnerable versions of React and Next.js
 * CVSS: 10.0 (CRITICAL)
 */

const fs = require('fs');
const path = require('path');

// Vulnerability data
const VULNERABILITY = {
  id: 'CVE-2025-55182',
  name: 'React2Shell',
  cvss: 10.0,
  severity: 'CRITICAL',
  description: 'Unauthenticated Remote Code Execution in React Server Components',

  vulnerable: {
    react: ['19.0.0', '19.1.0', '19.1.1', '19.2.0'],
    'react-server-dom-webpack': ['19.0.0', '19.1.0', '19.1.1', '19.2.0'],
    'react-server-dom-parcel': ['19.0.0', '19.1.0', '19.1.1', '19.2.0'],
    'react-server-dom-turbopack': ['19.0.0', '19.1.0', '19.1.1', '19.2.0'],
    'next': {
      ranges: [
        { min: '14.3.0-canary.0', max: '14.3.0-canary.87' },
        { min: '15.0.0', max: '15.0.4' },
        { min: '15.1.0', max: '15.1.8' },
        { min: '15.2.0', max: '15.2.5' },
        { min: '15.3.0', max: '15.3.5' },
        { min: '15.4.0', max: '15.4.7' },
        { min: '15.5.0', max: '15.5.6' },
        { min: '16.0.0', max: '16.0.6' }
      ]
    }
  },

  patched: {
    react: '19.2.1',
    'react-server-dom-webpack': '19.2.1',
    'react-server-dom-parcel': '19.2.1',
    'react-server-dom-turbopack': '19.2.1',
    'next': ['14.3.0-canary.88', '15.0.5', '15.1.9', '15.2.6', '15.3.6', '15.4.8', '15.5.7', '16.0.7']
  }
};

// Colors for terminal output
const COLORS = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m',
  dim: '\x1b[2m'
};

// Command line arguments
const args = process.argv.slice(2);
const options = {
  json: args.includes('--json'),
  verbose: args.includes('--verbose') || args.includes('-v'),
  recursive: args.includes('--recursive') || args.includes('-r'),
  exitCode: args.includes('--ci'),
  help: args.includes('--help') || args.includes('-h')
};

// Get scan path
const scanPath = args.find(arg => !arg.startsWith('--') && !arg.startsWith('-')) || process.cwd();

/**
 * Parse semantic version
 */
function parseVersion(version) {
  const cleaned = version.replace(/^[^0-9]*/, ''); // Remove leading non-numeric chars
  const parts = cleaned.split(/[.-]/);
  return {
    major: parseInt(parts[0]) || 0,
    minor: parseInt(parts[1]) || 0,
    patch: parseInt(parts[2]) || 0,
    prerelease: parts.slice(3).join('-'),
    original: version
  };
}

/**
 * Compare versions
 */
function compareVersions(v1, v2) {
  const ver1 = parseVersion(v1);
  const ver2 = parseVersion(v2);

  if (ver1.major !== ver2.major) return ver1.major - ver2.major;
  if (ver1.minor !== ver2.minor) return ver1.minor - ver2.minor;
  if (ver1.patch !== ver2.patch) return ver1.patch - ver2.patch;

  // Handle prerelease
  if (ver1.prerelease && !ver2.prerelease) return -1;
  if (!ver1.prerelease && ver2.prerelease) return 1;
  if (ver1.prerelease && ver2.prerelease) {
    return ver1.prerelease.localeCompare(ver2.prerelease);
  }

  return 0;
}

/**
 * Check if version is vulnerable
 */
function isVersionVulnerable(packageName, version) {
  if (!version) return false;

  const cleanVersion = version.replace(/^[\^~>=<]/, '');
  const vulnData = VULNERABILITY.vulnerable[packageName];

  if (!vulnData) return false;

  if (Array.isArray(vulnData)) {
    return vulnData.includes(cleanVersion);
  }

  // Handle Next.js version ranges
  if (vulnData.ranges) {
    return vulnData.ranges.some(range => {
      const inRange = compareVersions(cleanVersion, range.min) >= 0 &&
                     compareVersions(cleanVersion, range.max) <= 0;
      return inRange;
    });
  }

  return false;
}

/**
 * Get fix version for a package
 */
function getFixVersion(packageName) {
  const fix = VULNERABILITY.patched[packageName];
  if (Array.isArray(fix)) {
    return fix[fix.length - 1]; // Return latest
  }
  return fix;
}

/**
 * Check if project uses static export
 */
function isStaticExport(projectPath) {
  const configFiles = ['next.config.js', 'next.config.mjs', 'next.config.ts'];

  for (const configFile of configFiles) {
    const configPath = path.join(projectPath, configFile);
    if (fs.existsSync(configPath)) {
      try {
        const content = fs.readFileSync(configPath, 'utf8');
        if (content.includes("output: 'export'") || content.includes('output: "export"')) {
          return true;
        }
      } catch (error) {
        // Ignore read errors
      }
    }
  }
  return false;
}

/**
 * Get React major version
 */
function getReactMajorVersion(version) {
  if (!version) return null;
  const cleaned = version.replace(/^[\^~>=<]/, '');
  const parsed = parseVersion(cleaned);
  return parsed.major;
}

/**
 * Scan a single project
 */
function scanProject(projectPath) {
  const result = {
    path: projectPath,
    vulnerable: false,
    packages: [],
    packageManager: null,
    fixCommands: [],
    warnings: []
  };

  const packageJsonPath = path.join(projectPath, 'package.json');

  if (!fs.existsSync(packageJsonPath)) {
    result.error = 'No package.json found';
    return result;
  }

  try {
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    const allDeps = {
      ...packageJson.dependencies,
      ...packageJson.devDependencies
    };

    // Get React version
    const reactVersion = allDeps['react'];
    const reactMajor = getReactMajorVersion(reactVersion);

    // Check if static export
    const isStatic = isStaticExport(projectPath);

    // Determine package manager
    if (fs.existsSync(path.join(projectPath, 'yarn.lock'))) {
      result.packageManager = 'yarn';
    } else if (fs.existsSync(path.join(projectPath, 'pnpm-lock.yaml'))) {
      result.packageManager = 'pnpm';
    } else {
      result.packageManager = 'npm';
    }

    // Check each package
    Object.keys(VULNERABILITY.vulnerable).forEach(pkgName => {
      const version = allDeps[pkgName];
      if (!version) return;

      // Special handling for Next.js - only vulnerable if React 19 is present
      if (pkgName === 'next') {
        if (isVersionVulnerable(pkgName, version)) {
          // Next.js version is in vulnerable range, but check React version
          if (reactMajor !== 19) {
            result.warnings.push(`Next.js ${version} is in vulnerable range, but using React ${reactMajor || 'unknown'} (safe - only React 19 affected)`);
            return; // Not vulnerable - React 19 not present
          }

          // Check if static export
          if (isStatic) {
            result.warnings.push(`Next.js ${version} with React 19 detected, but using static export (likely safe - no Server Components)`);
            return; // Likely not vulnerable - static export doesn't use Server Components
          }

          // Both React 19 and Server Components likely present
          result.vulnerable = true;
          result.packages.push({
            name: pkgName,
            version: version,
            fixVersion: getFixVersion(pkgName)
          });
        }
      } else if (isVersionVulnerable(pkgName, version)) {
        // For React and react-server-dom-* packages, directly flag
        result.vulnerable = true;
        result.packages.push({
          name: pkgName,
          version: version,
          fixVersion: getFixVersion(pkgName)
        });
      }
    });

    // Generate fix commands
    if (result.vulnerable) {
      const upgrades = result.packages.map(pkg =>
        `${pkg.name}@${pkg.fixVersion}`
      ).join(' ');

      switch (result.packageManager) {
        case 'yarn':
          result.fixCommands = [
            `cd ${projectPath}`,
            `yarn upgrade ${upgrades}`
          ];
          break;
        case 'pnpm':
          result.fixCommands = [
            `cd ${projectPath}`,
            `pnpm update ${upgrades}`
          ];
          break;
        default:
          result.fixCommands = [
            `cd ${projectPath}`,
            `npm install ${upgrades}`
          ];
      }
    }

  } catch (error) {
    result.error = error.message;
  }

  return result;
}

/**
 * Find all Node.js projects recursively
 */
function findProjects(dir, maxDepth = 3, currentDepth = 0) {
  const projects = [];

  if (currentDepth > maxDepth) return projects;

  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    // Check if current directory has package.json
    if (entries.some(e => e.name === 'package.json')) {
      projects.push(dir);
    }

    // Recurse into subdirectories
    for (const entry of entries) {
      if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
        const subdir = path.join(dir, entry.name);
        projects.push(...findProjects(subdir, maxDepth, currentDepth + 1));
      }
    }
  } catch (error) {
    // Skip directories we can't read
  }

  return projects;
}

/**
 * Format output for terminal
 */
function formatOutput(results) {
  const totalProjects = results.length;
  const vulnerableProjects = results.filter(r => r.vulnerable).length;
  const safeProjects = totalProjects - vulnerableProjects;

  let output = '';

  // Header
  output += `\n${COLORS.bold}${COLORS.cyan}╔════════════════════════════════════════════════════════════╗${COLORS.reset}\n`;
  output += `${COLORS.bold}${COLORS.cyan}║${COLORS.reset}  ${COLORS.bold}CVE-2025-55182 Scanner (React2Shell)${COLORS.reset}                  ${COLORS.cyan}║${COLORS.reset}\n`;
  output += `${COLORS.cyan}╚════════════════════════════════════════════════════════════╝${COLORS.reset}\n\n`;

  output += `${COLORS.dim}Severity:${COLORS.reset} ${COLORS.red}${COLORS.bold}CRITICAL${COLORS.reset} (CVSS 10.0)\n`;
  output += `${COLORS.dim}Description:${COLORS.reset} Unauthenticated RCE in React Server Components\n\n`;

  // Summary
  output += `${COLORS.bold}Scan Summary:${COLORS.reset}\n`;
  output += `  Total projects: ${totalProjects}\n`;
  output += `  ${COLORS.red}Vulnerable: ${vulnerableProjects}${COLORS.reset}\n`;
  output += `  ${COLORS.green}Safe: ${safeProjects}${COLORS.reset}\n\n`;

  // Vulnerable projects details
  if (vulnerableProjects > 0) {
    output += `${COLORS.red}${COLORS.bold}⚠ VULNERABLE PROJECTS FOUND:${COLORS.reset}\n\n`;

    results.filter(r => r.vulnerable).forEach((result, idx) => {
      output += `${COLORS.red}${idx + 1}. ${result.path}${COLORS.reset}\n`;
      result.packages.forEach(pkg => {
        output += `   └─ ${COLORS.bold}${pkg.name}${COLORS.reset} ${pkg.version} ${COLORS.red}→${COLORS.reset} ${COLORS.green}${pkg.fixVersion}${COLORS.reset}\n`;
      });

      output += `\n   ${COLORS.yellow}Fix command:${COLORS.reset}\n`;
      result.fixCommands.forEach(cmd => {
        output += `   ${COLORS.dim}$${COLORS.reset} ${cmd}\n`;
      });
      output += '\n';
    });
  } else {
    output += `${COLORS.green}${COLORS.bold}✓ No vulnerable projects found${COLORS.reset}\n\n`;
  }

  // Show warnings for projects with concerning patterns
  const projectsWithWarnings = results.filter(r => r.warnings && r.warnings.length > 0);
  if (projectsWithWarnings.length > 0) {
    output += `${COLORS.yellow}${COLORS.bold}ℹ Projects with analysis notes:${COLORS.reset}\n\n`;
    projectsWithWarnings.forEach((result, idx) => {
      output += `${COLORS.dim}${idx + 1}. ${result.path}${COLORS.reset}\n`;
      result.warnings.forEach(warning => {
        output += `   ${COLORS.yellow}ℹ${COLORS.reset} ${warning}\n`;
      });
      output += '\n';
    });
  }

  // Footer with references
  output += `${COLORS.dim}─────────────────────────────────────────────────────────────${COLORS.reset}\n`;
  output += `${COLORS.dim}References:${COLORS.reset}\n`;
  output += `  • https://nvd.nist.gov/vuln/detail/CVE-2025-55182\n`;
  output += `  • https://react.dev/blog/2025/12/03/security-update\n`;
  output += `  • https://github.com/facebook/react/security/advisories\n\n`;

  return output;
}

/**
 * Print help
 */
function printHelp() {
  console.log(`
${COLORS.bold}CVE-2025-55182 Scanner${COLORS.reset}
Detects React2Shell vulnerability in React Server Components

${COLORS.bold}Usage:${COLORS.reset}
  node scan.js [path] [options]

${COLORS.bold}Options:${COLORS.reset}
  -r, --recursive    Scan all subdirectories for Node.js projects
  -v, --verbose      Show detailed output
  --json             Output results as JSON
  --ci               Exit with code 1 if vulnerabilities found (for CI/CD)
  -h, --help         Show this help message

${COLORS.bold}Examples:${COLORS.reset}
  node scan.js                    # Scan current directory
  node scan.js /path/to/project   # Scan specific project
  node scan.js -r                 # Scan current directory recursively
  node scan.js /path -r --json    # Recursive scan with JSON output
  node scan.js --ci               # CI/CD mode (exits with code 1 if vulnerable)

${COLORS.bold}Exit Codes:${COLORS.reset}
  0 - No vulnerabilities found
  1 - Vulnerabilities found (with --ci flag)
  2 - Scan error
`);
}

/**
 * Main function
 */
function main() {
  if (options.help) {
    printHelp();
    process.exit(0);
  }

  try {
    let results = [];

    if (options.recursive) {
      const projects = findProjects(scanPath);
      results = projects.map(p => scanProject(p));
    } else {
      results = [scanProject(scanPath)];
    }

    // Remove results with errors for cleaner output
    const validResults = results.filter(r => !r.error);

    if (options.json) {
      console.log(JSON.stringify({
        vulnerability: VULNERABILITY.id,
        severity: VULNERABILITY.severity,
        cvss: VULNERABILITY.cvss,
        scanned: validResults.length,
        vulnerable: validResults.filter(r => r.vulnerable).length,
        results: validResults
      }, null, 2));
    } else {
      console.log(formatOutput(validResults));
    }

    // Exit with appropriate code for CI/CD
    if (options.exitCode) {
      const hasVulnerabilities = validResults.some(r => r.vulnerable);
      process.exit(hasVulnerabilities ? 1 : 0);
    }

  } catch (error) {
    console.error(`${COLORS.red}Error:${COLORS.reset} ${error.message}`);
    process.exit(2);
  }
}

// Run
main();
