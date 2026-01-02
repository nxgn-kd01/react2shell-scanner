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

  // Related CVEs patched in same release
  relatedCVEs: [
    'CVE-2025-55184', // DoS (CVSS 7.5)
    'CVE-2025-55183', // Source Code Exposure (CVSS 5.3)
    'CVE-2025-67779'  // Additional case
  ],

  vulnerable: {
    react: ['19.0.0', '19.1.0', '19.1.1', '19.2.0'],
    'react-server-dom-webpack': ['19.0.0', '19.1.0', '19.1.1', '19.2.0'],
    'react-server-dom-parcel': ['19.0.0', '19.1.0', '19.1.1', '19.2.0'],
    'react-server-dom-turbopack': ['19.0.0', '19.1.0', '19.1.1', '19.2.0'],
    'next': {
      ranges: [
        { min: '14.0.0', max: '14.2.34' },
        { min: '14.3.0-canary.0', max: '14.3.0-canary.87' },
        { min: '15.0.0', max: '15.0.6' },
        { min: '15.1.0', max: '15.1.8' },
        { min: '15.2.0', max: '15.2.5' },
        { min: '15.3.0', max: '15.3.5' },
        { min: '15.4.0', max: '15.4.7' },
        { min: '15.5.0', max: '15.5.6' },
        { min: '16.0.0', max: '16.0.9' }
      ]
    },
    // Additional affected frameworks (per React official advisory)
    'react-router': ['7.0.0', '7.0.1', '7.0.2', '7.1.0', '7.1.1', '7.1.2', '7.1.3'],
    'waku': ['0.21.0', '0.21.1', '0.21.2', '0.21.3', '0.21.4', '0.21.5'],
    '@parcel/rsc': ['2.12.0', '2.13.0', '2.13.1', '2.13.2'],
    '@vitejs/plugin-rsc': ['0.1.0', '0.1.1', '0.1.2', '0.2.0'],
    'rwsdk': ['0.1.0', '0.2.0', '0.3.0', '0.4.0'],
    'expo': {
      ranges: [
        { min: '52.0.0', max: '52.0.9' }
      ]
    }
  },

  patched: {
    react: '19.2.1',
    'react-server-dom-webpack': '19.2.1',
    'react-server-dom-parcel': '19.2.1',
    'react-server-dom-turbopack': '19.2.1',
    'next': ['14.2.35', '14.3.0-canary.88', '15.0.7', '15.1.9', '15.2.6', '15.3.6', '15.4.8', '15.5.7', '16.0.10'],
    'react-router': '7.1.4',
    'waku': '0.21.6',
    '@parcel/rsc': '2.13.3',
    '@vitejs/plugin-rsc': '0.2.1',
    'rwsdk': '0.4.1',
    'expo': '52.0.10'
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
  const configFiles = ['next.config.js', 'next.config.mjs', 'next.config.ts', 'next.config.cjs'];

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
 * Check if project uses Server Functions ('use server' directive)
 * Returns: { found: boolean, files: string[] }
 */
function hasServerFunctions(projectPath) {
  const result = { found: false, files: [] };
  const extensions = ['.js', '.jsx', '.ts', '.tsx'];
  const dirsToSkip = ['node_modules', '.next', '.git', 'dist', 'build', '.turbo'];

  function scanDir(dir, depth = 0) {
    if (depth > 5) return; // Limit recursion depth

    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          if (!dirsToSkip.includes(entry.name) && !entry.name.startsWith('.')) {
            scanDir(fullPath, depth + 1);
          }
        } else if (entry.isFile() && extensions.some(ext => entry.name.endsWith(ext))) {
          try {
            const content = fs.readFileSync(fullPath, 'utf8');
            // Check for 'use server' directive (file-level or function-level)
            if (content.includes("'use server'") || content.includes('"use server"')) {
              result.found = true;
              result.files.push(fullPath.replace(projectPath + '/', ''));
            }
          } catch (e) {
            // Skip files we can't read
          }
        }
      }
    } catch (e) {
      // Skip directories we can't read
    }
  }

  scanDir(projectPath);
  return result;
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

    // Check for 'use server' directives
    const serverFunctions = hasServerFunctions(projectPath);

    // Determine package manager
    if (fs.existsSync(path.join(projectPath, 'yarn.lock'))) {
      result.packageManager = 'yarn';
    } else if (fs.existsSync(path.join(projectPath, 'pnpm-lock.yaml'))) {
      result.packageManager = 'pnpm';
    } else {
      result.packageManager = 'npm';
    }

    // Packages that require React 19 to be vulnerable
    const react19RequiredPackages = ['next', 'expo'];
    // Packages that directly include RSC (always vulnerable if in range)
    const directRscPackages = ['react-router', 'waku', '@parcel/rsc', '@vitejs/plugin-rsc', 'rwsdk'];

    // Check each package
    Object.keys(VULNERABILITY.vulnerable).forEach(pkgName => {
      const version = allDeps[pkgName];
      if (!version) return;

      // Special handling for Next.js and Expo - only vulnerable if React 19 is present
      if (react19RequiredPackages.includes(pkgName)) {
        if (isVersionVulnerable(pkgName, version)) {
          // Version is in vulnerable range, but check React version
          if (reactMajor !== 19) {
            result.warnings.push(`${pkgName} ${version} is in vulnerable range, but using React ${reactMajor || 'unknown'} (safe - only React 19 affected)`);
            return; // Not vulnerable - React 19 not present
          }

          // Check if static export (Next.js only)
          if (pkgName === 'next' && isStatic) {
            result.warnings.push(`Next.js ${version} with React 19 detected, but using static export (likely safe - no Server Components)`);
            return; // Likely not vulnerable - static export doesn't use Server Components
          }

          // Check for 'use server' directives
          if (!serverFunctions.found) {
            result.warnings.push(`${pkgName} ${version} with React 19 detected, but no 'use server' directives found (likely safe). Note: dynamically imported Server Functions require manual review.`);
            return; // Likely not vulnerable - no Server Functions detected
          }

          // Both React 19 and Server Functions present - VULNERABLE
          result.vulnerable = true;
          result.packages.push({
            name: pkgName,
            version: version,
            fixVersion: getFixVersion(pkgName)
          });
          // Add info about which files have server functions
          if (serverFunctions.files.length > 0) {
            result.serverFunctionFiles = serverFunctions.files.slice(0, 5); // Limit to first 5
          }
        }
      } else if (directRscPackages.includes(pkgName)) {
        // Direct RSC frameworks - always vulnerable if in version range
        if (isVersionVulnerable(pkgName, version)) {
          result.vulnerable = true;
          result.packages.push({
            name: pkgName,
            version: version,
            fixVersion: getFixVersion(pkgName)
          });
        }
      } else if (isVersionVulnerable(pkgName, version)) {
        // For React and react-server-dom-* packages
        // React 19.x is only vulnerable if Server Components are enabled
        if (pkgName === 'react' && isStatic) {
          // React 19 with static export - not vulnerable but should upgrade
          result.warnings.push(`React ${version} detected with static export (safe - no Server Components)`);
        } else if (!serverFunctions.found) {
          // No 'use server' directives found
          result.warnings.push(`${pkgName} ${version} detected, but no 'use server' directives found (likely safe). Note: dynamically imported Server Functions require manual review.`);
        } else {
          // React 19 with Server Functions - VULNERABLE
          result.vulnerable = true;
          result.packages.push({
            name: pkgName,
            version: version,
            fixVersion: getFixVersion(pkgName)
          });
          // Add info about which files have server functions
          if (serverFunctions.files.length > 0 && !result.serverFunctionFiles) {
            result.serverFunctionFiles = serverFunctions.files.slice(0, 5);
          }
        }
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

      // Show files with 'use server' directives
      if (result.serverFunctionFiles && result.serverFunctionFiles.length > 0) {
        output += `\n   ${COLORS.cyan}Server Functions found in:${COLORS.reset}\n`;
        result.serverFunctionFiles.forEach(file => {
          output += `   ${COLORS.dim}•${COLORS.reset} ${file}\n`;
        });
      }

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
  output += `${COLORS.dim}Related CVEs:${COLORS.reset} CVE-2025-55184 (DoS), CVE-2025-55183 (Source Exposure)\n`;
  output += `${COLORS.dim}Affected:${COLORS.reset} React, Next.js, react-router, waku, @parcel/rsc, expo\n\n`;
  output += `${COLORS.dim}References:${COLORS.reset}\n`;
  output += `  • https://react.dev/blog/2025/12/03/critical-security-vulnerability\n`;
  output += `  • https://nvd.nist.gov/vuln/detail/CVE-2025-55182\n`;
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
