#!/usr/bin/env bash

###############################################################################
# CVE-2025-55182 Scanner (React2Shell)
# Detects React Server Components RCE vulnerability
#
# Requirements: bash, jq (for JSON parsing)
# CVSS: 10.0 (CRITICAL)
###############################################################################

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# Configuration
CVE_ID="CVE-2025-55182"
CVE_NAME="React2Shell"
CVSS_SCORE="10.0"
SEVERITY="CRITICAL"

# Vulnerability data
VULNERABLE_REACT_VERSIONS=("19.0.0" "19.1.0" "19.1.1" "19.2.0")
PATCHED_REACT_VERSION="19.2.1"

# Next.js vulnerable version ranges (min-max pairs)
NEXTJS_VULN_RANGES=(
    "14.0.0:14.2.34"
    "14.3.0-canary.0:14.3.0-canary.87"
    "15.0.0:15.0.6"
    "15.1.0:15.1.8"
    "15.2.0:15.2.5"
    "15.3.0:15.3.5"
    "15.4.0:15.4.7"
    "15.5.0:15.5.6"
    "16.0.0:16.0.9"
)

# Additional affected frameworks (per React official advisory)
VULN_REACT_ROUTER_VERSIONS=("7.0.0" "7.0.1" "7.0.2" "7.1.0" "7.1.1" "7.1.2" "7.1.3")
PATCHED_REACT_ROUTER_VERSION="7.1.4"

VULN_WAKU_VERSIONS=("0.21.0" "0.21.1" "0.21.2" "0.21.3" "0.21.4" "0.21.5")
PATCHED_WAKU_VERSION="0.21.6"

VULN_PARCEL_RSC_VERSIONS=("2.12.0" "2.13.0" "2.13.1" "2.13.2")
PATCHED_PARCEL_RSC_VERSION="2.13.3"

VULN_VITE_RSC_VERSIONS=("0.1.0" "0.1.1" "0.1.2" "0.2.0")
PATCHED_VITE_RSC_VERSION="0.2.1"

VULN_RWSDK_VERSIONS=("0.1.0" "0.2.0" "0.3.0" "0.4.0")
PATCHED_RWSDK_VERSION="0.4.1"

# Expo vulnerable version ranges
EXPO_VULN_RANGES=(
    "52.0.0:52.0.9"
)
PATCHED_EXPO_VERSION="52.0.10"

# Global counters
TOTAL_PROJECTS=0
VULNERABLE_PROJECTS=0
SCAN_PATH=""
RECURSIVE=false
JSON_OUTPUT=false
VERBOSE=false
CI_MODE=false

# Results arrays
declare -a RESULTS=()
declare -a WARNINGS=()

###############################################################################
# Helper Functions
###############################################################################

print_help() {
    cat << EOF

${BOLD}CVE-2025-55182 Scanner${RESET}
Detects React2Shell vulnerability in React Server Components

${BOLD}Usage:${RESET}
  ./scan.sh [path] [options]

${BOLD}Options:${RESET}
  -r, --recursive    Scan all subdirectories for Node.js projects
  -v, --verbose      Show detailed output
  --json             Output results as JSON
  --ci               Exit with code 1 if vulnerabilities found (for CI/CD)
  -h, --help         Show this help message

${BOLD}Examples:${RESET}
  ./scan.sh                       # Scan current directory
  ./scan.sh /path/to/project      # Scan specific project
  ./scan.sh -r                    # Scan current directory recursively
  ./scan.sh /path -r --json       # Recursive scan with JSON output
  ./scan.sh --ci                  # CI/CD mode (exits with code 1 if vulnerable)

${BOLD}Requirements:${RESET}
  - bash 4.0+
  - jq (for JSON parsing)

${BOLD}Exit Codes:${RESET}
  0 - No vulnerabilities found
  1 - Vulnerabilities found (with --ci flag)
  2 - Scan error

EOF
}

check_requirements() {
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}Error: jq is required but not installed${RESET}"
        echo "Install with: brew install jq (macOS) or apt-get install jq (Linux)"
        exit 2
    fi
}

# Version comparison function
version_compare() {
    local ver1=$1
    local ver2=$2

    # Remove leading v and special characters
    ver1=$(echo "$ver1" | sed 's/^[^0-9]*//')
    ver2=$(echo "$ver2" | sed 's/^[^0-9]*//')

    # Split versions
    IFS='.' read -ra V1 <<< "$ver1"
    IFS='.' read -ra V2 <<< "$ver2"

    # Compare major, minor, patch
    for i in 0 1 2; do
        local v1_part=${V1[$i]:-0}
        local v2_part=${V2[$i]:-0}

        # Remove non-numeric suffixes
        v1_part=$(echo "$v1_part" | grep -oE '^[0-9]+')
        v2_part=$(echo "$v2_part" | grep -oE '^[0-9]+')

        if [[ $v1_part -gt $v2_part ]]; then
            echo "1"
            return
        elif [[ $v1_part -lt $v2_part ]]; then
            echo "-1"
            return
        fi
    done

    echo "0"
}

# Check if React version is vulnerable
is_react_vulnerable() {
    local version=$1
    version=$(echo "$version" | sed 's/^[\^~>=<]*//')

    for vuln_ver in "${VULNERABLE_REACT_VERSIONS[@]}"; do
        if [[ "$version" == "$vuln_ver" ]]; then
            return 0
        fi
    done
    return 1
}

# Check if Next.js version is vulnerable
is_nextjs_vulnerable() {
    local version=$1
    version=$(echo "$version" | sed 's/^[\^~>=<]*//')

    # Check against each vulnerable range
    for range in "${NEXTJS_VULN_RANGES[@]}"; do
        local min_ver=$(echo "$range" | cut -d':' -f1)
        local max_ver=$(echo "$range" | cut -d':' -f2)

        if [[ $(version_compare "$version" "$min_ver") -ge 0 ]] && \
           [[ $(version_compare "$version" "$max_ver") -le 0 ]]; then
            return 0
        fi
    done

    return 1
}

# Get package manager
detect_package_manager() {
    local project_path=$1

    if [[ -f "$project_path/yarn.lock" ]]; then
        echo "yarn"
    elif [[ -f "$project_path/pnpm-lock.yaml" ]]; then
        echo "pnpm"
    else
        echo "npm"
    fi
}

# Get fix version for Next.js based on current version
get_nextjs_fix_version() {
    local version=$1
    version=$(echo "$version" | sed 's/^[\^~>=<]*//')
    local major_minor=$(echo "$version" | grep -oE '^[0-9]+\.[0-9]+')

    # Return appropriate patched version
    case "$major_minor" in
        "14.0"|"14.1"|"14.2") echo "14.2.35" ;;
        "14.3") echo "14.3.0-canary.88" ;;
        "15.0") echo "15.0.7" ;;
        "15.1") echo "15.1.9" ;;
        "15.2") echo "15.2.6" ;;
        "15.3") echo "15.3.6" ;;
        "15.4") echo "15.4.8" ;;
        "15.5") echo "15.5.7" ;;
        "16.0") echo "16.0.10" ;;
        *) echo "16.0.10" ;; # Default to latest
    esac
}

# Check if a version is in a simple list of versions
is_version_in_list() {
    local version=$1
    shift
    local versions=("$@")
    version=$(echo "$version" | sed 's/^[\^~>=<]*//')

    for vuln_ver in "${versions[@]}"; do
        if [[ "$version" == "$vuln_ver" ]]; then
            return 0
        fi
    done
    return 1
}

# Check if Expo version is vulnerable
is_expo_vulnerable() {
    local version=$1
    version=$(echo "$version" | sed 's/^[\^~>=<]*//')

    for range in "${EXPO_VULN_RANGES[@]}"; do
        local min_ver=$(echo "$range" | cut -d':' -f1)
        local max_ver=$(echo "$range" | cut -d':' -f2)

        if [[ $(version_compare "$version" "$min_ver") -ge 0 ]] && \
           [[ $(version_compare "$version" "$max_ver") -le 0 ]]; then
            return 0
        fi
    done

    return 1
}

# Get React major version
get_react_major_version() {
    local version=$1
    version=$(echo "$version" | sed 's/^[\^~>=<]*//')
    echo "$version" | grep -oE '^[0-9]+' | head -1
}

# Check if project uses static export
is_static_export() {
    local project_path=$1

    for config_file in "next.config.js" "next.config.mjs" "next.config.ts" "next.config.cjs"; do
        local config_path="$project_path/$config_file"
        if [[ -f "$config_path" ]]; then
            if grep -q "output: ['\"]export['\"]" "$config_path"; then
                return 0
            fi
        fi
    done
    return 1
}

###############################################################################
# Scanning Functions
###############################################################################

scan_project() {
    local project_path=$1
    local package_json="$project_path/package.json"

    if [[ ! -f "$package_json" ]]; then
        return
    fi

    ((TOTAL_PROJECTS++))

    local vulnerable=false
    local vulnerable_packages=()
    local warnings=()
    local package_manager=$(detect_package_manager "$project_path")

    # Get React version and major version
    local react_version=$(jq -r '.dependencies.react // .devDependencies.react // "null"' "$package_json")
    local react_major=$(get_react_major_version "$react_version")

    # Check if static export
    local is_static=false
    if is_static_export "$project_path"; then
        is_static=true
    fi

    # Check React versions
    if [[ "$react_version" != "null" ]] && is_react_vulnerable "$react_version"; then
        # React 19.x is only vulnerable if Server Components are enabled
        if [[ "$is_static" == true ]]; then
            # React 19 with static export - not vulnerable but should upgrade
            warnings+=("React $react_version detected with static export (safe - no Server Components)")
        else
            # React 19 without static export - vulnerable
            vulnerable=true
            vulnerable_packages+=("react:$react_version:$PATCHED_REACT_VERSION")
        fi
    fi

    # Check react-server-dom packages (always vulnerable - these ARE Server Components)
    for pkg in "react-server-dom-webpack" "react-server-dom-parcel" "react-server-dom-turbopack"; do
        local pkg_version=$(jq -r ".dependencies.\"$pkg\" // .devDependencies.\"$pkg\" // \"null\"" "$package_json")
        if [[ "$pkg_version" != "null" ]] && is_react_vulnerable "$pkg_version"; then
            vulnerable=true
            vulnerable_packages+=("$pkg:$pkg_version:$PATCHED_REACT_VERSION")
        fi
    done

    # Check Next.js - only vulnerable if React 19 is present
    local next_version=$(jq -r '.dependencies.next // .devDependencies.next // "null"' "$package_json")
    if [[ "$next_version" != "null" ]] && is_nextjs_vulnerable "$next_version"; then
        # Next.js is in vulnerable range, but check React version
        if [[ "$react_major" != "19" ]]; then
            warnings+=("Next.js $next_version is in vulnerable range, but using React $react_major (safe - only React 19 affected)")
        elif [[ "$is_static" == true ]]; then
            warnings+=("Next.js $next_version with React 19 detected, but using static export (likely safe - no Server Components)")
        else
            # Both React 19 and Server Components likely present
            vulnerable=true
            local fix_version=$(get_nextjs_fix_version "$next_version")
            vulnerable_packages+=("next:$next_version:$fix_version")
        fi
    fi

    # Check Expo - only vulnerable if React 19 is present
    local expo_version=$(jq -r '.dependencies.expo // .devDependencies.expo // "null"' "$package_json")
    if [[ "$expo_version" != "null" ]] && is_expo_vulnerable "$expo_version"; then
        if [[ "$react_major" != "19" ]]; then
            warnings+=("expo $expo_version is in vulnerable range, but using React $react_major (safe - only React 19 affected)")
        else
            vulnerable=true
            vulnerable_packages+=("expo:$expo_version:$PATCHED_EXPO_VERSION")
        fi
    fi

    # Check react-router (direct RSC framework - always vulnerable if in range)
    local react_router_version=$(jq -r '.dependencies."react-router" // .devDependencies."react-router" // "null"' "$package_json")
    if [[ "$react_router_version" != "null" ]] && is_version_in_list "$react_router_version" "${VULN_REACT_ROUTER_VERSIONS[@]}"; then
        vulnerable=true
        vulnerable_packages+=("react-router:$react_router_version:$PATCHED_REACT_ROUTER_VERSION")
    fi

    # Check waku
    local waku_version=$(jq -r '.dependencies.waku // .devDependencies.waku // "null"' "$package_json")
    if [[ "$waku_version" != "null" ]] && is_version_in_list "$waku_version" "${VULN_WAKU_VERSIONS[@]}"; then
        vulnerable=true
        vulnerable_packages+=("waku:$waku_version:$PATCHED_WAKU_VERSION")
    fi

    # Check @parcel/rsc
    local parcel_rsc_version=$(jq -r '.dependencies."@parcel/rsc" // .devDependencies."@parcel/rsc" // "null"' "$package_json")
    if [[ "$parcel_rsc_version" != "null" ]] && is_version_in_list "$parcel_rsc_version" "${VULN_PARCEL_RSC_VERSIONS[@]}"; then
        vulnerable=true
        vulnerable_packages+=("@parcel/rsc:$parcel_rsc_version:$PATCHED_PARCEL_RSC_VERSION")
    fi

    # Check @vitejs/plugin-rsc
    local vite_rsc_version=$(jq -r '.dependencies."@vitejs/plugin-rsc" // .devDependencies."@vitejs/plugin-rsc" // "null"' "$package_json")
    if [[ "$vite_rsc_version" != "null" ]] && is_version_in_list "$vite_rsc_version" "${VULN_VITE_RSC_VERSIONS[@]}"; then
        vulnerable=true
        vulnerable_packages+=("@vitejs/plugin-rsc:$vite_rsc_version:$PATCHED_VITE_RSC_VERSION")
    fi

    # Check rwsdk (Redwood SDK)
    local rwsdk_version=$(jq -r '.dependencies.rwsdk // .devDependencies.rwsdk // "null"' "$package_json")
    if [[ "$rwsdk_version" != "null" ]] && is_version_in_list "$rwsdk_version" "${VULN_RWSDK_VERSIONS[@]}"; then
        vulnerable=true
        vulnerable_packages+=("rwsdk:$rwsdk_version:$PATCHED_RWSDK_VERSION")
    fi

    # Store results
    if [[ "$vulnerable" == true ]]; then
        ((VULNERABLE_PROJECTS++))

        # Generate fix commands
        local upgrades=""
        for pkg_info in "${vulnerable_packages[@]}"; do
            IFS=':' read -r pkg_name pkg_ver fix_ver <<< "$pkg_info"
            upgrades="$upgrades $pkg_name@$fix_ver"
        done

        local fix_cmd=""
        case "$package_manager" in
            yarn) fix_cmd="yarn upgrade$upgrades" ;;
            pnpm) fix_cmd="pnpm update$upgrades" ;;
            *) fix_cmd="npm install$upgrades" ;;
        esac

        # Store result
        local result="{\"path\":\"$project_path\",\"vulnerable\":true,\"packages\":["
        local first=true
        for pkg_info in "${vulnerable_packages[@]}"; do
            IFS=':' read -r pkg_name pkg_ver fix_ver <<< "$pkg_info"
            [[ "$first" == true ]] && first=false || result+=","
            result+="{\"name\":\"$pkg_name\",\"version\":\"$pkg_ver\",\"fixVersion\":\"$fix_ver\"}"
        done
        result+="],\"packageManager\":\"$package_manager\",\"fixCommand\":\"$fix_cmd\"}"

        RESULTS+=("$result")
    fi

    # Store warnings for projects with notes
    if [[ ${#warnings[@]} -gt 0 ]]; then
        local warning_entry="$project_path"
        for warning in "${warnings[@]}"; do
            warning_entry+="|$warning"
        done
        WARNINGS+=("$warning_entry")
    fi
}

find_projects() {
    local dir=$1
    local max_depth=${2:-3}
    local current_depth=${3:-0}

    if [[ $current_depth -gt $max_depth ]]; then
        return
    fi

    # Check if current directory has package.json
    if [[ -f "$dir/package.json" ]]; then
        scan_project "$dir"
    fi

    # Recurse into subdirectories
    if [[ "$RECURSIVE" == true ]]; then
        for entry in "$dir"/*; do
            if [[ -d "$entry" ]] && [[ ! "$(basename "$entry")" =~ ^\. ]] && [[ "$(basename "$entry")" != "node_modules" ]]; then
                find_projects "$entry" "$max_depth" $((current_depth + 1))
            fi
        done
    fi
}

###############################################################################
# Output Functions
###############################################################################

print_header() {
    cat << EOF

${CYAN}${BOLD}╔════════════════════════════════════════════════════════════╗${RESET}
${CYAN}${BOLD}║${RESET}  ${BOLD}CVE-2025-55182 Scanner (React2Shell)${RESET}                  ${CYAN}║${RESET}
${CYAN}╚════════════════════════════════════════════════════════════╝${RESET}

${DIM}Severity:${RESET} ${RED}${BOLD}CRITICAL${RESET} (CVSS 10.0)
${DIM}Description:${RESET} Unauthenticated RCE in React Server Components

EOF
}

print_summary() {
    local safe_projects=$((TOTAL_PROJECTS - VULNERABLE_PROJECTS))

    echo -e "${BOLD}Scan Summary:${RESET}"
    echo -e "  Total projects: $TOTAL_PROJECTS"
    echo -e "  ${RED}Vulnerable: $VULNERABLE_PROJECTS${RESET}"
    echo -e "  ${GREEN}Safe: $safe_projects${RESET}"
    echo ""
}

print_vulnerable_projects() {
    if [[ $VULNERABLE_PROJECTS -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}✓ No vulnerable projects found${RESET}\n"
        return
    fi

    echo -e "${RED}${BOLD}⚠ VULNERABLE PROJECTS FOUND:${RESET}\n"

    local idx=1
    for result in "${RESULTS[@]}"; do
        local path=$(echo "$result" | jq -r '.path')
        local fix_cmd=$(echo "$result" | jq -r '.fixCommand')

        echo -e "${RED}$idx. $path${RESET}"

        # Print vulnerable packages
        local pkg_count=$(echo "$result" | jq '.packages | length')
        for ((i=0; i<pkg_count; i++)); do
            local pkg_name=$(echo "$result" | jq -r ".packages[$i].name")
            local pkg_ver=$(echo "$result" | jq -r ".packages[$i].version")
            local fix_ver=$(echo "$result" | jq -r ".packages[$i].fixVersion")
            echo -e "   └─ ${BOLD}$pkg_name${RESET} $pkg_ver ${RED}→${RESET} ${GREEN}$fix_ver${RESET}"
        done

        echo -e "\n   ${YELLOW}Fix command:${RESET}"
        echo -e "   ${DIM}\$${RESET} cd $path"
        echo -e "   ${DIM}\$${RESET} $fix_cmd"
        echo ""

        ((idx++))
    done
}

print_warnings() {
    if [[ ${#WARNINGS[@]} -eq 0 ]]; then
        return
    fi

    echo -e "${YELLOW}${BOLD}ℹ Projects with analysis notes:${RESET}\n"

    local idx=1
    for warning_entry in "${WARNINGS[@]}"; do
        IFS='|' read -ra PARTS <<< "$warning_entry"
        local path="${PARTS[0]}"
        echo -e "${DIM}$idx. $path${RESET}"

        for ((i=1; i<${#PARTS[@]}; i++)); do
            echo -e "   ${YELLOW}ℹ${RESET} ${PARTS[$i]}"
        done
        echo ""

        ((idx++))
    done
}

print_footer() {
    cat << EOF
${DIM}─────────────────────────────────────────────────────────────${RESET}
${DIM}Related CVEs:${RESET} CVE-2025-55184 (DoS), CVE-2025-55183 (Source Exposure)
${DIM}Affected:${RESET} React, Next.js, react-router, waku, @parcel/rsc, expo

${DIM}References:${RESET}
  • https://react.dev/blog/2025/12/03/critical-security-vulnerability
  • https://nvd.nist.gov/vuln/detail/CVE-2025-55182
  • https://github.com/facebook/react/security/advisories

EOF
}

output_json() {
    local results_json="["
    local first=true
    for result in "${RESULTS[@]}"; do
        [[ "$first" == true ]] && first=false || results_json+=","
        results_json+="$result"
    done
    results_json+="]"

    cat << EOF
{
  "vulnerability": "$CVE_ID",
  "name": "$CVE_NAME",
  "severity": "$SEVERITY",
  "cvss": $CVSS_SCORE,
  "scanned": $TOTAL_PROJECTS,
  "vulnerable": $VULNERABLE_PROJECTS,
  "results": $results_json
}
EOF
}

###############################################################################
# Main
###############################################################################

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                print_help
                exit 0
                ;;
            -r|--recursive)
                RECURSIVE=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --json)
                JSON_OUTPUT=true
                shift
                ;;
            --ci)
                CI_MODE=true
                shift
                ;;
            -*)
                echo "Unknown option: $1"
                print_help
                exit 2
                ;;
            *)
                SCAN_PATH="$1"
                shift
                ;;
        esac
    done

    # Default to current directory
    [[ -z "$SCAN_PATH" ]] && SCAN_PATH="."

    # Check requirements
    check_requirements

    # Validate scan path
    if [[ ! -d "$SCAN_PATH" ]]; then
        echo -e "${RED}Error: Directory not found: $SCAN_PATH${RESET}"
        exit 2
    fi

    # Run scan
    find_projects "$SCAN_PATH"

    # Output results
    if [[ "$JSON_OUTPUT" == true ]]; then
        output_json
    else
        print_header
        print_summary
        print_vulnerable_projects
        print_warnings
        print_footer
    fi

    # Exit with appropriate code for CI/CD
    if [[ "$CI_MODE" == true ]] && [[ $VULNERABLE_PROJECTS -gt 0 ]]; then
        exit 1
    fi
}

# Run main
main "$@"
