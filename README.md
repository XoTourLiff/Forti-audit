# Forti-audit
Comprehensive automated auditing toolkit for FortiGate firewalls

## PolicyCheck Script
Advanced security policy analyzer that audits FortiGate firewall rules for security vulnerabilities and optimization opportunities:

**Security Analysis:**
- **Unused rules** - Identifies ACCEPT rules with zero bytes traffic (potential dead rules)
- **Critical permissive rules** - Detects ALL-ALL configurations (can be : source, destination, service)  
- **High-risk permissive rules** - Finds rules with single ALL configurations
- **Duplicate rules** - Locates redundant policy entries with identical configurations

**Compliance & Monitoring:**
- **Rules without logging** - Identifies policies missing proper audit trails
- **Detailed recommendations** - Provides prioritized security actions (CRITICAL/HIGH/MEDIUM)

**Output:** Comprehensive JSON report with statistics, detailed findings, and actionable recommendations

## ObjectsCheck Script  
Network connectivity validator for FortiGate address objects:

**Connectivity Testing:**
- **IP reachability verification** - Pings all IP addresses defined in FortiGate address objects
- **CIDR notation support** - Automatically extracts IPs from subnet definitions (192.168.1.0/24)
- **Real-time feedback** - Live ping status display during execution
- **Failed connectivity tracking** - Documents unreachable IPs with associated object names

**Network Health Assessment:**
- **Success rate calculation** - Overall network connectivity statistics  
- **Dead object identification** - Finds address objects pointing to unreachable resources

**Output:** JSON report with failed pings, object names, and network health summary

## Usage
Both scripts require JSON files in the same directory:
- `policycheck-forti.json` for policy analysis
- `objectscheck.json` for connectivity testing

Results are saved as detailed JSON reports for further analysis and remediation planning.
