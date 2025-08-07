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

## Prepare your Environment

### Download repository

```
git clone https://github.com/XoTourLiff/Forti-audit.git
```
Note: There is one JSON example file in each Python script directory.

### Download JSON files
#### Policies :

<img width="1904" height="496" alt="image" src="https://github.com/user-attachments/assets/9797d3c9-8209-492f-8789-a8ff76b1d4b6" />

<img width="400" height="169" alt="image" src="https://github.com/user-attachments/assets/88e6be38-d219-49c5-9709-ec8ff84503ef" />


⚠️ Place the JSON the same directory of PolicyCheck.py .
#### Objects :

<img width="1812" height="343" alt="image" src="https://github.com/user-attachments/assets/45e69513-6feb-4a12-a8c6-b9b8528a4a4e" />

<img width="339" height="382" alt="image" src="https://github.com/user-attachments/assets/d6236e34-d7e9-46e7-9889-919f592af564" />

<img width="380" height="108" alt="image" src="https://github.com/user-attachments/assets/b158e13d-c7bb-4ddc-a96e-6b47916a185d" />

⚠️ Place the JSON the same directory of ObjectsCheck.py .


## Usage

Both scripts require JSON files in their same directory:
- `policycheck-forti.json` for policy analysis
- `objectcheck.json` for connectivity testing

Results are saved as detailed JSON reports for further analysis and remediation planning.

[demonstration.webm](https://github.com/user-attachments/assets/b0604fde-4826-4960-859a-6b1e77f18a16)

**Then you can just sit back and check out the results.**

<img width="1205" height="402" alt="image" src="https://github.com/user-attachments/assets/02197b1b-e3d2-4c03-8131-624d420d0b7e" />





