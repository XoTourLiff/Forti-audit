#!/usr/bin/env python3

# Make sure JSON file is in the same directory as this script and named 'policycheck-forti.json'

import json
from collections import defaultdict, Counter
from datetime import datetime
import re
import time

class FortigateAuditor:

    def __init__(self, json_file_path=None, json_data=None):
        # Initialization of the auditor with JSON data
        if json_data:
           self.data = json_data
    
        # Adaptation for real Fortigate format
        if isinstance(self.data, list):
            # If data is directly a list of policies
            self.policies = self.data
        else:
            # If it's an object with a structure
            self.policies = self.data.get('policies', self.data.get('Policy', []))
            
        if not self.policies:
            print("ERROR: No policies found in JSON")
            print("STOP - Invalid or empty JSON structure")
            return None
            
        self.results = {}
    
    def _safe_string(self, value):
        """Safely converts a value to string"""
        if isinstance(value, list):
            return ', '.join(str(v) for v in value)
        return str(value) if value else ''
    
    def _extract_bytes_value(self, bytes_str):
        """Extract numeric value from bytes"""
        if not bytes_str or bytes_str == "0 B":
            return 0
        # Extract numbers from format "15420 MB", "5 KB", etc.
        match = re.search(r'(\d+(?:\.\d+)?)', str(bytes_str))
        return float(match.group(1)) if match else 0
    
    def audit_unused_rules(self):
        """Identify unused rules (Bytes = 0 B)"""
        unused_rules = []
        for i, policy in enumerate(self.policies):
            bytes_value = self._extract_bytes_value(policy.get('Bytes', '0 B'))
            action = self._safe_string(policy.get('Action', '')).upper()
            
            if bytes_value == 0 and action == 'ACCEPT':
                unused_rules.append({
                    'id': i + 1,
                    'name': self._safe_string(policy.get('Policy', f'Rule_{i+1}')),
                    'action': action,
                    'bytes': self._safe_string(policy.get('Bytes', '0 B')),
                    'source': self._safe_string(policy.get('Source', '')),
                    'destination': self._safe_string(policy.get('Destination', '')),
                    'service': self._safe_string(policy.get('Service', ''))
                })
        
        self.results['unused_rules'] = unused_rules
        return unused_rules
    
    def audit_permissive_rules(self):
        """Identify overly permissive rules with ALL ALL separation"""
        all_all_rules = []  # Critical: both source and destination are ALL
        single_all_rules = []  # High: only one of source/destination is ALL
        
        for i, policy in enumerate(self.policies):
            source = self._safe_string(policy.get('Source', '')).lower()
            destination = self._safe_string(policy.get('Destination', '')).lower() 
            service = self._safe_string(policy.get('Service', '')).lower()
            action = self._safe_string(policy.get('Action', '')).upper()
            
            src_any = source in ['all', 'any', ''] or 'any' in source or 'all' in source
            dst_any = destination in ['all', 'any', ''] or 'any' in destination or 'all' in destination
            srv_any = service in ['all', 'any', ''] or 'all' in service or 'any' in service
            
            if action == 'ACCEPT' and (src_any or dst_any or srv_any):
                rule_info = {
                    'id': i + 1,
                    'name': self._safe_string(policy.get('Policy', f'Rule_{i+1}')),
                    'source': self._safe_string(policy.get('Source', '')),
                    'destination': self._safe_string(policy.get('Destination', '')),
                    'service': self._safe_string(policy.get('Service', '')),
                    'src_any': src_any,
                    'dst_any': dst_any, 
                    'srv_any': srv_any
                }
                
                # Separate ALL ALL (critical) from single ALL (high)
                if src_any and dst_any and srv_any:
                    rule_info['risk_level'] = 'CRITICAL'
                    all_all_rules.append(rule_info)
                else:
                    rule_info['risk_level'] = 'HIGH'
                    single_all_rules.append(rule_info)
        
        self.results['all_all_rules'] = all_all_rules
        self.results['single_all_rules'] = single_all_rules
        return {'all_all_rules': all_all_rules, 'single_all_rules': single_all_rules}
    
    def audit_duplicate_rules(self):
        """Identify duplicate rules"""
        rule_signatures = defaultdict(list)
        
        for i, policy in enumerate(self.policies):
            action = self._safe_string(policy.get('Action', '')).upper()
            if action != 'ACCEPT':
                continue
                
            # Create unique signature for rule
            source = self._safe_string(policy.get('Source', '')).strip()
            destination = self._safe_string(policy.get('Destination', '')).strip()
            service = self._safe_string(policy.get('Service', '')).strip()
            interface_pair = self._safe_string(policy.get('Interface Pair', '')).strip()
            
            signature = f"{source}|{destination}|{service}|{interface_pair}|{action}"
            rule_signatures[signature].append({
                'id': i + 1,
                'name': self._safe_string(policy.get('Policy', f'Rule_{i+1}')),
                'bytes': self._safe_string(policy.get('Bytes', '0 B'))
            })
        
        # Convert to JSON serializable format
        duplicates = []
        for signature, rules in rule_signatures.items():
            if len(rules) > 1:
                duplicates.append({
                    'signature': signature,
                    'rules': rules,
                    'count': len(rules)
                })
        
        self.results['duplicate_rules'] = duplicates
        return duplicates
    
    def audit_logging(self):
        """Analyze log configuration"""
        no_logging = []
        with_logging = []
        
        for i, policy in enumerate(self.policies):
            log_setting = self._safe_string(policy.get('Log', '')).strip().lower()
            
            rule_info = {
                'id': i + 1,
                'name': self._safe_string(policy.get('Policy', f'Rule_{i+1}')),
                'log_setting': self._safe_string(policy.get('Log', '')),
                'action': self._safe_string(policy.get('Action', '')),
                'bytes': self._safe_string(policy.get('Bytes', '0 B'))
            }
            
            if log_setting in ['', 'none', 'disable']:
                no_logging.append(rule_info)
            else:
                with_logging.append(rule_info)
        
        self.results['logging'] = {
            'no_logging': no_logging,
            'with_logging': with_logging
        }
        return self.results['logging']
    
    def generate_json_report(self, output_file='firewall_audit_report.json'):
        """Generate a complete JSON audit report"""
        time.sleep(1)
        print(f"Generating JSON audit report...")
        
        # Execute all audits
        self.audit_unused_rules()
        permissive_results = self.audit_permissive_rules()
        self.audit_duplicate_rules()
        self.audit_logging()
        
        # Define total as the number of policies
        total = len(self.policies)
        
        # Structure of the report
        report = {
            "audit_info": {
                "date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "total_rules": total,
            },
            "summary": {
                "total_rules_analyzed": total,

                "all_all_rules_count": len(self.results['all_all_rules']),
                "all_all_rules_percent": f"{round(len(self.results['all_all_rules']) / total * 100, 2) if total > 0 else 0}%",

                "single_all_rules_count": len(self.results['single_all_rules']),
                "single_all_rules_percent": f"{round(len(self.results['single_all_rules']) / total * 100, 2) if total > 0 else 0}%",

                "duplicate_groups_count": len(self.results['duplicate_rules']),
                "duplicate_groups_percent": f"{round(len(self.results['duplicate_rules']) / total * 100, 2) if total > 0 else 0}%",

                "unused_rules_count": len(self.results['unused_rules']),
                "unused_rules_percent": f"{round(len(self.results['unused_rules']) / total * 100, 2) if total > 0 else 0}%",
                
                "rules_without_logging": len(self.results['logging']['no_logging']),
                "rules_without_logging_percent": f"{round(len(self.results['logging']['no_logging']) / total * 100, 2) if total > 0 else 0}%"
            },
            "detailed_results": {
                "unused_rules": self.results['unused_rules'],
                "all_all_rules": self.results['all_all_rules'],
                "single_all_rules": self.results['single_all_rules'],
                "duplicate_rules": self.results['duplicate_rules'],
                "without_logging": self.results['logging']['no_logging']
            },
            "recommendations": self._generate_recommendations()
        }

        # Save the JSON report
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"Audit saved in: {output_file}")
            return output_file
        except Exception as e:
            print(f"Error saving audit report: {e}")
            return None

    def _generate_recommendations(self):
        """Generate recommendations based on the audit"""
        recommendations = []
        
        if self.results.get('unused_rules'):
            recommendations.append({
                "priority": "HIGH",
                "category": "Cleanup",
                "issue": "Unused ACCEPT rules",
                "count": len(self.results['unused_rules']),
                "action": "Remove or disable these rules to reduce attack surface"
            })
        
        if self.results.get('all_all_rules'):
            recommendations.append({
                "priority": "CRITICAL",
                "category": "Security",
                "issue": "Rules with ALL ALL configuration",
                "count": len(self.results['all_all_rules']),
                "action": "URGENT: Restrict source, destination and services - these rules allow everything"
            })
        
        if self.results.get('single_all_rules'):
            recommendations.append({
                "priority": "HIGH",
                "category": "Security",
                "issue": "Rules with single ALL configuration",
                "count": len(self.results['single_all_rules']),
                "action": "Restrict sources, destinations and services according to least privilege principle"
            })
        
        if self.results.get('duplicate_rules'):
            recommendations.append({
                "priority": "MEDIUM",
                "category": "Optimization",
                "issue": "Duplicate rules",
                "count": len(self.results['duplicate_rules']),
                "action": "Consolidate or remove redundant rules"
            })
        
        no_logging = len(self.results.get('logging', {}).get('no_logging', []))
        if no_logging > 0:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "Monitoring",
                "issue": "Rules without logging",
                "count": no_logging,
                "action": "Enable logging for traceability and monitoring"
            })
        
        return recommendations

def load_json_from_file():
    """JSON local loading function"""
    try:
        with open('policycheck-forti.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            time.sleep(2)
        print(f"Policycheck-forti.json file loaded from local disk!")
        return data
    except FileNotFoundError:
        time.sleep(2)
        print("Error: File 'policycheck-forti.json' not found")
        time.sleep(2)
        print("Please put the file in the same directory as this script.")
        time.sleep(1)
        print("Make sure the file is named 'policycheck-forti.json'.")
        time.sleep(1)
        return None
    except Exception as e:
        print(f"ERROR: Unable to read Policycheck-forti.json")
        print(f"Details: {e}")
        return None

def main():
    """Main function to run the auditor"""
    print("\n" + "-" * 35)
    print("🛡️  FortiGate Firewall Auditor 🛡️")
    print("-" * 35, "\n")
    time.sleep(2)
    print(r"""
__________      .__  .__              _________ .__                   __    
\______   \____ |  | |__| ____ ___.__.\_   ___ \|  |__   ____   ____ |  | __
 |     ___/  _ \|  | |  |/ ___<   |  |/    \  \/|  |  \_/ __ \_/ ___\|  |/ /
 |    |  (  <_> )  |_|  \  \___\___  |\     \___|   Y  \  ___/\  \___|    < 
 |____|   \____/|____/__|\___  > ____| \______  /___|  /\___  >\___  >__|_ \
                             \/\/             \/     \/     \/     \/     \/

Author: XoTourLiff          

""")
    
    # Try to load JSON from local file
    user_data = load_json_from_file()
    
    if not user_data:
        print("\n❗Fatal error: No JSON data or the JSON format is invalid. ❗​\n")
        return
    
    auditor = FortigateAuditor(json_data=user_data)
    if not auditor or not hasattr(auditor, 'policies'):
        print("Failed to initialize auditor: invalid or incomplete JSON data.")
        return
    time.sleep(2)   
    print("Performing analysis on your actual data...")
    
    # Generate JSON report
    output_file = auditor.generate_json_report('firewall_audit_report.json')
    
    if output_file:
        time.sleep(1)
        print(f"\n🕵️  Report generated successfully named: '{output_file}', Enjoy your audit!🕵️\n")
    else:
        print("FAILED to generate JSON report, please check the logs for errors.")

if __name__ == "__main__":
    main()
