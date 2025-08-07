#!/usr/bin/env python3

import json
import subprocess
import platform
import ipaddress
from datetime import datetime
import time

class ObjectsPingChecker:
    
    def __init__(self, json_file_path='objectcheck.json'):
        """Initialize the ping checker with JSON data from local file"""
        self.json_file = json_file_path
        self.objects_data = None
        self.results = {
            'failed_pings': [],
            'successful_count': 0,
            'total_tested': 0
        }
    
    def load_objects_json(self):
        """Load objects data from local JSON file"""
        try:
            with open(self.json_file, 'r', encoding='utf-8') as f:
                self.objects_data = json.load(f)
            print(f"Successfully loaded {self.json_file} from local directory!")
            return True
        except FileNotFoundError:
            time.sleep(2)
            print(f"Error: File '{self.json_file}' not found in current directory")
            time.sleep(1)
            print("Please ensure the file is in the same directory as this script.")
            time.sleep(1)
            return False
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON format in {self.json_file}")
            print(f"Details: {e}")
            return False
        except Exception as e:
            print(f"Error: Unable to read {self.json_file}")
            print(f"Details: {e}")
            return False
    
    def _extract_ip_from_cidr(self, ip_cidr):
        """Extract IP address from CIDR notation (e.g., '192.168.1.1/24' -> '192.168.1.1')"""
        try:
            # Handle CIDR notation
            if '/' in ip_cidr:
                ip_part = ip_cidr.split('/')[0]
                # Validate if it's a real IP address
                ip_obj = ipaddress.ip_address(ip_part)
                return ip_part
            return None
        except (ValueError, ipaddress.AddressValueError):
            return None
    
    def _ping_ip(self, ip_address):
        """Ping a single IP address and return True if successful, False otherwise"""
        try:
            # Determine ping command based on operating system
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", "3000", ip_address]
            else:
                cmd = ["ping", "-c", "1", "-W", "3", ip_address]
            
            # Execute ping command with timeout
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return False
    
    def ping_all_objects(self):
        """Ping all IP addresses found in objects and collect results"""
        if not self.objects_data:
            print("No objects data loaded. Please load JSON file first.")
            return False
        
        print("Starting ping test for all object IP addresses...")
        print("-" * 50)
        
        # Process each object in the JSON
        for obj in self.objects_data:
            name = obj.get('Name', ['Unknown'])[0] if obj.get('Name') else 'Unknown'
            ip_list = obj.get('IP', [])
            
            # Skip if no IP addresses found
            if not ip_list:
                continue
            
            # Test each IP in the object
            for ip_cidr in ip_list:
                ip_address = self._extract_ip_from_cidr(ip_cidr)
                
                # Skip invalid IPs
                if not ip_address:
                    continue
                
                print(f"Pinging {ip_address} ({name})...", end=" ")
                self.results['total_tested'] += 1
                
                # Perform ping test
                if self._ping_ip(ip_address):
                    print("✓ Success")
                    self.results['successful_count'] += 1
                else:
                    print("✗ Failed")
                    self.results['failed_pings'].append({
                        'name': name,
                        'ip_address': ip_address,
                        'original_cidr': ip_cidr
                    })
        
        print("-" * 50)
        print(f"Ping test completed!")
        print(f"Total IPs tested: {self.results['total_tested']}")
        print(f"Successful pings: {self.results['successful_count']}")
        print(f"Failed pings: {len(self.results['failed_pings'])}")
        
        return True
    
    def generate_ping_report(self, output_file='ping_results.json'):
        """Generate JSON report with ping results"""
        print(f"Generating ping report...")
        
        # Create comprehensive report structure
        report = {
            "ping_audit_info": {
                "date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "source_file": self.json_file,
                "total_objects_processed": len(self.objects_data) if self.objects_data else 0
            },
            "summary": {
                "total_ips_tested": self.results['total_tested'],
                "successful_pings": self.results['successful_count'],
                "failed_pings_count": len(self.results['failed_pings']),
                "success_rate_percent": round(
                    (self.results['successful_count'] / self.results['total_tested'] * 100) 
                    if self.results['total_tested'] > 0 else 0, 2
                )
            },
            "failed_pings": self.results['failed_pings'],
            "recommendations": self._generate_ping_recommendations()
        }
        
        # Save JSON report to file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"Ping report saved successfully: {output_file}")
            return output_file
        except Exception as e:
            print(f"Error saving ping report: {e}")
            return None
    
    def _generate_ping_recommendations(self):
        """Generate recommendations based on ping results"""
        recommendations = []
        
        failed_count = len(self.results['failed_pings'])
        
        if failed_count > 0:
            recommendations.append({
                "priority": "HIGH",
                "category": "Network Connectivity",
                "issue": "Unreachable IP addresses in objects",
                "count": failed_count,
                "action": "Verify network connectivity and update or remove unreachable object IPs"
            })
        
        if self.results['successful_count'] > 0:
            recommendations.append({
                "priority": "INFO",
                "category": "Network Status",
                "issue": "Reachable IP addresses confirmed",
                "count": self.results['successful_count'],
                "action": "These objects are properly configured and reachable"
            })
        
        return recommendations

def main():
    """Main function to execute the ping checker"""
    print("\n" + "=" * 40)
    print("🔎 FORTIGATE OBJECTS PING CHECKER 🔎")
    print("=" * 40)
    time.sleep(2)
    print(r'''


      ___.        __               __         .__                   __    
  ____\_ |__     |__| ____   _____/  |_  ____ |  |__   ____   ____ |  | __
 /  _ \| __ \    |  |/ __ \_/ ___\   __\/ ___\|  |  \_/ __ \_/ ___\|  |/ /
(  <_> ) \_\ \   |  \  ___/\  \___|  | \  \___|   Y  \  ___/\  \___|    < 
 \____/|___  /\__|  |\___  >\___  >__|  \___  >___|  /\___  >\___  >__|_ \
           \/\______|    \/     \/          \/     \/     \/     \/     \/

Author: XoTourLiff

          ''')
    
    # Initialize the ping checker
    checker = ObjectsPingChecker()
    
    # Load JSON data from local file
    if not checker.load_objects_json():
        print("\n⚠️  Failed to load objects data. Exiting...⚠️\n")
        time.sleep(2)
        return
    
    # Perform ping tests on all objects
    time.sleep(1)
    print("Starting network connectivity tests...")
    time.sleep(1)
    
    if not checker.ping_all_objects():
        print("Failed to complete ping tests. Exiting...")
        return
    
    # Generate and save ping report
    time.sleep(1)
    output_file = checker.generate_ping_report()
    
    if output_file:
        print(f"\n✓ Ping analysis completed successfully!")
        print(f"Results saved in: {output_file}")
        print("\nYou can now review the failed pings and network connectivity status.")
    else:
        print("\n✗ Failed to generate ping report.")

if __name__ == "__main__":
    main()
