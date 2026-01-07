#!/usr/bin/env python3
"""
SecureNet Toolkit - Network Security Automation Suite
Author: Francis (theepreacher-ai)
Version: 1.0.0
License: MIT
"""

import argparse
import sys
from typing import Optional
from modules import port_scanner, network_mapper, dns_enum, ssl_analyzer, http_analyzer
from utils import logger, reporter, helpers

__version__ = "1.0.0"

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║              SecureNet Toolkit v{}                        ║
║        Network Security Automation Suite                     ║
╚══════════════════════════════════════════════════════════════╝
""".format(__version__)


class SecureNetToolkit:
    """Main class for SecureNet Toolkit"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.logger = logger.setup_logger(verbose)
        
    def run_port_scan(self, target: str, port_range: str = "1-1000", 
                     detect_services: bool = False) -> dict:
        """Execute port scanning module"""
        self.logger.info(f"Starting port scan on {target}")
        
        try:
            scanner = port_scanner.PortScanner(target, port_range, detect_services)
            results = scanner.scan()
            
            self.logger.info(f"Scan completed. Found {len(results['open_ports'])} open ports")
            return results
            
        except Exception as e:
            self.logger.error(f"Port scan failed: {str(e)}")
            return {}
    
    def run_network_discovery(self, network: str) -> dict:
        """Execute network discovery module"""
        self.logger.info(f"Starting network discovery on {network}")
        
        try:
            mapper = network_mapper.NetworkMapper(network)
            results = mapper.discover_hosts()
            
            self.logger.info(f"Discovery completed. Found {len(results['hosts'])} hosts")
            return results
            
        except Exception as e:
            self.logger.error(f"Network discovery failed: {str(e)}")
            return {}
    
    def run_dns_enum(self, domain: str, wordlist: Optional[str] = None) -> dict:
        """Execute DNS enumeration module"""
        self.logger.info(f"Starting DNS enumeration on {domain}")
        
        try:
            enumerator = dns_enum.DNSEnumerator(domain, wordlist)
            results = enumerator.enumerate()
            
            self.logger.info(f"Enumeration completed. Found {len(results['subdomains'])} subdomains")
            return results
            
        except Exception as e:
            self.logger.error(f"DNS enumeration failed: {str(e)}")
            return {}
    
    def run_ssl_check(self, target: str, check_expiry: bool = True) -> dict:
        """Execute SSL/TLS analysis module"""
        self.logger.info(f"Starting SSL/TLS analysis on {target}")
        
        try:
            analyzer = ssl_analyzer.SSLAnalyzer(target, check_expiry)
            results = analyzer.analyze()
            
            self.logger.info("SSL/TLS analysis completed")
            return results
            
        except Exception as e:
            self.logger.error(f"SSL/TLS analysis failed: {str(e)}")
            return {}
    
    def run_http_headers_check(self, url: str) -> dict:
        """Execute HTTP security headers analysis"""
        self.logger.info(f"Starting HTTP headers analysis on {url}")
        
        try:
            analyzer = http_analyzer.HTTPAnalyzer(url)
            results = analyzer.analyze_headers()
            
            self.logger.info("HTTP headers analysis completed")
            return results
            
        except Exception as e:
            self.logger.error(f"HTTP headers analysis failed: {str(e)}")
            return {}


def display_menu():
    """Display interactive menu"""
    print("\n[1] Port Scanner")
    print("[2] Network Discovery")
    print("[3] DNS Enumeration")
    print("[4] SSL/TLS Analyzer")
    print("[5] HTTP Security Headers")
    print("[6] Generate Report")
    print("[7] Settings")
    print("[0] Exit\n")


def interactive_mode():
    """Run toolkit in interactive mode"""
    print(BANNER)
    toolkit = SecureNetToolkit(verbose=True)
    
    while True:
        display_menu()
        choice = input("Select an option: ").strip()
        
        if choice == "1":
            target = input("Enter target IP/hostname: ").strip()
            port_range = input("Port range (default 1-1000): ").strip() or "1-1000"
            detect = input("Detect services? (y/n): ").lower() == 'y'
            
            results = toolkit.run_port_scan(target, port_range, detect)
            if results:
                print(f"\n[+] Open ports: {results.get('open_ports', [])}")
                
        elif choice == "2":
            network = input("Enter network (e.g., 192.168.1.0/24): ").strip()
            results = toolkit.run_network_discovery(network)
            if results:
                print(f"\n[+] Active hosts: {results.get('hosts', [])}")
                
        elif choice == "3":
            domain = input("Enter domain: ").strip()
            wordlist = input("Wordlist path (optional): ").strip() or None
            results = toolkit.run_dns_enum(domain, wordlist)
            if results:
                print(f"\n[+] Subdomains found: {len(results.get('subdomains', []))}")
                
        elif choice == "4":
            target = input("Enter target domain: ").strip()
            results = toolkit.run_ssl_check(target)
            if results:
                print(f"\n[+] SSL/TLS Grade: {results.get('grade', 'N/A')}")
                
        elif choice == "5":
            url = input("Enter URL: ").strip()
            results = toolkit.run_http_headers_check(url)
            if results:
                print(f"\n[+] Security Score: {results.get('score', 'N/A')}/100")
                
        elif choice == "6":
            print("\n[+] Report generation functionality")
            # Implement report generation
            
        elif choice == "7":
            print("\n[+] Settings functionality")
            # Implement settings
            
        elif choice == "0":
            print("\n[+] Exiting SecureNet Toolkit. Stay secure!")
            sys.exit(0)
            
        else:
            print("\n[-] Invalid option. Please try again.")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="SecureNet Toolkit - Network Security Automation Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    # Module-specific arguments
    parser.add_argument('--scan-ports', metavar='TARGET', help='Run port scanner on target')
    parser.add_argument('--port-range', default='1-1000', help='Port range to scan')
    parser.add_argument('--detect-services', action='store_true', help='Detect services on open ports')
    
    parser.add_argument('--discover-hosts', metavar='NETWORK', help='Discover hosts on network')
    parser.add_argument('--dns-enum', metavar='DOMAIN', help='Enumerate DNS records for domain')
    parser.add_argument('--wordlist', metavar='FILE', help='Wordlist for DNS enumeration')
    
    parser.add_argument('--ssl-check', metavar='TARGET', help='Analyze SSL/TLS configuration')
    parser.add_argument('--cert-expiry', action='store_true', help='Check certificate expiry')
    
    parser.add_argument('--http-headers', metavar='URL', help='Analyze HTTP security headers')
    parser.add_argument('--report', choices=['json', 'csv', 'html'], help='Generate report format')
    
    args = parser.parse_args()
    
    # If no arguments, run interactive mode
    if len(sys.argv) == 1:
        interactive_mode()
        return
    
    # Initialize toolkit
    toolkit = SecureNetToolkit(verbose=args.verbose)
    
    # Execute modules based on arguments
    results = {}
    
    if args.scan_ports:
        results = toolkit.run_port_scan(args.scan_ports, args.port_range, args.detect_services)
        
    elif args.discover_hosts:
        results = toolkit.run_network_discovery(args.discover_hosts)
        
    elif args.dns_enum:
        results = toolkit.run_dns_enum(args.dns_enum, args.wordlist)
        
    elif args.ssl_check:
        results = toolkit.run_ssl_check(args.ssl_check, args.cert_expiry)
        
    elif args.http_headers:
        results = toolkit.run_http_headers_check(args.http_headers)
    
    # Generate report if requested
    if results and args.report:
        report_gen = reporter.ReportGenerator(results, args.report)
        report_path = report_gen.generate()
        print(f"\n[+] Report saved to: {report_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {str(e)}")
        sys.exit(1)
