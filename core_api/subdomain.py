import requests
import threading
import argparse
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import sys
import json
import time
from urllib.parse import urlparse
import ssl
import socket

class AdvancedSubdomainFinder:
    def __init__(self, domain, wordlist_file=None, threads=20, timeout=5):
        self.domain = domain
        self.wordlist_file = wordlist_file
        self.threads = threads
        self.timeout = timeout
        self.found_subdomains = set()
        self.results = {}
        self.lock = threading.Lock()
        
        # Common subdomains wordlist (fallback)
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'test', 'staging',
            'dev', 'api', 'admin', 'blog', 'shop', 'forum', 'support', 'help', 'docs'
        ]
    
    def dns_enumeration(self, subdomain):
        """Enhanced DNS enumeration with multiple record types"""
        full_domain = f"{subdomain}.{self.domain}"
        
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(full_domain, record_type)
                with self.lock:
                    if full_domain not in self.results:
                        self.results[full_domain] = {}
                    self.results[full_domain][record_type] = [str(rdata) for rdata in answers]
                    
                    if full_domain not in self.found_subdomains:
                        self.found_subdomains.add(full_domain)
                        print(f"✓ {full_domain} ({record_type})")
                        
            except:
                continue
    
    def certificate_transparency(self):
        """Search Certificate Transparency logs"""
        print("Searching Certificate Transparency logs...")
        urls = [
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names",
        ]
        
        for url in urls:
            try:
                response = requests.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    if "crt.sh" in url:
                        data = json.loads(response.text)
                        for cert in data:
                            names = cert.get('name_value', '').split('\n')
                            for name in names:
                                if self.domain in name and name not in self.found_subdomains:
                                    self.found_subdomains.add(name)
                                    print(f"✓ {name} (CT)")
                    elif "certspotter" in url:
                        data = response.json()
                        for cert in data:
                            for dns_name in cert.get('dns_names', []):
                                if self.domain in dns_name and dns_name not in self.found_subdomains:
                                    self.found_subdomains.add(dns_name)
                                    print(f"✓ {dns_name} (CT)")
            except Exception as e:
                continue
    
    def search_apis(self):
        """Search various security APIs"""
        print("Searching security APIs...")
        
        apis = {
            "alienvault": f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns",
            "threatcrowd": f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}",
            "virustotal": f"https://www.virustotal.com/vtapi/v2/domain/report?apikey=YOUR_API_KEY&domain={self.domain}",
        }
        
        for source, url in apis.items():
            try:
                if "virustotal" in url and "YOUR_API_KEY" in url:
                    continue  # Skip without API key
                    
                response = requests.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    data = response.json()
                    self.parse_api_data(data, source)
            except:
                continue
    
    def parse_api_data(self, data, source):
        """Parse data from various APIs"""
        if source == "alienvault":
            for record in data.get('passive_dns', []):
                hostname = record.get('hostname', '')
                if hostname and self.domain in hostname and hostname not in self.found_subdomains:
                    self.found_subdomains.add(hostname)
                    print(f"✓ {hostname} ({source})")
        
        elif source == "threatcrowd":
            for subdomain in data.get('subdomains', []):
                if subdomain and subdomain not in self.found_subdomains:
                    self.found_subdomains.add(subdomain)
                    print(f"✓ {subdomain} ({source})")
    
    def permute_subdomains(self):
        """Generate permutations of found subdomains"""
        print("Generating subdomain permutations...")
        
        base_subs = list(self.found_subdomains)
        patterns = ['dev', 'staging', 'test', 'api', 'admin', 'backup', 'old', 'new']
        
        for sub in base_subs[:50]:  # Limit to first 50 to avoid too many permutations
            base = sub.replace(f".{self.domain}", "")
            for pattern in patterns:
                new_subs = [
                    f"{pattern}-{base}.{self.domain}",
                    f"{base}-{pattern}.{self.domain}",
                    f"{pattern}.{base}.{self.domain}",
                    f"{base}.{pattern}.{self.domain}",
                ]
                
                for new_sub in new_subs:
                    if new_sub not in self.found_subdomains:
                        try:
                            dns.resolver.resolve(new_sub, 'A')
                            self.found_subdomains.add(new_sub)
                            print(f"✓ {new_sub} (permutation)")
                        except:
                            pass
    
    def service_discovery(self, subdomain):
        """Discover services running on subdomain"""
        full_domain = f"{subdomain}.{self.domain}"
        ports = [80, 443, 8080, 8443, 3000, 5000, 8000]
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((full_domain, port))
                if result == 0:
                    protocol = "https" if port in [443, 8443] else "http"
                    print(f"  Service: {protocol}://{full_domain}:{port}")
                sock.close()
            except:
                pass
    
    def run_comprehensive_scan(self):
        """Run comprehensive subdomain discovery"""
        print(f"Starting comprehensive subdomain discovery for: {self.domain}")
        print("=" * 60)
        
        start_time = time.time()
        
        # 1. Certificate Transparency
        self.certificate_transparency()
        
        # 2. Search APIs
        self.search_apis()
        
        # 3. Bruteforce with wordlist
        if self.wordlist_file:
            print("Starting bruteforce enumeration...")
            try:
                with open(self.wordlist_file, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except:
                wordlist = self.common_subdomains
        else:
            wordlist = self.common_subdomains
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.dns_enumeration, wordlist)
        
        # 4. Permutations
        self.permute_subdomains()
        
        # 5. Service discovery for found subdomains
        print("\nDiscovering services...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(self.service_discovery, [s.replace(f".{self.domain}", "") for s in self.found_subdomains])
        
        end_time = time.time()
        
        # Print results
        print("\n" + "=" * 60)
        print(f"Scan completed in {end_time - start_time:.2f} seconds")
        print(f"Found {len(self.found_subdomains)} unique subdomains:")
        
        for subdomain in sorted(self.found_subdomains):
            print(f"  {subdomain}")

def main():
    parser = argparse.ArgumentParser(description='Advanced Subdomain Discovery Tool')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-w', '--wordlist', help='Wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads')
    parser.add_argument('-o', '--output', help='Output file (JSON)')
    parser.add_argument('-T', '--timeout', type=int, default=5, help='Request timeout')
    
    args = parser.parse_args()
    
    finder = AdvancedSubdomainFinder(args.domain, args.wordlist, args.threads, args.timeout)
    finder.run_comprehensive_scan()
    
    if args.output:
        output_data = {
            'domain': args.domain,
            'subdomains': list(finder.found_subdomains),
            'results': finder.results
        }
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"\nDetailed results saved to: {args.output}")

if __name__ == "__main__":
    main()