import requests
import re
import json
import time
import sys
import argparse
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import os
import hashlib
from collections import defaultdict
import threading
import warnings
import urllib3
import ssl
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Suppress SSL warnings
warnings.filterwarnings('ignore', category=urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CompetitiveAPIFinder:
    def __init__(self, target_url, max_threads=50, timeout=8, user_agent=None, verify_ssl=False):
        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.max_threads = max_threads
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        # Create session with proper SSL handling
        self.session = self.create_session()
        self.user_agent = user_agent or 'Mozilla/5.0 (compatible; AdvancedScanner/1.0)'
        self.session.headers.update({'User-Agent': self.user_agent})
        
        self.found_endpoints = set()
        self.scanned_count = 0
        self.lock = threading.Lock()
        self.results = []
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 0.1
        
        # Advanced filtering
        self.excluded_status_codes = {404, 400}
        self.excluded_sizes = set()
        self.content_filters = []

    def create_session(self):
        """Create requests session with proper SSL handling and retry strategy"""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD", "OPTIONS"]
        )
        
        # Create adapter with retry strategy
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
        
        # Mount adapters
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # SSL configuration
        if not self.verify_ssl:
            session.verify = False
        
        return session

    def load_combined_wordlists(self, user_wordlist_file=None, use_system_wordlist=True):
        """Load both user wordlist and system wordlist, combining them"""
        endpoints = set()
        
        # Load user wordlist if provided
        if user_wordlist_file and os.path.exists(user_wordlist_file):
            with open(user_wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                user_endpoints = {line.strip() for line in f if line.strip()}
            endpoints.update(user_endpoints)
            print(f"[*] Loaded {len(user_endpoints)} endpoints from user wordlist: {user_wordlist_file}")
        elif user_wordlist_file:
            print(f"[-] User wordlist not found: {user_wordlist_file}")
        
        # Load system wordlist if requested
        if use_system_wordlist:
            system_endpoints = self.get_comprehensive_wordlist()
            endpoints.update(system_endpoints)
            print(f"[*] Loaded {len(system_endpoints)} endpoints from system wordlist")
        
        # Convert to list and sort
        endpoints_list = list(endpoints)
        endpoints_list.sort()
        
        print(f"[*] Combined wordlist total: {len(endpoints_list)} endpoints")
        return endpoints_list

    def get_comprehensive_wordlist(self):
        """Return the comprehensive system wordlist"""
        # Your complete system wordlist goes here
        system_endpoints = [
            # API endpoints
            '/api', '/api/v1', '/api/v2', '/api/v3', '/v1', '/v2', '/v3',
            '/rest', '/rest/api', '/graphql', '/gql',
            
            # Authentication
            '/auth', '/oauth', '/oauth2', '/openid', '/login', '/logout',
            '/signin', '/signup', '/register', '/token', '/refresh',
            
            # User management
            '/users', '/user', '/profile', '/account', '/me', '/self',
            '/admin/users', '/customers', '/clients', '/members',
            
            # Administrative
            '/admin', '/administrator', '/manager', '/admin/dashboard',
            '/admin/panel', '/admin/settings', '/admin/config',
            '/wp-admin', '/administrator/login',
            
            # Data operations
            '/data', '/entities', '/resources', '/create', '/read',
            '/update', '/delete', '/list', '/get', '/post', '/put',
            '/patch', '/search', '/query', '/filter', '/find',
            
            # File operations
            '/files', '/file', '/documents', '/images', '/uploads',
            '/downloads', '/assets', '/storage', '/static', '/public',
            
            # Service endpoints
            '/service', '/services', '/microservice', '/gateway',
            '/health', '/status', '/ready', '/live', '/metrics',
            '/actuator', '/management',
            
            # Documentation
            '/docs', '/documentation', '/api-docs', '/swagger',
            '/swagger-ui', '/openapi', '/redoc',
            
            # Webhooks
            '/webhook', '/webhooks', '/hook', '/callback',
            '/notification', '/notify',
            
            # Payment
            '/payment', '/pay', '/checkout', '/billing',
            '/invoice', '/subscription', '/order', '/orders',
            
            # Development
            '/test', '/testing', '/dev', '/development',
            '/staging', '/sandbox', '/debug',
            
            # Common directories
            '/images', '/css', '/js', '/assets', '/static', '/public',
            '/uploads', '/downloads', '/files', '/documents',
            
            # Configuration files
            '/.env', '/config.json', '/configuration.yml', '/config.xml',
            '/.git/config', '/.htaccess', '/web.config', '/robots.txt',
            
            # Backup files
            '/backup', '/backups', '/bak', '/old', '/temp', '/tmp',
            
            # Common numeric endpoints
            '/0', '/1', '/2', '/3', '/4', '/5', '/6', '/7', '/8', '/9',
            '/00', '/01', '/02', '/03', '/10', '/100', '/1000',
            
            # Common alphabetical endpoints
            '/a', '/b', '/c', '/d', '/e', '/f', '/g', '/h', '/i', '/j',
            '/k', '/l', '/m', '/n', '/o', '/p', '/q', '/r', '/s', '/t',
            '/u', '/v', '/w', '/x', '/y', '/z',
            
            # Add more from your comprehensive wordlist...
            # This is a sample - include all your system endpoints
            
        ]
        
        # Add common extensions to system endpoints
        extensions = ['', '.php', '.html', '.jsp', '.asp', '.aspx', '.json', '.xml', '.txt']
        extended_endpoints = []
        
        for endpoint in system_endpoints:
            for ext in extensions:
                extended_endpoints.append(endpoint + ext)
        
        # Remove duplicates
        return list(set(extended_endpoints))

    def scan_endpoint(self, endpoint):
        """Advanced endpoint scanning with proper SSL handling"""
        full_url = urljoin(self.target_url, endpoint)
        results = []
        
        # Rate limiting
        self.respect_rate_limit()
        
        methods = ['GET', 'POST', 'HEAD', 'OPTIONS']
        for method in methods:
            try:
                response = self.session.request(
                    method, 
                    full_url, 
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=self.verify_ssl
                )
                
                if self.is_interesting_response(response, endpoint):
                    result = {
                        'endpoint': endpoint,
                        'method': method,
                        'status': response.status_code,
                        'size': len(response.content),
                        'content_type': response.headers.get('content-type', ''),
                        'url': full_url,
                        'headers': dict(response.headers),
                        'fingerprint': self.get_response_fingerprint(response)
                    }
                    results.append(result)
                    
            except requests.exceptions.SSLError as e:
                continue
            except requests.exceptions.RequestException as e:
                continue
            except Exception as e:
                continue
        
        with self.lock:
            self.scanned_count += 1
        
        return results

    def is_interesting_response(self, response, endpoint):
        """Determine if response is interesting based on multiple factors"""
        # Status code filtering
        if response.status_code in self.excluded_status_codes:
            return False
            
        # Size-based filtering
        content_size = len(response.content)
        if content_size in self.excluded_sizes:
            return False
            
        # Content-based filtering
        if self.is_default_page(response):
            return False
            
        # Special cases that are always interesting
        if response.status_code in [200, 201, 301, 302, 403, 500]:
            return True
            
        # Unusual status codes
        if response.status_code not in [404, 400, 401]:
            return True
            
        return False

    def get_response_fingerprint(self, response):
        """Create fingerprint for response to identify similar pages"""
        content_hash = hashlib.md5(response.content).hexdigest()[:8]
        return f"{response.status_code}-{len(response.content)}-{content_hash}"

    def is_default_page(self, response):
        """Check if response is a default error page"""
        default_indicators = [
            'page not found',
            '404 error',
            'not found',
            'error 404',
            'the page cannot be found'
        ]
        
        content_lower = response.text.lower()
        return any(indicator in content_lower for indicator in default_indicators)

    def respect_rate_limit(self):
        """Implement rate limiting"""
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        if elapsed < self.min_request_interval:
            time.sleep(self.min_request_interval - elapsed)
        self.last_request_time = time.time()

    def brute_force_endpoints(self, endpoints):
        """High-performance brute force scanning"""
        print(f"[*] Scanning {len(endpoints)} endpoints with {self.max_threads} threads...")
        if not self.verify_ssl:
            print("[*] SSL verification disabled - ignoring certificate warnings")
        
        all_results = []
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.scan_endpoint, endpoint): endpoint for endpoint in endpoints}
            
            for future in as_completed(futures):
                endpoint = futures[future]
                try:
                    results = future.result()
                    if results:
                        all_results.extend(results)
                        for result in results:
                            status_color = self.get_status_color(result['status'])
                            print(f"[{status_color}] {result['method']} {result['endpoint']} - Status: {result['status']} - Size: {result['size']}")
                    
                except Exception as e:
                    pass
                
                # Progress reporting
                if self.scanned_count % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = self.scanned_count / elapsed if elapsed > 0 else 0
                    print(f"[*] Progress: {self.scanned_count}/{len(endpoints)} | Rate: {rate:.1f} req/sec")
        
        return all_results

    def get_status_color(self, status_code):
        """Get color code for status code"""
        if 200 <= status_code < 300:
            return '\033[92m✓\033[0m'  # Green
        elif 300 <= status_code < 400:
            return '\033[93m→\033[0m'  # Yellow
        elif 400 <= status_code < 500:
            return '\033[91m✗\033[0m'  # Red
        else:
            return '\033[94m!\033[0m'  # Blue

    def crawl_for_endpoints(self, max_pages=10):
        """Advanced crawling with discovery"""
        print(f"[*] Crawling up to {max_pages} pages for endpoint discovery...")
        
        discovered_endpoints = set()
        pages_to_crawl = {self.target_url}
        crawled_pages = set()
        
        while pages_to_crawl and len(crawled_pages) < max_pages:
            url = pages_to_crawl.pop()
            if url in crawled_pages:
                continue
                
            try:
                response = self.session.get(url, timeout=self.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Discover new endpoints
                new_endpoints = self.extract_endpoints_from_html(soup, url)
                discovered_endpoints.update(new_endpoints)
                
                crawled_pages.add(url)
                
            except Exception as e:
                continue
        
        return list(discovered_endpoints)

    def extract_endpoints_from_html(self, soup, base_url):
        """Extract potential API endpoints from HTML"""
        endpoints = set()
        
        # Links
        for link in soup.find_all('a', href=True):
            href = link['href']
            if self.is_potential_endpoint(href):
                endpoints.add(href)
        
        # Forms
        for form in soup.find_all('form', action=True):
            action = form['action']
            if self.is_potential_endpoint(action):
                endpoints.add(action)
        
        return endpoints

    def is_potential_endpoint(self, url):
        """Check if URL looks like an API endpoint"""
        if not url or url.startswith(('javascript:', 'mailto:', 'tel:', '#')):
            return False
        
        # Filter out common static files
        static_extensions = {'.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', 
                           '.svg', '.woff', '.ttf', '.eot', '.pdf', '.zip', '.tar'}
        if any(url.lower().endswith(ext) for ext in static_extensions):
            return False
        
        return True

    def generate_comprehensive_report(self, results):
        """Generate detailed scan report"""
        report = {
            'scan_info': {
                'target_url': self.target_url,
                'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'scan_duration': getattr(self, 'scan_duration', 0),
                'total_endpoints_tested': getattr(self, 'total_tested', 0),
                'ssl_verification': self.verify_ssl,
            },
            'results': {
                'total_found': len(results),
                'by_status_code': defaultdict(list),
                'by_method': defaultdict(list),
                'unique_fingerprints': set(),
            },
            'endpoints': results
        }
        
        # Analyze results
        for result in results:
            report['results']['by_status_code'][result['status']].append(result)
            report['results']['by_method'][result['method']].append(result)
            report['results']['unique_fingerprints'].add(result['fingerprint'])
        
        return report

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Web Endpoint Scanner - Uses both user and system wordlists',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Use only user wordlist
  %(prog)s https://example.com -w my_wordlist.txt
  
  # Use only system wordlist
  %(prog)s https://example.com --system-only
  
  # Use both user and system wordlists (default)
  %(prog)s https://example.com -w my_wordlist.txt
  
  # Use system wordlist only with extensions
  %(prog)s https://example.com --system-only -x php,html
  
  # Quick scan with small combined wordlist
  %(prog)s https://example.com -w small_list.txt --quick
        '''
    )
    
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-w', '--wordlist', help='Path to user wordlist file')
    parser.add_argument('--system-only', action='store_true', help='Use only system wordlist (ignore user wordlist)')
    parser.add_argument('--no-system', action='store_true', help='Use only user wordlist (ignore system wordlist)')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('-o', '--output', help='Output file (JSON)')
    parser.add_argument('--crawl', action='store_true', help='Enable page crawling')
    parser.add_argument('--verify-ssl', action='store_true', help='Enable SSL certificate verification')
    parser.add_argument('--methods', default='GET,POST,HEAD', help='HTTP methods to try')
    parser.add_argument('-x', '--extensions', help='File extensions to append')
    parser.add_argument('--filter-status', help='Only show these status codes')
    parser.add_argument('--timeout', type=int, default=8, help='Request timeout')
    parser.add_argument('--rate-limit', type=float, help='Requests per second')
    parser.add_argument('--quick', action='store_true', help='Quick scan (first 500 endpoints only)')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        print("Error: URL must start with http:// or https://")
        sys.exit(1)
    
    try:
        print(f"[*] Starting Advanced Web Endpoint Scanner")
        print(f"[*] Target: {args.url}")
        print(f"[*] Threads: {args.threads}")
        print(f"[*] SSL Verification: {'Enabled' if args.verify_ssl else 'Disabled'}")
        
        scanner = CompetitiveAPIFinder(
            target_url=args.url,
            max_threads=args.threads,
            timeout=args.timeout,
            verify_ssl=args.verify_ssl
        )
        
        # Determine wordlist strategy
        use_system_wordlist = not args.no_system
        user_wordlist_file = args.wordlist if not args.system_only else None
        
        # Load combined wordlists
        endpoints = scanner.load_combined_wordlists(
            user_wordlist_file=user_wordlist_file,
            use_system_wordlist=use_system_wordlist
        )
        
        if not endpoints:
            print("[-] No endpoints to scan. Please provide a wordlist or enable system wordlist.")
            sys.exit(1)
        
        # Apply extensions if specified
        if args.extensions:
            extensions = args.extensions.split(',')
            extended_endpoints = []
            for endpoint in endpoints:
                for ext in extensions:
                    if not endpoint.endswith('.' + ext):
                        extended_endpoints.append(endpoint + '.' + ext)
            endpoints.extend(extended_endpoints)
            print(f"[*] Extended wordlist to {len(endpoints)} endpoints with extensions")
        
        # Quick scan mode
        if args.quick:
            original_count = len(endpoints)
            endpoints = endpoints[:500]
            print(f"[*] Quick scan enabled - using first {len(endpoints)} endpoints (from {original_count})")
        
        start_time = time.time()
        
        # Main scan
        results = scanner.brute_force_endpoints(endpoints)
        
        # Crawl if enabled
        if args.crawl:
            print("[*] Starting advanced crawling...")
            crawled_endpoints = scanner.crawl_for_endpoints()
            if crawled_endpoints:
                print(f"[*] Found {len(crawled_endpoints)} endpoints through crawling")
                crawl_results = scanner.brute_force_endpoints(crawled_endpoints)
                results.extend(crawl_results)
        
        scanner.scan_duration = time.time() - start_time
        scanner.total_tested = len(endpoints)
        
        # Generate report
        report = scanner.generate_comprehensive_report(results)
        
        # Print summary
        print(f"\n{'='*60}")
        print("SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"Target: {args.url}")
        print(f"Duration: {scanner.scan_duration:.2f} seconds")
        print(f"Endpoints tested: {scanner.total_tested}")
        print(f"Interesting endpoints found: {len(results)}")
        print(f"Requests/sec: {scanner.total_tested/scanner.scan_duration:.1f}")
        print(f"Wordlist: {'User + System' if args.wordlist and use_system_wordlist else 'System only' if use_system_wordlist else 'User only'}")
        
        # Status breakdown
        print(f"\nStatus Code Breakdown:")
        for status, endpoints in sorted(report['results']['by_status_code'].items()):
            print(f"  {status}: {len(endpoints)} endpoints")
        
        # Save results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Full results saved to: {args.output}")
        
        print(f"\n[*] Scan completed!")
        
    except KeyboardInterrupt:
        print(f"\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()