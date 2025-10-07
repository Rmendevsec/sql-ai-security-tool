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

# Disable SSL warnings
warnings.filterwarnings('ignore', category=urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class CompetitiveAPIFinder:
    def __init__(self, target_url, max_threads=50, timeout=8, user_agent=None):
        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.max_threads = max_threads
        self.timeout = timeout
        self.session = requests.Session()
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

    def load_wordlist(self, wordlist_file=None):
        """Load wordlist from file or use built-in comprehensive list"""
        if wordlist_file and os.path.exists(wordlist_file):
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                endpoints = [line.strip() for line in f if line.strip()]
            print(f"[*] Loaded {len(endpoints)} endpoints from {wordlist_file}")
        else:
            # Use the comprehensive built-in wordlist
            endpoints = self.get_comprehensive_wordlist()
            print(f"[*] Using built-in wordlist with {len(endpoints)} endpoints")
        
        return endpoints

    def get_comprehensive_wordlist(self):
        """Return the comprehensive wordlist"""
        # This would contain your entire wordlist
        # For brevity, I'll show the structure - you'd paste your full list here
        base_endpoints = [
            # API endpoints
            '/api', '/api/v1', '/api/v2', '/api/v3', '/v1', '/v2', '/v3',
            '/rest', '/rest/api', '/graphql', '/gql',
            
            # Admin endpoints
            '/admin', '/administrator', '/wp-admin', '/manager',
            '/admin/login', '/admin/dashboard', '/admin/config',
            
            # Common directories
            '/images', '/css', '/js', '/assets', '/static', '/public',
            '/uploads', '/downloads', '/files', '/documents',
            
            # Configuration files
            '/.env', '/config.json', '/configuration.yml',
            '/.git/config', '/.htaccess', '/web.config',
            
            # Backup files
            '/backup', '/backups', '/bak', '/old', '/temp',
            
            # Your entire wordlist would go here...
            # Include all the endpoints from your previous list
        ]
        
        # Add common extensions
        extensions = ['', '.php', '.html', '.jsp', '.asp', '.aspx', '.json', '.xml']
        extended_endpoints = []
        
        for endpoint in base_endpoints:
            for ext in extensions:
                extended_endpoints.append(endpoint + ext)
        
        return list(set(extended_endpoints))

    def scan_endpoint(self, endpoint):
        """Advanced endpoint scanning with multiple techniques"""
        full_url = urljoin(self.target_url, endpoint)
        results = []
        
        # Rate limiting
        self.respect_rate_limit()
        
        methods = ['GET', 'POST', 'HEAD', 'OPTIONS']
        for method in methods:
            try:
                response = self.session.request(
                    method, full_url, 
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False  # For testing purposes only
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
                
                # Find new pages to crawl
                new_urls = self.extract_urls_from_html(soup, url)
                pages_to_crawl.update(new_urls - crawled_pages)
                
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
        
        # Scripts and assets
        for script in soup.find_all('script', src=True):
            src = script['src']
            if self.is_potential_endpoint(src):
                endpoints.add(src)
        
        # Meta tags
        for meta in soup.find_all('meta', content=True):
            content = meta['content']
            if 'url' in content.lower() and self.is_potential_endpoint(content):
                endpoints.add(content)
        
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
        
        # Look for API patterns
        api_patterns = ['/api/', '/v1/', '/v2/', '/rest/', '/graphql', '/endpoint']
        if any(pattern in url.lower() for pattern in api_patterns):
            return True
        
        # Parameters often indicate endpoints
        if '?' in url and any(param in url.lower() for param in ['id=', 'token=', 'key=', 'api=']):
            return True
        
        return True

    def generate_comprehensive_report(self, results):
        """Generate detailed scan report"""
        report = {
            'scan_info': {
                'target_url': self.target_url,
                'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'scan_duration': getattr(self, 'scan_duration', 0),
                'total_endpoints_tested': getattr(self, 'total_tested', 0),
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
        description='Advanced Web Endpoint Scanner - Competitive with GoBuster',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s https://example.com -w common.txt -t 100
  %(prog)s https://api.example.com --crawl --methods GET,POST -o results.json
  %(prog)s https://test.com -x php,html --filter-status 200,301,302
        '''
    )
    
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('-o', '--output', help='Output file (JSON)')
    parser.add_argument('--crawl', action='store_true', help='Enable page crawling')
    parser.add_argument('--methods', default='GET,POST,HEAD', help='HTTP methods to try')
    parser.add_argument('-x', '--extensions', help='File extensions to append')
    parser.add_argument('--filter-status', help='Only show these status codes')
    parser.add_argument('--timeout', type=int, default=8, help='Request timeout')
    parser.add_argument('--rate-limit', type=float, help='Requests per second')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        print("Error: URL must start with http:// or https://")
        sys.exit(1)
    
    try:
        print(f"[*] Starting Competitive Web Endpoint Scanner")
        print(f"[*] Target: {args.url}")
        print(f"[*] Threads: {args.threads}")
        
        scanner = CompetitiveAPIFinder(
            target_url=args.url,
            max_threads=args.threads,
            timeout=args.timeout
        )
        
        # Load wordlist
        endpoints = scanner.load_wordlist(args.wordlist)
        
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
    
    
    