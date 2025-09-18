import re
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from ..utils.http_client import HTTPClient
from ..utils.logger import Logger

class APICrawler:
    def __init__(self):
        self.logger = Logger(__name__)
        self.http_client = HTTPClient()
        self.discovered_endpoints = set()
        self.js_files = set()
        
    def extract_endpoints_from_js(self, js_content, base_url):
        """Extract potential API endpoints from JavaScript files"""
        endpoints = set()
        
        # Common API endpoint patterns
        patterns = [
            r'["\'](/[a-zA-Z0-9_\-/.]+)["\']',
            r'fetch\(["\']([a-zA-Z0-9_\-/.]+)["\']',
            r'axios\.(get|post|put|delete)\(["\']([a-zA-Z0-9_\-/.]+)["\']',
            r'\.ajax\([^)]*url["\']?:["\']([a-zA-Z0-9_\-/.]+)["\']',
            r'window\.location\.href\s*=\s*["\']([a-zA-Z0-9_\-/.]+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                # Handle different regex group captures
                endpoint = match[1] if isinstance(match, tuple) and len(match) > 1 else match
                if endpoint.startswith(('http://', 'https://')):
                    endpoints.add(endpoint)
                else:
                    endpoints.add(urljoin(base_url, endpoint))
        
        return endpoints
    
    def find_js_files(self, soup, base_url):
        """Find all JavaScript files referenced in the page"""
        js_urls = set()
        
        for script in soup.find_all('script'):
            if script.get('src'):
                js_url = urljoin(base_url, script['src'])
                js_urls.add(js_url)
                
        return js_urls
    
    def crawl_page(self, url):
        """Crawl a single page for endpoints"""
        try:
            response = self.http_client.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all links
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith(('http://', 'https://')):
                    self.discovered_endpoints.add(href)
                else:
                    self.discovered_endpoints.add(urljoin(url, href))
            
            # Find all forms
            for form in soup.find_all('form', action=True):
                action = form['action']
                if action:
                    if action.startswith(('http://', 'https://')):
                        self.discovered_endpoints.add(action)
                    else:
                        self.discovered_endpoints.add(urljoin(url, action))
            
            # Find and process JavaScript files
            js_files = self.find_js_files(soup, url)
            for js_file in js_files:
                if js_file not in self.js_files:
                    self.js_files.add(js_file)
                    try:
                        js_response = self.http_client.get(js_file)
                        js_endpoints = self.extract_endpoints_from_js(js_response.text, url)
                        self.discovered_endpoints.update(js_endpoints)
                    except Exception as e:
                        self.logger.error(f"Error processing JS file {js_file}: {str(e)}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error crawling {url}: {str(e)}")
            return False
    
    def crawl(self, base_url, max_depth=2):
        """Main crawl method"""
        self.logger.info(f"Starting crawl of {base_url}")
        
        # Start with the base URL
        to_crawl = {base_url}
        crawled = set()
        depth = 0
        
        while to_crawl and depth < max_depth:
            next_to_crawl = set()
            
            for url in to_crawl:
                if url not in crawled:
                    self.logger.info(f"Crawling: {url}")
                    self.crawl_page(url)
                    crawled.add(url)
                    
                    # Add discovered endpoints to next crawl batch
                    for endpoint in self.discovered_endpoints:
                        parsed = urlparse(endpoint)
                        base_parsed = urlparse(base_url)
                        
                        # Only crawl same-domain endpoints
                        if parsed.netloc == base_parsed.netloc:
                            next_to_crawl.add(endpoint)
            
            to_crawl = next_to_crawl - crawled
            depth += 1
        
        self.logger.info(f"Crawling completed. Found {len(self.discovered_endpoints)} endpoints")
        return list(self.discovered_endpoints)