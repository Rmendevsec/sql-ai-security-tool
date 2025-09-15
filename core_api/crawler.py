"""
Advanced API crawler for discovering endpoints and parameters.
"""

import re
import time
from typing import Dict, List, Set, Optional, Tuple
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
import requests

from .utils import RequestUtils, is_api_endpoint, normalize_url, extract_parameters_from_url

class AdvancedAPICrawler:
    """Advanced crawler for API endpoint discovery."""
    
    def __init__(self, base_url: str, max_depth: int = 3, delay: float = 0.5, 
                 user_agent: str = None, cookies: Dict = None, headers: Dict = None):
        self.base_url = base_url
        self.max_depth = max_depth
        self.delay = delay
        self.visited_urls = set()
        self.discovered_endpoints = set()
        self.discovered_parameters = set()
        self.request_utils = RequestUtils()
        
        # Custom headers and cookies
        self.headers = headers or {}
        if user_agent:
            self.headers['User-Agent'] = user_agent
        
        self.cookies = cookies or {}
        
        # Common API endpoint patterns
        self.api_patterns = [
            r'/api/\w+', r'/v\d+/\w+', r'/graphql', r'/rest/\w+', 
            r'/json/\w+', r'/soap/\w+', r'/wsdl', r'/webapi/\w+'
        ]
    
    def is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to the same domain as base URL."""
        base_domain = urlparse(self.base_url).netloc
        url_domain = urlparse(url).netloc
        return base_domain == url_domain
    
    def should_crawl(self, url: str) -> bool:
        """Determine if a URL should be crawled."""
        # Skip non-HTTP URLs
        if not url.startswith(('http://', 'https://')):
            return False
        
        # Skip URLs from different domains
        if not self.is_same_domain(url):
            return False
        
        # Skip already visited URLs
        if url in self.visited_urls:
            return False
        
        # Skip common non-API resources
        excluded_extensions = ['.pdf', '.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico']
        if any(url.lower().endswith(ext) for ext in excluded_extensions):
            return False
        
        return True
    
    def extract_urls_from_html(self, html_content: str, base_url: str) -> Set[str]:
        """Extract URLs from HTML content."""
        urls = set()
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract links
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            if self.should_crawl(full_url):
                urls.add(normalize_url(full_url))
        
        # Extract form actions
        for form in soup.find_all('form', action=True):
            action = form['action']
            full_url = urljoin(base_url, action)
            if self.should_crawl(full_url):
                urls.add(normalize_url(full_url))
        
        # Extract script sources
        for script in soup.find_all('script', src=True):
            src = script['src']
            full_url = urljoin(base_url, src)
            if self.should_crawl(full_url):
                urls.add(normalize_url(full_url))
        
        return urls
    
    def extract_urls_from_js(self, js_content: str, base_url: str) -> Set[str]:
        """Extract URLs from JavaScript content."""
        urls = set()
        
        # Patterns for URLs in JavaScript
        patterns = [
            r'[\"\'](/[^\"\']+?)[\"\']',  # Relative URLs in quotes
            r'[\"\'](https?://[^\"\']+?)[\"\']',  # Absolute URLs in quotes
            r'url\([\"\']?([^\"\')]+)[\"\']?\)',  # CSS url() patterns
            r'fetch\([\"\']([^\"\']+)[\"\']\)',  # Fetch API calls
            r'axios\.\w+\([\"\']([^\"\']+)[\"\']\)',  # Axios calls
            r'\.ajax\([^}]*url[\s:]*[\"\']([^\"\']+)[\"\']',  # jQuery AJAX
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                full_url = urljoin(base_url, match)
                if self.should_crawl(full_url):
                    urls.add(normalize_url(full_url))
        
        return urls
    
    def extract_parameters(self, url: str, response: requests.Response) -> None:
        """Extract parameters from URL and response."""
        # Extract from URL query string
        url_params = extract_parameters_from_url(url)
        self.discovered_parameters.update(url_params)
        
        # TODO: Extract from JSON/XML response bodies
        # This would require parsing response content to find nested parameters
    
    def crawl_page(self, url: str, depth: int = 0) -> None:
        """Crawl a single page and extract endpoints/parameters."""
        if depth > self.max_depth:
            return
        
        if url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        print(f"Crawling: {url} (Depth: {depth})")
        
        # Make request with custom headers and cookies
        response = self.request_utils.make_request(
            url, 
            headers=self.headers, 
            cookies=self.cookies
        )
        
        if not response or response.status_code != 200:
            return
        
        # Check if this is an API endpoint
        if is_api_endpoint(url, response):
            self.discovered_endpoints.add(url)
            self.extract_parameters(url, response)
        
        # Extract URLs based on content type
        content_type = response.headers.get('Content-Type', '').lower()
        new_urls = set()
        
        if 'text/html' in content_type:
            new_urls = self.extract_urls_from_html(response.text, url)
        elif 'application/javascript' in content_type or 'text/javascript' in content_type:
            new_urls = self.extract_urls_from_js(response.text, url)
        
        # Recursively crawl discovered URLs
        for new_url in new_urls:
            time.sleep(self.delay)  # Respectful crawling
            self.crawl_page(new_url, depth + 1)
    
    def find_api_endpoints(self) -> Dict[str, List[str]]:
        """Main method to discover API endpoints."""
        print(f"Starting API endpoint discovery on: {self.base_url}")
        
        # Start crawling from base URL
        self.crawl_page(self.base_url)
        
        # Also try common API endpoints
        self.try_common_api_endpoints()
        
        return {
            'endpoints': list(self.discovered_endpoints),
            'parameters': list(self.discovered_parameters)
        }
    
    def try_common_api_endpoints(self) -> None:
        """Try common API endpoint patterns."""
        common_paths = [
            '/api', '/api/v1', '/api/v2', '/v1', '/v2', '/graphql',
            '/rest', '/json', '/xml', '/soap', '/webapi', '/service'
        ]
        
        for path in common_paths:
            test_url = urljoin(self.base_url, path)
            if self.should_crawl(test_url):
                response = self.request_utils.make_request(test_url)
                if response and response.status_code == 200:
                    if is_api_endpoint(test_url, response):
                        self.discovered_endpoints.add(test_url)
                        self.extract_parameters(test_url, response)
    
    def get_discovery_results(self) -> Dict[str, List[str]]:
        """Get the discovery results."""
        return {
            'endpoints': sorted(list(self.discovered_endpoints)),
            'parameters': sorted(list(self.discovered_parameters)),
            'visited_urls': sorted(list(self.visited_urls))
        }