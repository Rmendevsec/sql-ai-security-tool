"""
Utility functions for the Core API module.
"""

import re
import json
import random
import string
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote
from typing import Dict, List, Set, Any, Optional, Tuple
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

class RequestUtils:
    """Utility class for making HTTP requests with retries and custom headers."""
    
    def __init__(self, timeout: int = 10, retries: int = 3, backoff_factor: float = 0.5):
        self.timeout = timeout
        self.session = self._create_session(retries, backoff_factor)
    
    def _create_session(self, retries: int, backoff_factor: float) -> requests.Session:
        """Create a requests session with retry logic."""
        session = requests.Session()
        retry_strategy = Retry(
            total=retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
    
    def make_request(self, url: str, method: str = "GET", **kwargs) -> Optional[requests.Response]:
        """Make an HTTP request with error handling."""
        try:
            headers = kwargs.pop('headers', {})
            timeout = kwargs.pop('timeout', self.timeout)
            
            # Set default headers if not provided
            if 'User-Agent' not in headers:
                headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            
            response = self.session.request(
                method=method.upper(),
                url=url,
                headers=headers,
                timeout=timeout,
                **kwargs
            )
            return response
        except requests.RequestException as e:
            print(f"Request failed for {url}: {e}")
            return None

def generate_random_string(length: int = 8) -> str:
    """Generate a random string for fuzzing."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def is_json_response(response: requests.Response) -> bool:
    """Check if the response content is JSON."""
    content_type = response.headers.get('Content-Type', '').lower()
    return 'application/json' in content_type

def is_api_endpoint(url: str, response: requests.Response) -> bool:
    """
    Heuristic to determine if a URL is an API endpoint.
    """
    path = urlparse(url).path.lower()
    
    # Common API path patterns
    api_patterns = [
        r'/api/', r'/v\d+/', r'/graphql', r'/rest/', r'/json/', r'/xml/',
        r'/soap/', r'/wsdl', r'/webapi/', r'/service', r'/rpc/'
    ]
    
    # Check path patterns
    if any(re.search(pattern, path) for pattern in api_patterns):
        return True
    
    # Check content type
    content_type = response.headers.get('Content-Type', '').lower()
    if any(ct in content_type for ct in ['json', 'xml', 'api']):
        return True
    
    # Check for common API response structures
    try:
        if is_json_response(response):
            data = response.json()
            # Common API response structures
            if isinstance(data, dict) and any(key in data for key in ['data', 'result', 'items', 'error', 'status']):
                return True
    except (json.JSONDecodeError, ValueError):
        pass
    
    return False

def normalize_url(url: str) -> str:
    """Normalize URL by removing fragments and sorting query parameters."""
    parsed = urlparse(url)
    
    # Sort query parameters
    query_params = parse_qs(parsed.query)
    sorted_query = urlencode(query_params, doseq=True)
    
    # Reconstruct URL without fragment
    return parsed._replace(query=sorted_query, fragment='').geturl()

def extract_parameters_from_url(url: str) -> Set[str]:
    """Extract parameter names from URL query string."""
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    return set(query_params.keys())

def extract_parameters_from_body(body: str, content_type: str) -> Set[str]:
    """Extract parameter names from request body based on content type."""
    params = set()
    
    if 'application/x-www-form-urlencoded' in content_type:
        try:
            form_params = parse_qs(body)
            params.update(form_params.keys())
        except:
            pass
    
    elif 'application/json' in content_type:
        try:
            data = json.loads(body)
            # Recursively extract keys from JSON
            def extract_keys(obj, path=""):
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        new_path = f"{path}.{key}" if path else key
                        params.add(new_path)
                        extract_keys(value, new_path)
                elif isinstance(obj, list) and obj:
                    extract_keys(obj[0], f"{path}[]")
            extract_keys(data)
        except (json.JSONDecodeError, ValueError):
            pass
    
    return params

def detect_api_technology(response: requests.Response) -> List[str]:
    """Detect API technology based on response headers and content."""
    technologies = []
    headers = response.headers
    
    # Check server header
    server = headers.get('Server', '').lower()
    if 'apache' in server:
        technologies.append('Apache')
    elif 'nginx' in server:
        technologies.append('Nginx')
    elif 'iis' in server:
        technologies.append('IIS')
    
    # Check powered-by header
    powered_by = headers.get('X-Powered-By', '').lower()
    if 'php' in powered_by:
        technologies.append('PHP')
    elif 'asp.net' in powered_by:
        technologies.append('ASP.NET')
    elif 'node' in powered_by:
        technologies.append('Node.js')
    
    # Check content type for framework clues
    content_type = headers.get('Content-Type', '').lower()
    if 'django' in content_type:
        technologies.append('Django')
    elif 'flask' in content_type:
        technologies.append('Flask')
    elif 'express' in content_type:
        technologies.append('Express.js')
    
    # Check for API-specific headers
    if headers.get('X-API-Version'):
        technologies.append('Versioned API')
    if headers.get('X-RateLimit-Limit'):
        technologies.append('Rate Limited API')
    
    return technologies