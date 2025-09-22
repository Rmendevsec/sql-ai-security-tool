import json
import re
from urllib.parse import urlparse, parse_qs
from utils.logger import Logger


class APIParser:
    def __init__(self):
        self.logger = Logger(__name__)
    
    def parse_swagger(self, content, base_url):
        """Parse Swagger/OpenAPI documentation"""
        endpoints = set()
        
        try:
            if isinstance(content, str):
                spec = json.loads(content)
            else:
                spec = content
            
            # Check if it's OpenAPI 3.x
            if 'openapi' in spec and spec['openapi'].startswith('3'):
                servers = spec.get('servers', [{'url': base_url}])
                base_path = servers[0]['url'] if servers else base_url
                
                for path, methods in spec.get('paths', {}).items():
                    for method in methods.keys():
                        if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                            full_url = urljoin(base_path, path)
                            endpoints.add((full_url, method.upper()))
            
            # Check if it's Swagger 2.0
            elif 'swagger' in spec and spec['swagger'] == '2.0':
                base_path = spec.get('basePath', '')
                host = spec.get('host', urlparse(base_url).netloc)
                schemes = spec.get('schemes', ['https'])
                
                for path, methods in spec.get('paths', {}).items():
                    for method in methods.keys():
                        if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                            full_url = f"{schemes[0]}://{host}{base_path}{path}"
                            endpoints.add((full_url, method.upper()))
            
            return endpoints
            
        except Exception as e:
            self.logger.error(f"Error parsing Swagger/OpenAPI: {str(e)}")
            return set()
    
    def parse_robots_txt(self, content, base_url):
        """Parse robots.txt for endpoints"""
        endpoints = set()
        
        for line in content.split('\n'):
            if line.startswith('Allow:') or line.startswith('Disallow:'):
                path = line.split(':', 1)[1].strip()
                if path and path != '/':
                    endpoints.add(urljoin(base_url, path))
        
        return endpoints
    
    def parse_sitemap(self, content, base_url):
        """Parse sitemap.xml for endpoints"""
        endpoints = set()
        
        # Simple XML parsing for URLs
        url_pattern = r'<loc>(.*?)</loc>'
        matches = re.findall(url_pattern, content)
        
        for match in matches:
            endpoints.add(match)
        
        return endpoints
    
    def find_api_docs(self, html_content, base_url):
        """Find API documentation links in HTML"""
        endpoints = set()
        
        # Common API documentation patterns
        patterns = [
            r'href=[\'"](/swagger[^\'"]*)[\'"]',
            r'href=[\'"](/api/docs[^\'"]*)[\'"]',
            r'href=[\'"](/openapi[^\'"]*)[\'"]',
            r'href=[\'"]([^\'"]*swagger-ui[^\'"]*)[\'"]',
            r'href=[\'"](/redoc[^\'"]*)[\'"]',
            r'href=[\'"](/api/v[0-9]/docs[^\'"]*)[\'"]'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                endpoints.add(urljoin(base_url, match))
        
        return endpoints
    

class APIResponseParser:
    def __init__(self):
        pass