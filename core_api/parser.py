"""
Advanced response parser for analyzing API responses.
"""

import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
import requests

from .utils import is_json_response, detect_api_technology

class APIResponseParser:
    """Advanced parser for API responses."""
    
    def __init__(self):
        self.technologies = set()
        self.data_structures = {}
        self.authentication_methods = set()
        self.rate_limits = {}
    
    def parse_response(self, response: requests.Response) -> Dict[str, Any]:
        """Parse an API response and extract useful information."""
        result = {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'technology': [],
            'data_structure': {},
            'authentication_methods': [],
            'rate_limits': {},
            'content_analysis': {}
        }
        
        # Detect technology
        result['technology'] = detect_api_technology(response)
        
        # Check for authentication methods
        result['authentication_methods'] = self.detect_authentication(response)
        
        # Check for rate limiting
        result['rate_limits'] = self.detect_rate_limits(response)
        
        # Analyze content
        result['content_analysis'] = self.analyze_content(response)
        
        return result
    
    def detect_authentication(self, response: requests.Response) -> List[str]:
        """Detect authentication methods from response headers."""
        auth_methods = []
        headers = response.headers
        
        # Check WWW-Authenticate header
        if 'WWW-Authenticate' in headers:
            auth_header = headers['WWW-Authenticate'].lower()
            if 'bearer' in auth_header:
                auth_methods.append('Bearer Token')
            if 'basic' in auth_header:
                auth_methods.append('Basic Auth')
            if 'digest' in auth_header:
                auth_methods.append('Digest Auth')
        
        # Check for JWT in headers or cookies
        if any('jwt' in key.lower() or 'authorization' in key.lower() 
               for key in headers.keys()):
            auth_methods.append('JWT')
        
        # Check for OAuth
        if any('oauth' in key.lower() for key in headers.keys()):
            auth_methods.append('OAuth')
        
        # Check for API keys
        if any('api-key' in key.lower() or 'apikey' in key.lower() 
               for key in headers.keys()):
            auth_methods.append('API Key')
        
        return list(set(auth_methods))
    
    def detect_rate_limits(self, response: requests.Response) -> Dict[str, Any]:
        """Detect rate limiting information from response headers."""
        rate_limits = {}
        headers = response.headers
        
        # Common rate limit headers
        limit_headers = {
            'X-RateLimit-Limit': 'limit',
            'X-RateLimit-Remaining': 'remaining',
            'X-RateLimit-Reset': 'reset',
            'RateLimit-Limit': 'limit',
            'RateLimit-Remaining': 'remaining',
            'RateLimit-Reset': 'reset'
        }
        
        for header, key in limit_headers.items():
            if header in headers:
                rate_limits[key] = headers[header]
        
        return rate_limits
    
    def analyze_content(self, response: requests.Response) -> Dict[str, Any]:
        """Analyze the response content for structure and patterns."""
        analysis = {
            'content_type': response.headers.get('Content-Type', ''),
            'size_bytes': len(response.content),
            'is_json': False,
            'is_xml': False,
            'structure': {},
            'sensitive_data_patterns': []
        }
        
        content_type = response.headers.get('Content-Type', '').lower()
        
        # JSON analysis
        if is_json_response(response):
            analysis['is_json'] = True
            try:
                data = response.json()
                analysis['structure'] = self.analyze_json_structure(data)
                analysis['sensitive_data_patterns'] = self.find_sensitive_data(data)
            except (json.JSONDecodeError, ValueError):
                analysis['json_parse_error'] = True
        
        # XML analysis
        elif 'xml' in content_type:
            analysis['is_xml'] = True
            try:
                root = ET.fromstring(response.text)
                analysis['structure'] = self.analyze_xml_structure(root)
                analysis['sensitive_data_patterns'] = self.find_sensitive_data_xml(root)
            except ET.ParseError:
                analysis['xml_parse_error'] = True
        
        return analysis
    
    def analyze_json_structure(self, data: Any, path: str = "") -> Dict[str, Any]:
        """Recursively analyze JSON structure."""
        structure = {}
        
        if isinstance(data, dict):
            for key, value in data.items():
                new_path = f"{path}.{key}" if path else key
                if isinstance(value, (dict, list)):
                    structure[key] = {
                        'type': type(value).__name__,
                        'structure': self.analyze_json_structure(value, new_path)
                    }
                else:
                    structure[key] = {
                        'type': type(value).__name__,
                        'value_sample': str(value)[:100] if value else None
                    }
        elif isinstance(data, list) and data:
            # Analyze first item to infer structure
            structure['[]'] = {
                'type': 'array',
                'item_structure': self.analyze_json_structure(data[0], f"{path}[]")
            }
        
        return structure
    
    def analyze_xml_structure(self, element, depth: int = 0) -> Dict[str, Any]:
        """Analyze XML structure."""
        if depth > 5:  # Limit recursion depth
            return {'type': 'element', 'depth_limit_reached': True}
        
        structure = {
            'tag': element.tag,
            'attributes': dict(element.attrib),
            'children': {}
        }
        
        # Group children by tag name
        children_by_tag = {}
        for child in element:
            if child.tag not in children_by_tag:
                children_by_tag[child.tag] = []
            children_by_tag[child.tag].append(child)
        
        # Analyze children
        for tag, children in children_by_tag.items():
            if len(children) == 1:
                structure['children'][tag] = self.analyze_xml_structure(children[0], depth + 1)
            else:
                # Multiple children with same tag - treat as array
                structure['children'][tag] = {
                    'type': 'array',
                    'item_structure': self.analyze_xml_structure(children[0], depth + 1)
                }
        
        return structure
    
    def find_sensitive_data(self, data: Any, path: str = "") -> List[Dict[str, str]]:
        """Find potentially sensitive data in JSON structures."""
        sensitive_patterns = [
            ('email', r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            ('password', r'password|passwd|pwd', True),  # Case insensitive
            ('token', r'[a-zA-Z0-9_-]{10,}'),
            ('api_key', r'api[_-]?key', True),
            ('credit_card', r'\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}'),
            ('jwt', r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+')
        ]
        
        findings = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                new_path = f"{path}.{key}" if path else key
                
                # Check key names
                for pattern_name, pattern, is_regex in sensitive_patterns:
                    if is_regex:
                        if re.search(pattern, key, re.IGNORECASE if isinstance(is_regex, bool) and is_regex else 0):
                            findings.append({
                                'path': new_path,
                                'pattern': pattern_name,
                                'type': 'key_name',
                                'value': key
                            })
                    elif pattern in key.lower():
                        findings.append({
                            'path': new_path,
                            'pattern': pattern_name,
                            'type': 'key_name',
                            'value': key
                        })
                
                # Recursively check values
                if isinstance(value, (dict, list)):
                    findings.extend(self.find_sensitive_data(value, new_path))
                elif isinstance(value, str):
                    for pattern_name, pattern, is_regex in sensitive_patterns:
                        if is_regex:
                            if re.search(pattern, value, re.IGNORECASE if isinstance(is_regex, bool) and is_regex else 0):
                                findings.append({
                                    'path': new_path,
                                    'pattern': pattern_name,
                                    'type': 'value_content',
                                    'value_sample': value[:50] + '...' if len(value) > 50 else value
                                })
                        elif pattern in value.lower():
                            findings.append({
                                'path': new_path,
                                'pattern': pattern_name,
                                'type': 'value_content',
                                'value_sample': value[:50] + '...' if len(value) > 50 else value
                            })
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_path = f"{path}[{i}]"
                findings.extend(self.find_sensitive_data(item, new_path))
        
        return findings
    
    def find_sensitive_data_xml(self, element, path: str = "") -> List[Dict[str, str]]:
        """Find potentially sensitive data in XML structures."""
        # Similar implementation to find_sensitive_data but for XML
        # This would check element names, attributes, and text content
        return []  # Implementation omitted for brevity