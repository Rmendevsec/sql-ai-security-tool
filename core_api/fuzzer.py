"""
API Fuzzer - Tests endpoints for vulnerabilities
"""

import concurrent.futures
import json
import re
from urllib.parse import urlparse, parse_qs
from utils.http_client import HTTPClient
from utils.logger import setup_logger

logger = setup_logger(__name__)

class APIFuzzer:
    def __init__(self):
        self.http_client = HTTPClient()
        self.findings = []
        
        # Payloads for different vulnerability types
        self.payloads = {
            "sql_injection": [
                "' OR '1'='1", "' UNION SELECT NULL--", "admin'--", 
                "' OR 1=1--", "1; DROP TABLE users"
            ],
            "xss": [
                "<script>alert('XSS')</script>", "\"><script>alert('XSS')</script>",
                "javascript:alert('XSS')", "onload=alert('XSS')"
            ],
            "path_traversal": [
                "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
            ],
            "command_injection": [
                "; ls -la", "| whoami", "&& id"
            ],
            "idor": [
                "../user/1", "./admin/../user/2", "user/0"
            ]
        }
    
    def test_parameter(self, url, param_name, param_value, payload, payload_type, method="GET"):
        """Test a single parameter with a payload"""
        try:
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            query_params = parse_qs(parsed_url.query)
            
            # Replace the parameter value with payload
            query_params[param_name] = [payload]
            
            # Build new URL with fuzzed parameter
            new_query = "&".join([f"{k}={v[0]}" for k, v in query_params.items()])
            fuzzed_url = f"{base_url}?{new_query}"
            
            response = self.http_client.get(fuzzed_url)
            
            # Check for vulnerabilities
            vuln_info = self.check_response(response, payload_type, payload, param_name, url, method)
            if vuln_info:
                self.findings.append(vuln_info)
                return vuln_info
            
        except Exception as e:
            logger.error(f"Error testing {url}: {str(e)}")
        return None
    
    def check_response(self, response, payload_type, payload, param_name, url, method):
        """Check response for vulnerability indicators"""
        text = response.text.lower()
        
        # SQL Injection detection
        if payload_type == "sql_injection" and any(error in text for error in [
            "sql syntax", "mysql_fetch", "ora-01756", "postgresql"
        ]):
            return {
                "type": "SQL Injection",
                "url": url,
                "parameter": param_name,
                "method": method,
                "payload": payload,
                "evidence": "SQL error in response",
                "severity": "High"
            }
        
        # XSS detection
        if payload_type == "xss" and response.status_code == 200 and payload in response.text:
            return {
                "type": "XSS",
                "url": url,
                "parameter": param_name,
                "method": method,
                "payload": payload,
                "evidence": "XSS payload reflected in response",
                "severity": "Medium"
            }
        
        # Path Traversal detection
        if payload_type == "path_traversal" and any(indicator in text for indicator in [
            "root:", "daemon:", "/bin/bash", "etc/passwd"
        ]):
            return {
                "type": "Path Traversal",
                "url": url,
                "parameter": param_name,
                "method": method,
                "payload": payload,
                "evidence": "Sensitive file content in response",
                "severity": "High"
            }
        
        # Command Injection detection
        if payload_type == "command_injection" and any(indicator in text for indicator in [
            "bin/bash", "www/html", "permission denied", "cannot access"
        ]):
            return {
                "type": "Command Injection",
                "url": url,
                "parameter": param_name,
                "method": method,
                "payload": payload,
                "evidence": "Command output in response",
                "severity": "High"
            }
        
        return None
    
    def fuzz_endpoint(self, endpoint):
        """Fuzz a single endpoint"""
        logger.info(f"Fuzzing endpoint: {endpoint}")
        findings = []
        
        # Parse URL to get parameters
        parsed_url = urlparse(endpoint)
        if not parsed_url.query:
            return findings
        
        query_params = parse_qs(parsed_url.query)
        
        # Test each parameter with each payload type
        for param_name in query_params.keys():
            for payload_type, payload_list in self.payloads.items():
                for payload in payload_list:
                    try:
                        vuln_info = self.test_parameter(endpoint, param_name, query_params[param_name][0], payload, payload_type)
                        if vuln_info:
                            findings.append(vuln_info)
                            logger.warning(f"Vulnerability found: {vuln_info['type']} at {endpoint}")
                    except:
                        pass
        
        return findings
    
    def fuzz_endpoints(self, endpoints, max_threads=10):
        """Fuzz multiple endpoints with threading"""
        logger.info(f"Fuzzing {len(endpoints)} endpoints")
        all_findings = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_endpoint = {
                executor.submit(self.fuzz_endpoint, endpoint): endpoint for endpoint in endpoints
            }
            
            for future in concurrent.futures.as_completed(future_to_endpoint):
                endpoint = future_to_endpoint[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as e:
                    logger.error(f"Error fuzzing {endpoint}: {str(e)}")
        
        logger.info(f"Fuzzing completed. Found {len(all_findings)} vulnerabilities")
        return all_findings