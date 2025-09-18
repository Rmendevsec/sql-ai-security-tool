import json
import time
from urllib.parse import urljoin
from ..utils.http_client import HTTPClient
from ..utils.logger import Logger

class APIFuzzer:
    def __init__(self):
        self.logger = Logger(__name__)
        self.http_client = HTTPClient()
        self.vulnerabilities = []
    
    def load_payloads(self, payload_file="payloads/api_fuzz_payloads.json"):
        """Load fuzzing payloads from file"""
        try:
            with open(payload_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading payloads: {str(e)}")
            return {
                "sql_injection": ["' OR '1'='1", "' UNION SELECT NULL--", "1; DROP TABLE users"],
                "xss": ["<script>alert('XSS')</script>", "\"><script>alert('XSS')</script>"],
                "path_traversal": ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"],
                "command_injection": ["; ls -la", "| cat /etc/passwd", "&& whoami"],
                "idor": ["../user/1", "./admin/../user/2", "user/12345"]
            }
    
    def fuzz_parameter(self, url, param, payloads, method="GET"):
        """Fuzz a specific parameter with payloads"""
        results = []
        
        for payload_name, payload_list in payloads.items():
            for payload in payload_list:
                try:
                    # Prepare the request based on method
                    if method.upper() == "GET":
                        # For GET requests, add payload to query parameters
                        parsed_url = urlparse(url)
                        query_params = parse_qs(parsed_url.query)
                        query_params[param] = payload
                        
                        # Rebuild URL with fuzzed parameter
                        fuzzed_url = parsed_url._replace(query=None).geturl()
                        first_param = True
                        for key, values in query_params.items():
                            for value in values:
                                fuzzed_url += "?" if first_param else "&"
                                fuzzed_url += f"{key}={value}"
                                first_param = False
                        
                        response = self.http_client.get(fuzzed_url)
                    
                    else:
                        # For POST/PUT requests, add payload to body
                        if method.upper() in ["POST", "PUT"]:
                            data = {param: payload}
                            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                            response = self.http_client.request(method, url, data=data, headers=headers)
                        else:
                            self.logger.warning(f"Method {method} not supported for parameter fuzzing")
                            continue
                    
                    # Analyze response for potential vulnerabilities
                    vuln_info = self.analyze_response(response, payload_name, payload, param, url, method)
                    if vuln_info:
                        results.append(vuln_info)
                    
                    # Be polite with delay between requests
                    time.sleep(0.1)
                    
                except Exception as e:
                    self.logger.error(f"Error fuzzing {param} with {payload}: {str(e)}")
        
        return results
    
    def analyze_response(self, response, payload_type, payload, param, url, method):
        """Analyze response for potential vulnerabilities"""
        vuln_info = None
        
        # SQL Injection detection
        if payload_type == "sql_injection":
            sql_errors = [
                "sql syntax", "mysql_fetch", "ORA-01756", 
                "Microsoft OLE DB Provider", "PostgreSQL query failed"
            ]
            
            if any(error in response.text.lower() for error in sql_errors):
                vuln_info = {
                    "type": "SQL Injection",
                    "url": url,
                    "parameter": param,
                    "method": method,
                    "payload": payload,
                    "evidence": "SQL error in response",
                    "severity": "High"
                }
        
        # XSS detection
        elif payload_type == "xss":
            if payload in response.text and response.status_code in [200, 201]:
                vuln_info = {
                    "type": "XSS",
                    "url": url,
                    "parameter": param,
                    "method": method,
                    "payload": payload,
                    "evidence": "Payload reflected in response",
                    "severity": "Medium"
                }
        
        # Path Traversal detection
        elif payload_type == "path_traversal":
            if any(indicator in response.text for indicator in ["root:", "daemon:", "/bin/bash"]):
                vuln_info = {
                    "type": "Path Traversal",
                    "url": url,
                    "parameter": param,
                    "method": method,
                    "payload": payload,
                    "evidence": "Sensitive file content in response",
                    "severity": "High"
                }
        
        # Command Injection detection
        elif payload_type == "command_injection":
            command_indicators = [
                "bin/bash", "www/html", "etc/passwd", "Permission denied",
                "cannot access", "No such file or directory"
            ]
            
            if any(indicator in response.text for indicator in command_indicators):
                vuln_info = {
                    "type": "Command Injection",
                    "url": url,
                    "parameter": param,
                    "method": method,
                    "payload": payload,
                    "evidence": "Command output in response",
                    "severity": "High"
                }
        
        return vuln_info
    
    def fuzz_endpoint(self, endpoint, method="GET"):
        """Fuzz a single endpoint with all payloads"""
        self.logger.info(f"Fuzzing {method} {endpoint}")
        
        results = []
        payloads = self.load_payloads()
        
        # Parse URL to identify parameters
        parsed_url = urlparse(endpoint)
        query_params = parse_qs(parsed_url.query)
        
        # Fuzz each parameter
        for param in query_params.keys():
            param_results = self.fuzz_parameter(endpoint, param, payloads, method)
            results.extend(param_results)
        
        # Also test for IDOR if endpoint has numeric IDs in path
        if any(str(i) in endpoint for i in range(10)):
            for payload in payloads.get("idor", []):
                try:
                    # Replace potential ID values in path
                    fuzzed_url = re.sub(r'/\d+/', f'/{payload}/', endpoint)
                    fuzzed_url = re.sub(r'/\d+$', f'/{payload}', fuzzed_url)
                    
                    response = self.http_client.request(method, fuzzed_url)
                    
                    # If we get a successful response for unauthorized resource
                    if response.status_code in [200, 201]:
                        vuln_info = {
                            "type": "IDOR",
                            "url": fuzzed_url,
                            "parameter": "path",
                            "method": method,
                            "payload": payload,
                            "evidence": f"Access to resource {payload} returned {response.status_code}",
                            "severity": "Medium"
                        }
                        results.append(vuln_info)
                        
                except Exception as e:
                    self.logger.error(f"Error testing IDOR on {endpoint}: {str(e)}")
        
        return results