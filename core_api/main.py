#!/usr/bin/env python3
"""
Simple API Security Tester
A lightweight tool to test APIs for common security vulnerabilities
"""

import requests
import json
import sys
import time
from urllib.parse import urljoin, urlparse

# Color codes for output
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

class SimpleAPITester:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Simple-API-Tester/1.0',
            'Accept': 'application/json'
        })
        self.vulnerabilities = []
        self.tested_endpoints = set()
        self.payloads = {
            "sql_injection": ["' OR '1'='1", "' UNION SELECT NULL--", "admin'--", "' OR 1=1--"],
            "xss": ["<script>alert('XSS')</script>", "\"><script>alert('XSS')</script>"],
            "path_traversal": ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"],
            "cmdi": ["; ls -la", "| whoami", "&& id"],
            "idor": ["../user/1", "./admin/../user/2", "user/0"]
        }
    
    def print_status(self, message, status="info"):
        """Print colored status messages"""
        if status == "info":
            print(f"{Colors.BLUE}[+] {message}{Colors.END}")
        elif status == "success":
            print(f"{Colors.GREEN}[+] {message}{Colors.END}")
        elif status == "warning":
            print(f"{Colors.YELLOW}[!] {message}{Colors.END}")
        elif status == "error":
            print(f"{Colors.RED}[!] {message}{Colors.END}")
        elif status == "vuln":
            print(f"{Colors.RED}{Colors.BOLD}[VULN] {message}{Colors.END}")
    
    def test_endpoint(self, url, method="GET", params=None):
        """Test a single endpoint for vulnerabilities"""
        if url in self.tested_endpoints:
            return
        self.tested_endpoints.add(url)
        
        self.print_status(f"Testing {method} {url}", "info")
        
        try:
            # Test HTTP methods
            if method.upper() == "GET":
                response = self.session.get(url, timeout=10, params=params)
            elif method.upper() == "POST":
                response = self.session.post(url, timeout=10, json=params)
            elif method.upper() == "PUT":
                response = self.session.put(url, timeout=10, json=params)
            elif method.upper() == "DELETE":
                response = self.session.delete(url, timeout=10)
            else:
                return
            
            # Check for common vulnerabilities based on response
            self.check_vulnerabilities(response, url, method, params)
            
        except requests.exceptions.RequestException as e:
            self.print_status(f"Error testing {url}: {str(e)}", "error")
    
    def check_vulnerabilities(self, response, url, method, params):
        """Check response for signs of vulnerabilities"""
        text = response.text.lower()
        
        # SQL Injection detection
        if any(error in text for error in ["sql syntax", "mysql_fetch", "ora-01756", "postgresql"]):
            self.vulnerabilities.append({
                "type": "SQL Injection",
                "url": url,
                "method": method,
                "params": params,
                "evidence": "SQL error in response",
                "severity": "High"
            })
            self.print_status(f"SQL Injection vulnerability found at {url}", "vuln")
        
        # XSS detection
        if response.status_code == 200 and any(payload in response.text for payload in self.payloads["xss"]):
            self.vulnerabilities.append({
                "type": "XSS",
                "url": url,
                "method": method,
                "params": params,
                "evidence": "XSS payload reflected in response",
                "severity": "Medium"
            })
            self.print_status(f"XSS vulnerability found at {url}", "vuln")
        
        # Path Traversal detection
        if any(indicator in text for indicator in ["root:", "daemon:", "/bin/bash", "etc/passwd"]):
            self.vulnerabilities.append({
                "type": "Path Traversal",
                "url": url,
                "method": method,
                "params": params,
                "evidence": "Sensitive file content in response",
                "severity": "High"
            })
            self.print_status(f"Path Traversal vulnerability found at {url}", "vuln")
        
        # Command Injection detection
        if any(indicator in text for indicator in ["bin/bash", "www/html", "permission denied", "cannot access"]):
            self.vulnerabilities.append({
                "type": "Command Injection",
                "url": url,
                "method": method,
                "params": params,
                "evidence": "Command output in response",
                "severity": "High"
            })
            self.print_status(f"Command Injection vulnerability found at {url}", "vuln")
        
        # IDOR detection (if we can access other users' data)
        if "user" in url and response.status_code == 200:
            if any(indicator in text for indicator in ["email", "password", "admin", "user"]):
                self.vulnerabilities.append({
                    "type": "IDOR",
                    "url": url,
                    "method": method,
                    "params": params,
                    "evidence": "Sensitive data exposure",
                    "severity": "Medium"
                })
                self.print_status(f"IDOR vulnerability found at {url}", "vuln")
    
    def find_endpoints(self, base_url):
        """Try to discover API endpoints"""
        self.print_status(f"Discovering endpoints for {base_url}", "info")
        
        common_endpoints = [
            "/api/users", "/api/products", "/api/auth", "/api/login",
            "/api/admin", "/api/config", "/api/health", "/api/v1/users",
            "/user", "/admin", "/login", "/register", "/api", "/swagger",
            "/redoc", "/openapi", "/graphql", "/users", "/posts", "/comments"
        ]
        
        discovered = []
        
        for endpoint in common_endpoints:
            test_url = urljoin(base_url, endpoint)
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code < 400:  # Not 4xx or 5xx
                    discovered.append(test_url)
                    self.print_status(f"Found endpoint: {test_url}", "success")
            except:
                pass
        
        return discovered
    
    def test_auth(self, base_url):
        """Test authentication endpoints"""
        self.print_status("Testing authentication endpoints", "info")
        
        auth_endpoints = [
            "/api/login", "/login", "/auth", "/api/auth", "/oauth/token", "/signin"
        ]
        
        for endpoint in auth_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            # Test with common credentials
            common_logins = [
                {"username": "admin", "password": "admin"},
                {"username": "admin", "password": "password"},
                {"username": "test", "password": "test"},
                {"username": "user", "password": "user"},
                {"username": "root", "password": "root"},
                {"email": "admin@example.com", "password": "admin"},
                {"email": "test@example.com", "password": "test"}
            ]
            
            for credentials in common_logins:
                try:
                    response = self.session.post(test_url, json=credentials, timeout=10)
                    if response.status_code == 200 and ("token" in response.text or "success" in response.text.lower()):
                        self.vulnerabilities.append({
                            "type": "Weak Credentials",
                            "url": test_url,
                            "method": "POST",
                            "params": credentials,
                            "evidence": f"Accepted weak credentials: {credentials}",
                            "severity": "High"
                        })
                        self.print_status(f"Weak credentials accepted at {test_url}: {credentials}", "vuln")
                except:
                    pass
    
    def test_cors(self, base_url):
        """Test for CORS misconfigurations"""
        self.print_status("Testing CORS configurations", "info")
        
        test_endpoints = self.find_endpoints(base_url)
        test_endpoints.append(base_url)
        
        malicious_origins = [
            "https://evil.com",
            "http://attacker.com",
            "null",
            "https://" + "a" * 100 + ".com"
        ]
        
        for endpoint in test_endpoints:
            for origin in malicious_origins:
                try:
                    response = self.session.get(endpoint, timeout=5, headers={'Origin': origin})
                    acao = response.headers.get('Access-Control-Allow-Origin')
                    if acao == origin or acao == '*':
                        self.vulnerabilities.append({
                            "type": "CORS Misconfiguration",
                            "url": endpoint,
                            "method": "GET",
                            "params": {"Origin": origin},
                            "evidence": f"CORS allows origin: {acao}",
                            "severity": "Medium"
                        })
                        self.print_status(f"CORS misconfiguration at {endpoint} with origin {origin}", "vuln")
                except:
                    pass
    
    def fuzz_parameters(self, url):
        """Fuzz parameters with payloads"""
        self.print_status(f"Fuzzing parameters for {url}", "info")
        
        # Only test GET parameters for simplicity
        if '?' not in url:
            return
            
        base_url, query_string = url.split('?', 1)
        params = {}
        
        for param in query_string.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                params[key] = value
        
        # Test each parameter with payloads
        for param_name in params.keys():
            for payload_type, payload_list in self.payloads.items():
                for payload in payload_list:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        response = self.session.get(base_url, params=test_params, timeout=10)
                        self.check_vulnerabilities(response, base_url, "GET", test_params)
                        
                    except:
                        pass
    
    def scan(self, target_url):
        """Main scanning function"""
        self.print_status(f"Starting scan of {target_url}", "info")
        self.test_graphql(target_url)
        self.test_open_redirects(target_url)
        self.test_sensitive_info(target_url)
        self.test_rate_limit(target_url)
        # Discover endpoints
        endpoints = self.find_endpoints(target_url)
        endpoints.append(target_url)  # Also test the base URL
        
        # Test authentication
        self.test_auth(target_url)
        
        # Test CORS
        self.test_cors(target_url)
        
        # Test each endpoint with different HTTP methods
        for endpoint in endpoints:
            for method in ["GET", "POST", "PUT", "DELETE"]:
                self.test_endpoint(endpoint, method)
                
                # Test with parameters for POST/PUT
                if method in ["POST", "PUT"]:
                    test_params = {"test": "payload", "id": 1, "name": "test"}
                    self.test_endpoint(endpoint, method, test_params)
            
            # Fuzz parameters for GET endpoints
            if '?' in endpoint:
                self.fuzz_parameters(endpoint)
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate a simple vulnerability report"""
        print(f"\n{Colors.BLUE}{'='*60}{Colors.END}")
        print(f"{Colors.BLUE}{Colors.BOLD}API SECURITY SCAN REPORT{Colors.END}")
        print(f"{Colors.BLUE}{'='*60}{Colors.END}")
        
        if not self.vulnerabilities:
            self.print_status("No vulnerabilities found!", "success")
            return
        
        # Count vulnerabilities by severity
        high_count = sum(1 for v in self.vulnerabilities if v['severity'] == 'High')
        medium_count = sum(1 for v in self.vulnerabilities if v['severity'] == 'Medium')
        low_count = sum(1 for v in self.vulnerabilities if v['severity'] == 'Low')
        
        print(f"\n{Colors.BOLD}Summary:{Colors.END}")
        print(f"{Colors.RED}High: {high_count}{Colors.END}")
        print(f"{Colors.YELLOW}Medium: {medium_count}{Colors.END}")
        print(f"{Colors.BLUE}Low: {low_count}{Colors.END}")
        print(f"{Colors.BOLD}Total: {len(self.vulnerabilities)}{Colors.END}")
        
        self.print_status(f"\nFound {len(self.vulnerabilities)} vulnerabilities:", "warning")
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            color = Colors.RED if vuln['severity'] == 'High' else Colors.YELLOW if vuln['severity'] == 'Medium' else Colors.BLUE
            print(f"\n{color}{i}. {vuln['type']} ({vuln['severity']}){Colors.END}")
            print(f"   URL: {vuln['url']}")
            print(f"   Method: {vuln['method']}")
            if vuln.get('params'):
                print(f"   Parameters: {vuln['params']}")
            print(f"   Evidence: {vuln['evidence']}")

    def test_graphql(self, base_url):
        """Check for GraphQL introspection"""
        graphql_url = urljoin(base_url, "/graphql")
        self.print_status("Testing for GraphQL introspection", "info")
        
        query = {"query": "{ __schema { types { name } } }"}
        try:
            response = self.session.post(graphql_url, json=query, timeout=10)
            if "types" in response.text and response.status_code == 200:
                self.vulnerabilities.append({
                    "type": "GraphQL Introspection",
                    "url": graphql_url,
                    "method": "POST",
                    "params": query,
                    "evidence": "Introspection query succeeded",
                    "severity": "High"
                })
                self.print_status(f"GraphQL introspection enabled at {graphql_url}", "vuln")
        except:
            pass

    def test_open_redirects(self, base_url):
        """Check for open redirects"""
        self.print_status("Testing for open redirects", "info")
        redirect_params = ["next", "url", "redirect", "redirect_uri", "return"]
        evil_url = "https://evil.com"
        
        for param in redirect_params:
            test_url = f"{base_url}?{param}={evil_url}"
            try:
                response = self.session.get(test_url, allow_redirects=False, timeout=10)
                loc = response.headers.get("Location", "")
                if evil_url in loc:
                    self.vulnerabilities.append({
                        "type": "Open Redirect",
                        "url": test_url,
                        "method": "GET",
                        "params": {param: evil_url},
                        "evidence": f"Redirects to attacker: {loc}",
                        "severity": "Medium"
                    })
                    self.print_status(f"Open Redirect vulnerability at {test_url}", "vuln")
            except:
                pass

    def test_sensitive_info(self, base_url):
        """Look for sensitive information in responses"""
        self.print_status("Scanning for sensitive info exposure", "info")
        endpoints = self.find_endpoints(base_url)
        
        api_key_patterns = ["api_key", "apiKey", "AIza", "sk_live_", "Bearer "]
        private_key_patterns = ["-----BEGIN PRIVATE KEY-----", "ssh-rsa", "BEGIN RSA PRIVATE KEY"]
        
        for endpoint in endpoints:
            try:
                response = self.session.get(endpoint, timeout=10)
                for pattern in api_key_patterns + private_key_patterns:
                    if pattern.lower() in response.text.lower():
                        self.vulnerabilities.append({
                            "type": "Sensitive Data Exposure",
                            "url": endpoint,
                            "method": "GET",
                            "params": None,
                            "evidence": f"Found pattern: {pattern}",
                            "severity": "High"
                        })
                        self.print_status(f"Sensitive info found at {endpoint}: {pattern}", "vuln")
            except:
                pass

    def test_rate_limit(self, base_url):
        """Check for missing rate limiting"""
        self.print_status("Testing rate limiting on login endpoints", "info")
        login_url = urljoin(base_url, "/login")
        test_creds = {"username": "admin", "password": "wrongpassword"}
        
        try:
            responses = []
            for _ in range(5):
                r = self.session.post(login_url, json=test_creds, timeout=5)
                responses.append(r.status_code)
                time.sleep(0.5)
            
            if all(code == responses[0] for code in responses):
                self.vulnerabilities.append({
                    "type": "Missing Rate Limiting",
                    "url": login_url,
                    "method": "POST",
                    "params": test_creds,
                    "evidence": f"Same response for multiple failed logins: {responses}",
                    "severity": "Medium"
                })
                self.print_status("Rate limiting appears to be missing!", "vuln")
        except:
            pass

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        print("Example: python simple_api_tester.py https://api.example.com")
        print("Example: python simple_api_tester.py http://localhost:8000")
        sys.exit(1)
    
    target_url = sys.argv[1]
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    tester = SimpleAPITester()
    tester.scan(target_url)

if __name__ == "__main__":
    main()

