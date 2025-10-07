import requests
from urllib.parse import urljoin
import json
import base64

class AuthTester:
    def __init__(self, session):
        self.session = session
    
    def test_auth(self, base_url):
        """Test authentication endpoints with advanced techniques"""
        auth_endpoints = [
            "/api/login", "/login", "/auth", "/api/auth", "/oauth/token", "/signin",
            "/api/signin", "/api/vb1/login", "/api/v2/login", "/v1/auth", "/v2/auth"
        ]
        
        vulnerabilities = []
        
        for endpoint in auth_endpoints:
            test_url = urljoin(base_url, endpoint)
            
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
                        vulnerabilities.append({
                            "type": "Weak Credentials",
                            "url": test_url,
                            "method": "POST",
                            "params": credentials,
                            "evidence": f"Accepted weak credentials: {credentials}",
                            "severity": "High"
                        })
                except:
                    pass
            
            test_usernames = ["admin", "administrator", "root", "test", "user", "guest"]
            for username in test_usernames:
                try:
                    response = self.session.post(test_url, json={"username": username, "password": "invalid_password_123!"}, timeout=10)
                    if "invalid password" in response.text.lower() or "incorrect password" in response.text.lower():
                        vulnerabilities.append({
                            "type": "Username Enumeration",
                            "url": test_url,
                            "method": "POST",
                            "params": {"username": username},
                            "evidence": f"Username enumeration possible: {username}",
                            "severity": "Medium"
                        })
                except:
                    pass
            
            for i in range(10):
                try:
                    response = self.session.post(test_url, json={"username": "admin", "password": f"wrong_password_{i}"}, timeout=5)
                    if "locked" in response.text.lower() or "try again later" in response.text.lower():
                        vulnerabilities.append({
                            "type": "Account Lockout",
                            "url": test_url,
                            "method": "POST",
                            "params": {"attempts": i+1},
                            "evidence": f"Account lockout after {i+1} attempts",
                            "severity": "Low"
                        })
                        break
                except:
                    pass
        
        return vulnerabilities
    
    def test_jwt_vulnerabilities(self, jwt_tokens):
        """Test extracted JWT tokens for vulnerabilities"""
        vulnerabilities = []
        
        for token in jwt_tokens:
            try:
                parts = token.split('.')
                if len(parts) != 3:
                    continue
                    
                header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode())
                if header.get('alg') == 'none':
                    vulnerabilities.append({
                        "type": "JWT Algorithm None",
                        "url": "JWT Token",
                        "method": "N/A",
                        "params": {"token": token},
                        "evidence": "JWT uses 'none' algorithm which can be exploited",
                        "severity": "High"
                    })
            except:
                pass
            
            weak_secrets = ["secret", "password", "123456", "qwerty", "admin", "test", "key", "changeme"]
            for secret in weak_secrets:
                try:
                    import jwt
                    jwt.decode(token, secret, algorithms=['HS256'])
                    vulnerabilities.append({
                        "type": "JWT Weak Secret",
                        "url": "JWT Token",
                        "method": "N/A",
                        "params": {"token": token, "secret": secret},
                        "evidence": f"JWT can be decoded with weak secret: {secret}",
                        "severity": "High"
                    })
                    break
                except:
                    continue
        
        return vulnerabilities
    
    def test_cors(self, base_url, endpoints):
        """Test for CORS misconfigurations with advanced techniques"""
        vulnerabilities = []
        
        test_endpoints = endpoints + [base_url]
        
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
                        
                        vulnerabilities.append(vulnerability)
                except:
                    pass
        
        return vulnerabilities