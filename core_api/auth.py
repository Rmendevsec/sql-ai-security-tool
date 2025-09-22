"""
Authentication Tester - Tests authentication mechanisms
"""

import re
import base64
from urllib.parse import urljoin
from utils.http_client import HTTPClient
from utils.logger import setup_logger

logger = setup_logger(__name__)

class AuthTester:
    def __init__(self):
        self.http_client = HTTPClient()
        self.findings = []
    
    def test_basic_auth(self, url):
        """Test Basic Authentication vulnerabilities"""
        findings = []
        
        # Test with empty credentials
        try:
            response = self.http_client.get(url, auth=('', ''))
            if response.status_code == 200:
                findings.append({
                    "type": "Basic Auth Bypass",
                    "url": url,
                    "method": "GET",
                    "params": {"username": "", "password": ""},
                    "evidence": "Empty credentials accepted",
                    "severity": "High"
                })
                logger.warning(f"Basic Auth bypass at {url}")
        except:
            pass
        
        # Test with common credentials
        common_creds = [
            ('admin', 'admin'), ('admin', 'password'), ('root', 'root'),
            ('test', 'test'), ('user', 'user'), ('guest', 'guest')
        ]
        
        for username, password in common_creds:
            try:
                response = self.http_client.get(url, auth=(username, password))
                if response.status_code == 200:
                    findings.append({
                        "type": "Weak Basic Auth Credentials",
                        "url": url,
                        "method": "GET",
                        "params": {"username": username, "password": password},
                        "evidence": f"Accepted credentials: {username}:{password}",
                        "severity": "High"
                    })
                    logger.warning(f"Weak Basic Auth credentials at {url}: {username}:{password}")
                    break
            except:
                pass
        
        return findings
    
    def test_jwt(self, token):
        """Test JWT tokens for vulnerabilities"""
        findings = []
        
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return findings
            
            # Decode header without verification
            header = base64.urlsafe_b64decode(parts[0] + '==').decode()
            
            # Check for none algorithm
            if '"alg":"none"' in header or "'alg':'none'" in header:
                findings.append({
                    "type": "JWT Algorithm None",
                    "url": "JWT Token",
                    "method": "N/A",
                    "params": {"token": token[:50] + "..."},
                    "evidence": "JWT uses 'none' algorithm",
                    "severity": "High"
                })
                logger.warning("JWT with 'none' algorithm found")
        
        except:
            pass
        
        return findings
    
    def test_api_key(self, url):
        """Test API key authentication"""
        findings = []
        
        # Test with empty API key
        try:
            response = self.http_client.get(f"{url}?api_key=")
            if response.status_code == 200:
                findings.append({
                    "type": "API Key Bypass",
                    "url": url,
                    "method": "GET",
                    "params": {"api_key": ""},
                    "evidence": "Empty API key accepted",
                    "severity": "High"
                })
                logger.warning(f"API Key bypass at {url}")
        except:
            pass
        
        return findings
    
    def test_login_endpoints(self, base_url):
        """Test login endpoints for vulnerabilities"""
        findings = []
        login_endpoints = [
            "/api/login", "/login", "/auth", "/api/auth", 
            "/oauth/token", "/signin", "/api/signin"
        ]
        
        common_logins = [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "test", "password": "test"},
            {"username": "user", "password": "user"},
            {"email": "admin@example.com", "password": "admin"}
        ]
        
        for endpoint in login_endpoints:
            url = urljoin(base_url, endpoint)
            
            for credentials in common_logins:
                try:
                    response = self.http_client.post(url, json=credentials)
                    if response.status_code == 200 and ("token" in response.text or "success" in response.text.lower()):
                        findings.append({
                            "type": "Weak Login Credentials",
                            "url": url,
                            "method": "POST",
                            "params": credentials,
                            "evidence": f"Accepted weak credentials: {credentials}",
                            "severity": "High"
                        })
                        logger.warning(f"Weak credentials accepted at {url}: {credentials}")
                        break
                except:
                    pass
        
        return findings
    
    def test_all(self, base_url, endpoints):
        """Run all authentication tests"""
        logger.info("Running authentication tests")
        findings = []
        
        # Test login endpoints
        findings.extend(self.test_login_endpoints(base_url))
        
        # Test each endpoint for auth vulnerabilities
        for endpoint in endpoints:
            findings.extend(self.test_basic_auth(endpoint))
            findings.extend(self.test_api_key(endpoint))
            
            # Check for JWT tokens in responses
            try:
                response = self.http_client.get(endpoint)
                jwt_pattern = r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
                tokens = re.findall(jwt_pattern, response.text)
                for token in tokens:
                    findings.extend(self.test_jwt(token))
            except:
                pass
        
        logger.info(f"Authentication testing completed. Found {len(findings)} issues")
        return findings