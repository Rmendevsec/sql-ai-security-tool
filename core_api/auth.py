import json
import jwt
import time
from base64 import b64decode
from ..utils.http_client import HTTPClient
from ..utils.logger import Logger

class AuthTester:
    def __init__(self):
        self.logger = Logger(__name__)
        self.http_client = HTTPClient()
    
    def test_jwt(self, token):
        """Test JWT tokens for common vulnerabilities"""
        issues = []
        
        try:
            # Decode without verification to inspect header and payload
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            
            self.logger.info(f"JWT Header: {json.dumps(header, indent=2)}")
            self.logger.info(f"JWT Payload: {json.dumps(payload, indent=2)}")
            
            # Check for none algorithm vulnerability
            if header.get('alg') == 'none':
                issues.append({
                    "type": "JWT Algorithm None",
                    "severity": "High",
                    "description": "JWT uses 'none' algorithm which can be exploited"
                })
            
            # Check for weak secret key
            weak_secrets = ["secret", "password", "123456", "qwerty", "admin"]
            for secret in weak_secrets:
                try:
                    jwt.decode(token, secret, algorithms=[header.get('alg', 'HS256')])
                    issues.append({
                        "type": "JWT Weak Secret",
                        "severity": "High",
                        "description": f"JWT can be decoded with weak secret: {secret}"
                    })
                    break
                except jwt.InvalidSignatureError:
                    continue
            
            # Check if token is expired
            if 'exp' in payload and payload['exp'] < time.time():
                issues.append({
                    "type": "JWT Expired",
                    "severity": "Low",
                    "description": "JWT token is expired"
                })
            
            # Check for sensitive data in payload
            sensitive_keys = ['password', 'secret', 'key', 'token', 'credit', 'ssn']
            for key in payload:
                if any(sensitive in key.lower() for sensitive in sensitive_keys):
                    issues.append({
                        "type": "JWT Sensitive Data",
                        "severity": "Medium",
                        "description": f"Sensitive data found in JWT payload: {key}"
                    })
        
        except Exception as e:
            self.logger.error(f"Error analyzing JWT: {str(e)}")
            issues.append({
                "type": "JWT Invalid",
                "severity": "Low",
                "description": f"JWT token appears to be invalid: {str(e)}"
            })
        
        return issues
    
    def test_basic_auth(self, url):
        """Test for basic authentication vulnerabilities"""
        issues = []
        
        # Test with empty credentials
        response = self.http_client.get(url, auth=('', ''))
        if response.status_code == 200:
            issues.append({
                "type": "Basic Auth Bypass",
                "severity": "High",
                "description": "Empty credentials accepted for basic authentication"
            })
        
        # Test with common credentials
        common_creds = [
            ('admin', 'admin'), ('admin', 'password'), ('root', 'root'),
            ('test', 'test'), ('user', 'user'), ('guest', 'guest')
        ]
        
        for username, password in common_creds:
            response = self.http_client.get(url, auth=(username, password))
            if response.status_code == 200:
                issues.append({
                    "type": "Basic Auth Weak Credentials",
                    "severity": "High",
                    "description": f"Accepted credentials: {username}:{password}"
                })
                break
        
        return issues
    
    def test_api_key(self, url, key_param="api_key"):
        """Test API key authentication"""
        issues = []
        
        # Test with empty API key
        response = self.http_client.get(f"{url}?{key_param}=")
        if response.status_code == 200:
            issues.append({
                "type": "API Key Bypass",
                "severity": "High",
                "description": "Empty API key was accepted"
            })
        
        # Test with common API key values
        common_keys = ["test", "123456", "api", "key", "secret", "demo"]
        for key in common_keys:
            response = self.http_client.get(f"{url}?{key_param}={key}")
            if response.status_code == 200:
                issues.append({
                    "type": "API Key Weak Value",
                    "severity": "Medium",
                    "description": f"Common API key value accepted: {key}"
                })
                break
        
        return issues
    
    def test_cors(self, url):
        """Test for CORS misconfigurations"""
        issues = []
        
        # Test with Origin header
        origins = [
            "https://evil.com",
            "http://localhost",
            "null",
            "https://" + "a" * 100 + ".com"
        ]
        
        for origin in origins:
            response = self.http_client.get(url, headers={'Origin': origin})
            
            # Check if ACAO header is present and reflects the origin
            acao = response.headers.get('Access-Control-Allow-Origin')
            if acao:
                if acao == origin or acao == '*':
                    issues.append({
                        "type": "CORS Misconfiguration",
                        "severity": "Medium" if acao == '*' else "Low",
                        "description": f"Potential CORS issue with Origin: {origin}, ACAO: {acao}"
                    })
        
        return issues