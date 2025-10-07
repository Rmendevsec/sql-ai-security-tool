import re
import json
import base64

class Parser:
    def __init__(self):
        self.jwt_tokens = []
        self.sensitive_data = []
    
    def extract_jwt_tokens(self, response):
        """Extract JWT tokens from response"""
        jwt_pattern = r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
        matches = re.findall(jwt_pattern, response.text)
        for token in matches:
            if token not in self.jwt_tokens:
                self.jwt_tokens.append(token)
        
        for header, value in response.headers.items():
            if 'auth' in header.lower() or 'token' in header.lower() or 'jwt' in header.lower():
                matches = re.findall(jwt_pattern, value)
                for token in matches:
                    if token not in self.jwt_tokens:
                        self.jwt_tokens.append(token)
        
        return self.jwt_tokens
    
    def extract_sensitive_data(self, response, url):
        """Extract API keys and sensitive data from response"""
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
                if not any(match in sd['value'] for sd in self.sensitive_data):
                    self.sensitive_data.append({
                        'type': data_type,
                        'value': match,
                        'url': url
                    })
        
        for header, value in response.headers.items():
            if any(keyword in header.lower() for keyword in ['key', 'token', 'secret', 'password', 'credential']):
                if value and len(value) > 10:
                    self.sensitive_data.append({
                        'type': f'Header_{header}',
                        'value': value,
                        'url': url
                    })
        
        return self.sensitive_data
    
    def get_jwt_tokens(self):
        """Return extracted JWT tokens"""
        return self.jwt_tokens
    
    def get_sensitive_data(self):
        """Return extracted sensitive data"""
        return self.sensitive_data