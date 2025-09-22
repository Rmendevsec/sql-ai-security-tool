"""
HTTP Client - Handles HTTP requests with retries and timeouts
"""

import requests
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class HTTPClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'APISecurityScanner/1.0',
            'Accept': 'application/json, */*'
        })
    
    def request(self, method, url, **kwargs):
        """Make HTTP request with error handling"""
        try:
            # Set defaults
            if 'timeout' not in kwargs:
                kwargs['timeout'] = 10
            if 'verify' not in kwargs:
                kwargs['verify'] = False
            
            response = self.session.request(method, url, **kwargs)
            return response
        
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request failed: {str(e)}")
    
    def get(self, url, **kwargs):
        return self.request('GET', url, **kwargs)
    
    def post(self, url, **kwargs):
        return self.request('POST', url, **kwargs)
    
    def put(self, url, **kwargs):
        return self.request('PUT', url, **kwargs)
    
    def delete(self, url, **kwargs):
        return self.request('DELETE', url, **kwargs)