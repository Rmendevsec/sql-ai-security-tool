import sys
import requests
import os 
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from crawler import Crawler
from parser import Parser
from fuzzer import Fuzzer
from auth import AuthTester
from report import ReportGenerator


class AdvancedAPITester:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Advanced-API-Tester/1.0',
            'Accept': 'application/json, */*'
        })
        
        self.crawler = Crawler(self.session)
        self.parser = Parser()
        self.fuzzer = Fuzzer(self.session)
        self.auth_tester = AuthTester(self.session)
        self.reporter = ReportGenerator()
        
        self.vulnerabilities = []
        # Keep track of tested (method, url) pairs so each method is tested separately
        self.tested_endpoints = set()
        self.sensitive_data = []
    
    def test_endpoint(self, url, method="GET", params=None, headers=None, data=None):
        """Test a single endpoint for vulnerabilities"""
        key = (method.upper(), url)
        if key in self.tested_endpoints:
            return None
        self.tested_endpoints.add(key)
        
        self.crawler.print_status(f"Testing {method} {url}", "info")
        
        try:
            m = method.upper()
            if m == "GET":
                response = self.session.get(url, timeout=10, params=params, headers=headers)
            elif m == "POST":
                response = self.session.post(url, timeout=10, json=data, params=params, headers=headers)
            elif m == "PUT":
                response = self.session.put(url, timeout=10, json=data, params=params, headers=headers)
            elif m == "DELETE":
                response = self.session.delete(url, timeout=10, params=params, headers=headers)
            elif m == "PATCH":
                response = self.session.patch(url, timeout=10, json=data, params=params, headers=headers)
            elif m == "HEAD":
                response = self.session.head(url, timeout=10, params=params, headers=headers)
            elif m == "OPTIONS":
                response = self.session.options(url, timeout=10, params=params, headers=headers)
            else:
                return None
            
            # Extract data
            self.parser.extract_jwt_tokens(response)
            sensitive_data = self.parser.extract_sensitive_data(response, url)
            self.sensitive_data.extend(sensitive_data)
            
            # Check for vulnerabilities
            # For fuzzing/checking we pass params if present else data if present else empty dict
            check_payload = params if params is not None else (data if data is not None else {})
            vulns = self.fuzzer.check_vulnerabilities(response, url, method, check_payload)
            self.vulnerabilities.extend(vulns)
            
            return response
            
        except requests.exceptions.RequestException as e:
            self.crawler.print_status(f"Error testing {url}: {str(e)}", "error")
            return None
    
    def scan(self, target_url):
        """Main scanning function"""
        self.crawler.print_status(f"Starting advanced scan of {target_url}", "info")
        
        # Discover endpoints
        endpoints = self.crawler.find_endpoints(target_url)
        endpoints.append(target_url)
        
        # Test authentication
        auth_vulns = self.auth_tester.test_auth(target_url)
        self.vulnerabilities.extend(auth_vulns)
        
        # Test CORS
        cors_vulns = self.auth_tester.test_cors(target_url, endpoints)
        self.vulnerabilities.extend(cors_vulns)
        
        # Test each endpoint
        for endpoint in endpoints:
            for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]:
                # test without body / params
                self.test_endpoint(endpoint, method)
                
                # For methods that commonly accept a body, also test with typical payload
                if method in ["POST", "PUT", "PATCH"]:
                    test_data = {"test": "payload", "id": 1, "name": "test", "email": "test@example.com"}
                    self.test_endpoint(endpoint, method, data=test_data)
            
            # If endpoint has query params, fuzz them
            if '?' in endpoint:
                fuzz_vulns = self.fuzzer.fuzz_parameters(endpoint)
                self.vulnerabilities.extend(fuzz_vulns)
        
        # Test JWT vulnerabilities
        jwt_tokens = self.parser.get_jwt_tokens()
        jwt_vulns = self.auth_tester.test_jwt_vulnerabilities(jwt_tokens)
        self.vulnerabilities.extend(jwt_vulns)
        
        # Generate report
        sensitive_data = self.parser.get_sensitive_data()
        self.reporter.generate_report(self.vulnerabilities, sensitive_data)


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
