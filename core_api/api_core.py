from .crawler import APICrawler
from .parser import APIParser
from .fuzzer import APIFuzzer
from .auth import AuthTester
from .report import APIReport
from ..utils.http_client import HTTPClient
from ..utils.logger import Logger

class APICore:
    def __init__(self):
        self.logger = Logger(__name__)
        self.http_client = HTTPClient()
        self.crawler = APICrawler()
        self.parser = APIParser()
        self.fuzzer = APIFuzzer()
        self.auth_tester = AuthTester()
        self.report = APIReport()
    
    def analyze(self, target_url):
        """Main analysis method"""
        self.logger.info(f"Starting API analysis for {target_url}")
        
        # Step 1: Crawl for endpoints
        endpoints = self.crawler.crawl(target_url)
        
        # Step 2: Check for API documentation
        try:
            response = self.http_client.get(target_url)
            docs_endpoints = self.parser.find_api_docs(response.text, target_url)
            
            for doc_url in docs_endpoints:
                self.logger.info(f"Found API documentation: {doc_url}")
                doc_response = self.http_client.get(doc_url)
                
                # Try to parse Swagger/OpenAPI
                if 'swagger' in doc_response.text or 'openapi' in doc_response.text:
                    api_endpoints = self.parser.parse_swagger(doc_response.text, target_url)
                    endpoints.extend([url for url, method in api_endpoints])
        except Exception as e:
            self.logger.error(f"Error checking for API docs: {str(e)}")
        
        # Step 3: Test authentication mechanisms
        auth_issues = self.auth_tester.test_basic_auth(target_url)
        for issue in auth_issues:
            self.report.add_finding(issue)
        
        # Step 4: Fuzz each endpoint
        for endpoint in endpoints:
            # Test for common HTTP methods
            for method in ['GET', 'POST', 'PUT', 'DELETE']:
                try:
                    # First check if the endpoint exists with this method
                    response = self.http_client.request(method, endpoint)
                    
                    if response.status_code < 400:  # If not client error
                        # Fuzz the endpoint
                        fuzz_results = self.fuzzer.fuzz_endpoint(endpoint, method)
                        for result in fuzz_results:
                            self.report.add_finding(result)
                
                except Exception as e:
                    self.logger.error(f"Error testing {method} {endpoint}: {str(e)}")
        
        self.logger.info(f"Analysis completed. Found {len(self.report.findings)} issues.")
        
        return self.report