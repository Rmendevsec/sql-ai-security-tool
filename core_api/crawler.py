import requests
import re
import json
import base64
from urllib.parse import urljoin

class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

class Crawler:
    def __init__(self, session):
        self.session = session
        self.discovered_endpoints = set()
    
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
                if response.status_code < 400:
                    discovered.append(test_url)
                    self.discovered_endpoints.add(test_url)
                    self.print_status(f"Found endpoint: {test_url}", "success")
            except:
                pass
        
        extensions = [".json", ".xml", ".yaml", ".yml", ".php", ".asp", ".aspx", ".jsp", ".txt", ".bak", ".old", ".backup"]
        for ext in extensions:
            test_url = urljoin(base_url, f"/api{ext}")
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code < 400:
                    discovered.append(test_url)
                    self.discovered_endpoints.add(test_url)
                    self.print_status(f"Found endpoint: {test_url}", "success")
            except:
                pass
        
        api_patterns = [
            "/api/{id}", "/users/{id}", "/products/{id}", "/v1/{resource}",
            "/v2/{resource}", "/{version}/users", "/{version}/products"
        ]
        
        test_ids = ["1", "123", "test", "admin", "user", "guest"]
        for pattern in api_patterns:
            for test_id in test_ids:
                test_url = urljoin(base_url, pattern.replace("{id}", test_id).replace("{resource}", "test").replace("{version}", "v1"))
                try:
                    response = self.session.get(test_url, timeout=5)
                    if response.status_code < 400:
                        discovered.append(test_url)
                        self.discovered_endpoints.add(test_url)
                        self.print_status(f"Found endpoint: {test_url}", "success")
                except:
                    pass
        
        return discovered
    
    def get_discovered_endpoints(self):
        """Return all discovered endpoints"""
        return list(self.discovered_endpoints)