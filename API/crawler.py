import requests
import re
import json
import base64
from urllib.parse import urljoin
import requests
import random
import string
import hashlib
from urllib.parse import urljoin
from difflib import SequenceMatcher
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
    
def random_path():
    return "/.notfound-" + "".join(random.choices(string.ascii_letters + string.digits, k=16))

def text_similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()

def is_endpoint_alive(session: requests.Session, url: str, timeout=8, similarity_threshold=0.90):
    """
    Determine if an endpoint 'exists' with robust heuristics.
    Returns (exists: bool, info: dict)
    """
    info = {"url": url, "status": None, "final_url": None, "content_type": None,
            "content_length": None, "reason": [], "similarity": None}

    try:
        # 1) HEAD first (cheaper)
        try:
            head = session.head(url, allow_redirects=True, timeout=timeout)
            info["status"] = head.status_code
            info["final_url"] = head.url
            info["content_type"] = head.headers.get("Content-Type", "")
            info["content_length"] = int(head.headers.get("Content-Length", 0) or 0)
        except requests.RequestException:
            head = None

        # If HEAD gives clear 2xx/3xx -> consider present (but still fetch GET for body if needed)
        if head and 200 <= head.status_code < 400:
            info["reason"].append(f"HEAD returned {head.status_code}")
            # do a lightweight GET to inspect body when needed for catch-all detection
            resp = session.get(url, allow_redirects=True, timeout=timeout)
            info["status"] = resp.status_code
            info["final_url"] = resp.url
            info["content_type"] = resp.headers.get("Content-Type", "")
            body = resp.text or ""
        else:
            # HEAD was not useful -> do GET
            resp = session.get(url, allow_redirects=True, timeout=timeout)
            info["status"] = resp.status_code
            info["final_url"] = resp.url
            info["content_type"] = resp.headers.get("Content-Type", "")
            body = resp.text or ""

        # Interpret status codes
        code = info["status"]
        if code is None:
            return False, {**info, "reason": ["no response"]}

        if 200 <= code < 300:
            info["reason"].append(f"status {code} (2xx)")
            likely_present = True
        elif 300 <= code < 400:
            info["reason"].append(f"redirected {code}")
            likely_present = True
        elif code in (401, 403, 429):  # protected or rate-limited
            info["reason"].append(f"protected or rate-limited: {code}")
            likely_present = True
        elif code in (404, 410):
            info["reason"].append(f"not found: {code}")
            return False, info
        else:
            # 5xx or other codes: reachable but unstable
            info["reason"].append(f"server error or unknown code: {code}")
            likely_present = True

        # Baseline/differential check to avoid catch-all false positives
        # Only perform baseline if we got 2xx and a body (and site isn't obviously JSON API)
        if body is not None and len(body) > 0:
            # fetch baseline nonexistent path from same host
            base = url
            try:
                rand = random_path()
                base_host = url.split("/", 3)[:3]
                base_url = urljoin(url, rand)
                bresp = session.get(base_url, allow_redirects=True, timeout=timeout)
                base_body = bresp.text or ""
                sim = text_similarity(body, base_body)
                info["similarity"] = sim
                if sim >= similarity_threshold:
                    info["reason"].append(f"body similar to baseline (sim={sim:.3f}) -> likely catch-all")
                    return False, info
            except requests.RequestException:
                # baseline failed; ignore baseline check
                pass

        # Content-type heuristics: prefer JSON for API endpoints
        ct = info.get("content_type", "") or ""
        if "application/json" in ct or ct.endswith("+json"):
            info["reason"].append("content-type indicates JSON API")
            likely_present = True

        # Keyword heuristics: look for API or swagger markers
        lower_body = (body or "").lower()
        if any(k in lower_body for k in ("openapi", "swagger", "\"paths\"", "\"components\"")):
            info["reason"].append("openapi/swagger detected in body")
            likely_present = True

        # Final decision: require likely_present True
        return bool(likely_present), info

    except Exception as e:
        info["reason"].append(f"exception: {e}")
        return False, info