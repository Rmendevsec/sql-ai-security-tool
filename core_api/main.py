import sys
import json
import time
import logging
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# Import your modules (assume classes exist as in your project)
from crawler import Crawler
from fuzzer import Fuzzer
from parser import Parser
from auth import AuthTester
from report import ReportGenerator

# Try to import optional helpers (if you added them)
try:
    from swagger_discovery import fetch_swagger_json, extract_examples_from_schema  # type: ignore
    SWAGGER_AVAILABLE = True
except Exception:
    SWAGGER_AVAILABLE = False

try:
    from graphql_discovery import introspect_graphql, extract_graphql_operations  # type: ignore
    GRAPHQL_AVAILABLE = True
except Exception:
    GRAPHQL_AVAILABLE = False

try:
    from executor import parallel_map  # type: ignore
    PARALLEL_AVAILABLE = True
except Exception:
    PARALLEL_AVAILABLE = False


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

class MainOrchestrator:
    def __init__(self, base_url: str, workers: int = 15, rate_per_sec: float = 30.0):
        self.base_url = base_url.rstrip('/')
        self.workers = workers
        self.rate_per_sec = rate_per_sec

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Telsem-Advanced-Scanner/1.0",
            "Accept": "application/json, */*"
        })

        # Core modules
        self.crawler = Crawler(self.session)
        self.fuzzer = Fuzzer(self.session)
        self.parser = Parser()
        self.auth_tester = AuthTester(self.session)
        self.reporter = ReportGenerator()

        # State
        self.discovered_endpoints = set()
        self.vulnerabilities = []
        self.sensitive_data = []

    def safe_url(self, url: str) -> str:
        if url.startswith("http://") or url.startswith("https://"):
            return url
        return urljoin(self.base_url + "/", url.lstrip("/"))

    def discover_with_crawler(self):
        logging.info("Running crawler endpoint discovery...")
        try:
            found = self.crawler.find_endpoints(self.base_url)
            for e in found:
                self.discovered_endpoints.add(e)
            logging.info(f"Crawler discovered {len(found)} endpoints.")
        except Exception as e:
            logging.warning(f"Crawler discovery failed: {e}")

    def discover_with_swagger(self):
        if not SWAGGER_AVAILABLE:
            logging.debug("Swagger discovery not available (module missing).")
            return []

        logging.info("Running Swagger/OpenAPI discovery...")
        try:
            endpoints, spec = fetch_swagger_json(self.base_url, self.session)
            if endpoints:
                for method, url in endpoints:
                    full = self.safe_url(url)
                    # store as tuple (METHOD, URL)
                    self.discovered_endpoints.add((method.upper(), full))
                logging.info(f"Swagger discovered {len(endpoints)} endpoints.")
            # extract example payloads too
            examples = extract_examples_from_schema(spec) if spec else []
            example_items = []
            for method, path, example_body in examples:
                full = self.safe_url(path)
                example_items.append((method.upper(), full, example_body))
            return example_items
        except Exception as e:
            logging.warning(f"Swagger discovery failed: {e}")
            return []

    def discover_with_graphql(self):
        if not GRAPHQL_AVAILABLE:
            logging.debug("GraphQL discovery not available (module missing).")
            return []

        logging.info("Running GraphQL introspection...")
        try:
            gql_url, schema = introspect_graphql(self.base_url, self.session)
            if not gql_url or not schema:
                logging.info("No GraphQL endpoint found.")
                return []
            ops = extract_graphql_operations(schema)
            items = []
            for qname, args in ops.get("queries", []):
                items.append(("POST", gql_url, {"query": f"query {{ {qname} }}"}))
            for mname, args in ops.get("mutations", []):
                items.append(("POST", gql_url, {"query": f"mutation {{ {mname} }}"}))
            logging.info(f"GraphQL discovered {len(items)} operations.")
            return items
        except Exception as e:
            logging.warning(f"GraphQL discovery failed: {e}")
            return []

    def build_test_items(self):
        """
        Build a list of (method, url, data) items to test.
        Items can be:
          - ("GET", "https://example.com/api/users", None)
          - ("POST", "https://example.com/api/create", {"name": "test"})
        """
        items = []

        # Normalize discovered endpoints from crawler: if plain string treat as GET
        for ep in list(self.discovered_endpoints):
            if isinstance(ep, tuple) and len(ep) >= 2:
                method, url = ep[0].upper(), ep[1]
                items.append((method, self.safe_url(url), None))
            else:
                items.append(("GET", self.safe_url(ep if isinstance(ep, str) else str(ep)), None))

        # include root target
        items.append(("GET", self.base_url, None))

        # optional: add common body tests for POST/PUT/PATCH endpoints guessed by names
        more = []
        for method, url, data in list(items):
            # if the path suggests resource creation, add a sample JSON body
            if any(k in url.lower() for k in ["/create", "/register", "/signup", "/users", "/orders", "/products"]):
                more.append(("POST", url, {"test": "payload", "id": 1, "name": "test"}))
                more.append(("PUT", url, {"test": "payload", "id": 1, "name": "test"}))
        items.extend(more)

        return items

    def test_endpoint(self, item):
        """
        Thread-safe test of a single item: (method, url, data)
        Returns response or None. Also updates parser/fuzzer/report lists.
        """
        method, url, data = item
        method = method.upper()
        try:
            if method == "GET":
                resp = self.session.get(url, timeout=10, params=None)
            else:
                resp = self.session.request(method, url, json=data, timeout=12)

            # parse tokens and sensitive data
            try:
                self.parser.extract_jwt_tokens(resp)
                found = self.parser.extract_sensitive_data(resp, url)
                if found:
                    self.sensitive_data.extend(found)
            except Exception as e:
                logging.debug(f"Parser error for {url}: {e}")

            # check vulnerabilities using fuzzer heuristics on the response
            try:
                payload = {} if data is None else data
                vulns = self.fuzzer.check_vulnerabilities(resp, url, method, payload)
                if vulns:
                    self.vulnerabilities.extend(vulns)
                    # optional: print immediate findings
                    for v in vulns:
                        self.reporter.print_status(f"Found {v['type']} at {v['url']} severity={v['severity']}", "vuln")
            except Exception as e:
                logging.debug(f"Fuzzer check error for {url}: {e}")

            return resp

        except requests.RequestException as e:
            logging.debug(f"Request failed for {method} {url}: {e}")
            return None

    def run_parallel(self, items):
        # Prefer user-provided parallel_map if available
        if PARALLEL_AVAILABLE:
            logging.info("Using executor.parallel_map for multi-threaded scan.")
            return parallel_map(self.test_endpoint, items, workers=self.workers)
        # Fallback: local ThreadPoolExecutor
        logging.info(f"Using ThreadPoolExecutor with {self.workers} workers.")
        results = []
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = {ex.submit(self.test_endpoint, it): it for it in items}
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as e:
                    logging.debug(f"Worker exception: {e}")
                    results.append(None)
        return results

    def orchestrate(self):
        logging.info(f"Starting advanced scan on: {self.base_url}")

        # 1) Discover endpoints by crawling
        self.discover_with_crawler()

        # 2) Swagger discovery (examples)
        example_items = []
        if SWAGGER_AVAILABLE:
            example_items = self.discover_with_swagger()

        # 3) GraphQL discovery
        gql_items = []
        if GRAPHQL_AVAILABLE:
            gql_items = self.discover_with_graphql()

        # 4) Build the final item list
        items = self.build_test_items()

        # ensure items are unique by (method,url,data)
        normalized = []
        seen = set()
        for i in items:
            key = (i[0].upper(), i[1], json.dumps(i[2], sort_keys=True) if i[2] is not None else "")
            if key not in seen:
                seen.add(key)
                normalized.append(i)

        # add swagger/examples and gql items
        normalized.extend(example_items or [])
        normalized.extend(gql_items or [])

        logging.info(f"Prepared {len(normalized)} unique test items.")

        # 5) Run tests in parallel (rate throttling is coarse: sleep between batches if needed)
        results = self.run_parallel(normalized)

        # 6) Post-scan: run specialized auth/CORS/JWT tests
        try:
            auth_vulns = self.auth_tester.test_auth(self.base_url)
            self.vulnerabilities.extend(auth_vulns)
        except Exception as e:
            logging.debug(f"Auth tests failed: {e}")

        try:
            cors_vulns = self.auth_tester.test_cors(self.base_url, [it[1] for it in normalized if it])
            self.vulnerabilities.extend(cors_vulns)
        except Exception as e:
            logging.debug(f"CORS tests failed: {e}")

        try:
            jwt_tokens = self.parser.get_jwt_tokens()
            jwt_vulns = self.auth_tester.test_jwt_vulnerabilities(jwt_tokens)
            self.vulnerabilities.extend(jwt_vulns)
        except Exception as e:
            logging.debug(f"JWT tests failed: {e}")

        # 7) Deduplicate vulnerabilities by (type, url, evidence) quickly
        unique_vulns = []
        seen_v = set()
        for v in self.vulnerabilities:
            key = (v.get("type"), v.get("url"), v.get("evidence"))
            if key not in seen_v:
                seen_v.add(key)
                unique_vulns.append(v)
        self.vulnerabilities = unique_vulns

        # 8) Report
        try:
            self.reporter.generate_report(self.vulnerabilities, self.parser.get_sensitive_data())
        except Exception as e:
            logging.error(f"Report generation failed: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py https://target.example.com")
        sys.exit(1)

    target = sys.argv[1]
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    orchestrator = MainOrchestrator(target, workers=20, rate_per_sec=40.0)
    orchestrator.orchestrate()

if __name__ == "__main__":
    main()
