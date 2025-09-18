# core_api/fencer.py
"""
Fencer-like orchestrator for API discovery + testing.
Safe-by-default, consent-required, non-destructive testing.
"""

import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

# Import modules we already prepared (crawler, parser, fuzzer, auth, report)
from .crawler import discover_openapi, crawl, extract_from_html
from .parser import parse_openapi, normalize_url
from .fuzzer import fuzz_endpoint, fuzz_many
from .auth import ensure_consent, build_auth_headers
from .report import generate_report, summarize_results

log = logging.getLogger("fencer")
log.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
log.addHandler(handler)


class Fencer:
    def __init__(self, base_url, session=None, auth_conf=None, consent=False, max_pages=50, concurrency=4):
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.auth_conf = auth_conf
        self.consent = consent
        self.max_pages = max_pages
        self.concurrency = concurrency

    def discover(self):
        """Run discovery: OpenAPI + crawl + sitemap + heuristics"""
        ensure_consent(self.consent)
        log.info("Starting discovery for %s", self.base_url)

        endpoints = []

        # 1) OpenAPI discovery
        try:
            specs = discover_openapi(self.session, self.base_url)
            for s in specs:
                try:
                    r = self.session.get(s, timeout=10)
                    j = r.json()
                    endpoints += parse_openapi(j, base_url=self.base_url)
                    log.info("Parsed OpenAPI from %s", s)
                except Exception as e:
                    log.debug("Failed parsing spec %s: %s", s, e)
        except Exception as e:
            log.debug("OpenAPI discovery failed: %s", e)

        # 2) Crawl site for api-like URLs
        try:
            discovered = crawl(self.base_url, max_pages=self.max_pages, session=self.session)
            for url in discovered:
                # heuristics for API endpoints
                if "/api/" in urlparse(url).path or url.endswith(".json") or "graphql" in url.lower():
                    endpoints.append({"url": url, "method": "GET", "path": url})
        except Exception as e:
            log.debug("Crawl failed: %s", e)

        # 3) dedupe
        unique = {}
        for e in endpoints:
            key = (e.get("url"), e.get("method","GET").upper())
            if key not in unique:
                unique[key] = e
        self.endpoints = list(unique.values())
        log.info("Discovery finished: %d endpoints", len(self.endpoints))
        return self.endpoints

    def run_fuzz(self, max_tests=6, param_guess_list=None, param_name="q", aggressive=False):
        """Run conservative fuzzing against discovered endpoints."""
        ensure_consent(self.consent)
        if not hasattr(self, "endpoints"):
            raise RuntimeError("No endpoints discovered. Run discover() first.")
        log.info("Starting fuzzing on %d endpoints (concurrency=%d)", len(self.endpoints), self.concurrency)

        # prepare endpoints in expected format for fuzz_many (url + method)
        eps = []
        for e in self.endpoints:
            url = e.get("url") or normalize_url(self.base_url, e.get("path",""))
            method = e.get("method","GET")
            eps.append({"url": url, "method": method})

        results = fuzz_many(eps, concurrency=self.concurrency, consent=self.consent,
                            auth_conf=self.auth_conf, max_tests=max_tests, param_name=param_name)
        log.info("Fuzzing finished")
        self.results = results
        return results

    def save_report(self, out_dir="reports", name=None):
        if not hasattr(self, "results"):
            raise RuntimeError("No results to report. Run run_fuzz() first.")
        path = generate_report(self.results, out_dir=out_dir, name=name)
        log.info("Report saved to %s", path)
        return path

    def summary(self):
        if not hasattr(self, "results"):
            raise RuntimeError("No results to summarize.")
        return summarize_results(self.results)
