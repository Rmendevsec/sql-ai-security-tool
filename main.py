#!/usr/bin/env python3
"""
SQL-AI Security Tool - Graduation Project (INSA)
Main entry point for CLI usage.
"""

import argparse
import json
import sys

# Import project modules
from utils import logger, output
from core_api import crawler
from core_sql import scanner, injector
from core_ai import inference


def main():
    # CLI Argument Parser
    parser = argparse.ArgumentParser(
        description="SQL-AI Security Tool: SQLi Scanner + API Finder + AI Advisor"
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Target URL (e.g., http://example.com/api/users?id=1)"
    )
    parser.add_argument(
        "--output",
        default="report.json",
        help="Output file name (default: report.json)"
    )
    args = parser.parse_args()

    logger.log_info("Starting SQL-AI Security Tool...")

    # ------------------------------
    # Step 1: Crawl API endpoints
    # ------------------------------
    logger.log_info("Crawling target for endpoints...")
    endpoints = crawler.crawl(args.url)  # expected to return a list of dicts

    if not endpoints:
        logger.log_warning("No endpoints discovered. Exiting.")
        sys.exit(0)

    # ------------------------------
    # Step 2: SQL Injection Scan
    # ------------------------------
    logger.log_info("Running SQLi scanner...")
    scan_results = []
    for ep in endpoints:
        result = scanner.scan(ep["url"], ep.get("params", []))
        if result:
            scan_results.append(result)

    # ------------------------------
    # Step 3: Exploitation (if vuln)
    # ------------------------------
    exploitation_results = []
    for vuln in scan_results:
        if vuln.get("vulnerable"):
            exploit = injector.exploit(vuln["url"], vuln["param"])
            exploitation_results.append(exploit)

    # ------------------------------
    # Step 4: AI Explanation
    # ------------------------------
    logger.log_info("Asking AI Advisor for explanation...")
    explanations = []
    for vuln in scan_results:
        explanation = inference.explain(vuln)
        explanations.append(explanation)

    # ------------------------------
    # Step 5: Generate Report
    # ------------------------------
    final_report = {
        "target": args.url,
        "endpoints": endpoints,
        "vulnerabilities": scan_results,
        "exploitation": exploitation_results,
        "ai_explanations": explanations
    }

    output.save_json(final_report, args.output)
    logger.log_success(f"Report saved to {args.output}")


if __name__ == "__main__":
    main()
# usage example (not a file, paste into your main runner)
from core_api.crawler import crawl, discover_openapi
from core_api.parser import parse_openapi
from core_api.fuzzer import fuzz_many
from core_api.report import generate_report, summarize_results
import requests, json

base = "https://example-target.test"  # replace with target (must have permission)
session = requests.Session()

# 1) quick openapi discovery
specs = discover_openapi(session, base)
endpoints = []
for s in specs:
    resp = session.get(s)
    try:
        j = resp.json()
        endpoints += parse_openapi(j, base_url=base)
    except Exception:
        continue

# 2) generic crawl for more endpoints
pages = crawl(base, max_pages=30, session=session)
for p in pages:
    # naive heuristic: keep URLs that look like API endpoints
    if "/api/" in p or p.endswith(".json"):
        endpoints.append({"url": p, "method": "GET"})

# dedupe
unique = { (e['url'], e.get('method','GET')): e for e in endpoints }.values()
endpoints = list(unique)

# 3) run conservative fuzz (consent must be True)
results = fuzz_many(endpoints, consent=True, auth_conf=None, concurrency=4)

# 4) save report
path = generate_report(results)
print("Report saved to:", path)
print(summarize_results(results))
