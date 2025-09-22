#!/usr/bin/env python3
"""
SQL-AI Security Tool - Graduation Project (INSA)
Main entry point for CLI usage.
"""

import argparse
import sys
from core_api.crawler import APICrawler
from core_api.fuzzer import APIFuzzer
from core_api.auth import AuthTester
from core_api.report import ReportGenerator
from core_sql import scanner, injector
from core_ai import inference
from utils import logger, output


def main():
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
    crawler_instance = APICrawler()
    endpoints = crawler_instance.crawl(args.url)

    if not endpoints:
        logger.log_warning("No endpoints discovered. Exiting.")
        sys.exit(0)

    # ------------------------------
    # Step 2: SQL Injection Scan
    # ------------------------------
# Step 2: SQL Injection Scan
# Step 2: SQL Injection Scan
    logger.log_info("Running SQLi scanner...")
    scan_results = []

    for ep in endpoints:
        url = ep if isinstance(ep, str) else ep.get("url")
        params = [] if isinstance(ep, str) else ep.get("params", [])
        
        if not params:
            logger.log_warning(f"No parameters found for {url}, skipping SQLi scan.")
            continue
        
        result = scanner.scan(url, params)
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
