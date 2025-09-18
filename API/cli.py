# interface/cli.py
import argparse
import logging
import json
from fencer import Fencer
logging.basicConfig(level=logging.INFO)

def parse_args():
    p = argparse.ArgumentParser("fencer-cli", description="Lightweight Fencer-like API scanner (ethical testing only).")
    p.add_argument("target", help="Target base URL (e.g. https://api.example.test)")
    p.add_argument("--consent", action="store_true", help="Explicit consent to scan the provided target (required).")
    p.add_argument("--max-pages", type=int, default=50, help="Max pages to crawl for discovery")
    p.add_argument("--concurrency", type=int, default=4, help="How many endpoints to fuzz in parallel")
    p.add_argument("--max-tests", type=int, default=6, help="Max tests per endpoint (safe payloads)")
    p.add_argument("--out", default="reports", help="Output directory for results")
    p.add_argument("--auth", help="JSON string with auth info (e.g. '{\"type\":\"bearer\",\"token\":\"abc\"}')")
    return p.parse_args()

def main():
    args = parse_args()
    auth_conf = None
    if args.auth:
        try:
            auth_conf = json.loads(args.auth)
        except Exception as e:
            print("Invalid --auth JSON:", e)
            return

    f = Fencer(args.target, consent=args.consent, max_pages=args.max_pages, concurrency=args.concurrency, auth_conf=auth_conf)
    endpoints = f.discover()
    print("Discovered endpoints:", len(endpoints))
    results = f.run_fuzz(max_tests=args.max_tests)
    report = f.save_report(out_dir=args.out)
    print("Scan complete. Report:", report)
    print("Summary:", f.summary())

if __name__ == "__main__":
    main()
