# swagger_discovery.py
import requests
from urllib.parse import urljoin
from typing import List, Tuple

def fetch_swagger_json(base_url: str, session: requests.Session, paths=None):
    """Try common locations for OpenAPI/Swagger files and return parsed JSON."""
    candidates = [
        "/swagger.json", "/openapi.json", "/v2/api-docs",
        "/swagger/v1/swagger.json", "/api-docs", "/openapi.json"
    ]
    endpoints = []
    for c in candidates:
        try:
            url = urljoin(base_url, c)
            resp = session.get(url, timeout=6)
            if resp.status_code == 200:
                try:
                    spec = resp.json()
                except ValueError:
                    continue
                # parse paths
                for path, methods in spec.get("paths", {}).items():
                    for method in methods.keys():
                        endpoints.append((method.upper(), urljoin(base_url, path.lstrip("/"))))
                # attempt to find servers->basePath
                return endpoints, spec
        except requests.RequestException:
            continue
    return endpoints, None

def extract_examples_from_schema(spec: dict):
    """Return a list of (method, path, example_payload) if present in OpenAPI spec."""
    examples = []
    paths = spec.get("paths", {}) if spec else {}
    for path, methods in paths.items():
        for method, meta in methods.items():
            example_body = None
            # try requestBody -> content -> application/json -> example/examples
            rb = meta.get("requestBody", {})
            if rb:
                content = rb.get("content", {})
                app_json = content.get("application/json", {})
                if "example" in app_json:
                    example_body = app_json["example"]
                elif "examples" in app_json:
                    # pick first example
                    exs = app_json["examples"]
                    first = next(iter(exs.values()))
                    example_body = first.get("value") or first.get("example")
            examples.append((method.upper(), path, example_body))
    return examples
