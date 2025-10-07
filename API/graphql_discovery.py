# graphql_discovery.py
import requests
from urllib.parse import urljoin
import json

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args {
          name
          type { name kind ofType { name kind } }
        }
      }
    }
  }
}
"""

def introspect_graphql(base_url: str, session: requests.Session):
    """Attempt introspection on /graphql or given endpoint. Returns parsed schema or None."""
    endpoints = ["/graphql", "/v1/graphql", "/api/graphql"]
    for e in endpoints:
        url = urljoin(base_url, e)
        try:
            resp = session.post(url, json={"query": INTROSPECTION_QUERY}, timeout=6)
            if resp.status_code == 200:
                data = resp.json()
                if "data" in data and "__schema" in data["data"]:
                    return url, data["data"]["__schema"]
        except requests.RequestException:
            continue
    return None, None

def extract_graphql_operations(schema: dict):
    """Return lists of queries/mutations and their argument names."""
    ops = {"queries": [], "mutations": []}
    if not schema:
        return ops
    for t in schema.get("types", []):
        if t.get("name") in ("Query", "Mutation"):
            for f in t.get("fields", []) or []:
                args = [a.get("name") for a in (f.get("args") or [])]
                if t.get("name") == "Query":
                    ops["queries"].append((f.get("name"), args))
                else:
                    ops["mutations"].append((f.get("name"), args))
    return ops
