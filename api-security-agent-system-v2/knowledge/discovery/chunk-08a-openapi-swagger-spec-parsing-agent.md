# OpenAPI/Swagger Specification Parsing & Undocumented Endpoint Discovery — Agent Chunk 08a
> Source: 05-attack-surface-and-inventory-methodology.md
> Purpose: Parse discovered OpenAPI/Swagger specifications to extract complete endpoint inventories with parameters, auth requirements, and security metadata; compare spec endpoints against discovered endpoints to find undocumented APIs
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
When you find an OpenAPI spec, parse it to extract every endpoint path, HTTP method, parameter (path/query/body), security requirements, tags, and deprecation status. Identify endpoints explicitly marked with no authentication. Count potentially unauthenticated endpoints. Then compare the spec's endpoint list against endpoints discovered through JS analysis, traffic capture, and brute-forcing — any endpoint found in practice but missing from the spec is undocumented and likely untested.

---


#### 3.2.2 Parsing OpenAPI Specifications

```python
#!/usr/bin/env python3
"""Parse OpenAPI/Swagger spec to extract complete endpoint inventory."""
import json
import yaml
import sys

def parse_openapi_spec(filepath):
    """Parse an OpenAPI 3.x or Swagger 2.x specification."""
    with open(filepath) as f:
        if filepath.endswith(('.yaml', '.yml')):
            spec = yaml.safe_load(f)
        else:
            spec = json.load(f)

    # Detect version
    version = spec.get('openapi', spec.get('swagger', 'unknown'))
    print(f"Specification Version: {version}")

    # Extract base URL
    if 'servers' in spec:  # OpenAPI 3.x
        for server in spec['servers']:
            print(f"Server: {server.get('url')}")
            if 'description' in server:
                print(f"  Description: {server['description']}")
    elif 'host' in spec:  # Swagger 2.x
        scheme = spec.get('schemes', ['https'])[0]
        base_path = spec.get('basePath', '/')
        print(f"Server: {scheme}://{spec['host']}{base_path}")

    # Extract security schemes
    security_defs = (
        spec.get('components', {}).get('securitySchemes', {}) or
        spec.get('securityDefinitions', {})
    )
    if security_defs:
        print(f"\n{'='*60}")
        print("SECURITY SCHEMES:")
        print(f"{'='*60}")
        for name, scheme in security_defs.items():
            print(f"  {name}:")
            print(f"    Type: {scheme.get('type')}")
            if 'scheme' in scheme:
                print(f"    Scheme: {scheme['scheme']}")
            if 'in' in scheme:
                print(f"    Location: {scheme['in']}")
            if 'name' in scheme:
                print(f"    Parameter Name: {scheme['name']}")
            if 'flows' in scheme:
                for flow_name, flow in scheme['flows'].items():
                    print(f"    OAuth Flow: {flow_name}")
                    if 'authorizationUrl' in flow:
                        print(f"      Auth URL: {flow['authorizationUrl']}")
                    if 'tokenUrl' in flow:
                        print(f"      Token URL: {flow['tokenUrl']}")

    # Extract all endpoints
    paths = spec.get('paths', {})
    print(f"\n{'='*60}")
    print(f"ENDPOINTS ({len(paths)} paths):")
    print(f"{'='*60}")

    all_endpoints = []
    for path, methods in sorted(paths.items()):
        for method, details in methods.items():
            if method in ('get', 'post', 'put', 'patch', 'delete',
                          'head', 'options', 'trace'):
                endpoint = {
                    'path': path,
                    'method': method.upper(),
                    'summary': details.get('summary', ''),
                    'description': details.get('description', ''),
                    'tags': details.get('tags', []),
                    'security': details.get('security', []),
                    'parameters': [],
                    'request_body': None,
                    'responses': list(details.get('responses', {}).keys()),
                    'deprecated': details.get('deprecated', False),
                }

                # Extract parameters
                params = details.get('parameters', [])
                # Include path-level parameters
                params.extend(methods.get('parameters', []))
                for param in params:
                    p = {
                        'name': param.get('name'),
                        'in': param.get('in'),
                        'required': param.get('required', False),
                        'type': param.get('schema', {}).get('type',
                                    param.get('type', 'unknown')),
                    }
                    endpoint['parameters'].append(p)

                # Extract request body (OpenAPI 3.x)
                if 'requestBody' in details:
                    rb = details['requestBody']
                    content = rb.get('content', {})
                    endpoint['request_body'] = {
                        'required': rb.get('required', False),
                        'content_types': list(content.keys()),
                    }

                all_endpoints.append(endpoint)

                # Print endpoint details
                deprecated = " [DEPRECATED]" if endpoint['deprecated'] else ""
                security = " [NO AUTH]" if not endpoint['security'] and \
                    not spec.get('security') else ""
                print(f"\n  [{endpoint['method']}] {endpoint['path']}"
                      f"{deprecated}{security}")
                if endpoint['summary']:
                    print(f"    Summary: {endpoint['summary']}")
                if endpoint['tags']:
                    print(f"    Tags: {', '.join(endpoint['tags'])}")
                if endpoint['parameters']:
                    for p in endpoint['parameters']:
                        req = "*" if p['required'] else ""
                        print(f"    Param ({p['in']}): {p['name']}{req} "
                              f"[{p['type']}]")
                if endpoint['request_body']:
                    print(f"    Body Content Types: "
                          f"{', '.join(endpoint['request_body']['content_types'])}")
                    print(f"    Body Required: "
                          f"{endpoint['request_body']['required']}")

    # Summary statistics
    print(f"\n{'='*60}")
    print("SUMMARY:")
    print(f"{'='*60}")
    print(f"  Total Paths: {len(paths)}")
    print(f"  Total Operations: {len(all_endpoints)}")

    method_counts = {}
    for ep in all_endpoints:
        method_counts[ep['method']] = method_counts.get(ep['method'], 0) + 1
    for method, count in sorted(method_counts.items()):
        print(f"  {method}: {count} endpoints")

    deprecated_count = sum(1 for ep in all_endpoints if ep['deprecated'])
    if deprecated_count:
        print(f"  Deprecated: {deprecated_count} endpoints")

    no_auth = sum(1 for ep in all_endpoints
                  if not ep['security'] and not spec.get('security'))
    if no_auth:
        print(f"  Potentially Unauthenticated: {no_auth} endpoints")

    return all_endpoints

if __name__ == '__main__':
    parse_openapi_spec(sys.argv[1])
```

#### 3.2.3 Finding Undocumented Endpoints Not in Spec

After obtaining the OpenAPI specification, compare it with endpoints discovered through
other means (traffic analysis, JS analysis, brute-forcing) to find undocumented endpoints.

```python
#!/usr/bin/env python3
"""Compare discovered endpoints with OpenAPI spec to find undocumented APIs."""
import json
import re
import sys

def normalize_path(path):
    """Normalize path by replacing variable segments."""
    # Replace path parameters: {id}, :id, <id>
    normalized = re.sub(r'\{[^}]+\}', '{param}', path)
    normalized = re.sub(r':[a-zA-Z_]+', '{param}', normalized)
    normalized = re.sub(r'<[^>]+>', '{param}', normalized)
    # Replace numeric IDs
    normalized = re.sub(r'/[0-9]+(/|$)', '/{param}\\1', normalized)
    # Replace UUIDs
    normalized = re.sub(
        r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(/|$)',
        '/{param}\\1', normalized
    )
    return normalized.rstrip('/')

def load_spec_endpoints(spec_file):
    """Load endpoints from OpenAPI spec."""
    with open(spec_file) as f:
        spec = json.load(f)
    endpoints = set()
    for path in spec.get('paths', {}):
        endpoints.add(normalize_path(path))
    return endpoints

def load_discovered_endpoints(endpoints_file):
    """Load discovered endpoints from text file (one per line)."""
    endpoints = set()
    with open(endpoints_file) as f:
        for line in f:
            line = line.strip()
            if line:
                endpoints.add(normalize_path(line))
    return endpoints

if __name__ == '__main__':
    spec_endpoints = load_spec_endpoints(sys.argv[1])
    discovered_endpoints = load_discovered_endpoints(sys.argv[2])

    undocumented = discovered_endpoints - spec_endpoints
    print(f"Documented endpoints: {len(spec_endpoints)}")
    print(f"Discovered endpoints: {len(discovered_endpoints)}")
    print(f"Undocumented endpoints: {len(undocumented)}")

    if undocumented:
        print("\nUNDOCUMENTED ENDPOINTS:")
        for ep in sorted(undocumented):
            print(f"  {ep}")
```
