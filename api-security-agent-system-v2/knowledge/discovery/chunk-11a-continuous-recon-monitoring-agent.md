# Continuous Reconnaissance: Endpoint Alerting, Deprecated Monitoring & Inventory Automation — Agent Chunk 11a
> Source: 05-attack-surface-and-inventory-methodology.md
> Purpose: Set up continuous monitoring for new API endpoints, verify deprecated endpoints are truly decommissioned, and automate API inventory building from multiple discovery sources
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Deploy the new endpoint alerting script that periodically scans API paths and alerts on any endpoint that becomes accessible. Monitor deprecated endpoints to verify they return 404/410 and are not still serving responses. Use the APIInventoryBuilder class to combine endpoints discovered from OpenAPI specs, traffic logs, and JavaScript analysis into a unified inventory report. The report identifies potentially undocumented endpoints (found in traffic/JS but not in the spec) and deprecated-but-active endpoints — both are high-priority test targets.

---


### 7.2 New Endpoint Alerting

```python
#!/usr/bin/env python3
"""Monitor for new API endpoints via traffic analysis."""
import json
import os
import time
from datetime import datetime

KNOWN_ENDPOINTS_FILE = "/opt/api-monitor/known_endpoints.json"
ALERT_LOG = "/opt/api-monitor/alerts.log"

def load_known_endpoints():
    if os.path.exists(KNOWN_ENDPOINTS_FILE):
        with open(KNOWN_ENDPOINTS_FILE) as f:
            return json.load(f)
    return {"endpoints": {}, "last_updated": None}

def save_known_endpoints(data):
    data["last_updated"] = datetime.now().isoformat()
    with open(KNOWN_ENDPOINTS_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def alert_new_endpoint(endpoint, method, details):
    timestamp = datetime.now().isoformat()
    alert = f"[{timestamp}] NEW ENDPOINT: [{method}] {endpoint}"
    if details:
        alert += f" - {details}"
    print(alert)
    with open(ALERT_LOG, 'a') as f:
        f.write(alert + '\n')

def check_endpoint(url, method="GET"):
    """Check if an endpoint is accessible."""
    import requests
    try:
        response = requests.request(method, url, timeout=5, allow_redirects=False)
        return {
            "status": response.status_code,
            "content_type": response.headers.get("content-type", ""),
            "content_length": len(response.content),
            "server": response.headers.get("server", ""),
        }
    except requests.RequestException:
        return None

def monitor_endpoints(base_url, wordlist_file, interval=3600):
    """Periodically scan for new endpoints."""
    known = load_known_endpoints()

    with open(wordlist_file) as f:
        paths = [line.strip() for line in f if line.strip()]

    while True:
        print(f"[{datetime.now().isoformat()}] Scanning {len(paths)} paths...")
        for path in paths:
            url = f"{base_url}{path}"
            for method in ["GET", "POST"]:
                key = f"{method}:{path}"
                result = check_endpoint(url, method)
                if result and result["status"] not in (404, 000):
                    if key not in known["endpoints"]:
                        alert_new_endpoint(path, method, json.dumps(result))
                        known["endpoints"][key] = {
                            "first_seen": datetime.now().isoformat(),
                            **result
                        }

        save_known_endpoints(known)
        print(f"[{datetime.now().isoformat()}] Scan complete. "
              f"Known endpoints: {len(known['endpoints'])}")
        time.sleep(interval)
```

### 7.3 Deprecated Endpoint Monitoring

```bash
#!/bin/bash
# Monitor deprecated endpoints for continued accessibility

DEPRECATED_ENDPOINTS=(
  "/api/v1/users"
  "/api/v1/orders"
  "/api/v1/auth/login"
  "/api/v1/products"
  "/legacy/api/search"
  "/old/api/export"
)

BASE_URL="https://api.target.com"
LOG_FILE="/var/log/deprecated_api_monitor.log"

for endpoint in "${DEPRECATED_ENDPOINTS[@]}"; do
  for method in GET POST; do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -X "$method" "${BASE_URL}${endpoint}" --max-time 10)
    if [ "$code" != "404" ] && [ "$code" != "000" ] && [ "$code" != "410" ]; then
      msg="$(date -Iseconds) ALERT: Deprecated endpoint still active: \
[$method] ${endpoint} (HTTP ${code})"
      echo "$msg" | tee -a "$LOG_FILE"
    fi
  done
done
```

### 7.4 API Inventory Automation

```python
#!/usr/bin/env python3
"""Automated API inventory builder combining multiple discovery sources."""
import json
import os
from datetime import datetime

class APIInventoryBuilder:
    def __init__(self):
        self.endpoints = {}
        self.sources = []

    def add_from_openapi_spec(self, spec_file):
        """Import endpoints from OpenAPI specification."""
        with open(spec_file) as f:
            spec = json.load(f)
        for path, methods in spec.get('paths', {}).items():
            for method, details in methods.items():
                if method in ('get', 'post', 'put', 'patch', 'delete',
                              'head', 'options'):
                    key = f"{method.upper()}:{path}"
                    if key not in self.endpoints:
                        self.endpoints[key] = {
                            'path': path,
                            'method': method.upper(),
                            'sources': [],
                            'auth_required': bool(
                                details.get('security') or spec.get('security')
                            ),
                            'tags': details.get('tags', []),
                            'deprecated': details.get('deprecated', False),
                            'parameters': [],
                            'first_seen': datetime.now().isoformat(),
                        }
                    self.endpoints[key]['sources'].append('openapi_spec')
        self.sources.append(('openapi_spec', spec_file))

    def add_from_traffic_log(self, traffic_file):
        """Import endpoints from proxy traffic log."""
        with open(traffic_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(' ', 1)
                if len(parts) == 2:
                    method, path = parts[0].strip('[]'), parts[1]
                    key = f"{method}:{path}"
                    if key not in self.endpoints:
                        self.endpoints[key] = {
                            'path': path,
                            'method': method,
                            'sources': [],
                            'first_seen': datetime.now().isoformat(),
                        }
                    if 'traffic_analysis' not in self.endpoints[key].get('sources', []):
                        self.endpoints[key].setdefault('sources', []).append(
                            'traffic_analysis'
                        )
        self.sources.append(('traffic_analysis', traffic_file))

    def add_from_js_analysis(self, endpoints_file):
        """Import endpoints discovered from JavaScript analysis."""
        with open(endpoints_file) as f:
            for line in f:
                path = line.strip()
                if path:
                    key = f"UNKNOWN:{path}"
                    if key not in self.endpoints:
                        self.endpoints[key] = {
                            'path': path,
                            'method': 'UNKNOWN',
                            'sources': ['js_analysis'],
                            'first_seen': datetime.now().isoformat(),
                        }
                    else:
                        if 'js_analysis' not in self.endpoints[key]['sources']:
                            self.endpoints[key]['sources'].append('js_analysis')
        self.sources.append(('js_analysis', endpoints_file))

    def generate_report(self):
        """Generate inventory report."""
        report = {
            'generated': datetime.now().isoformat(),
            'sources': self.sources,
            'summary': {
                'total_endpoints': len(self.endpoints),
                'by_method': {},
                'by_source': {},
                'potentially_undocumented': 0,
                'deprecated_but_active': 0,
            },
            'endpoints': list(self.endpoints.values()),
        }

        for ep in self.endpoints.values():
            method = ep['method']
            report['summary']['by_method'][method] = \
                report['summary']['by_method'].get(method, 0) + 1
            for source in ep.get('sources', []):
                report['summary']['by_source'][source] = \
                    report['summary']['by_source'].get(source, 0) + 1
            if 'openapi_spec' not in ep.get('sources', []):
                report['summary']['potentially_undocumented'] += 1
            if ep.get('deprecated'):
                report['summary']['deprecated_but_active'] += 1

        return report

    def save_report(self, output_file):
        report = self.generate_report()
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Report saved to {output_file}")
        print(f"Total endpoints: {report['summary']['total_endpoints']}")
        print(f"Potentially undocumented: "
              f"{report['summary']['potentially_undocumented']}")
        return report
```

---

