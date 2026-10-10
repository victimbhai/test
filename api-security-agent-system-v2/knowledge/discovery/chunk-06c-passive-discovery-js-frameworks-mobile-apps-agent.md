# Passive API Discovery: Framework Routes, Environment Vars & Mobile App Reversing — Agent Chunk 06c
> Source: 05-attack-surface-and-inventory-methodology.md
> Purpose: Extract API routes from framework-specific JS patterns, find leaked environment variables, and reverse-engineer mobile apps (Android APK, iOS IPA) to discover API endpoints
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Search JavaScript bundles for framework-specific route patterns (React Router, Angular, Vue Router, Next.js). Look for inlined environment variables (REACT_APP_*, VITE_*, NEXT_PUBLIC_*) that leak API keys and internal URLs. For mobile targets, decompile APK/IPA files to extract API base URLs, Retrofit annotations, and certificate pinning configurations.

---


#### 2.1.4 Framework-Specific Route Configuration Extraction

**React Router:**
```javascript
// React Router route definitions typically look like:
// Search for patterns like these in the JavaScript bundles

// React Router v6
<Route path="/dashboard" element={<Dashboard />} />
<Route path="/api/users/:id" element={<UserProfile />} />

// React Router v5
<Route path="/dashboard" component={Dashboard} />
<Route path="/api/users/:id" component={UserProfile} />

// Programmatic routing
navigate('/api/users/' + userId)
history.push('/api/users/' + userId)
```

```bash
# Extract React Router paths from bundles
grep -oP 'path:\s*["'"'"']([^"'"'"']+)["'"'"']' *.js | sort -u
grep -oP 'path=["'"'"']([^"'"'"']+)["'"'"']' *.js | sort -u
grep -oP 'navigate\(["'"'"']([^"'"'"']+)["'"'"']' *.js | sort -u
grep -oP 'history\.push\(["'"'"']([^"'"'"']+)["'"'"']' *.js | sort -u
```

**Angular:**
```bash
# Angular route definitions
grep -oP "path:\s*'([^']+)'" *.js | sort -u
grep -oP 'loadChildren.*?([a-zA-Z]+Module)' *.js | sort -u

# Angular HttpClient usage
grep -oP "this\.http\.\w+\s*[<(]\s*'([^']+)'" *.js | sort -u
grep -oP 'this\.http\.\w+\s*[<(]\s*`([^`]+)`' *.js | sort -u

# Angular environment files (may be in bundles)
grep -oP 'apiUrl:\s*["'"'"']([^"'"'"']+)["'"'"']' *.js | sort -u
grep -oP 'baseUrl:\s*["'"'"']([^"'"'"']+)["'"'"']' *.js | sort -u
```

**Vue.js:**
```bash
# Vue Router route definitions
grep -oP "path:\s*'(/[^']+)'" *.js | sort -u
grep -oP 'name:\s*["'"'"']([^"'"'"']+)["'"'"']' *.js | sort -u

# Vue.js API calls
grep -oP 'this\.\$http\.\w+\(["'"'"']([^"'"'"']+)["'"'"']' *.js | sort -u
grep -oP 'Vue\.http\.\w+\(["'"'"']([^"'"'"']+)["'"'"']' *.js | sort -u
```

**Next.js:**
```bash
# Next.js API routes follow the file system convention: /pages/api/...
# In bundles, look for:
grep -oP '["'"'"']/api/[a-zA-Z0-9_/\[\]\-]+["'"'"']' *.js | sort -u

# Next.js getServerSideProps / getStaticProps fetch calls
grep -oP 'fetch\(["'"'"'`][^"'"'"'`]*/api/[^"'"'"'`]+["'"'"'`]' *.js | sort -u
```

#### 2.1.5 Environment Variable Leakage in JavaScript Bundles

JavaScript bundles compiled with tools like webpack, Vite, or Create React App often
inline environment variables at build time. These can expose sensitive configuration
including API keys, internal URLs, and service endpoints.

```bash
# Search for common environment variable patterns
grep -oP 'process\.env\.([A-Z_]+)' *.js | sort -u
grep -oP 'import\.meta\.env\.([A-Z_]+)' *.js | sort -u

# Search for specific sensitive variables
grep -iP '(API_KEY|API_SECRET|SECRET_KEY|PRIVATE_KEY|ACCESS_TOKEN|AUTH_TOKEN)' *.js
grep -iP '(AWS_ACCESS_KEY|AWS_SECRET|GOOGLE_API_KEY|STRIPE_KEY|FIREBASE)' *.js
grep -iP '(DATABASE_URL|REDIS_URL|MONGO_URI|POSTGRES|MYSQL)' *.js
grep -iP '(INTERNAL_URL|BACKEND_URL|SERVICE_URL|ADMIN_URL|DEBUG)' *.js

# Search for base64-encoded secrets
grep -oP '[A-Za-z0-9+/]{40,}={0,2}' *.js | while read -r encoded; do
  decoded=$(echo "$encoded" | base64 -d 2>/dev/null)
  if [ $? -eq 0 ] && echo "$decoded" | grep -qiP '(key|secret|token|password)'; then
    echo "POTENTIAL SECRET: $encoded -> $decoded"
  fi
done

# Common framework environment variable patterns
# Create React App: REACT_APP_*
grep -oP 'REACT_APP_[A-Z_]+' *.js | sort -u

# Vite: VITE_*
grep -oP 'VITE_[A-Z_]+' *.js | sort -u

# Next.js: NEXT_PUBLIC_*
grep -oP 'NEXT_PUBLIC_[A-Z_]+' *.js | sort -u

# Nuxt.js: NUXT_ENV_*
grep -oP 'NUXT_ENV_[A-Z_]+' *.js | sort -u

# Angular: environment.ts values inlined in bundles
grep -oP 'environment\.\w+\s*[:=]' *.js | sort -u
```

**Automated Environment Variable Extraction Script:**

```python
#!/usr/bin/env python3
"""Extract potential API keys and secrets from JavaScript bundles."""
import re
import sys

PATTERNS = {
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'AWS Secret Key': r'[0-9a-zA-Z/+]{40}',
    'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
    'Google OAuth Token': r'ya29\.[0-9A-Za-z\-_]+',
    'Firebase URL': r'https://[a-z0-9-]+\.firebaseio\.com',
    'Firebase API Key': r'AIza[0-9A-Za-z\-_]{35}',
    'Stripe Secret Key': r'sk_(live|test)_[0-9a-zA-Z]{24,}',
    'Stripe Publishable Key': r'pk_(live|test)_[0-9a-zA-Z]{24,}',
    'Slack Token': r'xox[baprs]-[0-9]{10,13}-[0-9a-zA-Z]{24}',
    'Slack Webhook': r'https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+',
    'GitHub Token': r'gh[pousr]_[A-Za-z0-9_]{36,}',
    'Twilio Account SID': r'AC[a-zA-Z0-9]{32}',
    'Twilio Auth Token': r'[a-f0-9]{32}',
    'SendGrid API Key': r'SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9\-_]{43}',
    'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
    'JWT Token': r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
    'Private Key': r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
    'Internal URL': r'https?://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9.]+[:/]?[^\s"\']*',
    'API Endpoint': r'["\'](https?://[a-zA-Z0-9.-]+/api/[^\s"\']+)["\']',
    'API Base URL Variable': r'(?:API_URL|API_BASE|BASE_URL|BACKEND_URL|SERVICE_URL)\s*[:=]\s*["\']([^"\']+)["\']',
}

def scan_file(filepath):
    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()

    findings = []
    for name, pattern in PATTERNS.items():
        matches = re.findall(pattern, content)
        if matches:
            for match in matches:
                findings.append((name, match))
    return findings

if __name__ == '__main__':
    for filepath in sys.argv[1:]:
        findings = scan_file(filepath)
        if findings:
            print(f"\n=== {filepath} ===")
            for name, value in findings:
                print(f"  [{name}]: {value[:80]}{'...' if len(str(value)) > 80 else ''}")
```

### 2.2 Mobile Application Analysis

Mobile applications are a rich source of API endpoint information because they must
contain the complete API client configuration, including base URLs, endpoint paths,
authentication mechanisms, and certificate pinning configurations.

#### 2.2.1 APK Decompilation for API Endpoints (Android)

**Using jadx (Java Decompiler for Android):**

```bash
# Installation
# Via package manager
sudo apt install jadx

# Or download from GitHub releases
wget https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip
unzip jadx-1.5.1.zip -d jadx
export PATH=$PATH:$(pwd)/jadx/bin

# Decompile APK to Java source
jadx -d output_dir target_app.apk

# Search for API endpoints in decompiled source
grep -rn "api/" output_dir/sources/ --include="*.java" | sort -u
grep -rn "https://" output_dir/sources/ --include="*.java" | sort -u
grep -rn "http://" output_dir/sources/ --include="*.java" | sort -u

# Search for API base URL definitions
grep -rn "BASE_URL\|baseUrl\|API_URL\|apiUrl\|ENDPOINT\|HOST" \
  output_dir/sources/ --include="*.java" | sort -u

# Search for Retrofit interface definitions (common Android API client)
grep -rn "@GET\|@POST\|@PUT\|@DELETE\|@PATCH\|@HEAD" \
  output_dir/sources/ --include="*.java" | sort -u

# Search for OkHttp configurations
grep -rn "OkHttpClient\|Interceptor\|addHeader\|certificatePinner" \
  output_dir/sources/ --include="*.java" | sort -u

# Search for authentication-related code
grep -rn "Authorization\|Bearer\|api[_-]key\|token\|auth" \
  output_dir/sources/ --include="*.java" | sort -u
```

**Using apktool (for resource and manifest analysis):**

```bash
# Installation
sudo apt install apktool

# Decompile APK (preserves resources and manifest)
apktool d target_app.apk -o apktool_output

# Examine AndroidManifest.xml for network configuration
cat apktool_output/AndroidManifest.xml

# Look for network_security_config.xml (certificate pinning configuration)
find apktool_output -name "network_security_config.xml" -exec cat {} \;

# Search for API URLs in resources
grep -rn "api\.\|/api/\|https://" apktool_output/res/ | sort -u

# Search for strings.xml for API configuration
grep -n "api\|url\|endpoint\|server\|host\|key\|secret\|token" \
  apktool_output/res/values/strings.xml

# Search smali code for API endpoints (when jadx fails)
grep -rn "\"https://\|\"http://\|/api/" apktool_output/smali/ | sort -u
grep -rn "api_key\|api_secret\|auth_token\|access_token" \
  apktool_output/smali/ | sort -u
```

#### 2.2.2 IPA Analysis (iOS)

```bash
# Extract IPA (it is a zip file)
unzip target_app.ipa -d ipa_output

# Find the main binary
find ipa_output -name "*.app" -type d

# Extract strings from the binary
strings ipa_output/Payload/*.app/<BinaryName> | \
  grep -iP "(api|https?://|endpoint|/v[0-9]+/)" | sort -u

# Search for plist files with API configuration
find ipa_output -name "*.plist" -exec plutil -p {} \; 2>/dev/null | \
  grep -i "api\|url\|endpoint\|server\|host\|key"

# Extract embedded frameworks and search them
find ipa_output -name "*.framework" -type d | while read -r fw; do
  binary=$(basename "$fw" .framework)
  if [ -f "$fw/$binary" ]; then
    strings "$fw/$binary" | grep -iP "(api|https?://)" | sort -u
  fi
done

# Check for embedded provisioning profiles (may contain server URLs)
find ipa_output -name "embedded.mobileprovision" -exec \
  security cms -D -i {} \; 2>/dev/null | grep -i "url\|api\|server"
```

#### 2.2.3 Certificate Pinning Bypass for Traffic Interception

Certificate pinning prevents interception of HTTPS traffic by validating the server's
certificate against a known (pinned) certificate or public key. Bypassing pinning is
necessary to observe API traffic from mobile applications.

**Using Frida for Certificate Pinning Bypass:**

```bash
# Install Frida tools
pip3 install frida-tools

# Install Frida server on the device (requires root/jailbreak)
# Download the appropriate Frida server for the target architecture
# Push to device and start

# Android - bypass SSL pinning with universal script
frida -U -l ssl_pinning_bypass.js -f com.target.app --no-pause

# Using objection (built on Frida) - simplified approach
pip3 install objection

# Android SSL pinning bypass
objection -g com.target.app explore
# Once in objection console:
# android sslpinning disable

# iOS SSL pinning bypass
objection -g com.target.app explore
# Once in objection console:
# ios sslpinning disable
```

**Frida SSL Pinning Bypass Script (Android):**

```javascript
// ssl_pinning_bypass.js
Java.perform(function() {
    // TrustManager bypass
    var TrustManagerImpl = Java.use(
        'com.android.org.conscrypt.TrustManagerImpl'
    );
    TrustManagerImpl.verifyChain.implementation = function(
        untrustedChain, trustAnchorChain, host, clientAuth,
        ocspData, tlsSctData
    ) {
        console.log('[+] Bypassing TrustManagerImpl for: ' + host);
        return untrustedChain;
    };

    // OkHttp CertificatePinner bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload(
            'java.lang.String', 'java.util.List'
        ).implementation = function(hostname, peerCertificates) {
            console.log('[+] Bypassing OkHttp CertificatePinner for: ' + hostname);
            return;
        };
    } catch(e) {
        console.log('[-] OkHttp CertificatePinner not found');
    }

    // WebViewClient bypass
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(
            view, handler, error
        ) {
            console.log('[+] Bypassing WebViewClient SSL error');
            handler.proceed();
        };
    } catch(e) {
        console.log('[-] WebViewClient not found');
    }
});
```
