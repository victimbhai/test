# Race Condition Attacks: Types & Techniques — Agent Chunk 24a
> Source: 07-advanced-api-vulnerability-classes.md
> Purpose: Understand API race condition types including TOCTOU authorization bypass, double-spend/duplicate transactions, coupon reuse, parallel account creation, rate limiting bypass, and distributed system consistency exploits
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Test state-changing API endpoints for race conditions by sending concurrent identical requests. Key targets: financial transactions (transfer/withdraw — send 10 concurrent requests to double-spend), coupon/discount codes (apply same code in parallel), account creation (create accounts with same email simultaneously), rate-limited endpoints (exceed limits via parallel requests before counter updates). Use the single-packet attack technique (HTTP/2 or TCP packet alignment) for precise timing.

---

## 3. Race Condition Vulnerabilities in APIs

### 3.1 Foundational Research

Race condition exploitation in web applications was transformed by James Kettle's "Smashing the State Machine" research, presented at Black Hat USA 2023. This research demonstrated that HTTP/2's stream multiplexing capability allows an attacker to deliver multiple requests to a server in a single TCP packet, achieving near-simultaneous processing that dramatically increases race condition exploitability.

Prior to this technique, exploiting race conditions required sending requests from multiple connections and hoping they arrived close enough together. Network jitter, server queuing, and processing delays made exploitation unreliable. The single-packet attack technique eliminates network-level timing variance, making previously theoretical race conditions practically exploitable.

### 3.2 The Single-Packet Attack Technique

HTTP/2 multiplexes multiple streams (requests) over a single TCP connection. The key insight is that multiple HTTP/2 frames can be buffered and sent in a single TCP packet. When the server receives this packet, it processes all the contained requests from its receive buffer near-simultaneously, before any individual request's processing has completed.

**Mechanism:**

1. The attacker opens an HTTP/2 connection to the target.
2. The attacker prepares N HTTP/2 request streams but does not send the final HEADERS or DATA frames.
3. The attacker sends all the final frames in a single TCP write operation.
4. The server's TCP stack delivers the entire packet to the application.
5. The HTTP/2 implementation demultiplexes the streams and dispatches all N requests for concurrent processing.
6. Because the requests arrive in the same packet, they bypass network-level timing defenses and are processed in the same event loop iteration or thread pool batch.

**For HTTP/1.1 targets**, a similar technique uses the last-byte synchronization approach:
1. Send N requests on N separate connections, each missing the final byte.
2. Send all final bytes simultaneously.
3. The server completes parsing all requests at approximately the same time.

This technique is less precise than HTTP/2 single-packet because it relies on N separate TCP connections, but it is effective against servers that do not support HTTP/2.

### 3.3 Types of API Race Conditions

#### 3.3.1 Time-of-Check to Time-of-Use (TOCTOU) in Authorization

The most security-critical race condition occurs when an authorization check and the authorized action are not atomic.

**Vulnerable pattern:**

```python
@app.route('/api/transfer', methods=['POST'])
def transfer():
    user = get_current_user()
    amount = request.json['amount']
    recipient = request.json['recipient']
    
    # CHECK: Does user have sufficient balance?
    balance = db.execute("SELECT balance FROM accounts WHERE user_id = %s", (user.id,)).fetchone()
    
    if balance['balance'] >= amount:
        # USE: Perform the transfer
        db.execute("UPDATE accounts SET balance = balance - %s WHERE user_id = %s", (amount, user.id))
        db.execute("UPDATE accounts SET balance = balance + %s WHERE user_id = %s", (amount, recipient))
        db.commit()
        return jsonify({"status": "success"})
    else:
        return jsonify({"status": "insufficient_funds"}), 400
```

**Attack:**

If the user has a balance of $1000 and sends 10 concurrent transfer requests for $1000 each:

1. All 10 requests read the balance: $1000
2. All 10 requests pass the `balance >= amount` check
3. All 10 requests execute the UPDATE, each subtracting $1000
4. Final balance: -$9000

The attacker has transferred $10,000 from an account with only $1000.

#### 3.3.2 Double-Spend / Duplicate Transaction Processing

```python
@app.route('/api/redeem', methods=['POST'])
def redeem_gift_card():
    code = request.json['code']
    
    # Check if gift card exists and is not redeemed
    card = db.execute("SELECT * FROM gift_cards WHERE code = %s AND redeemed = FALSE", (code,)).fetchone()
    
    if card:
        # Mark as redeemed and credit user
        db.execute("UPDATE gift_cards SET redeemed = TRUE WHERE code = %s", (code,))
        db.execute("UPDATE accounts SET balance = balance + %s WHERE user_id = %s", (card['value'], current_user.id))
        db.commit()
        return jsonify({"status": "redeemed", "value": card['value']})
    else:
        return jsonify({"status": "invalid_or_used"}), 400
```

If 10 requests to redeem the same $100 gift card arrive simultaneously, all 10 may read `redeemed = FALSE` before any of them has written `redeemed = TRUE`. The attacker receives $1000 in credit from a single $100 gift card.

#### 3.3.3 Coupon/Discount Code Reuse

Similar to gift card double-spend, but targeting single-use coupon codes:

```
Stream 1: POST /api/apply-coupon {"code": "SAVE50", "order_id": "order_1"}
Stream 3: POST /api/apply-coupon {"code": "SAVE50", "order_id": "order_2"}
Stream 5: POST /api/apply-coupon {"code": "SAVE50", "order_id": "order_3"}
```

A single-use coupon applied to three separate orders.

#### 3.3.4 Parallel Account Creation with Same Email

```python
@app.route('/api/register', methods=['POST'])
def register():
    email = request.json['email']
    
    # Check if email already exists
    existing = db.execute("SELECT id FROM users WHERE email = %s", (email,)).fetchone()
    
    if existing:
        return jsonify({"error": "email_taken"}), 409
    
    # Create user
    db.execute("INSERT INTO users (email, name) VALUES (%s, %s)", (email, request.json['name']))
    db.commit()
    return jsonify({"status": "created"})
```

Concurrent requests can create multiple accounts with the same email. This can lead to:
- Authentication confusion (which account does the email belong to?)
- Authorization bypass (different accounts may have different permissions)
- Account takeover (password reset goes to the first/last created account)

#### 3.3.5 Rate Limiting Bypass

Rate limits that check the current count before incrementing are vulnerable:

```python
def rate_limit_check(user_id, endpoint):
    current_count = redis.get(f"rate:{user_id}:{endpoint}")
    if current_count and int(current_count) >= MAX_REQUESTS:
        return False  # Rate limited
    redis.incr(f"rate:{user_id}:{endpoint}")
    return True  # Allowed
```

If 100 requests arrive simultaneously, all 100 may read `current_count = 0` before any increment has been written, bypassing the rate limit entirely.

#### 3.3.6 Race in Distributed Systems (Eventual Consistency Exploits)

In eventually consistent systems (NoSQL databases with read replicas, microservices with event-driven synchronization), the race window can be much larger — seconds or even minutes:

```
1. User changes password via Service A (writes to primary)
2. Attacker authenticates with old password via Service B (reads from replica that hasn't received the update)
3. Service B validates the old password successfully
```

