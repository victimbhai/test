# Race Condition Attacks: HTTP/2 Implementation & Detection — Agent Chunk 24b
> Source: 07-advanced-api-vulnerability-classes.md
> Purpose: Implement HTTP/2 single-packet race condition attacks using Python, detect race conditions through response analysis, and apply remediation patterns (database locks, idempotency keys, atomic operations)
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use the HTTP/2 single-packet attack technique: send multiple HTTP/2 streams in a single TCP packet so the server processes them simultaneously. Implement with Python h2 library or Burp Suite's "Send group in parallel" feature. Detect race conditions by analyzing response variations (different status codes, different balances, duplicate records created). Remediate with database-level locking (SELECT FOR UPDATE), idempotency keys, atomic database operations, and distributed locks (Redis SETNX).

---

### 3.4 HTTP/2 Single-Packet Attack Implementation

**Using Turbo Intruder (BApp Store):**

```python
# Turbo Intruder script for single-packet race condition
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          requestsPerConnection=100,
                          pipeline=False)
    
    # Queue all requests with the gate mechanism
    for i in range(20):
        engine.queue(target.req, gate='race1')
    
    # Open the gate - sends all requests simultaneously
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

**Using a custom Python HTTP/2 client:**

```python
import h2.connection
import h2.events
import socket
import ssl

def single_packet_race(host, port, requests):
    """Send multiple HTTP/2 requests in a single TCP packet."""
    
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2'])
    
    sock = socket.create_connection((host, port))
    sock = ctx.wrap_socket(sock, server_hostname=host)
    
    conn = h2.connection.H2Connection()
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    
    # Prepare all requests but buffer the data
    stream_ids = []
    for req_data in requests:
        stream_id = conn.get_next_available_stream_id()
        stream_ids.append(stream_id)
        
        headers = [
            (':method', req_data['method']),
            (':path', req_data['path']),
            (':authority', host),
            (':scheme', 'https'),
            ('content-type', 'application/json'),
        ]
        
        conn.send_headers(stream_id, headers)
        conn.send_data(stream_id, req_data['body'].encode(), end_stream=True)
    
    # Send ALL buffered data in a single write (single TCP packet)
    sock.sendall(conn.data_to_send())
    
    # Read responses
    responses = {}
    while len(responses) < len(requests):
        data = sock.recv(65535)
        events = conn.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.ResponseReceived):
                responses[event.stream_id] = {'headers': event.headers}
            elif isinstance(event, h2.events.DataReceived):
                responses.setdefault(event.stream_id, {})['data'] = \
                    responses.get(event.stream_id, {}).get('data', b'') + event.data
                conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
        sock.sendall(conn.data_to_send())
    
    return responses
```

### 3.5 Detection Methodology

**Manual testing approach:**

1. Identify state-changing endpoints (POST, PUT, PATCH, DELETE)
2. Determine what state is checked before the operation
3. Determine what state is modified by the operation
4. If the check and modification are not atomic, the endpoint is potentially vulnerable
5. Use Turbo Intruder or custom HTTP/2 clients to send 10-100 simultaneous requests
6. Analyze responses:
   - Multiple 200 OK responses where only one should succeed indicate a race condition
   - Inconsistent response bodies suggest partial success
   - Database state showing impossible values (negative balances, duplicate entries) confirms exploitation

**Automated detection:**

```python
# Race condition detection pattern
import asyncio
import aiohttp

async def test_race_condition(url, payload, num_requests=20):
    """Send concurrent requests and check for race conditions."""
    async with aiohttp.ClientSession() as session:
        tasks = []
        for _ in range(num_requests):
            tasks.append(session.post(url, json=payload))
        
        responses = await asyncio.gather(*tasks)
        
        success_count = sum(1 for r in responses if r.status == 200)
        
        if success_count > 1:
            print(f"POTENTIAL RACE CONDITION: {success_count}/{num_requests} requests succeeded")
            for r in responses:
                print(f"  Status: {r.status}, Body: {await r.text()}")
```

### 3.6 Remediation

**Database-level locking:**

```sql
-- Use SELECT ... FOR UPDATE to acquire a row-level lock
BEGIN;
SELECT balance FROM accounts WHERE user_id = 123 FOR UPDATE;
-- Now other transactions trying to read this row will block
UPDATE accounts SET balance = balance - 100 WHERE user_id = 123;
COMMIT;
```

**Atomic operations:**

```sql
-- Single atomic statement instead of check-then-act
UPDATE accounts 
SET balance = balance - 100 
WHERE user_id = 123 AND balance >= 100;
-- Check affected rows: if 0, insufficient balance
```

**Idempotency keys:**

```python
@app.route('/api/transfer', methods=['POST'])
def transfer():
    idempotency_key = request.headers.get('Idempotency-Key')
    if not idempotency_key:
        return jsonify({"error": "Idempotency-Key header required"}), 400
    
    # Use UNIQUE constraint on idempotency key
    try:
        db.execute(
            "INSERT INTO transactions (idempotency_key, user_id, amount, status) VALUES (%s, %s, %s, 'processing')",
            (idempotency_key, current_user.id, request.json['amount'])
        )
    except UniqueViolation:
        # Duplicate request - return the original result
        existing = db.execute("SELECT * FROM transactions WHERE idempotency_key = %s", (idempotency_key,)).fetchone()
        return jsonify({"status": existing['status']})
    
    # Process the unique transaction
    # ...
```

**Distributed locks (Redis-based):**

```python
import redis

def with_distributed_lock(lock_name, timeout=10):
    """Acquire a distributed lock before processing."""
    r = redis.Redis()
    lock = r.lock(f"lock:{lock_name}", timeout=timeout)
    
    if lock.acquire(blocking=True, blocking_timeout=5):
        try:
            yield
        finally:
            lock.release()
    else:
        raise Exception("Could not acquire lock")
```

**Unique database constraints:**

```sql
-- Prevent duplicate coupon applications
CREATE UNIQUE INDEX idx_coupon_usage ON coupon_usage (coupon_code, user_id);
-- Prevent duplicate accounts
CREATE UNIQUE INDEX idx_users_email ON users (email);
```
