# Gap Analysis: Testing Depth & Protocol Coverage — Agent Chunk 55c
> Source: 12-gap-analysis.md
> Purpose: Assess testing depth per vulnerability class and protocol-specific coverage gaps
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Assess testing depth levels: L1 (surface scan), L2 (standard manual), L3 (thorough hypothesis-driven), L4 (expert creative exploitation). Identify upgrade targets. Review protocol-specific coverage.

---

- **DAST tools for API security**: Dynamic testing tools integrated into CI/CD:
  - OWASP ZAP API scan
  - Nuclei for API testing
  - Burp Suite Enterprise for CI/CD
  - API-specific scanners (Astra, StackHawk)
- **IAST (Interactive Application Security Testing)**: Runtime agent-based testing for APIs during integration tests:
  - Contrast Security
  - Hdiv Security (now part of Datadog)
  - Synopsys Seeker

**API Contract Testing Security**

- **OpenAPI specification validation**: Testing that API implementations match their OpenAPI specifications and that specifications are secure.
- **Pact contract testing**: Using consumer-driven contract tests to detect breaking API changes that could introduce security gaps.
- **Schema validation as security control**: How enforcing strict schema validation in CI/CD prevents entire classes of injection attacks.
- **Backward compatibility security**: Ensuring API version updates do not regress security controls.

**Pipeline Credential Theft Targeting API Tokens**

- **CI/CD supply chain attacks**: Compromising CI/CD pipelines to steal API tokens:
  - Malicious pull request attacks (exposing secrets through PR builds)
  - Dependency confusion attacks targeting CI/CD package installation
  - Compromised CI/CD actions/plugins
  - Runner compromise and credential theft
- **Privilege escalation through CI/CD**: Using CI/CD pipeline access to escalate to production API credentials.
- **Build artifact poisoning**: Injecting malicious code into build artifacts that compromise API security at runtime.

**Platform-Specific CI/CD API Security**

- **GitHub Actions**: Secret exposure through `GITHUB_TOKEN` permissions, reusable workflow security, third-party action risks, OIDC federation for cloud API access.
- **GitLab CI**: CI/CD variable security, protected environments, pipeline trigger token security, OIDC integration.
- **Jenkins**: Credential management, pipeline script security, plugin vulnerability surface, API token management.
- **Azure DevOps**: Service connection security, variable group protection, pipeline approval gates.

**Artifact Registry API Security**

- **Container registry security**: Docker Hub, ECR, GCR, ACR API security — authentication, authorization, image signing.
- **Package registry security**: npm, PyPI, Maven, NuGet — API security for package publication and consumption.
- **Artifact integrity**: Code signing, SBOM generation, and verification through CI/CD APIs.

##### Specific Research Tasks

1. Document API key leakage patterns in CI/CD with real-world examples
2. Build SAST/DAST integration guide for API security testing in CI/CD
3. Develop CI/CD API security audit checklist (20+ items)
4. Document pipeline credential theft techniques with mitigations
5. Write platform-specific guides for GitHub Actions, GitLab CI, and Jenkins API security

---

#### Gap 6: LLM/AI API Security

**Current Coverage**: Mentioned in local corpus inventory; not substantively covered
**Priority**: HIGH
**Estimated Effort**: HIGH (50-60 hours)

##### What Is Missing

**Prompt Injection Through API Parameters**

- **Direct prompt injection**: Injecting LLM prompts through API parameters that are concatenated with system prompts:
  - JSON field injection where user input is embedded in LLM prompts
  - System prompt extraction through carefully crafted API inputs
  - Instruction override attacks ("Ignore previous instructions and...")
  - Prompt leaking through token-by-token streaming responses
- **Indirect prompt injection**: Injecting prompts through data that the LLM processes:
  - Web content poisoning for RAG-based APIs
  - Email content injection for AI assistant APIs
  - Document content injection for AI summarization APIs
  - Database content poisoning for AI-powered search APIs
- **Multi-modal prompt injection**: Injecting instructions through:
  - Image content (hidden text in images processed by vision APIs)
  - Audio content (hidden commands in audio processed by speech APIs)
  - Video content (instruction frames in video processing APIs)
- **Prompt injection detection and prevention**:
  - Input sanitization techniques specific to LLM APIs
  - Prompt injection classifier APIs and their bypass
  - Structural prompt isolation patterns
  - LLM output validation and sandboxing

**LLM API Rate Limiting and Cost Management**

- **Token-based rate limiting**: Rate limiting based on input/output token count rather than request count.
- **Cost amplification attacks**: Crafting inputs that maximize LLM API cost (long prompts, instructions to generate maximum-length responses).
- **Recursive API call exploitation**: AI agents that make API calls in loops, amplifying costs through recursive behavior.
- **Budget exhaustion attacks**: Deliberately exhausting API budget limits to cause denial of service.

**Model Stealing Through API Queries**

- **Model extraction attacks**: Using API queries to reconstruct model behavior:
  - Systematic query patterns that map decision boundaries
  - Distillation attacks using API query/response pairs
  - Side-channel attacks through API timing and token probabilities
- **API-level defenses**: Rate limiting, query detection, watermarking, and fingerprinting techniques.
- **Intellectual property risks**: Legal and technical aspects of model extraction through APIs.

**Training Data Extraction**

- **Memorization exploitation**: Crafting API queries that cause the model to regurgitate training data:
  - Verbatim text extraction through completion prompts
  - PII extraction from language model APIs
  - Extraction of training data that includes API keys, credentials, or other secrets
- **Differential privacy considerations**: How differential privacy training techniques affect API-level extraction risks.

**Authentication for AI Services**

- **API key security for AI services**: Unique challenges of AI API key management:
  - Client-side AI API key exposure (browser, mobile app)
  - API key scoping (model access, token limits, feature restrictions)
  - Usage-based billing abuse through stolen API keys
- **OAuth for AI APIs**: Implementing OAuth 2.0 for AI service APIs with appropriate scopes.
- **API key rotation for AI services**: Challenges of rotating API keys used by distributed AI applications.

**Retrieval Augmented Generation (RAG) Injection**

- **RAG poisoning attacks**: Injecting malicious content into the knowledge base that RAG systems retrieve:
  - Document injection into vector databases
  - Metadata manipulation to increase retrieval ranking
  - Embedding space manipulation
- **RAG authorization bypass**: Exploiting RAG systems to access documents the user should not have access to:
  - Cross-tenant data leakage through shared vector databases
  - Permission boundary bypass through semantic similarity
  - Document-level access control in RAG pipelines
- **RAG prompt leaking**: Extracting system prompts and retrieval context through crafted queries.

**Tool-Calling Security in AI Agents**

- **Tool call injection**: Manipulating AI agent behavior to make unauthorized tool calls:
  - Instructing agents to call APIs with attacker-controlled parameters
  - Confused deputy attacks where the agent acts on behalf of an attacker
  - Tool call chain exploitation (agent calls tool A which triggers tool B)
- **Tool call authorization**: How to properly authorize tool calls made by AI agents:
  - User-level permission scoping for agent actions
  - Confirmation workflows for high-risk tool calls
  - Audit logging of agent-initiated API calls
- **Tool call validation**: Validating tool call parameters before execution:
  - Schema validation for tool inputs
  - Business logic validation for tool call sequences
  - Rate limiting on agent-initiated tool calls

**Multi-Modal API Security**

- **Image input attacks**: Adversarial images that cause vision APIs to misclassify or execute hidden instructions.
- **Audio input attacks**: Adversarial audio that causes speech APIs to transcribe hidden commands.
- **Document input attacks**: Malicious documents (PDF, DOCX) that exploit document processing APIs.
- **Cross-modal attacks**: Combining multiple modalities to bypass single-modality security controls.

##### Specific Research Tasks

1. Develop prompt injection taxonomy with API-specific attack patterns
2. Build RAG injection test suite with common vector database configurations
3. Document tool-calling security patterns for AI agent APIs
4. Catalog AI/LLM API-specific CVEs and security incidents (2023-2025)
5. Develop 20+ AI/LLM API security test cases
6. Write remediation guidance for prompt injection, RAG injection, and tool-calling security
7. Analyze AI API security for major providers (OpenAI, Anthropic, Google, Azure)

---

#### Gap 7: Mobile API Backend Security

**Current Coverage**: Mobile app analysis for API discovery mentioned in Chapter 5
**Priority**: MEDIUM
**Estimated Effort**: MEDIUM (25-35 hours)

##### What Is Missing

**Certificate Pinning Implementation and Bypass**

- **Pinning implementation patterns**: Certificate vs public key pinning across platforms:
  - iOS: `URLSession` delegate pinning, `Info.plist` ATS configuration, third-party libraries (TrustKit, Alamofire)
  - Android: Network Security Config, OkHttp `CertificatePinner`, custom `TrustManager`
  - Cross-platform: React Native, Flutter, Xamarin pinning approaches
- **Pinning bypass techniques**: For legitimate security testing:
  - Frida-based bypass scripts (ios-ssl-bypass, android-ssl-pinning-bypass)
  - Objection framework for runtime SSL pinning bypass
  - Xposed framework modules (JustTrustMe, SSLUnpinning)
  - Manual patching of application binaries
  - Magisk/Zygisk modules for system-wide bypass
- **Pinning bypass detection**: How servers can detect that pinning has been bypassed:
  - Client certificate verification
  - Device attestation (SafetyNet/Play Integrity, DeviceCheck/App Attest)
  - TLS fingerprinting

**API Security for Offline-First Mobile Apps**

- **Local data security**: Encryption of API responses cached locally (SQLite encryption, encrypted SharedPreferences/Keychain).
- **Sync conflict resolution security**: How data synchronization between offline-first apps and APIs can be exploited to bypass server-side validation.
- **Offline token management**: JWT and refresh token storage and rotation for apps that operate offline for extended periods.
- **Delta sync attacks**: Manipulating incremental sync payloads to inject or modify data.

**Push Notification API Abuse**

- **Push notification spoofing**: Sending fraudulent push notifications through compromised API credentials (APNs key, FCM server key).
- **Push token harvesting**: Collecting device push tokens through API vulnerabilities for spam or phishing.
- **Silent push exploitation**: Using silent push notifications for device tracking or background task triggering.
- **Push notification content injection**: Injecting malicious content (deeplinks, URLs) into push notification payloads.

**Deep Linking and Custom URL Scheme Exploitation**

- **Deep link hijacking**: Registering competing custom URL schemes to intercept API authentication flows.
- **Universal Links/App Links security**: Misconfigured `apple-app-site-association` or `assetlinks.json` allowing deep link interception.
- **OAuth deep link interception**: Stealing authorization codes through deep link redirect interception.
- **Intent-based attacks (Android)**: Exploiting exported activities and intent filters for API credential theft.

**Mobile Biometric API Security**

- **Biometric authentication API bypass**: Bypassing `BiometricPrompt` (Android) or `LAContext` (iOS) to access API credentials without biometric verification.
- **Crypto-bound biometrics**: Ensuring biometric authentication is cryptographically bound to key access, not just a UI gate.
- **Fallback authentication attacks**: Exploiting PIN/password fallback mechanisms that bypass biometric requirements.

**API Key Protection in Mobile Apps**

- **Secure enclave usage**: Using hardware security modules (Android Keystore, iOS Secure Enclave) for API key storage.
- **App attestation for API security**: Using Play Integrity (Android) and App Attest (iOS) to verify legitimate apps before granting API access.
- **Runtime application self-protection (RASP)**: Detecting tampering, debugging, and reverse engineering at runtime.
- **API key obfuscation limitations**: Why obfuscation is not a security boundary and what it should be combined with.

##### Specific Research Tasks

1. Document certificate pinning implementation and bypass for iOS and Android
2. Develop mobile API backend security test methodology (15+ test cases)
3. Catalog mobile-specific API vulnerabilities from bug bounty reports
4. Write remediation guidance for mobile API key protection
5. Document push notification API abuse patterns and mitigations

---

#### Gap 8: Real-Time Communication API Security

**Current Coverage**: WebSocket and Server-Sent Events covered in Chapter 8
**Priority**: LOW-MEDIUM
**Estimated Effort**: MEDIUM (20-30 hours)

##### What Is Missing

**WebRTC Signaling API Security**

- **Signaling server vulnerabilities**: Authentication and authorization bypass in WebRTC signaling APIs (typically WebSocket or REST-based).
- **ICE candidate manipulation**: Injecting malicious ICE candidates to redirect media traffic.
- **SDP (Session Description Protocol) injection**: Manipulating SDP offers/answers to alter session parameters.
- **TURN server credential exposure**: API endpoints that expose TURN server credentials, enabling unauthorized relay usage.
- **Ooming of STUN/TURN servers through API-generated sessions**: Denial of service through excessive session creation.

**MQTT API Security**

- **MQTT authentication bypass**: Weak or missing authentication in MQTT brokers exposed through APIs:
  - Anonymous access to MQTT brokers
  - Default credential exploitation
  - MQTT-over-WebSocket authentication bypass
- **MQTT authorization (ACL) bypass**: Topic-level access control bypass:
  - Wildcard topic subscription (`#`, `+`) for information disclosure
  - Publishing to restricted topics
  - Topic injection through crafted topic strings
- **MQTT-specific attacks**:
  - Will message exploitation
  - Retained message poisoning
  - QoS downgrade attacks
  - Client ID collision exploitation
- **MQTT over WebSocket**: Browser-side MQTT client security considerations.

**AMQP/RabbitMQ API Security**

- **RabbitMQ Management API**: Authentication, authorization, and security of the HTTP management API (default on port 15672).
- **AMQP virtual host security**: Isolation between virtual hosts and cross-vhost access patterns.
- **Exchange and queue permission bypass**: Misconfigured permissions allowing unauthorized message consumption or publication.
- **Message payload security**: Encryption and integrity of AMQP messages.
- **Shovel and Federation security**: Security of inter-broker communication.

**Apache Kafka API Security**

- **Kafka authentication**: SASL mechanisms (PLAIN, SCRAM, GSSAPI, OAUTHBEARER) — security of each.
- **Kafka authorization**: ACL-based authorization bypass and misconfiguration patterns.
- **Kafka REST Proxy security**: Security of the Confluent REST Proxy that exposes Kafka through HTTP APIs.
- **Schema Registry API security**: Authentication and authorization for the Schema Registry API.
- **Kafka Connect API security**: Security of the Connect REST API for managing connectors.
- **Kafka Streams API security**: Security considerations for stream processing applications.

**Real-Time Database APIs**

- **Firebase Realtime Database and Firestore security**: Security rules misconfiguration and bypass:
  - Overly permissive rules (`.read: true`, `.write: true`)
  - Rule evaluation bypass through nested path access
  - Custom claims exploitation
  - Data validation rule bypass
  - Firebase Admin SDK credential exposure
- **Supabase API security**: Row-level security (RLS) policy bypass and PostgREST security considerations.
- **AWS AppSync security**: GraphQL subscription security, authorization mode misconfiguration.
- **Hasura API security**: Role-based access control bypass, metadata API exposure.

**Long-Polling Security Considerations**

- **Connection exhaustion**: Long-polling endpoints holding connections open for extended periods, enabling connection pool exhaustion.
- **Session fixation through long-poll**: Exploiting long-poll connections for session management bypass.
- **Resource consumption**: Memory and thread exhaustion through excessive long-poll connections.

##### Specific Research Tasks

1. Document MQTT API security testing methodology
2. Catalog Firebase security rule misconfiguration patterns
3. Develop Kafka API security testing checklist
4. Write real-time communication API security comparison guide
5. Create 10+ test cases for real-time communication API security

---

#### Gap 9: API Compliance and Regulatory Requirements

**Current Coverage**: Minimal
**Priority**: MEDIUM
**Estimated Effort**: MEDIUM (25-35 hours)

##### What Is Missing

**PCI DSS Requirements for Payment APIs**

- **PCI DSS 4.0 API-specific requirements**:
  - Requirement 6.2: Secure development practices for payment APIs
  - Requirement 6.3: Security vulnerabilities identification for APIs processing cardholder data
  - Requirement 6.4: Public-facing web application protection (WAF for payment APIs)
