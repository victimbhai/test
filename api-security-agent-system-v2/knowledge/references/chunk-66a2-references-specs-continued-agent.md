# References: Specifications Continued — Agent Chunk 66a2
> Source: 14-references.md
> Purpose: Continue reference for API-related specifications, authentication standards, and protocol security documentation
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Continue referencing API standards and specifications for implementation verification and report citations.

---

configuration metadata.

- **URL**: https://www.rfc-editor.org/rfc/rfc8414
- **Relevance**: Discovery of OAuth endpoints, supported grant types, and configuration;
  valuable for reconnaissance during API security testing

#### RFC 7662 -- OAuth 2.0 Token Introspection

Defines a method for a protected resource to query an authorization server about the
active state and metadata of an OAuth 2.0 token.

- **URL**: https://www.rfc-editor.org/rfc/rfc7662
- **Relevance**: Testing token validation, token revocation verification

#### RFC 7009 -- OAuth 2.0 Token Revocation

Defines an endpoint for clients to notify the authorization server that a previously
obtained token is no longer needed.

- **URL**: https://www.rfc-editor.org/rfc/rfc7009
- **Relevance**: Testing token lifecycle management and revocation effectiveness

### 1.3 HTTP and Transport RFCs

#### RFC 9113 -- HTTP/2

Defines the HTTP/2 protocol, including binary framing, multiplexing, header compression,
and server push.

- **URL**: https://www.rfc-editor.org/rfc/rfc9113
- **Published**: June 2022
- **Relevance**: HTTP/2-specific attack vectors including stream multiplexing abuse, HPACK
  bombing, and rapid reset attacks (CVE-2023-44487)
- **Supersedes**: RFC 7540

#### RFC 9114 -- HTTP/3

Defines the HTTP/3 protocol based on QUIC, providing multiplexed HTTP over UDP.

- **URL**: https://www.rfc-editor.org/rfc/rfc9114
- **Published**: June 2022
- **Relevance**: Emerging attack surface; QUIC-specific considerations for API security;
  UDP-based transport changes the threat model for network-level attacks

#### RFC 6455 -- The WebSocket Protocol

Defines the WebSocket protocol for bidirectional communication over a single TCP connection.

- **URL**: https://www.rfc-editor.org/rfc/rfc6455
- **Published**: December 2011
- **Relevance**: WebSocket APIs have unique security considerations including origin
  validation, message injection, and cross-site WebSocket hijacking

#### RFC 8259 -- The JavaScript Object Notation (JSON) Data Interchange Format

The authoritative specification for JSON syntax, superseding RFC 7159.

- **URL**: https://www.rfc-editor.org/rfc/rfc8259
- **Published**: December 2017
- **Relevance**: JSON parsing inconsistencies between implementations can lead to security
  vulnerabilities; understanding the specification helps identify parser differential attacks

#### RFC 9110 -- HTTP Semantics

Defines the semantics of HTTP messages, including methods, status codes, and header fields.

- **URL**: https://www.rfc-editor.org/rfc/rfc9110
- **Published**: June 2022
- **Relevance**: Authoritative reference for HTTP method semantics, status code meanings,
  and content negotiation -- essential for understanding API behavior

#### RFC 6265 -- HTTP State Management Mechanism (Cookies)

Defines HTTP cookie behavior, including setting, sending, and security attributes.

- **URL**: https://www.rfc-editor.org/rfc/rfc6265
- **Relevance**: Cookie-based session management in APIs, SameSite attribute testing,
  Secure and HttpOnly flag verification

### 1.4 API Specification Standards

#### OpenAPI Specification (OAS)

The industry standard for describing RESTful APIs.

| Version | Key Features                                          | URL                                         |
|---------|--------------------------------------------------------|----------------------------------------------|
| 3.0.3   | Callbacks, links, stable release                      | https://spec.openapis.org/oas/v3.0.3         |
| 3.1.0   | JSON Schema alignment, webhooks                       | https://spec.openapis.org/oas/v3.1.0         |
| 3.2.0   | Overlays, improved extensibility (planned/released)   | https://spec.openapis.org/oas/latest.html    |

- **Relevance**: OpenAPI specifications are a primary input for API security testing; they
  define endpoints, parameters, authentication schemes, and data models
- **Security-relevant features**: Security schemes (OAuth, API key, Bearer), parameter
  validation constraints, response schemas

#### GraphQL Specification

The specification for the GraphQL query language and runtime.

- **URL**: https://spec.graphql.org/
- **Latest stable**: October 2021
- **Relevance**: GraphQL-specific security considerations including introspection, query
  depth/complexity limits, batching, field-level authorization, and injection

#### AsyncAPI Specification

A specification for defining asynchronous APIs (WebSocket, MQTT, AMQP, Kafka).

- **URL**: https://www.asyncapi.com/docs/reference/specification/latest
- **Relevance**: Defines event-driven API interfaces; security testing of message brokers
  and streaming APIs

#### gRPC

Google's high-performance RPC framework using Protocol Buffers over HTTP/2.

- **URL**: https://grpc.io/docs/
- **Relevance**: gRPC API security testing, protobuf deserialization vulnerabilities,
  metadata injection, and channel security

### 1.5 NIST Standards

#### NIST SP 800-228 -- Guidelines for API Protection (Draft)

NIST guidance on securing APIs, covering API security architecture, threat modeling,
and protection strategies.

- **URL**: https://csrc.nist.gov/publications/detail/sp/800-228/final
- **Published**: Under development / recently published
- **Relevance**: Government and enterprise API security compliance requirements

#### NIST SP 800-63-3 -- Digital Identity Guidelines

Guidelines for digital identity services including authentication and federation.

- **URL**: https://pages.nist.gov/800-63-3/
- **Relevance**: Authentication strength levels (AAL), identity proofing, and federation
  assurance levels applicable to API authentication design

#### NIST SP 800-53 Rev. 5 -- Security and Privacy Controls

Comprehensive catalog of security and privacy controls for information systems.

- **URL**: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- **Relevance**: Compliance framework; maps API security controls to federal requirements

#### NIST SP 800-95 -- Guide to Secure Web Services

Guidance specific to securing web services including SOAP and REST.

- **URL**: https://csrc.nist.gov/publications/detail/sp/800-95/final
- **Relevance**: Foundational web services security architecture, somewhat dated but
  principles remain applicable

### 1.6 Industry Compliance Standards

#### PCI DSS v4.0

Payment Card Industry Data Security Standard, applicable to APIs that process, store,
or transmit cardholder data.

- **URL**: https://www.pcisecuritystandards.org/
- **Key requirements for APIs**:
  - Requirement 6: Develop and maintain secure systems (including APIs)
  - Requirement 7: Restrict access by business need-to-know
  - Requirement 8: Identify users and authenticate access
  - Requirement 10: Log and monitor all access

#### SOC 2 Type II

Service Organization Control 2 audit framework, relevant to API providers.

- **Trust Service Criteria relevant to APIs**:
  - CC6: Logical and Physical Access Controls
  - CC7: System Operations
  - CC8: Change Management

---

