---
title: "Security Event Framework for AI Systems"
abbrev: "AI Security Events"
category: info

docname: draft-iqbal-ai-security-events-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: SEC
workgroup:
keyword:
 - AI security
 - MCP
 - data loss prevention
venue:
  group:
  type:
  mail:
  arch:
  github:
  latest:

author:
 -
    fullname: Jawaid Iqbal
    organization: Zscaler
    email: jiqbal@zscaler.com
    role: editor

normative:
  RFC2119:
  RFC8174:

informative:


--- abstract

This document describes a comprehensive security event framework for monitoring AI agent systems, including agentic AI workflows, autonomous agent architectures, and tool-calling protocols.  While motivated by the Model Context Protocol (MCP), the framework applies broadly to any AI system exhibiting agent-like behaviors, addressing critical gaps in traditional security monitoring through standardized event taxonomies, correlation schemas, and detection approaches specifically designed for AI-mediated data access and semantic transformation.  The document describes five security event categories: Discovery, Risk Assessment, Data Access, Policy Enforcement, and Semantic Data Lineage.  Event schemas are designed as a domain-specific profile that complements existing security event standards (CEF, LEEF, OCSF) rather than replacing them, enabling integration with existing SIEM infrastructure while providing AI-specific semantics.  The framework is protocol-agnostic, supporting multiple AI agent frameworks including the Model Context Protocol (MCP), LangChain, and others.  It explicitly addresses diverse deployment patterns including direct client-server, gateway consolidation, embedded AI, autonomous agents, and multi-agent orchestration.  This document provides a taxonomy and event semantics for AI agent systems; it does not prescribe enforcement mechanisms or operational controls.


--- middle

# Introduction

## Problem Statement

AI agent systems introduce autonomous capabilities that transcend traditional security monitoring approaches.  These systems invoke tools to access enterprise data, transform information semantically through large language model processing, maintain conversational context across sessions, and operate through protocols designed for functionality rather than security observability.

Existing security frameworks generate events based on file movement, network traffic patterns, and process execution.  These approaches fail to detect AI-mediated data exfiltration where:

* Sensitive data is compressed semantically (500KB document to 2KB summary)
* Information is aggregated across multiple non-sensitive sources
* Data transformations occur within encrypted AI API calls
* Context persists across sessions without explicit data transfer

This document provides a domain-specific event taxonomy for AI agent systems that complements existing security event standards (CEF, LEEF, OCSF) by adding AI-specific semantics while maintaining interoperability with existing SIEM infrastructure.  Rather than replacing existing standards, this framework extends them to address unique AI agent security requirements.

## Critical Security Gaps

Analysis of production AI agent deployments has identified four critical architectural gaps in traditional security systems:

Gap 1: Visibility Gap. AI capabilities embedded within trusted domains operate outside inspection boundaries.  Production evidence from analyzed deployments indicates 30-40% of observed AI traffic operates within trusted application contexts, creating significant blind spots in security monitoring.

Gap 2: The Decoupled Transaction Gap. Traditional security logging assumes a synchronous, 1:1 relationship between a network session and a data transfer (e.g., a single POST request containing a file). AI agent interactions frequently split data transfer across multiple HTTP transactions, temporal boundaries, and semantic transformations. This violates fundamental assumptions in DLP and CASB architectures designed around atomic file operations.

Gap 3: Semantic Transformation Gap. Traditional data loss prevention systems operate on pattern matching, file signatures, and data fingerprinting - techniques effective for detecting verbatim file copies.  AI agents fundamentally transform data semantically: a 500KB confidential document becomes a 2KB summary that contains the same sensitive insights but matches zero DLP signatures.  In analyzed production traffic, traditional DLP systems achieved 0% detection of AI-mediated semantic data exposure while maintaining 95%+ accuracy for traditional file transfers.

Gap 4: Protocol Opacity Gap. The Model Context Protocol and similar agent frameworks operate as stateful, bidirectional communication channels.  Tool invocations, resource access, and data retrieval occur within encrypted sessions that expose minimal metadata. Traditional network security tools lack semantic awareness of MCP operations, treating agent traffic as generic HTTPS sessions.

## Motivating Use Cases

This framework addresses observable security requirements in enterprise AI deployments:

Use Case 1: Unmanaged AI Client Discovery. An AI-enabled code editor operates outside formal governance, accessing production databases through tool invocations.  Security teams require visibility into such unmanaged AI clients that operate outside formal AI governance frameworks.

Use Case 2: Cross-Session Data Correlation. An AI agent aggregates customer data across multiple tool calls spanning three days, then generates a comprehensive analysis.  Each individual tool call accesses non-sensitive data, but the aggregate reveals confidential business intelligence.  Traditional monitoring sees isolated, benign queries rather than systematic data exfiltration.

Use Case 3: Semantic Data Exposure. A user uploads a 45-page M&A term sheet to an AI service, receives strategic advice, then shares the AI-generated summary externally.  The summary contains no original document text but exposes deal structure, valuation multiples, and negotiation strategy.  File-based DLP systems detect neither the upload (encrypted API call) nor the exposure (novel text, no fingerprint match).

Use Case 4: Multi-Agent Orchestration Risk. An autonomous agent framework coordinates three specialized agents: one accesses financial data, another retrieves customer contracts, and a third generates forecasts.  The orchestration layer combines outputs to produce insights that violate data segregation policies.  Traditional monitoring sees three independent, policy-compliant transactions rather than a coordinated data aggregation operation.

## Scope and Applicability

This document describes an event taxonomy and correlation framework. It does not prescribe:

* Specific enforcement mechanisms or operational controls
* Required detection thresholds or sensitivity levels
* Mandatory implementation architectures
* Compliance or regulatory interpretations

The framework applies to environments where:

* AI agents access enterprise data through tool invocations
* Organizations require audit trails for AI-mediated data access
* Security teams need correlation across AI transactions
* Existing SIEM infrastructure requires AI-specific event context

The framework explicitly does not address:

* AI model training data governance
* Inference-time prompt injection attacks
* AI system availability or performance monitoring
* General application security logging

## Requirements Language

{::boilerplate bcp14-tagged}

## Terminology

AI Agent:
: An autonomous system that invokes tools, maintains conversational context, and operates through protocols like MCP.

Tool Invocation:
: An AI-initiated operation that accesses data, executes code, or interacts with external systems.

Semantic Transformation:
: The process by which AI systems compress, summarize, or reformulate data while preserving informational content.

Unmanaged AI Client:
: An AI agent operating outside formal governance frameworks, often embedded in developer tools or productivity applications.

Split-Transaction Transfer:
: Data access pattern where information moves across multiple HTTP transactions, temporal boundaries, or protocol layers rather than a single atomic operation.

# Architecture Overview

## Event Flow Model

The event framework observes AI agent operations at three distinct detection surfaces:

Network Telemetry Layer:
: Captures HTTP transactions, TLS metadata, and protocol-level indicators without requiring payload inspection. Production validation demonstrates >95% detection accuracy using User-Agent strings, temporal burst patterns, payload asymmetry, and endpoint signatures.

Application Integration Layer:
: Observes tool invocations, resource access, and data retrieval through MCP server instrumentation or similar agent framework hooks.

Semantic Analysis Layer:
: Correlates data access patterns across transactions, sessions, and agent interactions to detect aggregate information disclosure.

### Split-Transaction Transfer Model

Traditional security monitoring assumes atomic data transfers - a single HTTP POST containing a complete file, or a single database query returning a result set.  AI agent interactions frequently violate this assumption through patterns observed in production deployments:

* Temporal Splitting: Data access distributed across multiple tool invocations over hours or days (e.g., agent retrieves customer list on Monday, financial data on Tuesday, generates combined analysis on Wednesday)
* Semantic Splitting: Information transformed across transactions (e.g., agent reads 500KB document, extracts key points, generates 2KB summary, shares summary externally)
* Protocol Splitting: Data movement across multiple protocol layers (e.g., database query via MCP tool → LLM processing → external API call)
* Agent Splitting: Information aggregated through multi-agent coordination (e.g., Agent A retrieves data, Agent B analyzes, Agent C disseminates)

Detection of split-transaction transfers requires correlation of events across time, agents, and protocols - capabilities absent from traditional DLP and CASB systems designed around file-based operations.

## Detection Surfaces

Event generation may occur at multiple observation points:

* Network proxies or gateways (inline observation)
* MCP servers or agent frameworks (application-layer hooks)
* SIEM correlation engines (post-collection analysis)
* Endpoint agents (client-side monitoring)

## Deployment Pattern Taxonomy

The framework addresses five common deployment architectures observed in production AI systems:

### Direct Client-Server Pattern

AI client communicates directly with MCP servers or AI APIs. Detection relies on network telemetry and endpoint monitoring.

### Gateway Pattern

Centralized proxy or gateway consolidates AI traffic.  Enables inline policy enforcement and comprehensive logging.

### Embedded AI Pattern

AI capabilities embedded within trusted applications (e.g., code editors, productivity tools).  These often operate outside formal governance and require specialized detection methods.

### Autonomous Agent Pattern

Self-directed agents operating with minimal human supervision. Require continuous monitoring and automated risk assessment.

### Multi-Agent Orchestration Pattern

Coordinated agent systems with specialized roles.  Detection requires cross-agent correlation to identify aggregate risks.

# Event Taxonomy

The framework documents five event categories that capture AI agent security lifecycle:

## Discovery Events

Discovery events document the identification of AI agents, unmanaged clients, and protocol endpoints.  These events establish the foundational inventory for security monitoring.

Key attributes include agent type, protocol version, authentication context, and discovery method (network telemetry, application integration, or user report).

## Risk Assessment Events

Risk assessment events document security posture evaluation of discovered AI agents, including:

* Governance status (managed vs. unmanaged)
* Authentication and authorization mechanisms
* Data access scope and permissions
* Protocol security characteristics (encryption, integrity)
* Compliance posture relative to organizational policies

## Data Access Events

Data access events document AI agent interactions with enterprise resources, capturing:

* Tool invocations (type, target, parameters)
* Resource access (databases, APIs, file systems)
* Data volume and classification
* User-to-Agent (U2A) attribution
* Temporal patterns and access frequency

## Policy Enforcement Events

Policy enforcement events document security decisions and actions:

* Policy evaluations (allow, deny, alert)
* Enforcement actions (block, quarantine, log)
* Justification and rule matching
* Override mechanisms and approvals

## Semantic Data Lineage Events

Semantic data lineage events track data transformation and movement across AI interactions:

* Source data identification and classification
* Transformation operations (summarization, extraction, synthesis)
* Cross-session correlation identifiers
* Aggregate risk assessment
* Downstream data usage and distribution

# Common Event Schema Elements

All events in the framework share common schema elements that enable correlation and analysis:

## Event Classification

* event_type: Primary category (discovery, risk_assessment, data_access, policy_enforcement, semantic_lineage)
* event_subtype: Specific operation within category
* severity: Risk level (info, low, medium, high, critical)
* confidence: Detection confidence score (0.0-1.0)

## Correlation Fields

* correlation_id: Session or conversation identifier
* u2a_session_id: User-to-Agent session tracking
* parent_event_id: Reference to related events
* agent_chain_id: Multi-agent orchestration tracking

## Temporal Fields

* timestamp: Event occurrence time (ISO 8601)
* session_start_time: Session initiation
* session_end_time: Session termination
* event_sequence: Order within session

## Identity Fields

* user_id: Human user identifier
* agent_id: AI agent identifier
* client_id: Application or device identifier
* authentication_method: How identity was established

## Network Context

* source_ip: Originating IP address
* destination_ip: Target IP address
* user_agent: HTTP User-Agent string
* protocol: Transport protocol (https, mcp-stdio, grpc)
* tls_version: TLS protocol version

## Data Classification

* data_classification: Sensitivity level (public, internal, confidential, restricted)
* data_category: Type of information (financial, customer, source code, healthcare)
* data_volume: Bytes transferred or accessed

# Security Considerations

This framework addresses security monitoring for AI agent systems. Implementation introduces additional security considerations:

## Privacy Protection

Event collection must balance security visibility with privacy protection.  Implementations should:

* Capture metadata without recording conversation content
* Implement data minimization principles
* Respect regulatory requirements (GDPR, CCPA, etc.)
* Provide user transparency and consent mechanisms

## False Positive Management

Network telemetry-based detection may generate false positives. Production validation suggests multi-signal fusion (combining User-Agent, temporal patterns, and payload characteristics) achieves >95% accuracy.  Organizations should tune detection thresholds based on their risk tolerance and operational requirements.

## Evasion Resistance

Sophisticated adversaries may attempt to evade detection by:

* Manipulating User-Agent strings
* Introducing artificial delays to avoid temporal signatures
* Fragmenting data access across multiple agents or sessions

Defense requires layered detection combining network telemetry, application integration, and behavioral analysis.

## Encrypted Traffic Handling

Most AI agent traffic operates over TLS.  Network-based detection relies on unencrypted metadata (TLS handshakes, User-Agent strings, endpoint URLs, timing patterns).  Organizations requiring payload inspection must implement TLS interception with appropriate user notification and consent.

# IANA Considerations

This document has no IANA actions.

--- back

# JSON Schema Examples

## Discovery Event Example

~~~json
{
  "event_type": "discovery",
  "event_subtype": "unmanaged_client_detected",
  "timestamp": "2024-03-15T14:23:45Z",
  "agent_id": "cursor-ide-v0.42.1",
  "user_agent": "Electron/37.7.0",
  "detection_method": "network_telemetry",
  "confidence": 0.95,
  "network_context": {
    "source_ip": "10.0.1.42",
    "destination_host": "api2.cursor.sh",
    "protocol": "https"
  }
}
~~~

## Data Access Event Example

~~~json
{
  "event_type": "data_access",
  "event_subtype": "tool_invocation",
  "timestamp": "2024-03-15T14:25:12Z",
  "correlation_id": "session-a1b2c3d4",
  "u2a_session_id": "user-123-agent-cursor",
  "user_id": "user-123",
  "agent_id": "cursor-ide-v0.42.1",
  "tool_name": "file_upload",
  "data_classification": "source_code",
  "data_volume": 12519,
  "endpoint": "/aiserver.v1.filesyncservice/fsuploadfile",
  "network_context": {
    "source_ip": "10.0.1.42",
    "destination_host": "us-only.gcpp.cursor.sh",
    "protocol": "https",
    "method": "POST"
  }
}
~~~

## Semantic Lineage Event Example

~~~json
{
  "event_type": "semantic_lineage",
  "event_subtype": "cross_session_aggregation",
  "timestamp": "2024-03-15T14:30:00Z",
  "correlation_id": "lineage-e5f6g7h8",
  "source_events": [
    "event-123-data-access",
    "event-124-data-access",
    "event-125-transformation"
  ],
  "aggregate_risk": "high",
  "risk_factors": [
    "Multiple confidential sources accessed",
    "Data aggregated across 3-day period",
    "Output shared externally"
  ],
  "data_classification": "confidential",
  "total_data_volume": 524288,
  "transformation_type": "summarization"
}
~~~

# Production Validation Evidence

This appendix documents validation testing performed on production network traffic to assess the feasibility and accuracy of the proposed event framework.  The validation demonstrates that AI agent detection and monitoring can be achieved using network telemetry without requiring deep packet inspection of encrypted traffic.

Validation Methodology: Analysis of production Zscaler proxy logs from a single enterprise deployment, focusing on network-level indicators observable without decrypting AI conversations.  The validation specifically targeted detection of unmanaged AI clients operating outside formal governance frameworks.

Objective: Demonstrate that the event schemas described in this document can be populated from real network traffic and that detection signatures achieve acceptable accuracy without violating user privacy.

Key Finding: In the analyzed deployment, traditional file-based DLP systems achieved 0% detection of AI-mediated data exposure while network telemetry-based detection (using the methods described in this document) achieved >95% accuracy in identifying unmanaged AI client traffic.

## Dataset Characteristics

Source: Production Zscaler proxy logs
Duration: 28-minute observation window (08:04:34 - 08:32:49 UTC)
Total Transactions: 525 network sessions
Geographic Scope: United States traffic flows
Organization Type: Enterprise deployment with traditional DLP controls active

## Detection Results Summary

Unmanaged AI Client Detected: Cursor IDE (AI-powered code editor)
Traffic Volume: 57 transactions (10.8% of observed traffic)
Data Uploaded: 56 KB source code to third-party AI service
Traditional DLP Detection: 0% (no violations generated)
Network Telemetry Detection: 100% (all 57 Cursor transactions identified)

## Unmanaged MCP Client Signature Evidence

The following signatures were observed in production traffic for Cursor IDE, an AI-powered code editor that operates as an unmanaged MCP client:

User-Agent Signature: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.112
Desktop application masquerading as browser - validated and cross-referenced through additional analysis
Desktop client nature identified through correlation with "Electron/37.7.0" signatures

Endpoint Pattern: api2.cursor.sh/aiserver.v1.*
Service-oriented architecture (gRPC-style)
File synchronization: /aiserver.v1.filesyncservice/fsuploadfile
Dashboard services: /dashboardservice/getteams, /getuserprivacymode

Temporal Pattern - Sub-Second Burst:

~~~
08:04:34.000 UTC | POST | /dashboardservice/getteams (1,396 bytes)
08:04:34.000 UTC | POST | /aiservice/checkfeaturesstatus (2,252 bytes)
08:04:34.000 UTC | POST | /.../getuserprivacymode (1,417 bytes)
08:04:34.000 UTC | POST | /aiservice/checknumberconfigs (1,908 bytes)
~~~

Four API calls within same second timestamp - impossible for human browser interaction (typical human latency: 1-2 seconds minimum).

Payload Asymmetry: 18.37x request/response ratio
Total uploaded: 57,324 bytes
Total received: 3,120 bytes
Pattern indicates: large context uploads followed by minimal AI acknowledgment responses
Characteristic of code assistant workflows

## Semantic Data Exposure Evidence

File Upload Sequence: 5 transactions over 5 seconds to us-only.gcpp.cursor.sh:443

~~~
Transaction #557 | 08:10:10 UTC | 10,515 bytes
Transaction #559 | 08:10:11 UTC | 11,085 bytes
Transaction #562 | 08:10:12 UTC | 11,991 bytes
Transaction #564 | 08:10:14 UTC | 12,519 bytes (largest)
Transaction #567 | 08:10:15 UTC | 11,214 bytes
~~~

Endpoint: /aiserver.v1.filesyncservice/fsuploadfile
Method: POST
User-Agent: Unknown(connect-es/1.6.1)
Total: 57,324 bytes (56 KB)

Traditional DLP Coverage: File-oriented DLP controls did not generate violations for these uploads. No file downloads (HTTP GET with file MIME types), no file attachments, no cloud storage sync operations. Data transmitted in HTTP POST bodies (gRPC-Web serialization). Traditional DLP verdict: ALLOWED (observed only "POST -> 200 OK") Reality: 56 KB source code uploaded to third-party AI service

Payload sizes (10-12 KB) and /filesyncservice/fsuploadfile endpoint consistent with source code files being transmitted to AI backend.

## Detection Signature Validation

Multi-Signal Fusion Results: Single Signal Confidence: approximately 50-70%
Multi-Signal (3+) Confidence: >95%
Validated Approach: Correlate User-Agent + Temporal + Payload + Endpoint patterns

Telemetry Source Effectiveness (signals marked HIGH achieve >95% confidence when combined):

| Signal Type | Effectiveness | Production Coverage |
|:------------|:--------------|:--------------------|
| User-Agent Analysis | HIGH | 84% identified by this alone |
| Temporal Burst Patterns | HIGH | 100% distinguishes agent from human |
| Payload Asymmetry | HIGH | 100% identifies context upload |
| Endpoint Pattern Matching | HIGH | 100% matches gRPC-Web signatures |
| Protocol Analysis | MEDIUM | Confirms desktop agent vs. browser |
| TLS Fingerprinting | LOW | Supporting evidence only |
{: #detection-effectiveness title="Detection Signature Effectiveness"}

## Privacy Compliance

Data Captured (Metadata Only): Byte counts, User-Agent strings, URL endpoints, timestamps, TLS characteristics, IP addresses, HTTP status codes, protocol identifiers

Data NOT Captured (Content): No AI prompt content, no AI response content, no source code inspected, no variable/function names, no semantic meaning from code

Assessment: COMPLIANT with privacy requirements.  All detection via network metadata.  No deep packet inspection of AI prompts/responses performed or required.

## Key Validation Conclusions

1. Unmanaged MCP clients exist in production - Cursor IDE detected operating outside governance oversight, generating 10.8% of observed traffic

2. Network telemetry was sufficient in this dataset - 100% detection accuracy using User-Agent + timing + endpoints + payloads; no cloud API integration required

3. Cloud-side governance has no visibility - Zero integration detected; Cursor operated independently of enterprise AI control planes

4. Semantic exposure operated outside file-oriented DLP in this deployment - 56 KB uploaded via API payloads invisible to file-based DLP systems

5. Event schemas are implementable - Valid JSON events successfully generated from real network transactions

6. Privacy can be preserved - Metadata-only detection achieved 100% accuracy while protecting user privacy

## Validation Limitations

Single organization: Traffic from one enterprise deployment
Limited duration: 28-minute observation window
Known agent type: Cursor IDE; other AI agents may exhibit different signatures
No false negative analysis: Ground truth not available for comparison
Geographic specificity: United States traffic flows; other regions may differ

Despite these limitations, validation demonstrates the document addresses an observable, real-world security gap with implementable detection methods.

# Acknowledgements
{:numbered="false"}

The author thanks Yaroslav Rosomakho for valuable discussions during the development of this framework.
