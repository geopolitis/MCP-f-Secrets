Real-World Uses

CI/CD assistant rotates Vault-stored app secrets before a deploy, writes them via kv.write, and records the rotation in Git issues.
Internal support chatbot reads customer-specific credentials from KV and wipes them after troubleshooting with kv.delete.
DevSecOps automation signs Terraform plans or container manifests through transit.sign to keep provenance under Vault control.

Incident-response bot requests time-limited DB credentials (db.issue_creds), fetches logs, then revokes the lease when done.
Remote-ops assistant provisions just-in-time SSH access by generating OTPs or signing engineers’ keys (ssh.otp / ssh.sign).
Multi-team hub relays Vault events to downstream agents using the MCP SSE stream so they re-cache or re-trigger workflows when secrets change.
Each scenario relies on agents authenticating through the exposed auth modes, using scoped Vault prefixes to stay within policy, and leveraging MCP tools to perform Vault-backed actions programmatically.

Key Features

Auth & Scopes: Built-in API key, JWT (HS/RS with JWKS), and optional mTLS flows give you principals with scoped prefixes. Policy scripts (scripts/gen_policy.py, etc.) help mint matching Vault policies/tokens.
Vault Engines: KV v2 helpers plus transit, database, and SSH wrappers cover secret rotation, encryption/signing, dynamic credentials, and SSH OTP/signing flows. Child-token support keeps agent actions isolated.
MCP/HTTP Access: JSON-RPC tools and REST routes coexist, and there are smoke-test scripts (scripts/mcp_http_smoke.py, scripts/smoke.sh) to validate both paths. SSE broadcasts let other agents watch for secret changes.
Operational Glue: Structured logs, Prometheus metrics, OTEL hooks, and e2e scripts (scripts/e2e_local.sh) handle observability and local verification.


Overview

FastAPI service that fronts HashiCorp Vault features for both REST callers and Model Context Protocol (MCP) tools, exposing secrets, transit crypto, database, and SSH functionality (vault_mcp/app.py:1, vault_mcp/mcp_rpc.py:1).
Runs via main.py, which wires in the app factory and launches uvicorn with env-driven host/port/log-level controls (main.py:1).
Vault & Auth Plumbing

Creates authenticated Vault clients through tokens or AppRole exchange, with optional per-agent child tokens (vault_mcp/vault.py:1).
Enforces principals with scoped Vault prefixes, supporting API keys, JWT (HS256/RS256 with JWKS cache), and optional mTLS headers (vault_mcp/models.py:1, vault_mcp/auth/api_key.py:1, vault_mcp/auth/jwt_auth.py:1, vault_mcp/security.py:1).
Applies request-scoped rate limiting and path sanitization before hitting Vault, keeping agents in their allowed namespaces (vault_mcp/security.py:17).
HTTP Routes

Health endpoints plus readiness checks (now with standardized JSON), metrics, optional CORS, and Prometheus instrumentation (vault_mcp/routes/health.py:1, vault_mcp/app.py:1).
REST surfaces for KV v2 CRUD/version ops, transit crypto, dynamic DB creds/lease ops, SSH OTP and key signing, and debugging helpers, all scope-gated and logged (vault_mcp/routes/kv.py:1, vault_mcp/routes/transit.py, vault_mcp/routes/db.py, vault_mcp/routes/ssh.py, vault_mcp/routes/debug.py).
MCP Integration

Implements an MCP JSON-RPC router under /mcp/rpc, exporting tool schemas for each Vault capability and streaming resource change events via server-sent events (vault_mcp/mcp_rpc.py:1).
Optionally mounts fastapi_mcp helpers to serve the MCP inspector/HTTP transport alongside the RPC flow (vault_mcp/mcp_mount.py:1).
Operations & Tooling

Structured request/response logging to stdout and rotating files under logs/, plus optional OTEL tracing if configured (vault_mcp/app.py:9).
Configurable through environment variables or JSON/TOML/YAML config files detected at runtime (vault_mcp/settings.py:1).
Test suite covers auth modes, health endpoints, logging, KV, transit, SSH/DB flows, and MCP behaviors (tests/).

Both interfaces are present. The FastAPI app always mounts the MCP JSON-RPC router, and—unless you flip EXPOSE_REST_ROUTES off—it also registers the REST routes for KV, transit, DB, SSH, and debug operations (vault_mcp/app.py:91). So by default you get both the API endpoints and the MCP tools; you only drop the REST API if you explicitly disable it via that setting.

Tool Coverage

KV Suite: kv.read, kv.write, kv.list, kv.delete, kv.undelete, kv.destroy; scoped to the caller’s Vault prefix, with resource-change events emitted on mutations and optional version targeting for reads/undelete/destroy (vault_mcp/mcp_rpc.py:33-149).
Transit Crypto: transit.encrypt, transit.decrypt, transit.sign, transit.verify, transit.rewrap, transit.random; wrap Vault Transit APIs for symmetric, signing, and randomness operations, converting outputs (e.g., base64 vs hex) when requested (vault_mcp/mcp_rpc.py:150-210).
Database Leases: db.issue_creds, db.renew, db.revoke; issue dynamic database credentials and manage leases using Vault’s database secrets engine, returning lease metadata where available (vault_mcp/mcp_rpc.py:211-234).
SSH Access: ssh.otp, ssh.sign; generate one-time SSH passwords or sign public keys via Vault’s SSH secrets engine (vault_mcp/mcp_rpc.py:235-250).
Protocol Shape

Tools are exposed via JSON-RPC 2.0 at /mcp/rpc, with schema descriptors listing required inputs/outputs for MCP clients (vault_mcp/mcp_rpc.py:18-121).
Calls require authenticated principals; _require_scopes enforces scope sets (read/write/delete/list). Requests run against per-principal Vault clients, optionally using child tokens (vault_mcp/mcp_rpc.py:125, vault_mcp/security.py:17, vault_mcp/vault.py:16).
Events & Sessions

Tool operations that alter KV content trigger _broadcast_resource_changed, feeding an in-memory SSE bus so connected MCP clients can subscribe to resource updates (vault_mcp/mcp_rpc.py:103-146).
/mcp also serves as the base for mounting the FastAPI MCP inspector transport when fastapi_mcp is available, giving both JSON-RPC and HTTP transports for the same toolset (vault_mcp/mcp_mount.py:1).

Authentication

Incoming requests (REST or MCP) are funneled through get_principal, which tries API key, JWT, then optional mTLS auth; whichever yields a Principal wins (vault_mcp/security.py:4).
API key auth pulls the subject from the configured JSON map and grants full Vault scopes under DEFAULT_PREFIX/<subject> (vault_mcp/auth/api_key.py:1).
JWT auth validates HS256/RS256 tokens against configured issuer/audience, optionally loading JWKS from file/URL before minting the principal (vault_mcp/auth/jwt_auth.py:1).
mTLS auth extracts the subject from the client DN header (or the raw DN) after verifying the success header; it returns the same scope set the other built-ins use (vault_mcp/auth/mtls.py:1).
Principal Setup

Every principal carries subject, allowed scopes, and a Vault path prefix; requests without a principal are rejected as 401 (vault_mcp/security.py:11).
Rate limiting and scope enforcement happens via require_scopes, which also sanitizes incoming paths with kv_safe_path before anything hits Vault (vault_mcp/security.py:20).
Vault Session

Per-request Vault clients are created with the configured token/AppRole; if child tokens are enabled, new short-lived tokens scoped to the principal’s policy are issued to keep agent operations isolated (vault_mcp/vault.py:1).
Storage helpers wrap KV v2 reads, writes, deletes, and version management on the mount declared in settings (vault_mcp/vault.py:24).
REST Journey

With EXPOSE_REST_ROUTES enabled the FastAPI app wires KV, transit, DB, SSH, and debug routers alongside health/metrics endpoints (vault_mcp/app.py:84).
Example read: GET /secrets/{path} checks read scope, resolves the safe Vault path, reads from KV v2, and logs the response metadata (vault_mcp/routes/kv.py:18).
Example create/update: PUT /secrets/{path} requires write scope, writes KV data, re-reads for metadata, and emits structured logs (vault_mcp/routes/kv.py:7).
Transit, DB, and SSH routes follow the same pattern, mapping HTTP verbs and payloads to Vault engines while returning typed Pydantic responses.
MCP Journey

MCP clients call /mcp/rpc with JSON-RPC 2.0 requests; get_principal still authenticates them first, sharing the same scope/rate-limit pipeline (vault_mcp/mcp_rpc.py:249).
Each tool (e.g., kv.read, kv.write, transit.encrypt, db.issue_creds, ssh.sign) validates scope, transforms the request into Vault API calls, and returns structured results that match the advertised schema (vault_mcp/mcp_rpc.py:61).
Mutating tools broadcast resource-change events to SSE subscribers so agents can react to updates in near real time (vault_mcp/mcp_rpc.py:105).
Cross-Cutting

Structured request/response logs land in rotating files and stdout for observability (vault_mcp/app.py:13).
Configurable settings—from Vault connection to auth toggles and CORS—flow from environment or optional config files without relying on a .env load (vault_mcp/settings.py:1).



mermaid
flowchart TD
    subgraph Client
        A["Agent Request"]
    end

    subgraph FastAPI Service
        B["get_principal"]
        C["Principal Created<br/>subject + scopes + vault prefix"]
        D["require_scopes & Rate Limit"]
        E["Execute Route / MCP Tool"]
        F["Structured Logging & Metrics"]
    end

    subgraph Vault Access
        G["new_vault_client<br/>(token or AppRole)"]
        H{"CHILD_TOKEN_ENABLED?"}
        I["Child Token Issued<br/>(scoped policy)"]
        J["Vault Operation<br/>KV / Transit / DB / SSH"]
    end

    subgraph Outputs
        K["REST Response or JSON-RPC Result"]
        L["Resource Changed Event (SSE)"]
    end

    A --> B
    B -->|API Key / JWT / mTLS| C
    C --> D
    D -->|Scopes OK| E
    D -->|Missing scope| Z1["HTTP 403"]

    E --> F
    F --> K

    E --> G
    G --> H
    H -->|Yes| I --> J
    H -->|No| J
    J --> K
    J -->|Mutating KV| L

    K --> A

    style Client fill:#fef3c7,stroke:#d97706
    style FastAPI Service fill:#e0f2fe,stroke:#1d4ed8
    style Vault Access fill:#ede9fe,stroke:#7c3aed
    style Outputs fill:#dcfce7,stroke:#16a34a
    style Z1 fill:#fecaca,stroke:#b91c1c

    End-To-End Flow

1. Agent Bootstraps Identity

You provision credentials for the agent (API key, JWT signing material, or mTLS cert) aligned with Vault policies.
Server is configured via env/config (vault_mcp/settings.py:6) to enable the corresponding auth method and map API keys or JWKS.
2. Agent Calls MCP/HTTP Endpoint

Request hits FastAPI middleware that logs attempt and measures latency (vault_mcp/app.py:59).
Auth headers (e.g., X-API-Key, Authorization: Bearer, mTLS DN header) travel over TLS—your deployment must terminate HTTPS in front of uvicorn.
3. Authentication & Principal Creation

get_principal tries API key, JWT, then mTLS, returning the first success (vault_mcp/security.py:4).
API key map → subject + full scopes (vault_mcp/auth/api_key.py:16).
JWT verification supports HS256/RS256 with issuer/audience checks and JWKS caching (vault_mcp/auth/jwt_auth.py:34).
mTLS validates the verify header and extracts CN (vault_mcp/auth/mtls.py:7).
Failure → 401, no further processing.
4. Scope Enforcement & Rate Limiting

Route/tool dependencies call require_scopes, which enforces scope lists and per-subject rate limits (token bucket) to throttle abuse (vault_mcp/security.py:20).
Paths are sanitized (kv_safe_path) to prevent .. traversal outside the agent’s prefix (vault_mcp/security.py:27).
5. Vault Client Establishment

client_for_principal gets a base client via token/AppRole; optional child token is minted with policy mcp-agent-<subject> for least privilege (vault_mcp/vault.py:6).
If Vault auth fails, the request fails early.
6. Operation Execution

MCP tools or REST routes translate calls into Vault API operations (KV/transit/db/ssh) using the sanitized prefix and scoped token (vault_mcp/mcp_rpc.py:125, vault_mcp/routes/kv.py:7).
Read/write operations broadcast change events to SSE subscribers, but only after Vault accepts the change (vault_mcp/mcp_rpc.py:105).
7. Response & Telemetry

Structured logs capture request metadata (subject, path, status) to both stdout and rotating files (vault_mcp/app.py:21).
Prometheus counters/histograms emit metrics for observability (vault_mcp/app.py:50).
Errors map to meaningful HTTP/JSON-RPC responses; Vault-specific exceptions translate to 4xx/5xx codes (vault_mcp/app.py:73).
Security Posture

Auth layering, scope checks, path normalization, and optional child tokens create strong compartmentalization.
Rate limiting and request IDs assist in thwarting or investigating abuse.
Structured logging plus metrics give audit and monitoring hooks.
MCP/REST share the same principal pipeline, so both surfaces inherit the same controls.
Assumptions & Trust Boundaries

TLS termination (reverse proxy or uvicorn behind TLS) is required; repo doesn’t ship TLS by default.
Vault policies for agent subjects must be correctly scoped; misconfiguration here undermines isolation.
API key JSON / JWKS hosting must be protected since possession of those leads to Vault access.
SSE event stream is in-memory without auth beyond the original request; ensure clients maintain credentials.
Improvement Ideas

Add mutual TLS enforcement on the external ingress or integrate OAuth/OIDC flows for agents without pre-shared secrets.
Implement secret redaction in logs to avoid leaking payloads (currently keys are logged, though data values aren’t).
Persist audit trails (e.g., push logs to SIEM, enable Vault audit devices) to complement local rotating files.
Harden SSE by requiring per-subscription tokens or limiting retention of _recent_events.
Support Vault response-wrapping for delivering short-lived secrets.
Wire automated rotation for child-token policies and ensure rate-limit settings align with real traffic.
With those controls and careful Vault policy management, the design provides robust end-to-end security for agents retrieving and managing secrets.

flowchart TD
    A["Agent Bootstraps Identity<br/>(API key / JWT / mTLS cert)"]
    B["Agent Calls MCP/REST Endpoint<br/>(HTTPS)"]
    C["FastAPI Middleware Logs & Metrics<br/>(vault_mcp/app.py)"]
    D["get_principal Auth Chain<br/>API key ➜ JWT ➜ mTLS"]
    E["Principal Issued<br/>subject + scopes + vault prefix"]
    F["require_scopes & Rate Limit<br/>(scope check + token bucket)"]
    G["kv_safe_path Sanitizes Path"]
    H["client_for_principal<br/>Vault auth token/AppRole"]
    I{"CHILD_TOKEN_ENABLED?"}
    J["Issue Child Token<br/>policy mcp-agent-<subject>"]
    K["Execute Vault Operation<br/>KV / Transit / DB / SSH"]
    L["Broadcast Change Event (SSE)"]
    M["Structured Response / JSON-RPC Result"]
    N["Logs ➜ stdout & rotating files<br/>Metrics ➜ Prometheus"]

    A --> B --> C --> D --> E --> F --> G --> H --> I
    I -->|Yes| J --> K
    I -->|No| K
    K --> M
    K -->|Mutating KV| L
    C --> N
    M --> B

    style A fill:#fef3c7,stroke:#d97706
    style B fill:#fef3c7,stroke:#d97706
    style C fill:#e0f2fe,stroke:#1d4ed8
    style D fill:#e0f2fe,stroke:#1d4ed8
    style E fill:#e0f2fe,stroke:#1d4ed8
    style F fill:#e0f2fe,stroke:#1d4ed8
    style G fill:#e0f2fe,stroke:#1d4ed8
    style H fill:#ede9fe,stroke:#7c3aed
    style I fill:#ede9fe,stroke:#7c3aed
    style J fill:#ede9fe,stroke:#7c3aed
    style K fill:#ede9fe,stroke:#7c3aed
    style L fill:#dcfce7,stroke:#16a34a
    style M fill:#dcfce7,stroke:#16a34a
    style N fill:#d1fae5,stroke:#047857