# Threat Model (STRIDE)

This document analyses the security threats faced by the privacy risk
detection platform using the **STRIDE** methodology and proposes
mitigations implemented in the design.

| Threat | Description | Impact | Mitigation |
|-------|------------|-------|-----------|
| **Spoofing** | An attacker impersonates a legitimate user to access scan results or modify profiles. | Compromise of sensitive metadata and unauthorized system changes. | Use strong authentication with salted password hashing (e.g. PBKDF2) and JWTs.  Enforce HTTPS to protect credentials in transit.  Rate-limit login attempts and lock accounts after repeated failures. |
| **Tampering** | Unauthorized modification of profiles, detection rules, audit logs or scan results. | Corrupted detection behavior; loss of integrity and accountability. | Implement RBAC so only Admins and Super Admins can edit profiles.  Store audit logs in append-only tables.  Use database constraints and transaction management to prevent inconsistent state.  Sign profiles with HMAC for integrity verification. |
| **Repudiation** | Users or administrators deny having performed an action (e.g. export, deletion). | Difficulty proving compliance or investigating incidents. | Record immutable audit logs with timestamp, user ID, action and details.  Use cryptographically signed entries and restrict deletion to Super Admins.  Synchronise clocks using NTP to ensure accurate timestamps. |
| **Information disclosure** | Leaking sensitive personal data through the application or transport layer. | Violation of data confidentiality and GDPR provisions. | Process data locally with no default network egress.  Encrypt data at rest and in transit.  Expose only aggregated or masked information to normal users.  Do not log raw data.  Use Content Security Policy (CSP) headers to prevent browser leaks. |
| **Denial of Service (DoS)** | Attackers or misconfigured users submit very large files or many concurrent scans, exhausting resources. | Degraded availability or crash of the service. | Enforce file size limits and job quotas per user.  Use Celery worker concurrency controls and queue length limits.  Monitor CPU/RAM usage and implement graceful degradation (e.g. reject new scans when resources are low).  Use reverse proxy rate limiting. |
| **Elevation of privilege** | Bugs or misconfigurations allow a normal user to perform admin actions or read data they shouldn’t. | Compromise of system controls; potential for malicious changes. | Use explicit role checks on every endpoint via FastAPI dependencies.  Write integration tests that verify access control rules.  Isolate secrets via environment variables and use unique service accounts for each component. |

## Additional considerations

* **Supply chain security** - Third-party dependencies (Python packages,
  Node modules) could introduce vulnerabilities.  Pin versions in
  `requirements.txt` and `package.json`; use tools like Dependabot
  and `pip-audit` to detect known vulnerabilities.  Build Docker
  images from scratch and avoid downloading scripts at runtime.
* **Model attacks** - If NLP models are used, they should be stored
  locally and verified.  Disable model-based detection if the model
  cannot be trusted or has known vulnerabilities.
* **Physical security** - Because the system runs on-premise, ensure
  that servers and workstations are physically secured.  Encrypt
  drives and restrict access to hardware.
* **Incident response** - Document procedures for detecting,
  responding to and reporting data breaches.  Ensure that alerts from
  system logs or resource monitors are reviewed promptly.