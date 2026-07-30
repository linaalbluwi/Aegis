Architecture Decision Records

ADR-1: Kubernetes over Serverless
Decision: Deploy Aegis on Kubernetes with HPA
Rationale: Always-on security, stateful rate limiting, predictable latency

ADR-2: Chain of Responsibility
Decision: Use Chain of Responsibility for middleware pipeline
Rationale: Independent handlers, no code changes to add steps

ADR-3: Multi-Region Active-Passive
Decision: Two regions with DNS failover
Rationale: Region failure is rare but catastrophic

ADR-4: In-Memory Rate Limiting
Decision: In-memory now, Redis planned for multi-region
Rationale: Simple to start, Redis needed before production

ADR-5: Fail-Open over Fail-Closed
Decision: Allow traffic when overwhelmed
Rationale: Security should never cause outages
