# Aegis Scaling Strategies

## Current: Kubernetes HPA
- 3 replicas minimum, 10 maximum
- CPU >70% triggers scale up
- Rolling updates with zero downtime

## Alternatives
- **Serverless (Lambda):** Best for bursty workloads, cold starts acceptable
- **Edge (Workers):** Best for global APIs, lowest latency
- **Sidecar:** Best for microservices, one per backend pod

## Decision
K8s chosen for Aegis because:
1. Always-on security (no cold start gaps)
2. Stateful rate limiting (shared memory)
3. Predictable latency (<5ms)
4. Ecosystem integration (Prometheus, cert-manager)
