Alerting Rules for Aegis

Rule 1: High Attack Rate
Alert when attacks blocked per minute exceeds 50
Severity: Warning
Action: Check dashboard, investigate traffic spike

Rule 2: Error Budget Burning
Alert when error budget below 50 percent remaining
Severity: Warning
Action: Stop deployments, investigate failures

Rule 3: Error Budget Exhausted
Alert when error budget reaches 0
Severity: Critical
Action: Page on-call engineer, halt all changes

Rule 4: Aegis Pod Down
Alert when any pod is not ready for 5 minutes
Severity: Critical
Action: Page on-call, check pod logs

Rule 5: Circuit Breaker Open
Alert when circuit breaker opens for any backend
Severity: Critical
Action: Check backend health, verify failover

Rule 6: Fail-Open Mode Active
Alert when Aegis enters degraded mode
Severity: High
Action: Scale up replicas, investigate load

What NOT to alert on:
- Single 403 responses (normal attack blocking)
- Pod restarts during deployments (expected)
- Brief latency spikes under 50ms (normal variance)
- Individual rate limit triggers (expected behavior)
