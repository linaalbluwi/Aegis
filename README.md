# Aegis

Drop-in security middleware for FastAPI that protects against OWASP Top 10 API attacks.

## Quick Start

pip install aegis

from aegis import SecurityGate
app.add_middleware(SecurityGate)

## What It Detects

- SQL Injection
- XSS
- Command Injection
- Path Traversal
- JWT Attacks
- Data Leaks

## Docker

docker run -p 8443:8443 linaalbluwi/aegis

## Tests

python -m pytest tests/ -v

## License

MIT
