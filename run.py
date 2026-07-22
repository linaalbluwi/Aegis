#!/usr/bin/env python3
"""
Production entrypoint for Aegis with HTTPS support.
"""
import os
import uvicorn

if __name__ == "__main__":
    ssl_keyfile = os.getenv("AEGIS_SSL_KEY", "certs/key.pem")
    ssl_certfile = os.getenv("AEGIS_SSL_CERT", "certs/cert.pem")
    use_ssl = os.path.exists(ssl_keyfile) and os.path.exists(ssl_certfile)

    uvicorn.run(
        "aegis.main:app",
        host=os.getenv("AEGIS_HOST", "0.0.0.0"),
        port=int(os.getenv("AEGIS_PORT", "8443")),
        ssl_keyfile=ssl_keyfile if use_ssl else None,
        ssl_certfile=ssl_certfile if use_ssl else None,
        reload=False,
        workers=int(os.getenv("AEGIS_WORKERS", "4")),
    )
