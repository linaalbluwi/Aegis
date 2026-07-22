"""
Configuration for Aegis. All settings can be overridden via environment variables.
"""
import os


# Rate limiting
MAX_REQUESTS = int(os.getenv("AEGIS_MAX_REQUESTS", "60"))
WINDOW_SECONDS = int(os.getenv("AEGIS_WINDOW_SECONDS", "60"))
BLOCK_DURATION = int(os.getenv("AEGIS_BLOCK_DURATION", "120"))

# Input limits
MAX_BODY_SIZE = int(os.getenv("AEGIS_MAX_BODY_SIZE", "1048576"))      # 1MB
MAX_QUERY_LENGTH = int(os.getenv("AEGIS_MAX_QUERY_LENGTH", "2000"))
MAX_HEADER_LENGTH = int(os.getenv("AEGIS_MAX_HEADER_LENGTH", "8000"))
MAX_HEADER_COUNT = int(os.getenv("AEGIS_MAX_HEADER_COUNT", "100"))
MAX_BODY_SCAN = int(os.getenv("AEGIS_MAX_BODY_SCAN", "10000"))        # First 10KB
MAX_RESPONSE_SCAN = int(os.getenv("AEGIS_MAX_RESPONSE_SCAN", "100000"))

# JWT
JWT_SECRET = os.getenv("AEGIS_JWT_SECRET", None)

# Logging
LOG_DIR = os.getenv("AEGIS_LOG_DIR", "logs")
LOG_ROTATION_SIZE = int(os.getenv("AEGIS_LOG_ROTATION_SIZE", "10485760"))  # 10MB
LOG_BACKUP_COUNT = int(os.getenv("AEGIS_LOG_BACKUP_COUNT", "5"))

# Detectors (can be disabled individually)
ENABLE_SQLI = os.getenv("AEGIS_ENABLE_SQLI", "true").lower() == "true"
ENABLE_XSS = os.getenv("AEGIS_ENABLE_XSS", "true").lower() == "true"
ENABLE_COMMAND_INJECTION = os.getenv("AEGIS_ENABLE_COMMAND_INJECTION", "true").lower() == "true"
ENABLE_PATH_TRAVERSAL = os.getenv("AEGIS_ENABLE_PATH_TRAVERSAL", "true").lower() == "true"
ENABLE_JWT = os.getenv("AEGIS_ENABLE_JWT", "true").lower() == "true"
ENABLE_DATA_LEAK = os.getenv("AEGIS_ENABLE_DATA_LEAK", "true").lower() == "true"
ENABLE_RATE_LIMIT = os.getenv("AEGIS_ENABLE_RATE_LIMIT", "true").lower() == "true"
