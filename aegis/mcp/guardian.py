"""
MCP Security Guardian - validates tool calls for injection attacks.
"""
from aegis.detectors.sqli import detect_sqli
from aegis.detectors.xss import detect_xss
from aegis.detectors.command_injection import detect_command_injection
from aegis.detectors.path_traversal import detect_path_traversal
from aegis.utils.logger import log_event, get_severity


class MCPGuardian:
    """
    Security guardian for MCP tool calls.
    Validates parameters before tool execution.
    """

    def __init__(self, block_on_attack: bool = True):
        self.block_on_attack = block_on_attack
        self.blocked_count = 0
        self.allowed_count = 0

    def validate(self, params: dict, tool_name: str = "unknown") -> dict:
        """
        Validate tool call parameters for injection attacks.
        Returns {"safe": True/False, "findings": [...], "sanitized_params": {...}}
        """
        findings = []
        sanitized = {}

        for key, value in params.items():
            if isinstance(value, str):
                # Run all detectors
                findings.extend(detect_sqli(value))
                findings.extend(detect_xss(value))
                findings.extend(detect_command_injection(value))
                findings.extend(detect_path_traversal(value))

                # Sanitize: remove dangerous characters
                sanitized[key] = self._sanitize(value)
            else:
                sanitized[key] = value

        is_safe = len(findings) == 0

        if is_safe:
            self.allowed_count += 1
        else:
            self.blocked_count += 1
            for f in findings:
                log_event(
                    event_type=f"mcp_{f['type']}",
                    severity=get_severity(f["type"]),
                    client_ip="mcp_internal",
                    details={
                        **f,
                        "tool_name": tool_name,
                        "parameter": key,
                    },
                )

        return {
            "safe": is_safe,
            "findings": findings,
            "sanitized_params": sanitized if not is_safe else params,
        }

    def _sanitize(self, value: str) -> str:
        """Remove potentially dangerous characters from a string."""
        dangerous_chars = [";", "|", "&", "$", "`", "(", ")", "{", "}", "<", ">"]
        sanitized = value
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, "")
        return sanitized

    def get_stats(self) -> dict:
        """Return guardian statistics."""
        return {
            "total_checked": self.blocked_count + self.allowed_count,
            "blocked": self.blocked_count,
            "allowed": self.allowed_count,
            "block_rate": (
                f"{(self.blocked_count / max(1, self.blocked_count + self.allowed_count)) * 100:.1f}%"
            ),
        }
