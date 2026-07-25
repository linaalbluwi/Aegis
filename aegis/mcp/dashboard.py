"""
Aegis MCP Dashboard - real-time monitoring of security and token savings.
"""
import json
import os
from datetime import datetime
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from aegis.mcp.guardian import MCPGuardian
from aegis.mcp.token_optimizer import TokenOptimizer


class Dashboard:
    """Web dashboard for Aegis MCP monitoring."""

    def __init__(self, guardian: MCPGuardian, optimizer: TokenOptimizer):
        self.guardian = guardian
        self.optimizer = optimizer
        self.events = []
        self.app = FastAPI(title="Aegis MCP Dashboard")
        self._setup_routes()

    def log_event(self, event_type: str, detail: str):
        self.events.append({
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "type": event_type,
            "detail": detail,
        })
        if len(self.events) > 50:
            self.events = self.events[-50:]

    def _setup_routes(self):
        @self.app.get("/", response_class=HTMLResponse)
        async def home():
            return self._render()

        @self.app.get("/api/stats")
        async def stats():
            return {
                "security": self.guardian.get_stats(),
                "optimizer": self.optimizer.get_stats(),
                "events": self.events[-10:],
            }

    def _render(self) -> str:
        security = self.guardian.get_stats()
        optimizer = self.optimizer.get_stats()
        total_checked = security["total_checked"]
        blocked = security["blocked"]
        block_rate = (blocked / max(1, total_checked)) * 100
        tokens_saved = optimizer["total_tokens_saved"]
        cost_saved = round((tokens_saved / 1000) * 0.003, 2)

        events_html = ""
        for event in reversed(self.events[-10:]):
            color = {
                "blocked": "#ef4444",
                "cached": "#10b981",
                "optimized": "#f59e0b",
                "safe": "#6b7280",
            }.get(event["type"], "#6b7280")

            prefix = {
                "blocked": "[BLOCKED]",
                "cached": "[CACHED]",
                "optimized": "[OPTIMIZED]",
                "safe": "[PASSED]",
            }.get(event["type"], "")

            events_html += f"""
            <div style="padding: 8px 0; border-bottom: 1px solid #1f2937; color: {color};">
                <span style="color: #6b7280;">[{event['timestamp']}]</span>
                {prefix} {event['detail']}
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aegis MCP Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            min-height: 100vh;
        }}
        .header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border-bottom: 1px solid #334155;
            padding: 24px 32px;
        }}
        .header h1 {{ font-size: 28px; font-weight: 700; }}
        .header p {{ color: #94a3b8; margin-top: 4px; }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            padding: 24px 32px;
        }}
        .card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 20px;
        }}
        .card .label {{ color: #94a3b8; font-size: 14px; margin-bottom: 8px; }}
        .card .value {{ font-size: 36px; font-weight: 700; }}
        .card .sub {{ color: #94a3b8; font-size: 13px; margin-top: 4px; }}
        .green {{ color: #10b981; }}
        .red {{ color: #ef4444; }}
        .blue {{ color: #3b82f6; }}
        .yellow {{ color: #f59e0b; }}
        .events {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 12px;
            margin: 0 32px 32px;
            padding: 20px;
        }}
        .events h2 {{ font-size: 18px; margin-bottom: 16px; }}
        .footer {{
            text-align: center;
            padding: 16px;
            color: #475569;
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Aegis MCP Dashboard</h1>
        <p>Real-time security & token optimization for Model Context Protocol</p>
    </div>

    <div class="grid">
        <div class="card">
            <div class="label">Total Calls</div>
            <div class="value blue">{total_checked}</div>
            <div class="sub">tool invocations</div>
        </div>
        <div class="card">
            <div class="label">Attacks Blocked</div>
            <div class="value red">{blocked}</div>
            <div class="sub">{block_rate:.1f}% block rate</div>
        </div>
        <div class="card">
            <div class="label">Tokens Saved</div>
            <div class="value green">{tokens_saved:,}</div>
            <div class="sub">characters not sent</div>
        </div>
        <div class="card">
            <div class="label">API Cost Saved</div>
            <div class="value yellow">${cost_saved}</div>
            <div class="sub">estimated savings</div>
        </div>
    </div>

    <div class="events">
        <h2>Recent Activity</h2>
        {events_html if events_html else '<p style="color: #475569;">No activity yet</p>'}
    </div>

    <div class="footer">Aegis MCP &middot; Refresh for updates</div>
</body>
</html>"""
