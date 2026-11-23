"""Test-session isolation for Aegis-MCP.

Tests call ``firewall.reset()``, which deletes every ledger row. When the
developer environment exports ``AEGIS_DB_PATH`` (e.g. the Claude Code
dogfooding ledger ``.aegis_claude_audit.db``), that would wipe real audit
evidence. Point the suite at a throwaway database before ``app`` is imported.
"""

import os
import tempfile

os.environ["AEGIS_DB_PATH"] = os.path.join(
    tempfile.mkdtemp(prefix="aegis-mcp-tests-"), "aegis_mcp.db"
)
