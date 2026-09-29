import os
import tempfile

import pytest

from isihlangu.core.types import (
    OOBToken,
    OWASPCategory,
    Severity,
    TargetSpec,
    TargetType,
    VulnerabilityReport,
)
from isihlangu.storage.database import DatabaseManager


@pytest.mark.asyncio
async def test_live_datastore_write_verification() -> None:
    """Invariant 3 & 4: Verifies DDL migrations and live non-zero-row datastore write paths."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = os.path.join(tmpdir, "test_isihlangu.db")
        db = DatabaseManager(f"sqlite:///{db_file}")

        # 1. Apply DDL migrations
        await db.apply_migrations()

        # 2. Invariant 4: Confirm tables exist
        expected_tables = [
            "targets",
            "scan_sessions",
            "attack_hypotheses",
            "execution_logs",
            "canary_tokens",
            "vulnerabilities",
        ]
        await db.verify_tables_exist(expected_tables)

        # 3. Invariant 3: Insert Target and read back
        target = TargetSpec(
            id="target_test_01",
            name="Production Agent Sandbox",
            target_type=TargetType.MCP_SERVER,
            base_url="http://127.0.0.1:8000",
            allowed_domains=["localhost", "127.0.0.1"],
            config={"sample_rate": 1.0},
        )
        await db.insert_target(target)

        fetched_target = await db.get_target("target_test_01")
        assert fetched_target is not None
        assert fetched_target.id == "target_test_01"
        assert fetched_target.name == "Production Agent Sandbox"
        assert fetched_target.target_type == TargetType.MCP_SERVER
        assert fetched_target.config["sample_rate"] == 1.0

        # 4. Insert Scan Session
        await db.create_session("sess_001", "target_test_01")

        # 5. Insert Canary Token & simulate callback
        token = OOBToken(
            token_uuid="canary-uuid-12345",
            session_id="sess_001",
            expected_type="ssrf_out_of_band",
            target_component="fetch_url_tool",
        )
        await db.insert_canary_token(token)

        marked = await db.mark_canary_callback(
            token_uuid="canary-uuid-12345",
            source_ip="192.168.1.50",
            payload="GET /c/canary-uuid-12345 HTTP/1.1",
        )
        assert marked is True

        # 6. Insert Vulnerability Report and read back
        vuln = VulnerabilityReport(
            id="vuln_001",
            session_id="sess_001",
            title="SSRF Callback Verified",
            severity=Severity.HIGH,
            owasp_category=OWASPCategory.API07_SSRF,
            description="Canary callback received from internal host.",
            evidence={"ip": "192.168.1.50"},
            remediation_patch="RESTRICT_URL_REGEX",
        )
        await db.insert_vulnerability(vuln)

        vulns = await db.get_session_vulnerabilities("sess_001")
        assert len(vulns) == 1
        assert vulns[0].id == "vuln_001"
        assert vulns[0].severity == Severity.HIGH
        assert vulns[0].owasp_category == OWASPCategory.API07_SSRF

        # 7. Complete Session
        await db.complete_session("sess_001", summary={"status": "all_checks_passed"})

        # Confirm non-zero row counts across tables
        async with db.get_connection() as conn:
            cursor = await conn.execute("SELECT COUNT(*) as count FROM targets")
            assert (await cursor.fetchone())["count"] > 0

            cursor = await conn.execute("SELECT COUNT(*) as count FROM scan_sessions")
            assert (await cursor.fetchone())["count"] > 0

            cursor = await conn.execute("SELECT COUNT(*) as count FROM canary_tokens")
            assert (await cursor.fetchone())["count"] > 0

            cursor = await conn.execute("SELECT COUNT(*) as count FROM vulnerabilities")
            assert (await cursor.fetchone())["count"] > 0
