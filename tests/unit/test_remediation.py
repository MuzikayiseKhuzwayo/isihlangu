from isihlangu.core.types import OWASPCategory, Severity, VulnerabilityReport
from isihlangu.remediation.rls_patcher import RLSPatcher
from isihlangu.remediation.sarif_exporter import SARIFExporter
from isihlangu.remediation.schema_patcher import MCPSchemaPatcher


def test_mcp_schema_patcher() -> None:
    patcher = MCPSchemaPatcher()
    unhardened_schema = {
        "type": "object",
        "properties": {"url": {"type": "string"}},
        "required": ["url"],
    }

    # Patch URL restriction
    patched_url = patcher.patch_url_property(unhardened_schema, allowed_domains=["trusted.internal"])
    assert "pattern" in patched_url["properties"]["url"]
    assert "trusted\\.internal" in patched_url["properties"]["url"]["pattern"]

    # Patch Tenant Isolation
    patched_tenant = patcher.add_tenant_isolation(unhardened_schema)
    assert "tenant_id" in patched_tenant["properties"]
    assert "tenant_id" in patched_tenant["required"]


def test_rls_patcher() -> None:
    sql = RLSPatcher.generate_rls_sql("documents")
    assert 'ENABLE ROW LEVEL SECURITY' in sql
    assert 'tenant_isolation_select_documents' in sql
    assert 'current_setting(\'app.current_tenant_id\', true)' in sql


def test_sarif_exporter() -> None:
    vuln = VulnerabilityReport(
        id="vuln_test_1",
        session_id="sess_1",
        title="BOLA in User Tool",
        severity=Severity.HIGH,
        owasp_category=OWASPCategory.API01_BOLA,
        description="Missing tenant boundary check.",
        evidence={"tool_name": "delete_user"},
        remediation_patch="ALTER TABLE ...",
    )

    sarif = SARIFExporter.to_sarif([vuln], "Target Test")
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "API01"
    assert result["level"] == "error"
