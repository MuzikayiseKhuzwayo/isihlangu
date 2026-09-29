"""Row-Level Security (RLS) Patcher: Synthesizes SQL tenant isolation policies."""


class RLSPatcher:
    """Generates PostgreSQL / Supabase Row-Level Security policies."""

    @staticmethod
    def generate_rls_sql(table_name: str, tenant_col: str = "tenant_id") -> str:
        """Generates DDL to enable RLS and enforce tenant separation via JWT / session claims."""
        return f"""-- Isihlangu Shield Auto-Generated RLS Remediation
ALTER TABLE "{table_name}" ENABLE ROW LEVEL SECURITY;

-- Select Policy
CREATE POLICY "tenant_isolation_select_{table_name}"
ON "{table_name}"
FOR SELECT
USING ({tenant_col} = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid);

-- Insert Policy
CREATE POLICY "tenant_isolation_insert_{table_name}"
ON "{table_name}"
FOR INSERT
WITH CHECK ({tenant_col} = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid);

-- Update Policy
CREATE POLICY "tenant_isolation_update_{table_name}"
ON "{table_name}"
FOR UPDATE
USING ({tenant_col} = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid);

-- Delete Policy
CREATE POLICY "tenant_isolation_delete_{table_name}"
ON "{table_name}"
FOR DELETE
USING ({tenant_col} = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid);
"""
