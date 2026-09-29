"""Asynchronous datastore manager and repository for Isihlangu."""

import json
import os
import pathlib
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import aiosqlite

from isihlangu.core.errors import DatastoreIntegrityError
from isihlangu.core.types import (
    AttackHypothesis,
    OOBToken,
    OWASPCategory,
    Severity,
    TargetSpec,
    TargetType,
    VulnerabilityReport,
)


class DatabaseManager:
    """Manages SQLite / PostgreSQL connection and schema operations with strict verification."""

    def __init__(self, db_path: str = "./data/isihlangu.db") -> None:
        self.db_path = db_path
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        if self.db_path.startswith("sqlite+aiosqlite:///"):
            clean_path = self.db_path.replace("sqlite+aiosqlite:///", "")
        elif self.db_path.startswith("sqlite:///"):
            clean_path = self.db_path.replace("sqlite:///", "")
        else:
            clean_path = self.db_path

        p = pathlib.Path(clean_path)
        if not p.parent.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
        self.clean_path = str(p)

    @asynccontextmanager
    async def get_connection(self) -> AsyncGenerator[aiosqlite.Connection, None]:
        conn = await aiosqlite.connect(self.clean_path)
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
        finally:
            await conn.close()

    async def apply_migrations(self, migration_file_path: str | None = None) -> None:
        """Applies SQL migration file to active database and verifies tables exist."""
        if not migration_file_path:
            # Default to repo migration path
            base_dir = pathlib.Path(__file__).resolve().parent.parent.parent.parent
            migration_file_path = str(
                base_dir / "database" / "migrations" / "20260929_001_initial_schema.sql"
            )

        if not os.path.exists(migration_file_path):
            raise DatastoreIntegrityError(f"Migration file not found: {migration_file_path}")

        with open(migration_file_path, encoding="utf-8") as f:
            full_sql = f.read()

        # Split UP and DOWN (rollback) sections
        up_sql = full_sql.split("-- rollback")[0]

        async with self.get_connection() as conn:
            try:
                await conn.executescript(up_sql)
                await conn.commit()
            except Exception as e:
                raise DatastoreIntegrityError(f"Failed to execute migration script: {e}") from e

        # Invariant 4 Verification: verify tables in information_schema / sqlite_master
        expected_tables = [
            "targets",
            "scan_sessions",
            "attack_hypotheses",
            "execution_logs",
            "canary_tokens",
            "vulnerabilities",
        ]
        await self.verify_tables_exist(expected_tables)

    async def verify_tables_exist(self, expected_tables: list[str]) -> None:
        """Verifies that all specified tables are present in the datastore."""
        async with self.get_connection() as conn:
            cursor = await conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
            rows = await cursor.fetchall()
            existing_tables = {row["name"] for row in rows}

            missing = [t for t in expected_tables if t not in existing_tables]
            if missing:
                raise DatastoreIntegrityError(
                    f"Live schema verification failed: missing tables {missing}. "
                    f"Present tables: {existing_tables}"
                )

    async def insert_target(self, target: TargetSpec) -> None:
        """Inserts or updates a target specification."""
        async with self.get_connection() as conn:
            await conn.execute(
                """
                INSERT OR REPLACE INTO targets (id, name, target_type, base_url, config_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    target.id,
                    target.name,
                    target.target_type.value,
                    target.base_url,
                    json.dumps(target.config),
                ),
            )
            await conn.commit()

    async def get_target(self, target_id: str) -> TargetSpec | None:
        """Retrieves a target by ID."""
        async with self.get_connection() as conn:
            cursor = await conn.execute(
                "SELECT id, name, target_type, base_url, config_json, created_at FROM targets WHERE id = ?",
                (target_id,),
            )
            row = await cursor.fetchone()
            if not row:
                return None
            return TargetSpec(
                id=row["id"],
                name=row["name"],
                target_type=TargetType(row["target_type"]),
                base_url=row["base_url"],
                config=json.loads(row["config_json"]),
            )

    async def create_session(self, session_id: str, target_id: str) -> None:
        """Creates a new scan session."""
        async with self.get_connection() as conn:
            await conn.execute(
                """
                INSERT INTO scan_sessions (id, target_id, status)
                VALUES (?, ?, 'running')
                """,
                (session_id, target_id),
            )
            await conn.commit()

    async def complete_session(
        self, session_id: str, summary: dict[str, Any], error: str | None = None
    ) -> None:
        """Marks scan session completed with summary JSON."""
        status = "failed" if error else "completed"
        async with self.get_connection() as conn:
            await conn.execute(
                """
                UPDATE scan_sessions
                SET status = ?, summary_json = ?, error_message = ?, completed_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (status, json.dumps(summary), error, session_id),
            )

    async def insert_hypothesis(self, hypothesis: AttackHypothesis) -> None:
        """Persists an attack hypothesis for a scan session."""
        async with self.get_connection() as conn:
            await conn.execute(
                """
                INSERT INTO attack_hypotheses (id, session_id, category, description, target_component, proposed_test, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    hypothesis.id,
                    hypothesis.session_id,
                    hypothesis.category,
                    hypothesis.description,
                    hypothesis.target_component,
                    hypothesis.proposed_test,
                    hypothesis.status,
                ),
            )
            await conn.commit()

    async def insert_canary_token(self, token: OOBToken) -> None:
        """Persists a canary token for OOB tracking."""
        async with self.get_connection() as conn:
            await conn.execute(
                """
                INSERT INTO canary_tokens (token_uuid, session_id, expected_type, target_component)
                VALUES (?, ?, ?, ?)
                """,
                (
                    token.token_uuid,
                    token.session_id,
                    token.expected_type,
                    token.target_component,
                ),
            )
            await conn.commit()

    async def get_canary_token(self, token_uuid: str) -> dict[str, Any] | None:
        """Retrieves canary token status and callback details."""
        async with self.get_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT token_uuid, session_id, expected_type, target_component, callback_received, callback_source_ip, callback_payload, verified_at
                FROM canary_tokens WHERE token_uuid = ?
                """,
                (token_uuid,),
            )
            row = await cursor.fetchone()
            if not row:
                return None
            return {
                "token_uuid": row["token_uuid"],
                "session_id": row["session_id"],
                "expected_type": row["expected_type"],
                "target_component": row["target_component"],
                "callback_received": bool(row["callback_received"]),
                "callback_source_ip": row["callback_source_ip"],
                "callback_payload": row["callback_payload"],
                "verified_at": row["verified_at"],
            }

    async def mark_canary_callback(
        self, token_uuid: str, source_ip: str, payload: str | None = None
    ) -> bool:
        """Marks a canary callback as received. Returns True if token was found and updated."""
        async with self.get_connection() as conn:
            cursor = await conn.execute(
                """
                UPDATE canary_tokens
                SET callback_received = 1, callback_source_ip = ?, callback_payload = ?, verified_at = CURRENT_TIMESTAMP
                WHERE token_uuid = ?
                """,
                (source_ip, payload or "", token_uuid),
            )
            await conn.commit()
            return cursor.rowcount > 0

    async def insert_vulnerability(self, vuln: VulnerabilityReport) -> None:
        """Persists a verified vulnerability finding."""
        async with self.get_connection() as conn:
            await conn.execute(
                """
                INSERT INTO vulnerabilities (
                    id, session_id, hypothesis_id, title, severity, owasp_category, description, evidence_json, remediation_patch
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    vuln.id,
                    vuln.session_id,
                    vuln.hypothesis_id,
                    vuln.title,
                    vuln.severity.value,
                    vuln.owasp_category.value,
                    vuln.description,
                    json.dumps(vuln.evidence),
                    vuln.remediation_patch,
                ),
            )
            await conn.commit()

    async def get_session_vulnerabilities(self, session_id: str) -> list[VulnerabilityReport]:
        """Returns all vulnerabilities recorded for a session."""
        async with self.get_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT id, session_id, hypothesis_id, title, severity, owasp_category, description, evidence_json, remediation_patch
                FROM vulnerabilities WHERE session_id = ?
                """,
                (session_id,),
            )
            rows = await cursor.fetchall()
            return [
                VulnerabilityReport(
                    id=r["id"],
                    session_id=r["session_id"],
                    hypothesis_id=r["hypothesis_id"],
                    title=r["title"],
                    severity=Severity(r["severity"]),
                    owasp_category=OWASPCategory(r["owasp_category"]),
                    description=r["description"],
                    evidence=json.loads(r["evidence_json"]),
                    remediation_patch=r["remediation_patch"],
                )
                for r in rows
            ]
