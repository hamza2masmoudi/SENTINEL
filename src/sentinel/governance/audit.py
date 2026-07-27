import csv
import io
import json
import sqlite3
import threading
import time
from typing import Any

from pydantic import BaseModel, Field

from sentinel.exceptions import StorageError
from sentinel.governance.hashchain import HashChain


class AuditRecord(BaseModel):
    """Immutable audit entry capturing an LLM interaction and security decisions.

    Attributes:
        record_id: Unique record identifier.
        session_id: Session context identifier.
        tenant_id: Multi-tenant partition key.
        timestamp: Epoch creation timestamp.
        input_text: Raw user prompt input.
        output_text: Generated assistant response or redaction note.
        decision: Final governance action ('allow', 'warn', 'block').
        composite_score: Evaluated ensemble threat risk score.
        details: Granular detector findings.
        block_hash: Hash chain block digest for tamper evidence.
    """

    record_id: str
    session_id: str = Field(default="default")
    tenant_id: str = Field(default="default")
    timestamp: float = Field(default_factory=time.time)
    input_text: str
    output_text: str = Field(default="")
    decision: str = Field(default="allow")
    composite_score: float = Field(default=0.0, ge=0.0, le=1.0)
    details: dict[str, Any] = Field(default_factory=dict)
    block_hash: str = Field(default="")


class AuditLogger:
    """Thread-safe audit logger backed by SQLite and hash chaining.

    Attributes:
        database_path: File path or in-memory URI for SQLite storage.
        hash_chain: Active HashChain verifying ledger continuity.
    """

    def __init__(self, database_path: str = ":memory:") -> None:
        """Initialize AuditLogger database tables and cryptographic chain.

        Args:
            database_path: SQLite path string (or ':memory:').

        Returns:
            None

        Raises:
            StorageError: If database initialization fails.

        Examples:
            >>> logger = AuditLogger()
            >>> logger.database_path
            ':memory:'
        """
        self.database_path: str = database_path
        self.hash_chain: HashChain = HashChain()
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(database_path, check_same_thread=False)
        self._init_database()

    def _init_database(self) -> None:
        """Create necessary schema tables if they do not exist.

        Args:
            None

        Returns:
            None

        Raises:
            StorageError: If schema creation encounters database errors.

        Examples:
            >>> pass
        """
        try:
            with self._lock:
                cursor = self._connection.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS audit_records (
                        record_id TEXT PRIMARY KEY,
                        session_id TEXT,
                        tenant_id TEXT,
                        timestamp REAL,
                        input_text TEXT,
                        output_text TEXT,
                        decision TEXT,
                        composite_score REAL,
                        details TEXT,
                        block_hash TEXT
                    )
                    """)
                self._connection.commit()
        except Exception as err:
            raise StorageError(
                f"Database init failed: {err}", backend="sqlite"
            ) from err

    def record_interaction(
        self,
        record_id: str,
        input_text: str,
        output_text: str = "",
        decision: str = "allow",
        composite_score: float = 0.0,
        session_id: str = "default",
        tenant_id: str = "default",
        details: dict[str, Any] | None = None,
    ) -> AuditRecord:
        """Persist interaction and seal into the cryptographic hash chain.

        Args:
            record_id: Unique record ID.
            input_text: Input prompt text.
            output_text: Generated response.
            decision: Verdict action ('allow', 'warn', 'block').
            composite_score: Threat score.
            session_id: Session identifier.
            tenant_id: Client partition key.
            details: Findings dictionary.

        Returns:
            AuditRecord: The permanently stored audit record.

        Raises:
            StorageError: If database insertion fails.

        Examples:
            >>> logger = AuditLogger()
            >>> rec = logger.record_interaction("r1", "Hello")
            >>> rec.record_id
            'r1'
        """
        with self._lock:
            meta = details if details is not None else {}
            chain_payload = {
                "record_id": record_id,
                "input_text": input_text,
                "decision": decision,
                "score": composite_score,
            }
            block = self.hash_chain.add_block(chain_payload)

            record = AuditRecord(
                record_id=record_id,
                session_id=session_id,
                tenant_id=tenant_id,
                timestamp=block.timestamp,
                input_text=input_text,
                output_text=output_text,
                decision=decision,
                composite_score=composite_score,
                details=meta,
                block_hash=block.hash,
            )

            try:
                cursor = self._connection.cursor()
                cursor.execute(
                    """
                    INSERT INTO audit_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.record_id,
                        record.session_id,
                        record.tenant_id,
                        record.timestamp,
                        record.input_text,
                        record.output_text,
                        record.decision,
                        record.composite_score,
                        json.dumps(record.details),
                        record.block_hash,
                    ),
                )
                self._connection.commit()
                return record
            except Exception as err:
                raise StorageError(
                    f"Insert record failed: {err}", backend="sqlite"
                ) from err

    def list_records(
        self,
        tenant_id: str | None = None,
        limit: int = 100,
    ) -> list[AuditRecord]:
        """Fetch audit records matching query parameters.

        Args:
            tenant_id: Optional tenant filter.
            limit: Maximum rows to return.

        Returns:
            list[AuditRecord]: Query result records.

        Raises:
            StorageError: If query execution fails.

        Examples:
            >>> logger = AuditLogger()
            >>> len(logger.list_records())
            0
        """
        with self._lock:
            try:
                cursor = self._connection.cursor()
                if tenant_id is not None:
                    cursor.execute(
                        "SELECT * FROM audit_records WHERE tenant_id = ? "
                        "ORDER BY timestamp DESC LIMIT ?",
                        (tenant_id, limit),
                    )
                else:
                    query = (
                        "SELECT * FROM audit_records ORDER BY timestamp DESC LIMIT ?"
                    )
                    cursor.execute(query, (limit,))

                rows = cursor.fetchall()
                results: list[AuditRecord] = []
                for row in rows:
                    results.append(
                        AuditRecord(
                            record_id=row[0],
                            session_id=row[1],
                            tenant_id=row[2],
                            timestamp=row[3],
                            input_text=row[4],
                            output_text=row[5],
                            decision=row[6],
                            composite_score=row[7],
                            details=json.loads(row[8]),
                            block_hash=row[9],
                        )
                    )
                return results
            except Exception as err:
                raise StorageError(
                    f"Select records failed: {err}", backend="sqlite"
                ) from err

    def verify_integrity(self) -> bool:
        """Verify that the cryptographic hash chain has not been tampered with.

        Args:
            None

        Returns:
            bool: True if audit chain is intact.

        Raises:
            AuditIntegrityError: If chain hashes do not match.

        Examples:
            >>> logger = AuditLogger()
            >>> logger.verify_integrity()
            True
        """
        with self._lock:
            valid, _ = self.hash_chain.verify_integrity()
            return valid

    def export_csv(self) -> str:
        """Export all stored audit records into formatted CSV text.

        Args:
            None

        Returns:
            str: Comma-separated values document string.

        Raises:
            None

        Examples:
            >>> logger = AuditLogger()
            >>> csv_data = logger.export_csv()
            >>> "record_id" in csv_data
            True
        """
        records = self.list_records(limit=10000)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "record_id",
                "session_id",
                "tenant_id",
                "timestamp",
                "decision",
                "score",
                "block_hash",
            ]
        )
        for r in records:
            writer.writerow(
                [
                    r.record_id,
                    r.session_id,
                    r.tenant_id,
                    r.timestamp,
                    r.decision,
                    r.composite_score,
                    r.block_hash,
                ]
            )
        return output.getvalue()
