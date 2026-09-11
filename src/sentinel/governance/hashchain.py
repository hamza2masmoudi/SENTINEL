import hashlib
import json
import threading
import time
from typing import Any

from pydantic import BaseModel, Field

from sentinel.exceptions import AuditIntegrityError


class AuditBlock(BaseModel):
    """An immutable link in the cryptographic audit hash chain.

    Attributes:
        index: Sequential block height.
        timestamp: Epoch timestamp of creation.
        data: Arbitrary structured payload recorded in the block.
        previous_hash: Digest of the immediately preceding block.
        hash: Cryptographic SHA-256 digest of this block's contents.
    """

    index: int = Field(ge=0)
    timestamp: float = Field(default_factory=time.time)
    data: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str
    hash: str

    @classmethod
    def calculate_hash(
        cls,
        index: int,
        timestamp: float,
        data: dict[str, Any],
        previous_hash: str,
        algorithm: str = "sha256",
    ) -> str:
        """Compute the deterministic digest of block fields.

        Args:
            index: Block position index.
            timestamp: Block creation timestamp.
            data: Structured payload mapping.
            previous_hash: Digest of previous block.
            algorithm: Hash function ('sha256' or 'sha512').

        Returns:
            str: Hexadecimal hash digest string.

        Raises:
            None

        Examples:
            >>> h = AuditBlock.calculate_hash(0, 1000.0, {"msg": "init"}, "0" * 64)
            >>> len(h)
            64
        """
        canonical_data = json.dumps(data, sort_keys=True)
        raw_payload = f"{index}:{timestamp}:{canonical_data}:{previous_hash}"
        hasher = getattr(hashlib, algorithm, hashlib.sha256)
        return hasher(raw_payload.encode("utf-8")).hexdigest()


class HashChain:
    """Thread-safe cryptographic ledger establishing tamper-evident audit trails.

    Attributes:
        algorithm: Hashing algorithm ('sha256' or 'sha512').
        chain: Ordered list of validated AuditBlock records.
    """

    def __init__(self, algorithm: str = "sha256") -> None:
        """Initialize a new HashChain starting with a verified genesis block.

        Args:
            algorithm: Cryptographic hashing algorithm name.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> hc = HashChain()
            >>> len(hc.chain)
            1
        """
        self.algorithm: str = algorithm
        self._lock = threading.RLock()
        self.chain: list[AuditBlock] = []
        self._create_genesis_block()

    @property
    def height(self) -> int:
        """Return the total number of blocks in the audit chain."""
        with self._lock:
            return len(self.chain)

    def _create_genesis_block(self) -> AuditBlock:
        """Generate and append the foundational genesis block.

        Args:
            None

        Returns:
            AuditBlock: The newly minted genesis block.

        Raises:
            None

        Examples:
            >>> pass
        """
        genesis_time = 0.0
        genesis_data: dict[str, Any] = {"event": "genesis_block"}
        initial_hash = "0" * 64
        block_hash = AuditBlock.calculate_hash(
            0, genesis_time, genesis_data, initial_hash, self.algorithm
        )
        block = AuditBlock(
            index=0,
            timestamp=genesis_time,
            data=genesis_data,
            previous_hash=initial_hash,
            hash=block_hash,
        )
        self.chain.append(block)
        return block

    def add_block(self, data: dict[str, Any]) -> AuditBlock:
        """Append a new record to the chain linked to the preceding block hash.

        Args:
            data: Structured payload to store immutably.

        Returns:
            AuditBlock: The newly committed block.

        Raises:
            None

        Examples:
            >>> hc = HashChain()
            >>> blk = hc.add_block({"action": "blocked_injection"})
            >>> blk.index
            1
        """
        with self._lock:
            prev_block = self.chain[-1]
            new_index = prev_block.index + 1
            now = time.time()
            new_hash = AuditBlock.calculate_hash(
                new_index, now, data, prev_block.hash, self.algorithm
            )
            block = AuditBlock(
                index=new_index,
                timestamp=now,
                data=data,
                previous_hash=prev_block.hash,
                hash=new_hash,
            )
            self.chain.append(block)
            return block

    def verify_integrity(self) -> tuple[bool, int | None]:
        """Traverse the chain to verify cryptographic links and detect tampering.

        Args:
            None

        Returns:
            tuple[bool, int | None]: Verification success and compromised index.

        Raises:
            AuditIntegrityError: If chain tampering or corruption is discovered.

        Examples:
            >>> hc = HashChain()
            >>> hc.verify_integrity()
            (True, None)
        """
        with self._lock:
            for i in range(1, len(self.chain)):
                current = self.chain[i]
                previous = self.chain[i - 1]

                if current.previous_hash != previous.hash:
                    raise AuditIntegrityError(
                        f"Hash pointer mismatch at block {current.index}",
                        record_id=str(current.index),
                        expected_hash=previous.hash,
                        actual_hash=current.previous_hash,
                    )

                recalculated = AuditBlock.calculate_hash(
                    current.index,
                    current.timestamp,
                    current.data,
                    current.previous_hash,
                    self.algorithm,
                )
                if current.hash != recalculated:
                    raise AuditIntegrityError(
                        f"Tampered block content detected at index {current.index}",
                        record_id=str(current.index),
                        expected_hash=recalculated,
                        actual_hash=current.hash,
                    )

            return True, None

    def export_chain(self) -> list[dict[str, Any]]:
        """Export serialized representation of all blocks in the ledger.

        Args:
            None

        Returns:
            list[dict[str, Any]]: List of block dictionary records.

        Raises:
            None

        Examples:
            >>> hc = HashChain()
            >>> exported = hc.export_chain()
            >>> len(exported)
            1
        """
        with self._lock:
            return [b.model_dump() for b in self.chain]
