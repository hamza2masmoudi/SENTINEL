import hashlib
import secrets
import threading
import time
from typing import Literal

from pydantic import BaseModel, Field

from sentinel.exceptions import AuthenticationError

RoleType = Literal["admin", "auditor", "user", "readonly"]

_ROLE_PERMISSIONS: dict[RoleType, set[str]] = {
    "admin": {
        "analyze",
        "guard",
        "audit_read",
        "audit_verify",
        "policies_write",
        "policies_read",
        "compliance_report",
        "admin_manage",
    },
    "auditor": {
        "audit_read",
        "audit_verify",
        "compliance_report",
        "policies_read",
    },
    "user": {
        "analyze",
        "guard",
        "policies_read",
    },
    "readonly": {
        "policies_read",
    },
}


class APIKeyRecord(BaseModel):
    """Metadata record for a provisioned client API key.

    Attributes:
        key_id: Unique public identifier for the key.
        key_hash: SHA-256 hash of the secret token.
        tenant_id: Multi-tenant partition assigned to this key.
        role: Primary security role ('admin', 'auditor', 'user', 'readonly').
        scopes: Granular custom permissions granting access.
        created_at: Epoch timestamp of creation.
        is_active: Boolean flag permitting or revoking key usage.
    """

    key_id: str
    key_hash: str
    tenant_id: str = Field(default="default")
    role: RoleType = Field(default="user")
    scopes: list[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)
    is_active: bool = Field(default=True)


class RBACManager:
    """Thread-safe role-based access control and API key authentication manager.

    Attributes:
        keys_by_id: Map of key_id to APIKeyRecord.
        keys_by_hash: Map of hashed secret to key_id.
    """

    def __init__(self) -> None:
        """Initialize RBACManager with an empty in-memory credentials store.

        Args:
            None

        Returns:
            None

        Raises:
            None

        Examples:
            >>> rbac = RBACManager()
            >>> len(rbac.keys_by_id)
            0
        """
        self.keys_by_id: dict[str, APIKeyRecord] = {}
        self.keys_by_hash: dict[str, str] = {}
        self._lock = threading.RLock()

    def _hash_token(self, token: str) -> str:
        """Calculate SHA-256 digest of an API secret token.

        Args:
            token: Raw secret key string.

        Returns:
            str: Hexadecimal hash digest.

        Raises:
            None

        Examples:
            >>> pass
        """
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_api_key(
        self,
        tenant_id: str = "default",
        role: RoleType = "user",
        scopes: list[str] | None = None,
    ) -> tuple[str, APIKeyRecord]:
        """Generate and register a new cryptographically secure API key.

        Args:
            tenant_id: Client partition identifier.
            role: Security role assigned to the key.
            scopes: Optional custom permission strings.

        Returns:
            tuple[str, APIKeyRecord]: Raw API key string and its stored record.

        Raises:
            None

        Examples:
            >>> rbac = RBACManager()
            >>> raw_key, rec = rbac.create_api_key("acme", "admin")
            >>> raw_key.startswith("snt_")
            True
        """
        with self._lock:
            key_id = f"kid_{secrets.token_hex(8)}"
            raw_token = f"snt_{secrets.token_urlsafe(32)}"
            token_hash = self._hash_token(raw_token)

            record = APIKeyRecord(
                key_id=key_id,
                key_hash=token_hash,
                tenant_id=tenant_id,
                role=role,
                scopes=scopes if scopes is not None else [],
            )

            self.keys_by_id[key_id] = record
            self.keys_by_hash[token_hash] = key_id
            return raw_token, record

    def authenticate_key(self, raw_token: str) -> APIKeyRecord:
        """Validate an incoming raw API key against stored cryptographic digests.

        Args:
            raw_token: Secret key transmitted in HTTP authorization headers.

        Returns:
            APIKeyRecord: Authenticated key metadata.

        Raises:
            AuthenticationError: If token is unknown, invalid, or revoked.

        Examples:
            >>> rbac = RBACManager()
            >>> token, _ = rbac.create_api_key()
            >>> rec = rbac.authenticate_key(token)
            >>> rec.is_active
            True
        """
        token_hash = self._hash_token(raw_token)
        with self._lock:
            key_id = self.keys_by_hash.get(token_hash)
            if key_id is None:
                raise AuthenticationError("Invalid API key")

            record = self.keys_by_id.get(key_id)
            if record is None or not record.is_active:
                raise AuthenticationError("API key revoked or inactive")

            return record

    def authorize(self, record: APIKeyRecord, required_permission: str) -> bool:
        """Verify that an authenticated key holds permission for the requested action.

        Args:
            record: Active APIKeyRecord instance.
            required_permission: Permission identifier (e.g., 'guard', 'audit_read').

        Returns:
            bool: True if authorized, False otherwise.

        Raises:
            None

        Examples:
            >>> rbac = RBACManager()
            >>> _, rec = rbac.create_api_key(role="readonly")
            >>> rbac.authorize(rec, "guard")
            False
            >>> rbac.authorize(rec, "policies_read")
            True
        """
        if required_permission in record.scopes:
            return True

        allowed_role_perms = _ROLE_PERMISSIONS.get(record.role, set())
        return required_permission in allowed_role_perms
