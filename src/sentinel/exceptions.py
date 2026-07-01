from collections.abc import Mapping
from typing import Any


class SentinelError(Exception):
    """Base exception for all errors raised by the SENTINEL framework.

    Attributes:
        message: Human-readable error description.
        details: Optional mapping containing structured contextual information.
    """

    def __init__(self, message: str, details: Mapping[str, Any] | None = None) -> None:
        """Initialize a SentinelError instance.

        Args:
            message: Explanation of the error condition.
            details: Optional dictionary with diagnostic parameters.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> err = SentinelError("System initialization failed")
            >>> str(err)
            'System initialization failed'
        """
        super().__init__(message)
        self.message: str = message
        self.details: Mapping[str, Any] = details if details is not None else {}

    def to_dict(self) -> dict[str, Any]:
        """Convert the exception details to a structured dictionary.

        Args:
            None

        Returns:
            dict[str, Any]: Serialized representation of the error.

        Raises:
            None

        Examples:
            >>> err = SentinelError("Failure", {"code": 500})
            >>> err.to_dict()["message"]
            'Failure'
        """
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "details": dict(self.details),
        }


class ConfigurationError(SentinelError):
    """Exception raised when configuration validation or loading fails.

    Attributes:
        message: Human-readable error description.
        details: Diagnostic parameters such as invalid key or expected type.
    """

    def __init__(self, message: str, details: Mapping[str, Any] | None = None) -> None:
        """Initialize a ConfigurationError.

        Args:
            message: Explanation of the invalid configuration.
            details: Contextual details such as the invalid field or value.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> err = ConfigurationError("Missing key", {"field": "api_key"})
            >>> err.details["field"]
            'api_key'
        """
        super().__init__(message, details)


class DetectionError(SentinelError):
    """Exception raised when a detection module fails during evaluation.

    Attributes:
        message: Human-readable error description.
        detector_name: Name of the detector that encountered an error.
        details: Additional diagnostic parameters.
    """

    def __init__(
        self,
        message: str,
        detector_name: str = "unknown",
        details: Mapping[str, Any] | None = None,
    ) -> None:
        """Initialize a DetectionError.

        Args:
            message: Failure explanation.
            detector_name: Identifier of the detector that failed.
            details: Contextual metadata for debugging.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> err = DetectionError("Inference failed", detector_name="inj")
            >>> err.detector_name
            'inj'
        """
        merged_details: dict[str, Any] = dict(details) if details is not None else {}
        merged_details["detector_name"] = detector_name
        super().__init__(message, merged_details)
        self.detector_name: str = detector_name


class PolicyViolationError(SentinelError):
    """Exception raised when an interaction violates active security policies.

    Attributes:
        message: Description of the policy violation.
        policy_name: Identifier of the policy that triggered the violation.
        action_taken: Action dictated by the policy (such as block or warn).
        details: Diagnostic parameters.
    """

    def __init__(
        self,
        message: str,
        policy_name: str,
        action_taken: str = "block",
        details: Mapping[str, Any] | None = None,
    ) -> None:
        """Initialize a PolicyViolationError.

        Args:
            message: Violation explanation.
            policy_name: Name of the policy that triggered.
            action_taken: Action executed (default: 'block').
            details: Additional diagnostic parameters.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> err = PolicyViolationError("PII denied", policy_name="no-pii")
            >>> err.policy_name
            'no-pii'
        """
        merged_details: dict[str, Any] = dict(details) if details is not None else {}
        merged_details["policy_name"] = policy_name
        merged_details["action_taken"] = action_taken
        super().__init__(message, merged_details)
        self.policy_name: str = policy_name
        self.action_taken: str = action_taken


class AuditIntegrityError(SentinelError):
    """Exception raised when audit integrity verification fails.

    Attributes:
        message: Failure explanation.
        record_id: Identifier of the tampered or corrupted audit record.
        expected_hash: Hash expected according to chain validation.
        actual_hash: Hash computed from the existing record.
        details: Diagnostic details.
    """

    def __init__(
        self,
        message: str,
        record_id: str | None = None,
        expected_hash: str | None = None,
        actual_hash: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        """Initialize an AuditIntegrityError.

        Args:
            message: Explanation of the verification failure.
            record_id: ID of the compromised record, if known.
            expected_hash: Expected cryptographic digest.
            actual_hash: Computed cryptographic digest.
            details: Contextual details.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> err = AuditIntegrityError("Hash mismatch", record_id="rec-1")
            >>> err.record_id
            'rec-1'
        """
        merged_details: dict[str, Any] = dict(details) if details is not None else {}
        if record_id is not None:
            merged_details["record_id"] = record_id
        if expected_hash is not None:
            merged_details["expected_hash"] = expected_hash
        if actual_hash is not None:
            merged_details["actual_hash"] = actual_hash
        super().__init__(message, merged_details)
        self.record_id: str | None = record_id
        self.expected_hash: str | None = expected_hash
        self.actual_hash: str | None = actual_hash


class NetworkTimeoutError(SentinelError):
    """Exception raised when an external network service request times out.

    Attributes:
        message: Failure explanation.
        service_name: Name of the remote service requested.
        timeout_seconds: Duration in seconds after which request timed out.
        details: Contextual diagnostic parameters.
    """

    def __init__(
        self,
        message: str,
        service_name: str,
        timeout_seconds: float,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        """Initialize a NetworkTimeoutError.

        Args:
            message: Explanation of timeout condition.
            service_name: Remote endpoint or service label.
            timeout_seconds: Timeout threshold configured in seconds.
            details: Diagnostic information.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> err = NetworkTimeoutError("Call timed out", "ollama", 5.0)
            >>> err.service_name
            'ollama'
        """
        merged_details: dict[str, Any] = dict(details) if details is not None else {}
        merged_details["service_name"] = service_name
        merged_details["timeout_seconds"] = timeout_seconds
        super().__init__(message, merged_details)
        self.service_name: str = service_name
        self.timeout_seconds: float = timeout_seconds


class AuthenticationError(SentinelError):
    """Exception raised when API authentication or authorization checks fail.

    Attributes:
        message: Authentication failure description.
        identity: Client or user identity associated with the request.
        details: Diagnostic parameters.
    """

    def __init__(
        self,
        message: str,
        identity: str = "anonymous",
        details: Mapping[str, Any] | None = None,
    ) -> None:
        """Initialize an AuthenticationError.

        Args:
            message: Failure explanation.
            identity: Requesting identity or key identifier.
            details: Diagnostic information.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> err = AuthenticationError("Invalid token", identity="c-42")
            >>> err.identity
            'c-42'
        """
        merged_details: dict[str, Any] = dict(details) if details is not None else {}
        merged_details["identity"] = identity
        super().__init__(message, merged_details)
        self.identity: str = identity


class RateLimitExceededError(SentinelError):
    """Exception raised when a client exceeds the allowed request rate.

    Attributes:
        message: Description of rate limit event.
        retry_after_seconds: Number of seconds before requests may resume.
        details: Contextual rate limiting metrics.
    """

    def __init__(
        self,
        message: str,
        retry_after_seconds: float = 60.0,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        """Initialize a RateLimitExceededError.

        Args:
            message: Rate limit explanation.
            retry_after_seconds: Time to wait before retrying in seconds.
            details: Diagnostic rate limit values.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> err = RateLimitExceededError("Too fast", retry_after_seconds=30.0)
            >>> err.retry_after_seconds
            30.0
        """
        merged_details: dict[str, Any] = dict(details) if details is not None else {}
        merged_details["retry_after_seconds"] = retry_after_seconds
        super().__init__(message, merged_details)
        self.retry_after_seconds: float = retry_after_seconds


class StorageError(SentinelError):
    """Exception raised when database or file storage operations fail.

    Attributes:
        message: Description of storage error.
        backend: Name of the storage system (e.g., 'sqlite', 'postgresql').
        details: Diagnostic parameters.
    """

    def __init__(
        self,
        message: str,
        backend: str = "sqlite",
        details: Mapping[str, Any] | None = None,
    ) -> None:
        """Initialize a StorageError.

        Args:
            message: Failure explanation.
            backend: Storage engine involved.
            details: Diagnostic information.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> err = StorageError("Disk full", backend="sqlite")
            >>> err.backend
            'sqlite'
        """
        merged_details: dict[str, Any] = dict(details) if details is not None else {}
        merged_details["backend"] = backend
        super().__init__(message, merged_details)
        self.backend: str = backend
