import re
from typing import Any

from pydantic import BaseModel, Field

from sentinel.exceptions import PolicyViolationError

_DESTRUCTIVE_COMMANDS = [
    re.compile(r"\b(?:rm\s+-(?:rf|fr|r|f)|mkfs|dd\s+if=|format\s+[a-z]:)\b", re.I),
    re.compile(r"\b(?:shutdown\s+-(?:h|r)|reboot|init\s+0)\b", re.I),
    re.compile(r"\b(?:chmod\s+(?:-R\s+)?777|chown\s+-R\s+root)\b", re.I),
]

_DESTRUCTIVE_SQL = [
    re.compile(r"\b(?:drop\s+(?:table|database|schema|user)|truncate\s+table)\b", re.I),
    re.compile(r"\b(?:delete\s+from\s+[^\s;]+\s*(?:;|$))\b", re.I),
]

_SSRF_INDICATORS = [
    re.compile(
        r"https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254)", re.I
    ),
    re.compile(r"https?://\[::1\]", re.I),
]


class ToolCall(BaseModel):
    """Specification of an agent tool or function call.

    Attributes:
        tool_name: Name of the invoked function or tool.
        arguments: Dictionary of arguments provided to the tool.
    """

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolGuardResult(BaseModel):
    """Verdict produced by the agent tool execution guardrail.

    Attributes:
        allowed: True if the tool invocation meets security policies.
        tool_name: Name of the tool evaluated.
        blocked: True if the invocation was prohibited.
        threat_category: Identified threat classification.
        reason: Justification narrative for blocking or permitting.
    """

    allowed: bool
    tool_name: str
    blocked: bool
    threat_category: str = Field(default="safe")
    reason: str | None = Field(default=None)


class ToolGuard:
    """Guardrail validating and sandboxing autonomous agent tool invocations.

    Attributes:
        allowed_tools: Whitelist of allowed tool names.
        prohibited_tools: Blacklist of prohibited tool names.
    """

    def __init__(
        self,
        allowed_tools: list[str] | None = None,
        prohibited_tools: list[str] | None = None,
    ) -> None:
        """Initialize ToolGuard.

        Args:
            allowed_tools: Whitelist of approved tool names.
            prohibited_tools: Blacklist of banned tool names.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> tg = ToolGuard()
            >>> tg.allowed_tools is None
            True
        """
        self.allowed_tools: list[str] | None = allowed_tools
        self.prohibited_tools: set[str] = (
            set(prohibited_tools) if prohibited_tools is not None else set()
        )

    def _check_string_threats(self, val_str: str) -> tuple[bool, str]:
        """Inspect a string argument for command injection, SQL attacks, or SSRF.

        Args:
            val_str: String argument to evaluate.

        Returns:
            tuple[bool, str]: (Threat detected, Category name).

        Raises:
            None

        Examples:
            >>> pass
        """
        for pattern in _DESTRUCTIVE_COMMANDS:
            if pattern.search(val_str):
                return True, "destructive_shell_command"

        for pattern in _DESTRUCTIVE_SQL:
            if pattern.search(val_str):
                return True, "destructive_sql_query"

        for pattern in _SSRF_INDICATORS:
            if pattern.search(val_str):
                return True, "ssrf_network_probe"

        return False, "safe"

    def _validate_arguments(
        self, arguments: dict[str, Any]
    ) -> tuple[bool, str, str | None]:
        """Recursively inspect argument values for dangerous payloads.

        Args:
            arguments: Dictionary of arguments passed to tool.

        Returns:
            tuple[bool, str, str | None]: (Has threat, Category, Reason).

        Raises:
            None

        Examples:
            >>> pass
        """
        for key, val in arguments.items():
            val_str = str(val)
            has_threat, category = self._check_string_threats(val_str)
            if has_threat:
                return (
                    True,
                    category,
                    f"Dangerous payload in argument '{key}': {category}",
                )
        return False, "safe", None

    def validate_tool_call(
        self, tool_call: ToolCall, raise_on_block: bool = False
    ) -> ToolGuardResult:
        """Validate tool invocation against policies and parameters.

        Args:
            tool_call: The ToolCall instance to evaluate.
            raise_on_block: Whether to raise PolicyViolationError if blocked.

        Returns:
            ToolGuardResult: Evaluation outcome and status.

        Raises:
            PolicyViolationError: If blocked and raise_on_block is True.

        Examples:
            >>> tg = ToolGuard(allowed_tools=["calculator"])
            >>> res = tg.validate_tool_call(ToolCall(tool_name="calculator"))
            >>> res.allowed
            True
        """
        name = tool_call.tool_name

        if self.allowed_tools is not None and name not in self.allowed_tools:
            if raise_on_block:
                raise PolicyViolationError(
                    f"Tool '{name}' is not in allowed whitelist",
                    policy_name="tool_whitelist_policy",
                    action_taken="block",
                )
            return ToolGuardResult(
                allowed=False,
                tool_name=name,
                blocked=True,
                threat_category="unauthorized_tool",
                reason=f"Tool '{name}' not permitted by whitelist",
            )

        if name in self.prohibited_tools:
            if raise_on_block:
                raise PolicyViolationError(
                    f"Tool '{name}' is explicitly prohibited",
                    policy_name="tool_blacklist_policy",
                    action_taken="block",
                )
            return ToolGuardResult(
                allowed=False,
                tool_name=name,
                blocked=True,
                threat_category="prohibited_tool",
                reason=f"Tool '{name}' is blacklisted",
            )

        has_threat, category, reason = self._validate_arguments(tool_call.arguments)
        if has_threat:
            if raise_on_block:
                raise PolicyViolationError(
                    reason or "Dangerous tool argument detected",
                    policy_name="tool_argument_safety_policy",
                    action_taken="block",
                )
            return ToolGuardResult(
                allowed=False,
                tool_name=name,
                blocked=True,
                threat_category=category,
                reason=reason,
            )

        return ToolGuardResult(
            allowed=True,
            tool_name=name,
            blocked=False,
            threat_category="safe",
            reason="Tool invocation authorized",
        )
