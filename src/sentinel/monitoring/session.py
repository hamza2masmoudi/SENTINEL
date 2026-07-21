import threading
import time
from typing import Any

from pydantic import BaseModel, Field


class ConversationTurn(BaseModel):
    """Record of a single conversational interaction turn.

    Attributes:
        role: Entity initiating the turn ('user' or 'assistant').
        content: Message text.
        timestamp: Epoch timestamp when the turn was logged.
        risk_score: Threat score evaluated for this turn.
        flagged: Whether security threats were triggered.
    """

    role: str
    content: str
    timestamp: float = Field(default_factory=time.time)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    flagged: bool = Field(default=False)


class SessionProfile(BaseModel):
    """Behavioral profile and conversation state for an active session.

    Attributes:
        session_id: Unique session identifier string.
        tenant_id: Multi-tenant partition key.
        user_id: Optional client user identifier.
        created_at: Epoch timestamp of session creation.
        updated_at: Epoch timestamp of latest recorded activity.
        turns: Ordered sequence of conversation turns.
        total_requests: Aggregate counter of requests processed.
        cumulative_risk: Sum of risk scores recorded across turns.
    """

    session_id: str
    tenant_id: str = Field(default="default")
    user_id: str | None = Field(default=None)
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    turns: list[ConversationTurn] = Field(default_factory=list)
    total_requests: int = Field(default=0, ge=0)
    cumulative_risk: float = Field(default=0.0, ge=0.0)

    def calculate_requests_per_minute(self) -> float:
        """Compute the current request rate per minute for this session.

        Args:
            None

        Returns:
            float: Estimated requests per minute.

        Raises:
            None

        Examples:
            >>> profile = SessionProfile(session_id="s1")
            >>> profile.calculate_requests_per_minute()
            0.0
        """
        elapsed_seconds = max(1.0, time.time() - self.created_at)
        return (self.total_requests / elapsed_seconds) * 60.0


class SessionManager:
    """Thread-safe session state registry and profiling store.

    Attributes:
        sessions: In-memory dictionary storing active SessionProfile instances.
    """

    def __init__(self) -> None:
        """Initialize SessionManager with an empty thread-safe store.

        Args:
            None

        Returns:
            None

        Raises:
            None

        Examples:
            >>> sm = SessionManager()
            >>> len(sm.sessions)
            0
        """
        self.sessions: dict[str, SessionProfile] = {}
        self._lock = threading.RLock()

    def get_or_create(
        self,
        session_id: str,
        tenant_id: str = "default",
        user_id: str | None = None,
    ) -> SessionProfile:
        """Retrieve an existing session or initialize a new profile.

        Args:
            session_id: Identifier of the target session.
            tenant_id: Tenant partition key.
            user_id: Optional user identifier.

        Returns:
            SessionProfile: Retrieved or newly created session profile.

        Raises:
            None

        Examples:
            >>> sm = SessionManager()
            >>> s = sm.get_or_create("s-42")
            >>> s.session_id
            's-42'
        """
        with self._lock:
            if session_id not in self.sessions:
                self.sessions[session_id] = SessionProfile(
                    session_id=session_id,
                    tenant_id=tenant_id,
                    user_id=user_id,
                )
            return self.sessions[session_id]

    def record_interaction(
        self,
        session_id: str,
        role: str,
        content: str,
        risk_score: float = 0.0,
        flagged: bool = False,
    ) -> SessionProfile:
        """Record a conversation turn and update behavioral profiling metrics.

        Args:
            session_id: Target session identifier.
            role: Speaker role ('user' or 'assistant').
            content: Turn text payload.
            risk_score: Evaluated threat score.
            flagged: Boolean threat status.

        Returns:
            SessionProfile: Updated profile.

        Raises:
            None

        Examples:
            >>> sm = SessionManager()
            >>> prof = sm.record_interaction("s1", "user", "Hello", 0.0)
            >>> prof.total_requests
            1
        """
        with self._lock:
            session = self.get_or_create(session_id)
            turn = ConversationTurn(
                role=role,
                content=content,
                risk_score=risk_score,
                flagged=flagged,
            )
            session.turns.append(turn)
            session.total_requests += 1
            session.cumulative_risk += risk_score
            session.updated_at = time.time()
            return session

    def get_context_dict(self, session_id: str) -> dict[str, Any]:
        """Extract a detector-compatible context dictionary for this session.

        Args:
            session_id: Target session ID.

        Returns:
            dict[str, Any]: Context dictionary containing history and rate metrics.

        Raises:
            None

        Examples:
            >>> sm = SessionManager()
            >>> ctx = sm.get_context_dict("s1")
            >>> "history" in ctx
            True
        """
        with self._lock:
            session = self.get_or_create(session_id)
            history = [t.content for t in session.turns]
            return {
                "history": history,
                "requests_per_minute": session.calculate_requests_per_minute(),
                "total_requests": session.total_requests,
                "cumulative_risk": session.cumulative_risk,
            }
