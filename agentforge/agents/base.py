"""BaseAgent abstract class shared by all LangGraph nodes.

Each concrete agent inherits from BaseAgent and implements `run(state)`,
returning a *partial state update* dict.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage

from agentforge.agents.models import AgentRole, get_model, model_name_for
from agentforge.config import Settings, get_settings
from agentforge.core.cost_tracker import CostTracker, estimate_cost_usd
from agentforge.observability.metrics import llm_calls_total

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Common scaffolding: model handle, cost tracking, structured trace logging."""

    role: AgentRole
    name: str

    def __init__(
        self,
        *,
        cost_tracker: CostTracker | None = None,
        settings: Settings | None = None,
        model: BaseChatModel | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.cost_tracker = cost_tracker or CostTracker()
        self._model_override = model
        self._model: BaseChatModel | None = model

    @property
    def model(self) -> BaseChatModel:
        if self._model is None:
            self._model = self._model_override or get_model(self.role, settings=self.settings)
        return self._model

    @property
    def model_id(self) -> str:
        return model_name_for(self.role)

    @abstractmethod
    async def run(self, state: dict[str, Any]) -> dict[str, Any]:
        """Execute one step against the LangGraph state, returning a partial update."""

    # ---- helpers ----------------------------------------------------------------

    def _record_cost(
        self,
        response: AIMessage | Any,
        *,
        campaign_id: str | None = None,
    ) -> float:
        """Record cost for an LLM response and return the USD amount."""
        usage = _extract_usage(response)
        cost = self.cost_tracker.record_call(
            agent=self.name,
            model=self.model_id,
            input_tokens=usage["input_tokens"],
            output_tokens=usage["output_tokens"],
            campaign_id=campaign_id,
        )
        llm_calls_total.labels(agent=self.name, model=self.model_id).inc()
        return float(cost)

    def _trace(self, event: str, **fields: Any) -> dict[str, Any]:
        """Build a trace entry that nodes can append to state.agent_trace."""
        return {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent": self.name,
            "event": event,
            **fields,
        }


def _extract_usage(response: Any) -> dict[str, int]:
    """Best-effort token-usage extraction across LangChain provider responses."""
    usage_meta = getattr(response, "usage_metadata", None) or {}
    if usage_meta:
        return {
            "input_tokens": int(usage_meta.get("input_tokens", 0) or 0),
            "output_tokens": int(usage_meta.get("output_tokens", 0) or 0),
        }
    md = getattr(response, "response_metadata", None) or {}
    usage = md.get("usage") or md.get("token_usage") or {}
    return {
        "input_tokens": int(usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0),
        "output_tokens": int(usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0),
    }
