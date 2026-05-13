"""Per-role LLM factory.

Each agent role gets its own model + temperature. The factory hides the
provider split (Anthropic vs Groq) behind a single `BaseChatModel` interface
so the agents stay provider-agnostic.

Model assignments follow CLAUDE.md §2, but use the current-gen Claude 4.x
family (Sonnet 4.6, Haiku 4.5) instead of the older 3.5 series referenced
in the original CLAUDE.md.
"""

from __future__ import annotations

import logging
from enum import Enum

from langchain_anthropic import ChatAnthropic
from langchain_core.language_models import BaseChatModel
from langchain_groq import ChatGroq

from agentforge.config import Settings, get_settings

logger = logging.getLogger(__name__)


class AgentRole(str, Enum):
    RED_TEAM = "red_team"            # permissive — Groq Llama for offensive prompts
    JUDGE = "judge"                  # closed/trusted — Claude Sonnet 4.6, temp=0
    ORCHESTRATOR = "orchestrator"    # cost-efficient — Claude Haiku 4.5
    DOCUMENTATION = "documentation"  # high-quality reports — Claude Sonnet 4.6


# Default models per role. Override with env vars REDTEAM_MODEL, JUDGE_MODEL, etc.
_DEFAULTS = {
    AgentRole.RED_TEAM: ("groq", "llama-3.3-70b-versatile", 0.9),
    AgentRole.JUDGE: ("anthropic", "claude-sonnet-4-6", 0.0),
    AgentRole.ORCHESTRATOR: ("anthropic", "claude-haiku-4-5-20251001", 0.2),
    AgentRole.DOCUMENTATION: ("anthropic", "claude-sonnet-4-6", 0.3),
}


def get_model(
    role: AgentRole,
    *,
    settings: Settings | None = None,
    temperature: float | None = None,
) -> BaseChatModel:
    s = settings or get_settings()
    provider, model_name, default_temp = _DEFAULTS[role]
    temp = default_temp if temperature is None else temperature

    if provider == "groq":
        if not s.groq_api_key:
            raise RuntimeError(
                f"GROQ_API_KEY required for {role.value} (model={model_name})"
            )
        return ChatGroq(
            model=model_name,
            temperature=temp,
            api_key=s.groq_api_key.get_secret_value(),
            max_tokens=2048,
        )
    if provider == "anthropic":
        if not s.anthropic_api_key:
            raise RuntimeError(
                f"ANTHROPIC_API_KEY required for {role.value} (model={model_name})"
            )
        return ChatAnthropic(
            model=model_name,
            temperature=temp,
            api_key=s.anthropic_api_key.get_secret_value(),
            max_tokens=4096,
        )
    raise ValueError(f"Unknown provider: {provider}")


def model_name_for(role: AgentRole) -> str:
    """Return the model id used for a role (for cost tracking / logging)."""
    return _DEFAULTS[role][1]


def get_fallback_model(role: AgentRole, *, settings: Settings | None = None) -> BaseChatModel | None:
    """Return an OpenAI fallback for the role, or None if no fallback available.

    Why: Anthropic returns 529 (overloaded) under heavy load and even tenacity
    retries can't recover. The Judge calls are the most critical — if we
    can't get a verdict we lose the whole campaign. OpenAI gpt-4o is a
    high-quality drop-in fallback that uses a different provider entirely.
    """
    s = settings or get_settings()
    if not s.openai_api_key:
        return None

    try:
        from langchain_openai import ChatOpenAI  # type: ignore[import-not-found]
    except ImportError:
        logger.warning("langchain-openai not installed — no fallback judge available")
        return None

    if role == AgentRole.JUDGE:
        return ChatOpenAI(
            model="gpt-4o",
            temperature=0.0,
            api_key=s.openai_api_key.get_secret_value(),
            max_tokens=2048,
        )
    if role == AgentRole.ORCHESTRATOR:
        return ChatOpenAI(
            model="gpt-4o-mini",
            temperature=0.2,
            api_key=s.openai_api_key.get_secret_value(),
            max_tokens=1024,
        )
    if role == AgentRole.DOCUMENTATION:
        return ChatOpenAI(
            model="gpt-4o",
            temperature=0.3,
            api_key=s.openai_api_key.get_secret_value(),
            max_tokens=4096,
        )
    return None
