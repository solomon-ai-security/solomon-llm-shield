"""
Solomon LLM Shield - Enterprise-grade LLM security guardrail library.

Protects input prompts and output responses from prompt injections,
data leakage, PII exposure, and other LLM security threats.
"""

__version__ = "2.0.0"
__author__ = "Solomon AI Security"

from .core import LLMGuard, LLMInputGuard, LLMOutputGuard, scan_output
from .async_shield import (
    ShieldConfig,
    ShieldDecision,
    GuardrailResult,
    ShieldGuardrail,
    CanaryGuardrail,
    EntropyGuardrail,
    GroundingGuardrail,
)

__all__ = [
    "__version__",
    "LLMGuard",
    "LLMInputGuard",
    "LLMOutputGuard",
    "scan_output",
    "ShieldConfig",
    "ShieldDecision",
    "GuardrailResult",
    "ShieldGuardrail",
    "CanaryGuardrail",
    "EntropyGuardrail",
    "GroundingGuardrail",
]
