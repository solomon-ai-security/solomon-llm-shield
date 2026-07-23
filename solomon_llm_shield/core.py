from __future__ import annotations
from typing import *
import re, json, logging, ast, math, hmac, hashlib, sqlite3, time, uuid, asyncio, io, tokenize, os, string, copy, unicodedata, urllib.request, urllib.error
from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass, field, asdict, fields
from .constants import *
from .constants import _LOGGER, _calculate_risk_score, _TextReplaceBuilder
from .formatters import *
from .formatters import _FORMATTERS, _format_text
from .ast_scanner import *
from .ast_scanner import (
    _Issue, _Metrics, _ASTVisitor, _DEFAULT_CONFIG, _BIDI_CHARACTERS,
    _PYTHON_CODE_BLOCK_RE, _SHELL_CODE_BLOCK_RE, _SQL_CODE_BLOCK_RE,
    _PROMPT_INJECTION_PATTERNS, _SUSPICIOUS_URL_RE, _LLM_SECRET_LEAK_PATTERNS,
    _INLINE_CODE_RE, _HIGH, _MEDIUM, _LOW, _Cwe, _RANKING, _build_test_set
)
from .async_shield import *


# MAIN UNIFIED CLASS
# ===========================================================================

class LLMGuard:
    """
    Unified self-contained guardrail for protecting LLM text output.

    Combines three scanning paradigms:
      1. Chain-based scanner : scan(prompt, output)
      2. AST-based security analysis : scan_ast(text)
      3. Policy-driven regex scanner : scan_output(text)
         and high-level guard(text) / guard_output(text)
    """

    VERSION = "2.0.0"
    DEFAULT_TIMEOUT_SEC = 5
    DEFAULT_READING_SPEED_WPM = 200
    _internal_logger = _LOGGER

    # ── Enums ──────────────────────────────────────────────────────────

    class RiskLevel(str, Enum):
        NONE = "none"; LOW = "low"; MEDIUM = "medium"; HIGH = "high"; CRITICAL = "critical"
        @classmethod
        def from_score(cls, score):
            if not (0.0 <= score <= 1.0):
                raise ValueError(f"score must be in [0.0, 1.0], got {score!r}")
            if score < 0.10: return cls.NONE
            if score < 0.40: return cls.LOW
            if score < 0.75: return cls.MEDIUM
            if score < 0.90: return cls.HIGH
            return cls.CRITICAL

    class GuardType(str, Enum):
        PROMPT = "prompt"; OUTPUT = "output"; TOOL = "tool"

    class PolicyAction(str, Enum):
        BLOCK = "block"; WARN = "warn"; LOG = "log"

    class EventType(str, Enum):
        DECISION = "decision"; SCAN = "scan"; TOOL_CALL = "tool_call"

    class LogFormat(str, Enum):
        JSON = "json"; TEXT = "text"

    class MatchType(str, Enum):
        STR = "str"; WORD = "word"

    class RedactMode(str, Enum):
        PARTIAL = "partial"; ALL = "all"; HASH = "hash"

    # ── Exceptions ─────────────────────────────────────────────────────

    class LLMSecurityError(Exception):
        def __init__(self, message, context=None):
            super().__init__(message)
            self.message = message
            self.context = context or {}
        def __repr__(self):
            return f"{type(self).__name__}({self.message!r})"

    class BlockedByPolicyError(LLMSecurityError):
        def __init__(self, reasons, score=1.0, decision=None, policy_name="unknown", context=None):
            self.reasons = reasons; self.score = score; self.decision = decision; self.policy_name = policy_name
            reason_summary = "; ".join(reasons) if reasons else "no details provided"
            super().__init__(f"Request blocked by policy {policy_name!r} (score={score:.3f}): {reason_summary}", context)
        def to_dict(self):
            return {"error": type(self).__name__, "reasons": self.reasons, "score": round(self.score, 4), "policy_name": self.policy_name}

    class OutputBlockedError(BlockedByPolicyError):
        def __init__(self, reasons, score=1.0, output_snippet="", decision=None, policy_name="unknown", context=None):
            self.output_snippet = output_snippet[:120]
            super().__init__(reasons=reasons, score=score, decision=decision, policy_name=policy_name, context=context)
        def to_dict(self):
            base = super().to_dict(); base["output_snippet"] = self.output_snippet; return base

    class GuardError(LLMSecurityError):
        def __init__(self, guard_name, message, original_error=None, context=None):
            self.guard_name = guard_name; self.original_error = original_error
            super().__init__(f"Guard fault in {guard_name!r}: {message}", context)

    class ConfigError(Exception):
        pass

    class ConfigValidationError(ConfigError):
        def __init__(self, errors):
            self.errors = errors
            bullet = "\n  - ".join(errors)
            super().__init__(f"Config validation failed with {len(errors)} error(s):\n  - {bullet}")

    class ConfigSourceError(ConfigError):
        pass

    # ── Dataclasses ────────────────────────────────────────────────────

    @dataclass
    class ScannerResult:
        """Per-scanner result (from llm-guard-inspired source)."""
        is_valid: bool
        risk_score: float
        sanitized_output: str
        metadata: Dict[str, Any] = field(default_factory=dict)

    @dataclass
    class AuditEntry:
        scanner: str
        is_valid: bool
        risk_score: float
        elapsed_ms: float
        metadata: Dict[str, Any] = field(default_factory=dict)

    @dataclass
    class _CheckResult:
        matched: bool
        score: float = 0.0
        reason: str = ""
        matched_text: str = ""
        redact_spans: Optional[List[Tuple[int, int]]] = None
        def __post_init__(self):
            if self.redact_spans is None:
                self.redact_spans = []

    _NO_MATCH = None  # initialised after class body

    @dataclass
    class ScanResult:
        allowed: bool
        score: float
        reasons: List[str] = field(default_factory=list)
        safe_output: Optional[str] = None
        guard_type: Optional[Any] = None
        metadata: Dict[str, Any] = field(default_factory=dict)
        def __post_init__(self):
            if self.guard_type is None:
                self.guard_type = LLMGuard.GuardType.PROMPT
            if not (0.0 <= self.score <= 1.0):
                raise ValueError(f"ScanResult.score must be in [0.0, 1.0], got {self.score!r}")
        @property
        def risk_level(self):
            return LLMGuard.RiskLevel.from_score(self.score)
        @property
        def is_clean(self):
            return self.allowed and self.score < 0.10
        def to_dict(self):
            return {"allowed": self.allowed, "score": round(self.score, 4), "risk_level": self.risk_level.value, "reasons": self.reasons, "safe_output": self.safe_output, "guard_type": self.guard_type.value, "metadata": self.metadata}

    @dataclass
    class GuardDecision:
        allowed: bool
        score: float
        reasons: List[str] = field(default_factory=list)
        safe_output: Optional[str] = None
        warned: bool = False
        scan_results: List[Any] = field(default_factory=list)
        action: Optional[Any] = None
        def __post_init__(self):
            if self.action is None:
                self.action = LLMGuard.PolicyAction.LOG
            if not (0.0 <= self.score <= 1.0):
                raise ValueError(f"GuardDecision.score must be in [0.0, 1.0], got {self.score!r}")
        @property
        def risk_level(self):
            return LLMGuard.RiskLevel.from_score(self.score)
        @property
        def was_blocked(self):
            return not self.allowed
        @property
        def output_results(self):
            return [r for r in self.scan_results if r.guard_type == LLMGuard.GuardType.OUTPUT]
        @classmethod
        def blocked(cls, reasons, score=1.0, scan_results=None):
            return cls(allowed=False, score=score, reasons=reasons, safe_output=None, warned=False, scan_results=scan_results or [], action=LLMGuard.PolicyAction.BLOCK)
        @classmethod
        def allowed_with_warning(cls, safe_output, reasons, score, scan_results=None):
            return cls(allowed=True, score=score, reasons=reasons, safe_output=safe_output, warned=True, scan_results=scan_results or [], action=LLMGuard.PolicyAction.WARN)
        @classmethod
        def clean(cls, safe_output, scan_results=None):
            return cls(allowed=True, score=0.0, reasons=[], safe_output=safe_output, warned=False, scan_results=scan_results or [], action=LLMGuard.PolicyAction.LOG)
        def to_dict(self):
            return {"allowed": self.allowed, "score": round(self.score, 4), "risk_level": self.risk_level.value, "reasons": self.reasons, "safe_output": self.safe_output, "warned": self.warned, "action": self.action.value, "scan_results": [r.to_dict() for r in self.scan_results]}

    @dataclass
    class SecurityEvent:
        event_type: Any
        timestamp: str
        allowed: bool
        score: float
        risk_level: str
        reasons: List[str]
        action: str
        guard_type: Optional[str] = None
        policy_name: str = "unknown"
        provider_name: str = "unknown"
        tool_name: Optional[str] = None
        tool_call_id: Optional[str] = None
        safe_output_present: bool = False
        duration_ms: Optional[float] = None
        trace_id: Optional[str] = None
        span_id: Optional[str] = None
        extra: Dict[str, Any] = field(default_factory=dict)
        def to_dict(self):
            d = asdict(self); d["event_type"] = self.event_type.value; return d
        def to_json(self):
            return json.dumps(self.to_dict(), default=str)
        def to_text(self):
            parts = [f"event={self.event_type.value}", f"ts={self.timestamp[:19]}Z", f"allowed={self.allowed}", f"score={self.score:.4f}", f"risk={self.risk_level}", f"action={self.action}", f"policy={self.policy_name}", f"provider={self.provider_name}"]
            if self.guard_type: parts.append(f"guard={self.guard_type}")
            if self.tool_name: parts.append(f"tool={self.tool_name}")
            if self.tool_call_id: parts.append(f"call_id={self.tool_call_id}")
            if self.duration_ms is not None: parts.append(f"duration_ms={self.duration_ms:.1f}")
            if self.trace_id: parts.append(f"trace_id={self.trace_id}")
            if self.reasons: parts.append(f'reasons="{"; ".join(self.reasons)}"')
            for k, v in self.extra.items():
                parts.append(f"{k}={v!r}")
            return " ".join(parts)

    @dataclass
    class GuardConfig:
        enabled: bool = True
        block_threshold: Optional[float] = None
        warn_threshold: Optional[float] = None
        def __post_init__(self):
            for attr, label in ((self.block_threshold, "block_threshold"), (self.warn_threshold, "warn_threshold")):
                if attr is not None and not (0.0 <= attr <= 1.0):
                    raise ValueError(f"GuardConfig.{label} must be in [0.0, 1.0], got {attr!r}")
            if (self.block_threshold is not None and self.warn_threshold is not None and self.warn_threshold >= self.block_threshold):
                raise ValueError(f"GuardConfig.warn_threshold must be strictly less than block_threshold. Got warn={self.warn_threshold}, block={self.block_threshold}")

    @dataclass
    class Policy:
        name: str = "default"
        block_threshold: float = 0.75
        warn_threshold: float = 0.40
        raise_on_block: bool = True
        prompt_guard: Any = field(default_factory=lambda: LLMGuard.GuardConfig())
        output_guard: Any = field(default_factory=lambda: LLMGuard.GuardConfig())
        tool_guard: Any = field(default_factory=lambda: LLMGuard.GuardConfig())
        allowed_tools: Optional[List[str]] = None
        blocked_tools: Set[str] = field(default_factory=set)
        redact_on_warn: bool = True
        log_clean_requests: bool = False
        metadata: Dict[str, Any] = field(default_factory=dict)
        def __post_init__(self):
            if not (0.0 <= self.block_threshold <= 1.0):
                raise ValueError(f"Policy.block_threshold must be in [0.0, 1.0], got {self.block_threshold!r}")
            if not (0.0 <= self.warn_threshold <= 1.0):
                raise ValueError(f"Policy.warn_threshold must be in [0.0, 1.0], got {self.warn_threshold!r}")
            if self.warn_threshold >= self.block_threshold:
                raise ValueError(f"Policy.warn_threshold must be strictly less than block_threshold. Got warn={self.warn_threshold}, block={self.block_threshold}")
            if not self.name or not self.name.strip():
                raise ValueError("Policy.name must be a non-empty string.")
            if self.allowed_tools is not None:
                self.allowed_tools = [t.lower().strip() for t in self.allowed_tools]
            self.blocked_tools = {t.lower().strip() for t in self.blocked_tools}
        def effective_block_threshold(self, guard):
            cfg = self._guard_config(guard)
            return cfg.block_threshold if cfg.block_threshold is not None else self.block_threshold
        def effective_warn_threshold(self, guard):
            cfg = self._guard_config(guard)
            return cfg.warn_threshold if cfg.warn_threshold is not None else self.warn_threshold
        def is_guard_enabled(self, guard):
            return self._guard_config(guard).enabled
        def _guard_config(self, guard):
            return {LLMGuard.GuardType.PROMPT: self.prompt_guard, LLMGuard.GuardType.OUTPUT: self.output_guard, LLMGuard.GuardType.TOOL: self.tool_guard}[guard]
        def is_tool_allowed(self, tool_name):
            normalised = tool_name.lower().strip()
            if normalised in self.blocked_tools:
                return False
            if self.allowed_tools is None:
                return True
            return normalised in self.allowed_tools
        def action_for_score(self, score, guard):
            if score >= self.effective_block_threshold(guard):
                return LLMGuard.PolicyAction.BLOCK
            if score >= self.effective_warn_threshold(guard):
                return LLMGuard.PolicyAction.WARN
            return LLMGuard.PolicyAction.LOG
        def replace(self, **kwargs):
            valid = {f.name for f in fields(self)}
            unknown = set(kwargs) - valid
            if unknown:
                raise TypeError(f"Policy.replace() got unknown field(s): {sorted(unknown)}")
            current = {f.name: getattr(self, f.name) for f in fields(self)}
            current.update(kwargs)
            return LLMGuard.Policy(**current)
        def with_allowed_tools(self, tools):
            return self.replace(allowed_tools=tools)
        def with_blocked_tools(self, tools):
            return self.replace(blocked_tools=set(tools))
        def to_dict(self):
            return {"name": self.name, "block_threshold": self.block_threshold, "warn_threshold": self.warn_threshold, "raise_on_block": self.raise_on_block, "prompt_guard": {"enabled": self.prompt_guard.enabled, "block_threshold": self.prompt_guard.block_threshold, "warn_threshold": self.prompt_guard.warn_threshold}, "output_guard": {"enabled": self.output_guard.enabled, "block_threshold": self.output_guard.block_threshold, "warn_threshold": self.output_guard.warn_threshold}, "tool_guard": {"enabled": self.tool_guard.enabled, "block_threshold": self.tool_guard.block_threshold, "warn_threshold": self.tool_guard.warn_threshold}, "allowed_tools": self.allowed_tools, "blocked_tools": sorted(self.blocked_tools), "redact_on_warn": self.redact_on_warn, "log_clean_requests": self.log_clean_requests, "metadata": self.metadata}
        def __repr__(self):
            return f"Policy(name={self.name!r}, block={self.block_threshold}, warn={self.warn_threshold}, raise_on_block={self.raise_on_block})"

    # Initialise _NO_MATCH now that _CheckResult is defined
    _NO_MATCH = _CheckResult(matched=False)

    # ── Regex patterns  ──────────────────

    _FLAGS = re.IGNORECASE | re.DOTALL

    _RE_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9]{20,60}\b")
    _RE_ANTHROPIC_KEY = re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,80}\b")
    _RE_GITHUB_TOKEN = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")
    _RE_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
    _RE_AWS_SECRET = re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]?([A-Za-z0-9/+=]{40})\b")
    _RE_GOOGLE_KEY = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
    _RE_STRIPE_KEY = re.compile(r"\b(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}\b")
    _RE_SLACK_TOKEN = re.compile(r"\bxox[bpoa]-[0-9A-Za-z\-]{10,50}\b")
    _RE_GENERIC_API_KEY = re.compile(r"(?i)(api[_\-\s]?key|apikey|api[_\-\s]?secret|access[_\-\s]?key)\s*[:=]\s*['\"]?([A-Za-z0-9\-_\.]{16,64})['\"]?")
    _RE_JWT = re.compile(r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b")
    _RE_SSH_PRIVATE_KEY = re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.IGNORECASE)
    _RE_GENERIC_PASSWORD = re.compile(r"(?i)(password|passwd|secret|token|credential|auth_token|bearer)\s*[:=]\s*['\"]([^'\"]{8,})['\"]")
    _RE_DESTRUCTIVE_CMD = re.compile(r"""(rm\s+-[rf]{1,2}[f r]*\s+[/~]|rm\s+--no-preserve-root\s+/|mkfs\.[a-z0-9]+\s+/dev/|dd\s+.*of=/dev/[sh]d|:()\{:|:\s*\(\s*\)\s*\{|shutdown\s+(-[rh]\s+)?now|halt\b|poweroff\b|format\s+[cCdDeEfF]:\s*/?)""", re.IGNORECASE | re.VERBOSE)
    _RE_NETWORK_RECON = re.compile(r"""(nmap\s+(-[a-zA-Z0-9]+\s+)*[0-9./]+|masscan\s+|(netcat|nc)\s+(-[a-zA-Z]+\s+)*\d+\.\d+|(curl|wget)\s+.*(-O\s+|--output\s+)|sqlmap\s+|hydra\s+|metasploit|msfconsole|msfvenom)""", re.IGNORECASE | re.VERBOSE)
    _RE_PRIVILEGE_ESCALATION = re.compile(r"""(sudo\s+(su|bash|sh|zsh|fish|-i)|sudo\s+chmod\s+[0-7]*7[0-7]*\s+/|chmod\s+[uo]\+s\s+|/etc/passwd\s*<<|echo\s+.*>>\s*/etc/passwd|visudo\s*;?\s*echo)""", re.IGNORECASE | re.VERBOSE)
    _RE_SSN = re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
    _RE_CREDIT_CARD = re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b")
    _RE_PHONE_NUMBER = re.compile(r"\b(\+?1[-.\s]?)?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b")
    _RE_EMAIL_ADDRESS = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
    _RE_SHELLCODE_PATTERN = re.compile(r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){7,}")
    _RE_RANSOMWARE_KEYWORDS = re.compile(r"""(encrypt\s+(all|your|the|every|each)\s+(files?|documents?|data|disk)|(AES|RSA|Salsa20|ChaCha20)\s+encrypt.{0,40}(ransom|bitcoin|payment)|your\s+files\s+have\s+been\s+encrypted|(pay|send)\s+.{0,30}(bitcoin|btc|monero|xmr).{0,30}(decrypt|restore|recover)|bitcoin\s+wallet\s+address\s*:)""", re.IGNORECASE | re.VERBOSE)
    _RE_REVERSE_SHELL = re.compile(r"""(bash\s+-i\s+>&?\s*/dev/tcp/|python[23]?\s+-c\s+['"]\s*import\s+socket|nc\s+(-e\s+/bin/(sh|bash)|--exec)|perl\s+-e\s+['"]\s*use\s+Socket|php\s+-r\s+['"]\s*\$sock\s*=|powershell.{0,30}New-Object.{0,30}Net\.Sockets)""", re.IGNORECASE | re.VERBOSE)
    _RE_SELF_HARM_INSTRUCTIONS = re.compile(r"""((step[s\-\s]+(by[- ]step\s+)?(instructions?|guide|method|way)\s+to\s+(kill|harm|hurt|injure|end\s+your\s+life|commit\s+suicide|self[- ]harm))|(how\s+to\s+(overdose|hang\s+yourself|slit\s+your\s+wrists|jump\s+from))|(lethal\s+dose\s+of.{0,60}(mg|milligrams?|pills?|tablets?)))""", re.IGNORECASE | re.VERBOSE)
    _RE_VIOLENCE_INSTRUCTIONS = re.compile(r"""((step[- ]by[- ]step|detailed?\s+instructions?)\s+(for|to|on\s+how\s+to)\s+(make|build|construct|assemble|create|synthesize|manufacture)\s+(a\s+)?(bomb|explosive|weapon|poison|toxin|nerve\s+agent|IED)|(synthesis|production|manufacture)\s+of\s+(sarin|VX|novichok|ricin|anthrax|botulinum))""", re.IGNORECASE | re.VERBOSE)
    _RE_SYSTEM_PROMPT_ECHO = re.compile(r"(my\s+system\s+prompt\s+(is|says?|reads?|contains?)|my\s+(hidden\s+|secret\s+|original\s+)?instructions?\s+(are|say|read|contain)|i\s+(was\s+)?instructed\s+to\s+(keep|not\s+reveal|hide|conceal))", re.IGNORECASE | re.DOTALL)
    _RE_INJECTION_ECHO = re.compile(r"(ignore\s+(all\s+)?previous\s+instructions?|you\s+are\s+now\s+(DAN|in\s+developer\s+mode)|as\s+DAN[,\s])", re.IGNORECASE | re.DOTALL)

    # ── URL regex  ─────────────────────────────────────────────

    _URL_REGEX = re.compile(r"https?://[^\s<>\"']+|www\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:/[^\s<>\"']*)?")


    # ── Config field sets ──────────────────────────────────────────────

    _THRESHOLD_FIELDS = {"block_threshold", "warn_threshold"}
    _BOOL_FIELDS = {"raise_on_block", "redact_on_warn", "log_clean_requests"}
    _GUARD_KEYS = {"prompt_guard", "output_guard", "tool_guard"}
    _VALID_GUARD_FIELDS = {"enabled", "block_threshold", "warn_threshold"}
    _ENV_PREFIX = "LLM_SECURITY_"
    _ENV_FIELD_MAP: Dict[str, Tuple[str, Any]] = {
        "NAME": ("name", str), "BLOCK_THRESHOLD": ("block_threshold", float),
        "WARN_THRESHOLD": ("warn_threshold", float),
        "RAISE_ON_BLOCK": ("raise_on_block", None), "REDACT_ON_WARN": ("redact_on_warn", None),
        "LOG_CLEAN_REQUESTS": ("log_clean_requests", None),
        "ALLOWED_TOOLS": ("allowed_tools", None), "BLOCKED_TOOLS": ("blocked_tools", None),
        "PROMPT_GUARD_ENABLED": ("_prompt_guard_enabled", None),
        "OUTPUT_GUARD_ENABLED": ("_output_guard_enabled", None),
        "TOOL_GUARD_ENABLED": ("_tool_guard_enabled", None),
    }

    # ── Class-level state ──────────────────────────────────────────────

    _default_policy: Optional["LLMGuard.Policy"] = None
    _handlers: List[Callable] = []
    _checks_cache: Optional[List[Tuple[Callable, str]]] = None

    # ═══════════════════════════════════════════════════════════════════
    # CONSTRUCTOR
    # ═══════════════════════════════════════════════════════════════════

    def __init__(
        self,
        *,
        
        enable_sensitive: bool = True,
        enable_secrets: bool = True,
        enable_regex: bool = True,
        enable_banned_substrings: bool = True,
        enable_malicious_urls: bool = True,
        enable_url_reachability: bool = False,
        enable_competitors: bool = False,
        enable_json_validation: bool = False,
        enable_reading_time: bool = False,
        enable_invisible_text: bool = True,
        enable_refusal_detection: bool = False,
        sensitive_threshold: float = 0.5,
        secrets_redact_mode: "LLMGuard.RedactMode" = RedactMode.ALL,
        regex_patterns: Optional[List[str]] = None,
        regex_is_blocked: bool = True,
        regex_redact: bool = True,
        banned_substrings: Optional[List[str]] = None,
        banned_substrings_redact: bool = False,
        competitors: Optional[List[str]] = None,
        competitors_redact: bool = True,
        max_reading_time_minutes: float = 1.0,
        truncate_reading_time: bool = False,
        refusal_threshold: float = 0.5,
        url_reachability_timeout: int = 5,
        success_status_codes: Optional[List[int]] = None,
        required_json_elements: int = 0,
        repair_json: bool = True,
        fail_fast: bool = False,
        log_level: str = "INFO",
        
        severity_level: str = "low",
        confidence_level: str = "low",
        profile: Optional[dict] = None,
        bandit_config: Optional[dict] = None,
        ignore_nosec: bool = False,
        output_format: str = "text",
        
        policy: Optional["LLMGuard.Policy"] = None,
        log_format: Optional["LLMGuard.LogFormat"] = None,
        provider_name: str = "output-guard",
        shield_config: Optional[ShieldConfig] = None,
    ):
        
        self.enable_sensitive = enable_sensitive
        self.enable_secrets = enable_secrets
        self.enable_regex = enable_regex
        self.enable_banned_substrings = enable_banned_substrings
        self.enable_malicious_urls = enable_malicious_urls
        self.enable_url_reachability = enable_url_reachability
        self.enable_competitors = enable_competitors
        self.enable_json_validation = enable_json_validation
        self.enable_reading_time = enable_reading_time
        self.enable_invisible_text = enable_invisible_text
        self.enable_refusal_detection = enable_refusal_detection
        self.sensitive_threshold = sensitive_threshold
        self.secrets_redact_mode = secrets_redact_mode
        self._compiled_regex: List[Pattern[str]] = [re.compile(p) for p in (regex_patterns or [])]
        self.regex_is_blocked = regex_is_blocked
        self.regex_redact = regex_redact
        self.banned_substrings = list(banned_substrings) if banned_substrings is not None else list(DEFAULT_BANNED_SUBSTRINGS)
        self.banned_substrings_redact = banned_substrings_redact
        self.competitors = list(competitors or [])
        self.competitors_redact = competitors_redact
        self.max_reading_time_minutes = max_reading_time_minutes
        self.truncate_reading_time = truncate_reading_time
        self.refusal_threshold = refusal_threshold
        self.url_reachability_timeout = url_reachability_timeout
        self.success_status_codes = success_status_codes or [200, 201, 202]
        self.required_json_elements = required_json_elements
        self.repair_json = repair_json
        self.fail_fast = fail_fast
        self._audit_trail: List[LLMGuard.AuditEntry] = []
        _LOGGER.setLevel(log_level)

        #  params
        self.profile = profile or {}
        self.config = dict(_DEFAULT_CONFIG)
        if bandit_config:
            self.config.update(bandit_config)
        self.ignore_nosec = ignore_nosec
        self.output_format = output_format
        self._sev_map = {"all": 0, "low": 1, "medium": 2, "high": 3}
        self.severity_filter = self._sev_map.get(severity_level, 1)
        self.confidence_filter = self._sev_map.get(confidence_level, 1)
        self.results: List[_Issue] = []
        self.skipped: List[Tuple[str, str]] = []
        self.metrics = _Metrics()
        self.scores: List[dict] = []
        self.baseline: List[_Issue] = []
        self._raw_text: str = ""

        #  params
        self._policy = policy or self.get_default_policy()
        self._log_format = log_format or self.LogFormat.JSON
        self._provider_name = provider_name
        self._sec_logger = self.SecurityEventLogger(policy=self._policy, provider_name=provider_name, fmt=self._log_format)

        #  params
        self.shield_config = shield_config
        self._shield_auditor = None
        self._shield_bucket = None
        self._shield_pipeline: List[ShieldGuardrail] = []
        if self.shield_config:
            self._shield_auditor = AsyncNativeAuditor(self.shield_config.db_path, self.shield_config.secret_key)
            self._shield_bucket = TokenBucket(self.shield_config.tpm_limit, self.shield_config.tpm_limit / 60.0)
            self._shield_pipeline = [
                CanaryGuardrail(self.shield_config.canary_patterns),
                EntropyGuardrail(self.shield_config.entropy_threshold),
                ShieldSecurityPIIGuardrail(self.shield_config.secret_key),
                GroundingGuardrail(self.shield_config.grounding_threshold)
            ]

    # ═══════════════════════════════════════════════════════════════════
    # API 1: CHAIN-BASED SCAN 
    # ═══════════════════════════════════════════════════════════════════

    @property
    def audit_trail(self) -> List["LLMGuard.AuditEntry"]:
        return list(self._audit_trail)

    def scan(self, prompt: str, output: str) -> Tuple[str, bool, Dict[str, float], List["LLMGuard.AuditEntry"]]:
        self._audit_trail.clear()
        sanitized = output
        risk_scores: Dict[str, float] = {}
        is_valid_flags: Dict[str, bool] = {}
        if output is None or output.strip() == "":
            return sanitized, True, risk_scores, self._audit_trail
        chain = self._build_chain()
        for name, fn in chain:
            result = self._run_scanner(name, fn, prompt, sanitized)
            is_valid_flags[name] = result.is_valid
            risk_scores[name] = result.risk_score
            sanitized = result.sanitized_output
            if self.fail_fast and not result.is_valid:
                _LOGGER.warning("Scanner failed (fail_fast), aborting chain", extra={"scanner": name, "risk": result.risk_score})
                break
        overall_valid = all(is_valid_flags.values()) if is_valid_flags else True
        return sanitized, overall_valid, risk_scores, list(self._audit_trail)

    def _build_chain(self):
        chain = []
        if self.enable_invisible_text: chain.append(("InvisibleText", self._scan_invisible_text))
        if self.enable_banned_substrings: chain.append(("BanSubstrings", self._scan_banned_substrings))
        if self.enable_refusal_detection: chain.append(("NoRefusal", self._scan_no_refusal))
        if self.enable_competitors: chain.append(("BanCompetitors", self._scan_ban_competitors))
        if self.enable_secrets: chain.append(("Secrets", self._scan_secrets))
        if self.enable_sensitive: chain.append(("Sensitive", self._scan_sensitive))
        if self.enable_regex: chain.append(("Regex", self._scan_regex))
        if self.enable_malicious_urls: chain.append(("MaliciousURLs", self._scan_malicious_urls))
        if self.enable_url_reachability: chain.append(("URLReachability", self._scan_url_reachability))
        if self.enable_json_validation: chain.append(("JSON", self._scan_json))
        if self.enable_reading_time: chain.append(("ReadingTime", self._scan_reading_time))
        return chain

    def _run_scanner(self, name, fn, prompt, output) -> "LLMGuard.ScannerResult":
        import time
        t0 = time.perf_counter()
        try:
            res = fn(prompt, output)
        except Exception as e:
            _LOGGER.exception("Scanner raised, treating as invalid", extra={"scanner": name})
            res = LLMGuard.ScannerResult(is_valid=False, risk_score=1.0, sanitized_output=output, metadata={"error": repr(e)})
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        entry = LLMGuard.AuditEntry(scanner=name, is_valid=res.is_valid, risk_score=res.risk_score, elapsed_ms=round(elapsed_ms, 3), metadata=res.metadata)
        self._audit_trail.append(entry)
        return res

    def _scan_invisible_text(self, prompt, output):
        has_unicode = any(ord(c) > 127 for c in output)
        if not has_unicode:
            return LLMGuard.ScannerResult(True, -1.0, output)
        chars_found = []
        cleaned = []
        for ch in output:
            if unicodedata.category(ch) in {"Cf", "Co", "Cn"}:
                chars_found.append(ch)
                continue
            cleaned.append(ch)
        sanitized = "".join(cleaned)
        if chars_found:
            return LLMGuard.ScannerResult(False, 1.0, sanitized, metadata={"invisible_chars": chars_found})
        return LLMGuard.ScannerResult(True, 0.0, sanitized)

    def _scan_banned_substrings(self, prompt, output):
        sanitized = output
        matched = []
        for s in self.banned_substrings:
            if s.lower() in sanitized.lower():
                matched.append(s)
        if not matched:
            return LLMGuard.ScannerResult(True, -1.0, sanitized)
        if self.banned_substrings_redact:
            for s in matched:
                sanitized = re.compile(re.escape(s), re.IGNORECASE).sub("[REDACTED]", sanitized)
        return LLMGuard.ScannerResult(False, 1.0, sanitized, metadata={"matched": matched})

    def _scan_no_refusal(self, prompt, output):
        lowered = output.lower()
        for phrase in DEFAULT_REFUSAL_PHRASES:
            if phrase.lower() in lowered:
                return LLMGuard.ScannerResult(False, 1.0, output, metadata={"phrase": phrase})
        return LLMGuard.ScannerResult(True, -1.0, output)

    def _scan_ban_competitors(self, prompt, output):
        if not self.competitors:
            return LLMGuard.ScannerResult(True, -1.0, output)
        builder = _TextReplaceBuilder(output)
        detected = []
        for comp in self.competitors:
            pattern = re.compile(r"\b" + re.escape(comp) + r"\b", re.IGNORECASE)
            for m in list(pattern.finditer(builder.output_text))[::-1]:
                detected.append(comp)
                if self.competitors_redact:
                    builder.replace_text_get_insertion_index("[REDACTED]", m.start(), m.end())
        if detected:
            return LLMGuard.ScannerResult(False, 1.0, builder.output_text, metadata={"competitors": detected})
        return LLMGuard.ScannerResult(True, -1.0, output)

    def _redact_secret(self, value):
        if self.secrets_redact_mode == LLMGuard.RedactMode.PARTIAL:
            if len(value) <= 4:
                return "******"
            return f"{value[:2]}..{value[-2:]}"
        if self.secrets_redact_mode == LLMGuard.RedactMode.HASH:
            return "hash:" + hashlib.md5(value.encode("utf-8")).hexdigest()[:12]
        return "******"

    def _scan_secrets(self, prompt, output):
        builder = _TextReplaceBuilder(output)
        found_types = []
        all_matches = []
        for secret_type, pattern in SECRET_PATTERNS:
            for m in pattern.finditer(builder.output_text):
                all_matches.append((m.start(), m.end(), m.group(0), secret_type))
        if not all_matches:
            return LLMGuard.ScannerResult(True, -1.0, output)
        all_matches.sort(key=lambda x: (x[0], -(x[1] - x[0])))
        deduped = []
        last_end = -1
        for start, end, val, st in all_matches:
            if start < last_end:
                continue
            deduped.append((start, end, val, st))
            last_end = end
        for start, end, val, st in sorted(deduped, key=lambda x: x[0], reverse=True):
            found_types.append(st)
            builder.replace_text_get_insertion_index(self._redact_secret(val), start, end)
        return LLMGuard.ScannerResult(False, 1.0, builder.output_text, metadata={"secret_types": found_types})

    def _scan_sensitive(self, prompt, output):
        builder = _TextReplaceBuilder(output)
        detected = []
        all_matches = []
        for group in PII_PATTERNS:
            score = group["score"]
            for expr in group["expressions"]:
                pattern = re.compile(expr)
                for m in pattern.finditer(builder.output_text):
                    all_matches.append((m.start(), m.end(), m.group(0), group["name"], score))
        if not all_matches:
            return LLMGuard.ScannerResult(True, -1.0, output)
        all_matches.sort(key=lambda x: (x[0], -x[4], -(x[1] - x[0])))
        deduped = []
        last_end = -1
        for start, end, val, name, score in all_matches:
            if start < last_end:
                continue
            deduped.append((start, end, val, name, score))
            last_end = end
        max_score = 0.0
        for start, end, val, name, score in sorted(deduped, key=lambda x: x[0], reverse=True):
            detected.append({"type": name, "value": val, "score": score})
            max_score = max(max_score, score)
            placeholder = f"[REDACTED_{name}_{len(detected)}]"
            builder.replace_text_get_insertion_index(placeholder, start, end)
        if detected:
            risk = _calculate_risk_score(max_score, self.sensitive_threshold)
            return LLMGuard.ScannerResult(False, risk, builder.output_text, metadata={"entities": detected})
        return LLMGuard.ScannerResult(True, -1.0, output)

    def _scan_regex(self, prompt, output):
        if not self._compiled_regex:
            return LLMGuard.ScannerResult(True, -1.0, output)
        builder = _TextReplaceBuilder(output)
        any_match = False
        any_allowed_match = False
        matched_patterns = []
        for pattern in self._compiled_regex:
            matches = list(pattern.finditer(builder.output_text))
            if not matches:
                continue
            any_match = True
            matched_patterns.append(pattern.pattern)
            if self.regex_is_blocked:
                if self.regex_redact:
                    for m in matches[::-1]:
                        builder.replace_text_get_insertion_index("[REDACTED]", m.start(), m.end())
                return LLMGuard.ScannerResult(False, 1.0, builder.output_text, metadata={"patterns": matched_patterns})
            else:
                any_allowed_match = True
        if self.regex_is_blocked:
            return LLMGuard.ScannerResult(True, -1.0, builder.output_text)
        if any_allowed_match:
            return LLMGuard.ScannerResult(True, -1.0, builder.output_text, metadata={"matched_allowed": matched_patterns})
        return LLMGuard.ScannerResult(False, 1.0, builder.output_text, metadata={"reason": "no allowed pattern matched"})

    def _scan_malicious_urls(self, prompt, output):
        urls = self._URL_REGEX.findall(output)
        if not urls:
            return LLMGuard.ScannerResult(True, -1.0, output)
        suspicious = []
        for url in urls:
            m = re.match(r"(?:https?://)?([^/\s:]+)", url)
            if not m:
                continue
            host = m.group(1).lower()
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
                suspicious.append(url); continue
            tld = host.rsplit(".", 1)[-1] if "." in host else ""
            if tld in SUSPICIOUS_TLDS:
                suspicious.append(url); continue
            if "@" in host or re.search(r"https?://[^/@\s]+:[^/@\s]+@", url):
                suspicious.append(url); continue
            if len(url) > 200 or host.count(".") > 4:
                suspicious.append(url); continue
            if "xn--" in host:
                suspicious.append(url)
        if suspicious:
            return LLMGuard.ScannerResult(False, 0.75, output, metadata={"urls": suspicious})
        return LLMGuard.ScannerResult(True, -0.25, output, metadata={"urls": urls})

    def _is_url_reachable(self, url):
        try:
            req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "LLMGuard/1.0"})
            with urllib.request.urlopen(req, timeout=self.url_reachability_timeout) as r:
                return r.status in self.success_status_codes
        except urllib.error.HTTPError:
            try:
                req = urllib.request.Request(url, method="GET", headers={"User-Agent": "LLMGuard/1.0"})
                with urllib.request.urlopen(req, timeout=self.url_reachability_timeout) as r:
                    return r.status in self.success_status_codes
            except Exception:
                return False
        except Exception:
            return False

    def _scan_url_reachability(self, prompt, output):
        urls = self._URL_REGEX.findall(output)
        if not urls:
            return LLMGuard.ScannerResult(True, -1.0, output)
        unreachable = [u for u in urls if not self._is_url_reachable(u)]
        if unreachable:
            return LLMGuard.ScannerResult(False, 1.0, output, metadata={"unreachable": unreachable})
        return LLMGuard.ScannerResult(True, -1.0, output)

    def _scan_json(self, prompt, output):
        candidates = self._find_json_objects(output)
        valid = []
        repaired_count = 0
        for cand in candidates:
            try:
                json.loads(cand)
                valid.append(cand)
            except ValueError:
                if self.repair_json:
                    repaired = self._repair_json(cand)
                    try:
                        json.loads(repaired)
                        valid.append(repaired)
                        output = output.replace(cand, repaired)
                        repaired_count += 1
                        continue
                    except ValueError:
                        pass
        if len(valid) < self.required_json_elements:
            return LLMGuard.ScannerResult(False, 1.0, output, metadata={"found": len(valid), "required": self.required_json_elements, "repaired": repaired_count})
        if len(valid) != len(candidates):
            return LLMGuard.ScannerResult(False, 1.0, output, metadata={"valid": len(valid), "total": len(candidates), "repaired": repaired_count})
        return LLMGuard.ScannerResult(True, -1.0, output, metadata={"valid": len(valid), "repaired": repaired_count})

    @staticmethod
    def _find_json_objects(text):
        results = []
        i = 0
        n = len(text)
        while i < n:
            if text[i] != "{":
                i += 1
                continue
            depth = 0
            start = i
            in_str = False
            esc = False
            while i < n:
                ch = text[i]
                if in_str:
                    if esc:
                        esc = False
                    elif ch == "\\":
                        esc = True
                    elif ch == '"':
                        in_str = False
                else:
                    if ch == '"':
                        in_str = True
                    elif ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            results.append(text[start:i + 1])
                            i += 1
                            break
                i += 1
            else:
                break
        return results

    @staticmethod
    def _repair_json(s):
        s = re.sub(r'([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*:)', r'\1"\2"\3', s)
        s = re.sub(r',\s*([}\]])', r'\1', s)
        opens_b = s.count("{") - s.count("}")
        opens_bk = s.count("[") - s.count("]")
        if opens_b > 0:
            s = s + ("}" * opens_b)
        if opens_bk > 0:
            s = s + ("]" * opens_bk)
        return s

    def _scan_reading_time(self, prompt, output):
        words = output.split()
        wc = len(words)
        minutes = wc / self.DEFAULT_READING_SPEED_WPM
        if minutes > self.max_reading_time_minutes:
            if self.truncate_reading_time:
                max_words = int(self.max_reading_time_minutes * self.DEFAULT_READING_SPEED_WPM)
                output = " ".join(words[:max_words])
            return LLMGuard.ScannerResult(False, 1.0, output, metadata={"minutes": minutes, "words": wc})
        return LLMGuard.ScannerResult(True, -1.0, output, metadata={"minutes": minutes, "words": wc})

    # ═══════════════════════════════════════════════════════════════════
    # API 2: AST-BASED SECURITY SCAN 
    # ═══════════════════════════════════════════════════════════════════

    def scan_ast(self, text: str) -> List[_Issue]:
        """AST-based security analysis of LLM output text."""
        self.results = []
        self.skipped = []
        self.metrics = _Metrics()
        self.scores = []
        self._raw_text = text
        self._scan_trojan_source(text)
        self._scan_prompt_injection(text)
        self._scan_secret_leaks(text)
        self._scan_suspicious_urls(text)
        py_blocks = _PYTHON_CODE_BLOCK_RE.findall(text)
        if py_blocks:
            for i, block in enumerate(py_blocks):
                self._analyze_python_code(block, f"<llm_python_block_{i}>")
        else:
            try:
                ast.parse(text)
                self._analyze_python_code(text, "<llm_output>")
            except SyntaxError:
                pass
        for i, block in enumerate(_SHELL_CODE_BLOCK_RE.findall(text)):
            self._analyze_shell_code(block, f"<llm_shell_block_{i}>")
        for i, block in enumerate(_SQL_CODE_BLOCK_RE.findall(text)):
            self._analyze_sql_code(block, f"<llm_sql_block_{i}>")
        self.metrics.aggregate()
        return self.get_issues()

    def get_issues(self, sev_filter=None, conf_filter=None):
        sev = sev_filter or _RANKING[self.severity_filter]
        conf = conf_filter or _RANKING[self.confidence_filter]
        if not sev:
            sev = _LOW
        if not conf:
            conf = _LOW
        results = [i for i in self.results if i.filter(sev, conf)]
        if self.baseline:
            return [a for a in results if a not in self.baseline]
        return results

    def results_count(self, sev_filter=None, conf_filter=None):
        return len(self.get_issues(sev_filter, conf_filter))

    def get_report(self, output_format=None, verbose=False):
        fmt = output_format or self.output_format
        formatter = _FORMATTERS.get(fmt, _format_text)
        issues = self.get_issues()
        if fmt in ("text", "txt"):
            return formatter(issues, self.metrics, self.skipped, verbose=verbose)
        return formatter(issues, self.metrics, self.skipped)

    def populate_baseline(self, data):
        try:
            jdata = json.loads(data)
            for j in jdata.get("results", []):
                issue = _Issue(severity=j.get("issue_severity", _UNDEFINED))
                issue.fname = j.get("filename", "")
                issue.severity = j.get("issue_severity", _UNDEFINED)
                issue.cwe = _Cwe(j.get("issue_cwe", {}).get("id", 0))
                issue.confidence = j.get("issue_confidence", _UNDEFINED)
                issue.text = j.get("issue_text", "")
                issue.test = j.get("test_name", "")
                issue.test_id = j.get("test_id", "")
                issue.lineno = j.get("line_number")
                issue.linerange = j.get("line_range", [])
                self.baseline.append(issue)
        except Exception:
            pass

    def is_safe(self, sev_filter=None, conf_filter=None):
        return self.results_count(sev_filter, conf_filter) == 0

    def _analyze_python_code(self, code, fname):
        fdata = io.BytesIO(code.encode("utf-8"))
        try:
            data = fdata.read()
            lines = data.splitlines()
            self.metrics.begin(fname)
            self.metrics.count_locs(lines)
            nosec_lines = {}
            if not self.ignore_nosec:
                fdata.seek(0)
                try:
                    tokens = tokenize.tokenize(fdata.readline)
                    for toktype, tokval, (lineno, _), _, _ in tokens:
                        if toktype == tokenize.COMMENT:
                            nosec_lines[lineno] = self._parse_nosec_comment(tokval)
                except tokenize.TokenError:
                    pass
            testset = _build_test_set(self.profile)
            visitor = _ASTVisitor(fname, fdata, testset, nosec_lines, self.metrics, self.config)
            score = visitor.process(data.decode("utf-8"))
            self.scores.append(score)
            self.metrics.count_issues([score])
            self.results.extend(visitor.results)
        except SyntaxError:
            self.skipped.append((fname, "syntax error while parsing AST"))
        except Exception as e:
            self.skipped.append((fname, f"exception while scanning: {e}"))

    def _analyze_shell_code(self, code, fname):
        dangerous_patterns = [
            (re.compile(r"\brm\s+-rf\s+/(?:\s|$)"), "HIGH", "Destructive 'rm -rf /' detected in shell code"),
            (re.compile(r"\b(?:curl|wget)\s+.*\|\s*(?:sh|bash|zsh)"), "HIGH", "Remote code execution: piping download to shell"),
            (re.compile(r"\beval\s+['\"]"), "MEDIUM", "eval usage in shell code"),
            (re.compile(r"\$\("), "MEDIUM", "Command substitution in shell code"),
            (re.compile(r"\bchmod\s+\+x\s+/(?:etc|usr|bin|sbin|root)"), "HIGH", "Privilege escalation: chmod on system path"),
            (re.compile(r"\b(?:nc|ncat|netcat)\s+.*-e\s+"), "HIGH", "Reverse shell pattern detected"),
            (re.compile(r"\bsudo\s+"), "MEDIUM", "sudo usage in shell code"),
            (re.compile(r"\bexport\s+(?:LD_PRELOAD|PATH)="), "MEDIUM", "Environment manipulation in shell code"),
        ]
        for lineno, line in enumerate(code.splitlines(), start=1):
            for pattern, sev, msg in dangerous_patterns:
                if pattern.search(line):
                    issue = _Issue(severity=sev, confidence=_HIGH, cwe=_Cwe.OS_COMMAND_INJECTION, text=msg, test_id="LLM-SHELL", lineno=lineno)
                    issue.fname = fname; issue.linerange = [lineno]; issue.test = "shell_code_analysis"
                    self.results.append(issue)

    def _analyze_sql_code(self, code, fname):
        dangerous_patterns = [
            (re.compile(r";\s*(?:DROP|DELETE|TRUNCATE|ALTER)\s", re.IGNORECASE), "HIGH", "SQL injection: stacked query with destructive operation"),
            (re.compile(r"--\s", re.IGNORECASE), "MEDIUM", "SQL comment in query — possible injection"),
            (re.compile(r"\bUNION\s+(?:ALL\s+)?SELECT\b", re.IGNORECASE), "MEDIUM", "UNION SELECT in SQL — possible injection"),
            (re.compile(r"\bOR\s+1\s*=\s*1\b", re.IGNORECASE), "HIGH", "SQL injection: OR 1=1 pattern"),
            (re.compile(r"\b(?:xp_cmdshell|sp_executesql)\b", re.IGNORECASE), "HIGH", "SQL injection: dangerous stored procedure"),
        ]
        for lineno, line in enumerate(code.splitlines(), start=1):
            for pattern, sev, msg in dangerous_patterns:
                if pattern.search(line):
                    issue = _Issue(severity=sev, confidence=_HIGH, cwe=_Cwe.SQL_INJECTION, text=msg, test_id="LLM-SQL", lineno=lineno)
                    issue.fname = fname; issue.linerange = [lineno]; issue.test = "sql_code_analysis"
                    self.results.append(issue)

    def _scan_trojan_source(self, text):
        for lineno, line in enumerate(text.splitlines(), start=1):
            for char in _BIDI_CHARACTERS:
                if char in line:
                    col = line.index(char) + 1
                    issue = _Issue(severity=_HIGH, confidence=_MEDIUM, cwe=_Cwe.INAPPROPRIATE_ENCODING_FOR_OUTPUT_CONTEXT, text="LLM output contains bidirectional control characters (%r)." % char, lineno=lineno, col_offset=col, test_id="B613")
                    issue.fname = "<llm_output>"; issue.linerange = [lineno]; issue.test = "trojansource"
                    self.results.append(issue)

    def _scan_prompt_injection(self, text):
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern, msg in _PROMPT_INJECTION_PATTERNS:
                if pattern.search(line):
                    issue = _Issue(severity=_HIGH, confidence=_MEDIUM, cwe=_Cwe.IMPROPER_INPUT_VALIDATION, text=msg, test_id="LLM-PI", lineno=lineno)
                    issue.fname = "<llm_output>"; issue.linerange = [lineno]; issue.test = "prompt_injection_detection"
                    self.results.append(issue)

    def _scan_secret_leaks(self, text):
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern, msg in _LLM_SECRET_LEAK_PATTERNS:
                if pattern.search(line):
                    issue = _Issue(severity=_HIGH, confidence=_HIGH, cwe=_Cwe.HARD_CODED_PASSWORD, text=msg, test_id="LLM-SECRET", lineno=lineno)
                    issue.fname = "<llm_output>"; issue.linerange = [lineno]; issue.test = "secret_leak_detection"
                    self.results.append(issue)

    def _scan_suspicious_urls(self, text):
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _SUSPICIOUS_URL_RE.search(line):
                issue = _Issue(severity=_MEDIUM, confidence=_MEDIUM, cwe=_Cwe.IMPROPER_ACCESS_CONTROL, text="Suspicious URL in LLM output (localhost / metadata endpoint / bind-all-interfaces).", test_id="LLM-URL", lineno=lineno)
                issue.fname = "<llm_output>"; issue.linerange = [lineno]; issue.test = "suspicious_url_detection"
                self.results.append(issue)

    def _parse_nosec_comment(self, comment):
        found = _NOSEC_COMMENT.search(comment)
        if not found:
            return None
        matches = found.groupdict()
        nosec_tests = matches.get("tests", "")
        test_ids: Set[str] = set()
        if nosec_tests:
            for test in _NOSEC_COMMENT_TESTS.finditer(nosec_tests):
                test_match = test.group(1)
                for tid, _, _, _, _ in _PLUGIN_REGISTRY:
                    if test_match == tid:
                        test_ids.add(test_match); break
                else:
                    for tid, name, _, _, _ in _PLUGIN_REGISTRY:
                        if test_match == name:
                            test_ids.add(tid); break
        return test_ids

    # ═══════════════════════════════════════════════════════════════════
    # API 3: POLICY-DRIVEN SCAN 
    # ═══════════════════════════════════════════════════════════════════

    # --- 23 regex checks ---

    @staticmethod
    def _check_openai_key(text):
        spans = [(m.start(), m.end()) for m in LLMGuard._RE_OPENAI_KEY.finditer(text)]
        if not spans: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.95, reason=f"OpenAI API key detected in output ({len(spans)} occurrence(s))", matched_text="sk-...[redacted]", redact_spans=spans)

    @staticmethod
    def _check_anthropic_key(text):
        spans = [(m.start(), m.end()) for m in LLMGuard._RE_ANTHROPIC_KEY.finditer(text)]
        if not spans: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.95, reason=f"Anthropic API key detected in output ({len(spans)} occurrence(s))", matched_text="sk-ant-...[redacted]", redact_spans=spans)

    @staticmethod
    def _check_github_token(text):
        spans = [(m.start(), m.end()) for m in LLMGuard._RE_GITHUB_TOKEN.finditer(text)]
        if not spans: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.95, reason=f"GitHub token detected in output ({len(spans)} occurrence(s))", matched_text="gh...[redacted]", redact_spans=spans)

    @staticmethod
    def _check_aws_credentials(text):
        key_spans = [(m.start(), m.end()) for m in LLMGuard._RE_AWS_KEY.finditer(text)]
        sec_spans = [(m.start(1), m.end(1)) for m in LLMGuard._RE_AWS_SECRET.finditer(text)]
        all_spans = key_spans + sec_spans
        if not all_spans: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.97, reason=f"AWS credentials detected in output ({len(all_spans)} occurrence(s))", matched_text="AKIA...[redacted]", redact_spans=all_spans)

    @staticmethod
    def _check_google_key(text):
        spans = [(m.start(), m.end()) for m in LLMGuard._RE_GOOGLE_KEY.finditer(text)]
        if not spans: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.95, reason=f"Google API key detected in output ({len(spans)} occurrence(s))", matched_text="AIza...[redacted]", redact_spans=spans)

    @staticmethod
    def _check_stripe_key(text):
        spans = [(m.start(), m.end()) for m in LLMGuard._RE_STRIPE_KEY.finditer(text)]
        if not spans: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.95, reason=f"Stripe API key detected in output ({len(spans)} occurrence(s))", matched_text="sk_...[redacted]", redact_spans=spans)

    @staticmethod
    def _check_slack_token(text):
        spans = [(m.start(), m.end()) for m in LLMGuard._RE_SLACK_TOKEN.finditer(text)]
        if not spans: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.93, reason=f"Slack token detected in output ({len(spans)} occurrence(s))", matched_text="xox...[redacted]", redact_spans=spans)

    @staticmethod
    def _check_generic_api_key(text):
        spans = [(m.start(), m.end()) for m in LLMGuard._RE_GENERIC_API_KEY.finditer(text)]
        if not spans: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.85, reason=f"Generic API key assignment detected ({len(spans)} occurrence(s))", matched_text="api_key=...[redacted]", redact_spans=spans)

    @staticmethod
    def _check_jwt(text):
        spans = [(m.start(), m.end()) for m in LLMGuard._RE_JWT.finditer(text)]
        if not spans: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.90, reason=f"JWT token detected in output ({len(spans)} occurrence(s))", matched_text="eyJ...[redacted]", redact_spans=spans)

    @staticmethod
    def _check_ssh_private_key(text):
        m = LLMGuard._RE_SSH_PRIVATE_KEY.search(text)
        if not m: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.98, reason="SSH/TLS private key block detected in output", matched_text="-----BEGIN PRIVATE KEY-----[redacted]", redact_spans=[(m.start(), len(text))])

    @staticmethod
    def _check_generic_password(text):
        spans = [(m.start(), m.end()) for m in LLMGuard._RE_GENERIC_PASSWORD.finditer(text)]
        if not spans: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.88, reason=f"Password/secret assignment detected ({len(spans)} occurrence(s))", matched_text="password=...[redacted]", redact_spans=spans)

    @staticmethod
    def _check_destructive_command(text):
        m = LLMGuard._RE_DESTRUCTIVE_CMD.search(text)
        if not m: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.95, reason=f"Destructive OS command detected: '{m.group(0).strip()[:60]}'", matched_text=m.group(0).strip()[:60])

    @staticmethod
    def _check_network_recon(text):
        m = LLMGuard._RE_NETWORK_RECON.search(text)
        if not m: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.82, reason=f"Network recon/exploit tool usage detected: '{m.group(0).strip()[:60]}'", matched_text=m.group(0).strip()[:60])

    @staticmethod
    def _check_privilege_escalation(text):
        m = LLMGuard._RE_PRIVILEGE_ESCALATION.search(text)
        if not m: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.88, reason=f"Privilege escalation command detected: '{m.group(0).strip()[:60]}'", matched_text=m.group(0).strip()[:60])

    @staticmethod
    def _check_ssn(text):
        spans = [(m.start(), m.end()) for m in LLMGuard._RE_SSN.finditer(text)]
        if not spans: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.90, reason=f"Social Security Number detected ({len(spans)} occurrence(s))", matched_text="XXX-XX-XXXX[redacted]", redact_spans=spans)

    @staticmethod
    def _check_credit_card(text):
        spans = [(m.start(), m.end()) for m in LLMGuard._RE_CREDIT_CARD.finditer(text)]
        if not spans: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.92, reason=f"Credit card number detected ({len(spans)} occurrence(s))", matched_text="XXXX-XXXX-XXXX-XXXX[redacted]", redact_spans=spans)

    @staticmethod
    def _check_shellcode(text):
        m = LLMGuard._RE_SHELLCODE_PATTERN.search(text)
        if not m: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.90, reason="Shellcode byte sequence detected in output", matched_text=m.group(0)[:40] + "...")

    @staticmethod
    def _check_ransomware(text):
        m = LLMGuard._RE_RANSOMWARE_KEYWORDS.search(text)
        if not m: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.95, reason=f"Ransomware indicator detected: '{m.group(0).strip()[:60]}'", matched_text=m.group(0).strip()[:60])

    @staticmethod
    def _check_reverse_shell(text):
        m = LLMGuard._RE_REVERSE_SHELL.search(text)
        if not m: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.97, reason=f"Reverse shell payload detected: '{m.group(0).strip()[:60]}'", matched_text=m.group(0).strip()[:60])

    @staticmethod
    def _check_self_harm_instructions(text):
        m = LLMGuard._RE_SELF_HARM_INSTRUCTIONS.search(text)
        if not m: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.98, reason="Self-harm instructions detected in output", matched_text="[self-harm content detected]")

    @staticmethod
    def _check_violence_instructions(text):
        m = LLMGuard._RE_VIOLENCE_INSTRUCTIONS.search(text)
        if not m: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.98, reason=f"Weapon/dangerous substance instructions detected: '{m.group(0).strip()[:60]}'", matched_text=m.group(0).strip()[:60])

    @staticmethod
    def _check_system_prompt_echo(text):
        m = LLMGuard._RE_SYSTEM_PROMPT_ECHO.search(text)
        if not m: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.80, reason=f"Model appears to be echoing system prompt content: '{m.group(0).strip()[:60]}'", matched_text=m.group(0).strip()[:60])

    @staticmethod
    def _check_injection_echo(text):
        m = LLMGuard._RE_INJECTION_ECHO.search(text)
        if not m: return LLMGuard._NO_MATCH
        return LLMGuard._CheckResult(matched=True, score=0.85, reason=f"Model is echoing injection content: '{m.group(0).strip()[:60]}'", matched_text=m.group(0).strip()[:60])

    @classmethod
    def _get_checks(cls):
        if cls._checks_cache is None:
            cls._checks_cache = [
                (cls._check_openai_key, "credential_leak"), (cls._check_anthropic_key, "credential_leak"),
                (cls._check_github_token, "credential_leak"), (cls._check_aws_credentials, "credential_leak"),
                (cls._check_google_key, "credential_leak"), (cls._check_stripe_key, "credential_leak"),
                (cls._check_slack_token, "credential_leak"), (cls._check_generic_api_key, "credential_leak"),
                (cls._check_jwt, "credential_leak"), (cls._check_ssh_private_key, "credential_leak"),
                (cls._check_generic_password, "credential_leak"),
                (cls._check_destructive_command, "os_command"), (cls._check_network_recon, "os_command"),
                (cls._check_privilege_escalation, "os_command"),
                (cls._check_ssn, "sensitive_data"), (cls._check_credit_card, "sensitive_data"),
                (cls._check_shellcode, "malware_indicator"), (cls._check_ransomware, "malware_indicator"),
                (cls._check_reverse_shell, "malware_indicator"),
                (cls._check_self_harm_instructions, "harmful_content"), (cls._check_violence_instructions, "harmful_content"),
                (cls._check_system_prompt_echo, "data_exfiltration"), (cls._check_injection_echo, "injection_echo"),
            ]
        return cls._checks_cache

    @staticmethod
    def _apply_redactions(text, redaction_map):
        all_spans = []
        for category, spans in redaction_map.items():
            for start, end in spans:
                all_spans.append((start, end, category))
        all_spans.sort(key=lambda x: x[0], reverse=True)
        result = text
        for start, end, category in all_spans:
            placeholder = f"[REDACTED:{category.upper()}]"
            result = result[:start] + placeholder + result[end:]
        return result

    @classmethod
    def scan_output(cls, text, policy=None, *, short_circuit=True):
        active_policy = policy or cls.get_default_policy()
        if not active_policy.is_guard_enabled(cls.GuardType.OUTPUT):
            return cls.ScanResult(allowed=True, score=0.0, reasons=[], guard_type=cls.GuardType.OUTPUT, metadata={"skipped": True, "reason": "output_guard disabled in policy"})
        if not text or not text.strip():
            return cls.ScanResult(allowed=True, score=0.0, reasons=[], guard_type=cls.GuardType.OUTPUT, metadata={"skipped": True, "reason": "empty output"})
        block_threshold = active_policy.effective_block_threshold(cls.GuardType.OUTPUT)
        checks = cls._get_checks()
        reasons, categories, redaction_map, max_score, checks_run = [], [], {}, 0.0, 0
        for check_fn, category in checks:
            checks_run += 1
            result = check_fn(text)
            if result.matched:
                reasons.append(result.reason)
                categories.append(category)
                if result.score > max_score:
                    max_score = result.score
                if result.redact_spans:
                    redaction_map.setdefault(category, []).extend(result.redact_spans)
                if short_circuit and max_score >= block_threshold:
                    break
        allowed = max_score < block_threshold
        return cls.ScanResult(allowed=allowed, score=round(max_score, 4), reasons=reasons, safe_output=None, guard_type=cls.GuardType.OUTPUT, metadata={"categories": list(dict.fromkeys(categories)), "check_count": checks_run, "total_checks": len(checks), "has_redactable_spans": bool(redaction_map), "_redaction_map": redaction_map})

    @classmethod
    def scan_and_redact(cls, text, policy=None, *, short_circuit=False):
        active_policy = policy or cls.get_default_policy()
        base = cls.scan_output(text, active_policy, short_circuit=short_circuit)
        if base.metadata.get("skipped"):
            return cls.ScanResult(allowed=base.allowed, score=base.score, reasons=base.reasons, safe_output=text, guard_type=cls.GuardType.OUTPUT, metadata=base.metadata)
        redaction_map = base.metadata.get("_redaction_map", {})
        safe_output = None
        if base.allowed:
            safe_output = cls._apply_redactions(text, redaction_map) if redaction_map else text
        elif active_policy.redact_on_warn:
            safe_output = cls._apply_redactions(text, redaction_map) if redaction_map else None
        return cls.ScanResult(allowed=base.allowed, score=base.score, reasons=base.reasons, safe_output=safe_output, guard_type=cls.GuardType.OUTPUT, metadata=base.metadata)

    @classmethod
    def redact_output(cls, text, policy=None):
        result = cls.scan_and_redact(text, policy, short_circuit=False)
        return (result.safe_output or text), result.reasons

    @classmethod
    def guard_output(cls, text, policy=None, *, raise_on_block=None, extra=None):
        import time as _time
        active_policy = policy or cls.get_default_policy()
        start = _time.perf_counter()
        try:
            scan = cls.scan_and_redact(text, active_policy)
        except Exception as exc:
            raise cls.GuardError(guard_name="output_guard", message=str(exc), original_error=exc) from exc
        action = active_policy.action_for_score(scan.score, cls.GuardType.OUTPUT)
        decision = cls.GuardDecision(allowed=scan.allowed, score=round(scan.score, 4), reasons=scan.reasons, safe_output=scan.safe_output, warned=action == cls.PolicyAction.WARN, scan_results=[scan], action=action)
        elapsed_ms = (_time.perf_counter() - start) * 1000
        cls.log_decision(decision, policy=active_policy, duration_ms=elapsed_ms, extra=extra)
        should_raise = raise_on_block if raise_on_block is not None else active_policy.raise_on_block
        if not scan.allowed and should_raise:
            raise cls.OutputBlockedError(reasons=scan.reasons, score=scan.score, output_snippet=text[:120], decision=decision, policy_name=active_policy.name)
        return decision

    def guard(self, text, *, policy=None, raise_on_block=None, extra=None):
        return self.guard_output(text, policy=policy or self._policy, raise_on_block=raise_on_block, extra=extra)

    # --- Policy presets ---

    @classmethod
    def strict_policy(cls, name="strict", **overrides):
        defaults = dict(name=name, block_threshold=0.40, warn_threshold=0.15, raise_on_block=True, redact_on_warn=True, log_clean_requests=True)
        defaults.update(overrides)
        return cls.Policy(**defaults)

    @classmethod
    def balanced_policy(cls, name="balanced", **overrides):
        defaults = dict(name=name, block_threshold=0.75, warn_threshold=0.40, raise_on_block=True, redact_on_warn=True, log_clean_requests=False)
        defaults.update(overrides)
        return cls.Policy(**defaults)

    @classmethod
    def logging_only_policy(cls, name="logging-only", **overrides):
        defaults = dict(name=name, block_threshold=1.0, warn_threshold=0.0, raise_on_block=False, redact_on_warn=False, log_clean_requests=True)
        defaults.update(overrides)
        return cls.Policy(**defaults)

    # --- Config loading ---

    @classmethod
    def load_policy_from_dict(cls, data):
        data = copy.deepcopy(data)
        for guard_key in ("prompt_guard", "output_guard", "tool_guard"):
            if guard_key in data and isinstance(data[guard_key], dict):
                data[guard_key] = cls.GuardConfig(**data[guard_key])
        if "blocked_tools" in data and isinstance(data["blocked_tools"], list):
            data["blocked_tools"] = set(data["blocked_tools"])
        valid_fields = {f.name for f in fields(cls.Policy)}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls.Policy(**filtered)

    @classmethod
    def load_policy_from_yaml(cls, path):
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise ImportError("PyYAML is required to load policies from YAML. Install it with: pip install pyyaml") from exc
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Policy YAML file not found: {path!r}")
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict):
            raise ValueError(f"YAML must contain a mapping at top level. Got {type(data).__name__!r}")
        return cls.load_policy_from_dict(data)

    @classmethod
    def _parse_bool(cls, value):
        norm = value.strip().lower()
        if norm in {"1", "true", "yes", "on"}: return True
        if norm in {"0", "false", "no", "off"}: return False
        raise cls.ConfigValidationError([f"Cannot parse {value!r} as boolean. Use: 1/0, true/false, yes/no, on/off"])

    @staticmethod
    def _parse_csv_list(value):
        return [item.strip() for item in value.split(",") if item.strip()]

    @staticmethod
    def _parse_csv_set(value):
        return set(LLMGuard._parse_csv_list(value))

    @staticmethod
    def _deep_merge(base, override):
        result = copy.deepcopy(base)
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = LLMGuard._deep_merge(result[key], value)
            else:
                result[key] = copy.deepcopy(value)
        return result

    @classmethod
    def validate_config_dict(cls, data):
        errors = []
        for field_name in cls._THRESHOLD_FIELDS:
            if field_name in data:
                val = data[field_name]
                if not isinstance(val, (int, float)):
                    errors.append(f"{field_name} must be a number, got {type(val).__name__!r}")
                elif not (0.0 <= float(val) <= 1.0):
                    errors.append(f"{field_name} must be in [0.0, 1.0], got {val!r}")
        block = data.get("block_threshold", 0.75)
        warn = data.get("warn_threshold", 0.40)
        try:
            if float(warn) >= float(block):
                errors.append(f"warn_threshold ({warn}) must be strictly less than block_threshold ({block})")
        except (TypeError, ValueError):
            pass
        for field_name in cls._BOOL_FIELDS:
            if field_name in data and not isinstance(data[field_name], bool):
                errors.append(f"{field_name} must be boolean, got {type(data[field_name]).__name__!r}")
        if "name" in data:
            if not isinstance(data["name"], str) or not data["name"].strip():
                errors.append("name must be a non-empty string")
        if "allowed_tools" in data and data["allowed_tools"] is not None:
            if not isinstance(data["allowed_tools"], list):
                errors.append(f"allowed_tools must be a list, got {type(data['allowed_tools']).__name__!r}")
            elif not all(isinstance(t, str) for t in data["allowed_tools"]):
                errors.append("allowed_tools must contain only strings")
        if "blocked_tools" in data:
            bt = data["blocked_tools"]
            if not isinstance(bt, (list, set)):
                errors.append(f"blocked_tools must be list/set, got {type(bt).__name__!r}")
            elif not all(isinstance(t, str) for t in bt):
                errors.append("blocked_tools must contain only strings")
        for guard_key in cls._GUARD_KEYS:
            if guard_key not in data:
                continue
            gval = data[guard_key]
            if isinstance(gval, cls.GuardConfig):
                continue
            if not isinstance(gval, dict):
                errors.append(f"{guard_key} must be dict or GuardConfig, got {type(gval).__name__!r}")
                continue
            unknown = set(gval.keys()) - cls._VALID_GUARD_FIELDS
            for uk in sorted(unknown):
                errors.append(f"{guard_key}: unknown field {uk!r}")
            for sub_field in ("block_threshold", "warn_threshold"):
                if sub_field in gval and gval[sub_field] is not None:
                    sv = gval[sub_field]
                    if not isinstance(sv, (int, float)):
                        errors.append(f"{guard_key}.{sub_field} must be number, got {type(sv).__name__!r}")
                    elif not (0.0 <= float(sv) <= 1.0):
                        errors.append(f"{guard_key}.{sub_field} must be in [0.0, 1.0], got {sv!r}")
            g_block = gval.get("block_threshold")
            g_warn = gval.get("warn_threshold")
            if (g_block is not None and g_warn is not None and isinstance(g_block, (int, float)) and isinstance(g_warn, (int, float)) and float(g_warn) >= float(g_block)):
                errors.append(f"{guard_key}.warn_threshold ({g_warn}) must be strictly less than {guard_key}.block_threshold ({g_block})")
        if errors:
            raise cls.ConfigValidationError(errors)

    @classmethod
    def _resolve_env_overrides(cls):
        overrides = {}
        guard_toggles = {}
        for env_suffix, (field_name, _) in cls._ENV_FIELD_MAP.items():
            env_key = f"{cls._ENV_PREFIX}{env_suffix}"
            raw = os.environ.get(env_key)
            if raw is None:
                continue
            if env_suffix in ("RAISE_ON_BLOCK", "REDACT_ON_WARN", "LOG_CLEAN_REQUESTS", "PROMPT_GUARD_ENABLED", "OUTPUT_GUARD_ENABLED", "TOOL_GUARD_ENABLED"):
                value = cls._parse_bool(raw)
            elif env_suffix in ("BLOCK_THRESHOLD", "WARN_THRESHOLD"):
                value = float(raw)
            elif env_suffix == "ALLOWED_TOOLS":
                value = cls._parse_csv_list(raw)
            elif env_suffix == "BLOCKED_TOOLS":
                value = cls._parse_csv_set(raw)
            else:
                value = raw
            if field_name.startswith("_") and field_name.endswith("_enabled"):
                guard_key = field_name[1:-8]
                guard_toggles[guard_key] = value
            else:
                overrides[field_name] = value
        for guard_field, enabled in guard_toggles.items():
            if guard_field not in overrides:
                overrides[guard_field] = {}
            if isinstance(overrides[guard_field], dict):
                overrides[guard_field]["enabled"] = enabled
        return overrides

    @classmethod
    def load_config(cls, *, yaml_path=None, data=None, use_env=True, validate=True, base_policy=None):
        merged = (base_policy or cls.balanced_policy()).to_dict()
        if yaml_path is not None:
            if not os.path.isfile(yaml_path):
                raise cls.ConfigSourceError(f"Config YAML file not found: {yaml_path!r}")
            try:
                import yaml
            except ImportError as exc:
                raise cls.ConfigSourceError("PyYAML required. Install: pip install pyyaml") from exc
            with open(yaml_path, "r", encoding="utf-8") as fh:
                file_data = yaml.safe_load(fh) or {}
            if not isinstance(file_data, dict):
                raise cls.ConfigSourceError(f"YAML must contain mapping, got {type(file_data).__name__!r}")
            merged = cls._deep_merge(merged, file_data)
        if data is not None:
            merged = cls._deep_merge(merged, data)
        if use_env:
            env_overrides = cls._resolve_env_overrides()
            if env_overrides:
                merged = cls._deep_merge(merged, env_overrides)
        if validate:
            cls.validate_config_dict(merged)
        return cls.load_policy_from_dict(merged)

    # --- Default policy registry ---

    @classmethod
    def get_default_policy(cls):
        if cls._default_policy is None:
            cls._default_policy = cls.balanced_policy()
        return cls._default_policy

    @classmethod
    def set_default_policy(cls, policy):
        if not isinstance(policy, cls.Policy):
            raise TypeError(f"Expected Policy instance, got {type(policy).__name__!r}")
        cls._default_policy = policy

    @classmethod
    def reset_default_policy(cls):
        cls._default_policy = None

    # --- Audit logging ---

    @classmethod
    def add_handler(cls, handler):
        cls._handlers.append(handler)

    @classmethod
    def remove_handler(cls, handler):
        try:
            cls._handlers.remove(handler)
        except ValueError:
            pass

    @classmethod
    def clear_handlers(cls):
        cls._handlers.clear()

    @classmethod
    def _dispatch(cls, event):
        for handler in cls._handlers:
            try:
                handler(event)
            except Exception:
                cls._internal_logger.error("LLMGuard: handler %r raised:\n%s", handler, traceback.format_exc())

    @staticmethod
    def _utcnow_iso():
        return datetime.now(tz=timezone.utc).isoformat()

    @staticmethod
    def _stdlib_level(allowed, warned):
        if not allowed: return logging.ERROR
        if warned: return logging.WARNING
        return logging.INFO

    @classmethod
    def _write_to_logger(cls, event, logger, fmt):
        level = cls._stdlib_level(allowed=event.allowed, warned=(event.action == "warn"))
        message = event.to_json() if fmt == cls.LogFormat.JSON else event.to_text()
        logger.log(level, message)

    @classmethod
    def log_decision(cls, decision, *, policy=None, provider_name="unknown", logger=None, fmt=None, duration_ms=None, trace_id=None, span_id=None, extra=None):
        if fmt is None:
            fmt = cls.LogFormat.JSON
        target_logger = logger or cls._internal_logger
        event = cls.SecurityEvent(event_type=cls.EventType.DECISION, timestamp=cls._utcnow_iso(), allowed=decision.allowed, score=round(decision.score, 4), risk_level=decision.risk_level.value, reasons=list(decision.reasons), action=decision.action.value, policy_name=policy.name if policy else "unknown", provider_name=provider_name, safe_output_present=decision.safe_output is not None, duration_ms=duration_ms, trace_id=trace_id, span_id=span_id, extra=extra or {})
        cls._write_to_logger(event, target_logger, fmt)
        cls._dispatch(event)
        return event

    @classmethod
    def log_scan_result(cls, result, *, policy=None, provider_name="unknown", logger=None, fmt=None, extra=None):
        if fmt is None:
            fmt = cls.LogFormat.JSON
        target_logger = logger or cls._internal_logger
        event = cls.SecurityEvent(event_type=cls.EventType.SCAN, timestamp=cls._utcnow_iso(), allowed=result.allowed, score=round(result.score, 4), risk_level=result.risk_level.value, reasons=list(result.reasons), action="block" if not result.allowed else "log", guard_type=result.guard_type.value, policy_name=policy.name if policy else "unknown", provider_name=provider_name, extra=extra or {})
        cls._write_to_logger(event, target_logger, fmt)
        cls._dispatch(event)
        return event

    # --- SecurityEventLogger nested class ---

    class SecurityEventLogger:
        def __init__(self, policy=None, provider_name="unknown", fmt=None, logger=None, default_extra=None):
            self.policy = policy
            self.provider_name = provider_name
            self.fmt = fmt or LLMGuard.LogFormat.JSON
            self.logger = logger or LLMGuard._internal_logger
            self.default_extra = default_extra or {}

        def _merge_extra(self, extra):
            merged = dict(self.default_extra)
            if extra:
                merged.update(extra)
            return merged

        def log_decision(self, decision, *, duration_ms=None, trace_id=None, span_id=None, extra=None):
            return LLMGuard.log_decision(decision, policy=self.policy, provider_name=self.provider_name, logger=self.logger, fmt=self.fmt, duration_ms=duration_ms, trace_id=trace_id, span_id=span_id, extra=self._merge_extra(extra))

        def log_scan_result(self, result, *, extra=None):
            return LLMGuard.log_scan_result(result, policy=self.policy, provider_name=self.provider_name, logger=self.logger, fmt=self.fmt, extra=self._merge_extra(extra))

    # --- Instance property for policy ---

    @property
    def policy(self):
        return self._policy

    @policy.setter
    def policy(self, value):
        if not isinstance(value, self.Policy):
            raise TypeError(f"policy must be a Policy instance, got {type(value).__name__!r}")
        self._policy = value
        self._policy = value
        self._sec_logger.policy = value

    # ═══════════════════════════════════════════════════════════════════
    # API 4: ASYNC REALTIME SHIELD
    # ═══════════════════════════════════════════════════════════════════

    def add_custom_rule(self, rule: ShieldGuardrail):
        """Inject a custom async guardrail into the shield pipeline."""
        if self._shield_pipeline is not None:
            self._shield_pipeline.append(rule)
        return self

    async def __aenter__(self):
        if self._shield_auditor:
            self._shield_auditor.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._shield_auditor:
            await self._shield_auditor.stop()

    async def protect(self, text: str, context: Optional[dict] = None) -> str:
        """Shield protection for complete outputs."""
        if not self.shield_config:
            raise RuntimeError("Shield mode requires shield_config in __init__")

        trace_id = str(uuid.uuid4())
        
        if self._shield_bucket and not await self._shield_bucket.consume(len(text)):
            msg = "Rate Limit Exceeded (DoS Protection)"
            if self._shield_auditor:
                self._shield_auditor.log(trace_id, ShieldDecision.BLOCK.value, [msg], len(text))
            raise ValueError(f"Shield BLOCKED: {msg}")

        if len(text) > self.shield_config.max_context_length:
            msg = "Output Context Length Exceeded"
            if self._shield_auditor:
                self._shield_auditor.log(trace_id, ShieldDecision.BLOCK.value, [msg], len(text))
            raise ValueError(f"Shield BLOCKED: {msg}")

        current_text = text
        reasons = []
        final_decision = ShieldDecision.ALLOW

        for rule in self._shield_pipeline:
            result, updated_text = await rule.check(current_text, context)
            if result.decision == ShieldDecision.BLOCK:
                if self._shield_auditor:
                    self._shield_auditor.log(trace_id, ShieldDecision.BLOCK.value, [result.reason or rule.name], len(text))
                raise ValueError(f"Shield BLOCKED by {rule.name}: {result.reason}")
            elif result.decision == ShieldDecision.TRANSFORM:
                current_text = updated_text
                reasons.append(f"{rule.name} (transformed)")
                final_decision = ShieldDecision.TRANSFORM

        if self._shield_auditor:
            self._shield_auditor.log(trace_id, final_decision.value, reasons or ["clean"], len(text))

        return current_text

    async def protect_stream(self, text_stream: AsyncGenerator[str, None], context: Optional[dict] = None) -> AsyncGenerator[str, None]:
        """Shield protection for streaming outputs."""
        if not self.shield_config:
            raise RuntimeError("Shield mode requires shield_config in __init__")

        buffer = ""
        trace_id = str(uuid.uuid4())
        last_flush = time.monotonic()
        total_tokens = 0

        async for chunk in text_stream:
            buffer += chunk
            total_tokens += len(chunk)
            
            if self._shield_bucket and not await self._shield_bucket.consume(len(chunk)):
                if self._shield_auditor:
                    self._shield_auditor.log(trace_id, ShieldDecision.BLOCK.value, ["Rate Limit Exceeded"], total_tokens)
                raise ValueError("Shield BLOCKED: Rate Limit Exceeded")

            if total_tokens > self.shield_config.max_context_length:
                if self._shield_auditor:
                    self._shield_auditor.log(trace_id, ShieldDecision.BLOCK.value, ["Context Length Exceeded"], total_tokens)
                raise ValueError("Shield BLOCKED: Context Length Exceeded")

            now = time.monotonic()
            if (now - last_flush) >= self.shield_config.stream_flush_timeout or '\n' in chunk:
                try:
                    safe_chunk = await self.protect(buffer, context)
                    yield safe_chunk
                except ValueError as e:
                    yield f"\n\n[SHIELD INTERVENTION: {str(e)}]\n"
                    return
                finally:
                    buffer = ""
                    last_flush = time.monotonic()

        if buffer:
            try:
                safe_chunk = await self.protect(buffer, context)
                yield safe_chunk
            except ValueError as e:
                yield f"\n\n[SHIELD INTERVENTION: {str(e)}]\n"


# ===========================================================================
# SPECIALIZED SUBCLASSES: INPUT vs OUTPUT
# ===========================================================================

class LLMInputGuard(LLMGuard):
    """
    Specialized guardrail for validating **user inputs / prompts**.

    Inherits all scanning engines from LLMGuard but defaults to
    input-oriented checks:
      - Prompt injection detection (scan_ast)
      - Secret / API key leak prevention (scan_output regex checks)
      - Malicious Python/Shell/SQL code detection (scan_ast)
      - Invisible text / trojan source detection

    Output-oriented scanners (competitors, refusal detection, reading time)
    are disabled by default but can be re-enabled via constructor kwargs.

    Quick start::

        guard = LLMInputGuard()
        # Check for prompt injections and malicious code
        issues = guard.scan_ast(user_prompt)
        # Check for leaked secrets in user text
        decision = guard.guard_input(user_prompt)
    """

    def __init__(self, **kwargs):
        # Input-oriented defaults
        defaults = dict(
            enable_sensitive=False,       # PII masking is output concern
            enable_secrets=True,          # Catch user-leaked API keys
            enable_regex=True,            # Custom regex still useful
            enable_banned_substrings=True, # Banned words in input
            enable_malicious_urls=True,   # Suspicious URLs in prompts
            enable_url_reachability=False,
            enable_competitors=False,     # Competitors are output concern
            enable_json_validation=False, # JSON validation is output concern
            enable_reading_time=False,    # Reading time is output concern
            enable_invisible_text=True,   # Trojan source in input
            enable_refusal_detection=False, # Refusal is output concern
            provider_name="input-guard",
        )
        defaults.update(kwargs)
        super().__init__(**defaults)

    def guard_input(self, text: str, *, policy=None, raise_on_block=None, extra=None):
        """
        High-level convenience method for input validation.

        Runs both:
          1. AST-based scan (prompt injection, malicious code, secret leaks)
          2. Policy-driven regex scan (credentials, destructive commands)

        Returns a GuardDecision with combined results.
        """
        # AST scan for prompt injection and code analysis
        ast_issues = self.scan_ast(text)

        # Policy-driven regex scan
        decision = self.guard_output(
            text,
            policy=policy or self._policy,
            raise_on_block=raise_on_block,
            extra=extra,
        )

        # Merge AST issues into the decision
        if ast_issues:
            ast_reasons = [f"[AST] {issue.text}" for issue in ast_issues]
            combined_reasons = list(decision.reasons) + ast_reasons
            max_score = max(decision.score, 0.9) if ast_issues else decision.score
            action = self._policy.action_for_score(max_score, self.GuardType.PROMPT)

            return self.GuardDecision(
                allowed=action != self.PolicyAction.BLOCK,
                score=round(max_score, 4),
                reasons=combined_reasons,
                safe_output=decision.safe_output,
                warned=action == self.PolicyAction.WARN,
                scan_results=decision.scan_results,
                action=action,
            )

        return decision


class LLMOutputGuard(LLMGuard):
    """
    Specialized guardrail for validating **LLM-generated outputs**.

    Inherits all scanning engines from LLMGuard but defaults to
    output-oriented checks:
      - PII / sensitive data masking
      - Competitor mention blocking
      - Credential leak detection in responses
      - Destructive command / shellcode / ransomware detection
      - System prompt echo / injection echo detection
      - Refusal detection
      - Reading time limits
      - Invisible text / trojan source detection

    Input-oriented scanners (prompt injection AST) are still available
    via scan_ast() but are not run by default in guard() calls.

    Quick start::

        guard = LLMOutputGuard()
        # Scan and redact LLM output
        decision = guard.guard(model_response)
        # Or use the chain scanner
        sanitized, valid, scores, trail = guard.scan(prompt, output)
    """

    def __init__(self, **kwargs):
        # Output-oriented defaults
        defaults = dict(
            enable_sensitive=True,        # PII masking
            enable_secrets=True,          # Credential leak detection
            enable_regex=True,            # Custom regex patterns
            enable_banned_substrings=True, # Banned substrings
            enable_malicious_urls=True,   # Suspicious URLs in output
            enable_url_reachability=False,
            enable_competitors=False,     # Off by default, enable with competitors=[]
            enable_json_validation=False,
            enable_reading_time=False,
            enable_invisible_text=True,   # Invisible text in output
            enable_refusal_detection=False,
            provider_name="output-guard",
        )
        defaults.update(kwargs)
        super().__init__(**defaults)

    def guard(self, text, *, policy=None, raise_on_block=None, extra=None):
        """
        Overrides base guard to combine chain-based scanners (BanCompetitors, etc.)
        with the regex-based scanners.
        """
        import time as _time
        active_policy = policy or self._policy
        start = _time.perf_counter()
        
        # 1. Regex scan
        try:
            scan = LLMGuard.scan_and_redact(text, active_policy)
        except Exception as exc:
            raise self.GuardError(guard_name="output_guard", message=str(exc), original_error=exc) from exc

        # 2. Chain scan (runs Competitors, PII masking, JSON repair, etc)
        sanitized, valid, scores, trail = self.scan(prompt="N/A", output=scan.safe_output or text)

        # Merge results
        if not valid:
            chain_reasons = [f"Output violated {k}" for k, v in scores.items() if v >= 1.0]
            if not chain_reasons:
                chain_reasons = ["Output blocked by chain scanner"]
            
            combined_reasons = list(scan.reasons) + chain_reasons
            max_score = 1.0
            safe_out = None
        else:
            combined_reasons = scan.reasons
            max_score = scan.score
            safe_out = sanitized if sanitized != text else (scan.safe_output or text)

        action = active_policy.action_for_score(max_score, self.GuardType.OUTPUT)
        decision = self.GuardDecision(
            allowed=action != self.PolicyAction.BLOCK,
            score=round(max_score, 4),
            reasons=combined_reasons,
            safe_output=safe_out,
            warned=action == self.PolicyAction.WARN,
            scan_results=[scan],
            action=action,
        )

        elapsed_ms = (_time.perf_counter() - start) * 1000
        self.log_decision(decision, policy=active_policy, duration_ms=elapsed_ms, extra=extra)

        # Check raise
        should_raise = raise_on_block if raise_on_block is not None else active_policy.raise_on_block
        if not decision.allowed and should_raise:
            raise self.OutputBlockedError(reasons=decision.reasons, score=decision.score, output_snippet=text[:120], decision=decision, policy_name=active_policy.name)
            
        return decision


# ===========================================================================
# MODULE-LEVEL CONVENIENCE FUNCTION
# ===========================================================================

def scan_output(guard: LLMGuard, prompt: str, output: str, fail_fast: Optional[bool] = None) -> Tuple[str, bool, Dict[str, float], List[LLMGuard.AuditEntry]]:
    """Functional wrapper that mirrors llm_guard.scan_output semantics."""
    if fail_fast is not None:
        previous = guard.fail_fast
        guard.fail_fast = fail_fast
        try:
            return guard.scan(prompt, output)
        finally:
            guard.fail_fast = previous
    return guard.scan(prompt, output)


