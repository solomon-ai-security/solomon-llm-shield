from __future__ import annotations
from typing import *
import re, json, logging, ast, math, hmac, hashlib, sqlite3, time, uuid, asyncio
from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass, field, asdict


# ASYNC SHIELD SUBSYSTEMS (from LLMSecureOutputShield)
# ===========================================================================

class ShieldDecision(Enum):
    """Decision outcome for async shield guardrails."""
    ALLOW = "allow"
    BLOCK = "block"
    TRANSFORM = "transform"


@dataclass
class GuardrailResult:
    """Per-guardrail check result for async shield pipeline."""
    decision: ShieldDecision
    reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ShieldConfig:
    """Configuration for async realtime shield mode.

    Attributes:
        secret_key: Master key for HMAC operations and audit chain.
        db_path: Path to SQLite audit database.
        tpm_limit: Tokens-per-minute rate limit (DoS protection).
        grounding_threshold: n-gram overlap threshold for hallucination check.
        entropy_threshold: Shannon entropy threshold for detecting encoded secrets.
        stream_flush_timeout: Max seconds to buffer streaming chunks.
        max_context_length: Hard output-length cap to prevent OOM.
        canary_patterns: List of canary token strings to watch for.
    """
    secret_key: str
    db_path: str = "enterprise_shield.db"
    tpm_limit: int = 15000
    grounding_threshold: float = 0.35
    entropy_threshold: float = 4.3
    stream_flush_timeout: float = 0.5
    max_context_length: int = 100000
    canary_patterns: List[str] = field(default_factory=list)


class TokenBucket:
    """Async rate limiter for Denial of Service protection.

    Uses a token-bucket algorithm with continuous refill.
    Thread-safe via asyncio.Lock.
    """
    def __init__(self, capacity: int, fill_rate: float):
        self.capacity = float(capacity)
        self.fill_rate = fill_rate
        self.tokens = float(capacity)
        self.last_fill = time.monotonic()
        self._lock = asyncio.Lock()

    async def consume(self, amount: int) -> bool:
        async with self._lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.last_fill) * self.fill_rate)
            self.last_fill = now
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False


class AsyncNativeAuditor:
    """Zero-latency auditor with tamper-proof Merkle chain.

    Writes audit entries to SQLite asynchronously via a background
    worker task.  Each row is chained to the previous via HMAC-SHA256,
    making any post-hoc tampering detectable.
    """
    def __init__(self, db_path: str, secret_key: str):
        self.db_path = db_path
        self.secret_key = secret_key.encode()
        self._queue: asyncio.Queue = asyncio.Queue()
        self._worker_task: Optional[asyncio.Task] = None
        self._init_db_sync()

    def _init_db_sync(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    trace_id TEXT, timestamp TEXT, decision TEXT,
                    reasons TEXT, original_len INTEGER,
                    prev_hash TEXT, current_hash TEXT
                )
            """)

    def _hash(self, payload: str) -> str:
        return hmac.new(self.secret_key, payload.encode(), hashlib.sha256).hexdigest()

    def _sync_write(self, item: dict):
        """Synchronous write called via asyncio.to_thread."""
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cur = conn.cursor()
            cur.execute("SELECT current_hash FROM audit_log ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            prev_hash = row[0] if row else "0" * 64

            ts = datetime.now(timezone.utc).isoformat()
            payload = f"{item['trace_id']}|{ts}|{item['decision']}|{prev_hash}"
            curr_hash = self._hash(payload)

            cur.execute("""
                INSERT INTO audit_log (trace_id, timestamp, decision, reasons, original_len, prev_hash, current_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (item['trace_id'], ts, item['decision'], item['reasons'], item['orig_len'], prev_hash, curr_hash))
            conn.commit()

    async def _worker(self):
        while True:
            item = await self._queue.get()
            if item is None:
                self._queue.task_done()
                break
            try:
                await asyncio.to_thread(self._sync_write, item)
            except Exception as e:
                logging.error(f"Audit DB Write Failed: {e}")
            finally:
                self._queue.task_done()

    def start(self):
        self._worker_task = asyncio.create_task(self._worker())

    async def stop(self):
        if self._worker_task:
            await self._queue.put(None)
            await self._worker_task

    def log(self, trace_id: str, decision: str, reasons: list, orig_len: int):
        self._queue.put_nowait({
            "trace_id": trace_id, "decision": decision,
            "reasons": "; ".join(reasons), "orig_len": orig_len
        })


class ShieldGuardrail:
    """Base class for async shield guardrail rules."""
    def __init__(self, name: str):
        self.name = name

    async def check(self, text: str, context: Optional[dict] = None) -> Tuple[GuardrailResult, str]:
        raise NotImplementedError


class CanaryGuardrail(ShieldGuardrail):
    """Detects canary token leaks — strings injected into system prompts
    to verify the model does not echo them."""
    def __init__(self, patterns: List[str]):
        super().__init__("canary_leak")
        self.patterns = patterns

    async def check(self, text: str, context: Optional[dict] = None) -> Tuple[GuardrailResult, str]:
        for pattern in self.patterns:
            if pattern in text:
                return GuardrailResult(ShieldDecision.BLOCK, "Canary Token Leaked"), text
        return GuardrailResult(ShieldDecision.ALLOW), text


class EntropyGuardrail(ShieldGuardrail):
    """Uses Shannon entropy to detect high-density secret strings that
    escape traditional regex patterns."""
    def __init__(self, threshold: float):
        super().__init__("shannon_entropy")
        self.threshold = threshold

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob)

    async def check(self, text: str, context: Optional[dict] = None) -> Tuple[GuardrailResult, str]:
        for word in text.split():
            if len(word) > 16 and self._calculate_entropy(word) > self.threshold:
                return GuardrailResult(ShieldDecision.BLOCK, f"High Entropy Secret: {word[:4]}***"), text
        return GuardrailResult(ShieldDecision.ALLOW), text


class ShieldSecurityPIIGuardrail(ShieldGuardrail):
    """Combined injection detection and PII masking guardrail.

    Unlike the regex-only checks in LLMOutputGuard, this guardrail
    replaces detected PII with deterministic HMAC-based tokens so that
    the same input always produces the same pseudonym.
    """
    def __init__(self, secret_key: str):
        super().__init__("security_and_pii")
        self.secret_key = secret_key.encode()
        self._patterns = {
            "SEC_INJECTION": re.compile(r"(ignore|repeat|bypass|reveal).*(instruction|system|prompt)", re.I),
            "SEC_CODE": re.compile(r"\b(eval|exec|os\.system|subprocess|rm\s+-rf)\b"),
            "PII_EMAIL": re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
            "PII_KEY": re.compile(r"(sk-[a-zA-Z0-9]{48}|ghp_[a-zA-Z0-9]{36})"),
        }

    async def check(self, text: str, context: Optional[dict] = None) -> Tuple[GuardrailResult, str]:
        new_text = text
        found_pii = []

        for name, pat in self._patterns.items():
            if name.startswith("SEC_") and pat.search(text):
                return GuardrailResult(ShieldDecision.BLOCK, f"Policy Violation: {name}"), text

            if name.startswith("PII_"):
                for m in set(pat.findall(text)):
                    found_pii.append(name)
                    h = hmac.new(self.secret_key, m.encode(), hashlib.sha256).hexdigest()[:6]
                    new_text = new_text.replace(m, f"[{name}_{h}]")

        if found_pii:
            return GuardrailResult(ShieldDecision.TRANSFORM, f"Masked: {found_pii}"), new_text
        return GuardrailResult(ShieldDecision.ALLOW), new_text


class GroundingGuardrail(ShieldGuardrail):
    """Anti-hallucination check via n-gram overlap between output and
    provided RAG context.  Blocks outputs that diverge too far from
    the retrieval context."""
    def __init__(self, threshold: float):
        super().__init__("anti_hallucination")
        self.threshold = threshold

    async def check(self, text: str, context: Optional[dict] = None) -> Tuple[GuardrailResult, str]:
        rag_context = context.get("rag_context") if context else None
        if not rag_context:
            return GuardrailResult(ShieldDecision.ALLOW), text

        out_ng = {w[i:i+3] for w in re.findall(r'\w{3,}', text.lower()) for i in range(len(w)-2)}
        ctx_ng = {w[i:i+3] for w in re.findall(r'\w{3,}', rag_context.lower()) for i in range(len(w)-2)}

        if out_ng and len(out_ng.intersection(ctx_ng)) / len(out_ng) < self.threshold:
            return GuardrailResult(ShieldDecision.BLOCK, "Factual Grounding Failure (Hallucination)"), text
        return GuardrailResult(ShieldDecision.ALLOW), text



