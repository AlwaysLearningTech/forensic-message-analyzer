"""
AI-powered analysis module for forensic message analyzer. Uses Anthropic Claude (via Azure AI or direct API) for advanced threat detection and content analysis in family law proceedings.

Supports two processing modes:
- Batch API (default): Submits all requests asynchronously at 50% cost discount. Prompt caching further reduces costs on repeated system prompts.
- Synchronous: Real-time processing with rate limiting (for development/testing).
"""

import os
import json
import time
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import pandas as pd
import logging
from dataclasses import dataclass

try:
    from anthropic import Anthropic, APIConnectionError, APITimeoutError
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    APIConnectionError = type("APIConnectionError", (Exception,), {})
    APITimeoutError = type("APITimeoutError", (Exception,), {})

from ..config import Config
from ..forensic_utils import ForensicRecorder
from ..utils.pricing import get_pricing, get_token_overhead

logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiter for synchronous API calls to respect token limits."""

    def __init__(self, max_requests_per_minute: int = 40, max_tokens_per_minute: int = 25000):
        self.max_requests_per_minute = max_requests_per_minute
        self.max_tokens_per_minute = max_tokens_per_minute
        self.request_times: List[float] = []
        self.token_counts: List[Tuple[float, int]] = []

    def wait_if_needed(self, estimated_tokens: int = 0):
        current_time = time.time()

        # Clean old entries (older than 60 seconds)
        self.request_times = [t for t in self.request_times if current_time - t < 60]
        self.token_counts = [(t, c) for t, c in self.token_counts if current_time - t < 60]

        # Check request limit
        if len(self.request_times) >= self.max_requests_per_minute:
            sleep_time = 60 - (current_time - self.request_times[0]) + 0.1
            if sleep_time > 0:
                time.sleep(sleep_time)

        # Check token limit
        current_tokens = sum(c for _, c in self.token_counts)
        if current_tokens + estimated_tokens > self.max_tokens_per_minute and self.token_counts:
            sleep_time = 60 - (current_time - self.token_counts[0][0]) + 0.1
            if sleep_time > 0:
                time.sleep(sleep_time)

        # Record this request
        self.request_times.append(current_time)
        self.token_counts.append((current_time, estimated_tokens))


def _extract_json(text: str) -> dict:
    """Extract JSON from a response that may contain markdown code fences."""
    # Strip markdown code fences if present
    cleaned = re.sub(r'^```(?:json)?\s*', '', text.strip())
    cleaned = re.sub(r'\s*```$', '', cleaned)
    return json.loads(cleaned)


def _sanitize_endpoint(endpoint: Optional[str]) -> str:
    """Return an endpoint safe to write to forensic logs.

    Strips embedded userinfo (``https://user:token@host``) and any query string that might carry credentials, leaving scheme + host + path.
    """
    if not endpoint:
        return "api.anthropic.com"
    try:
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(endpoint)
        # Drop userinfo by taking only the hostname[:port]
        netloc = parts.hostname or ""
        if parts.port:
            netloc = f"{netloc}:{parts.port}"
        # Drop query and fragment in case they carry tokens
        return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    except Exception:
        return "<redacted>"


class AIAnalyzer:
    """
    AI-powered analysis using Anthropic Claude Opus.

    Supports two processing modes:
    - Batch API (default): Submits all requests asynchronously at 50% cost discount.
      Uses prompt caching for additional savings on repeated system prompts.
    - Synchronous: Processes requests one at a time with rate limiting.
    """

    def __init__(self, forensic_recorder: Optional[ForensicRecorder] = None, config: Optional[Config] = None):
        self.forensic = forensic_recorder or ForensicRecorder()

        # Get configuration from provided or fresh config instance
        _config = config if config is not None else Config()
        self.api_key = _config.ai_api_key
        self.endpoint = _config.ai_endpoint
        # Two-model setup: AI_TAGGING_MODEL drives per-message classification, AI_SUMMARY_MODEL drives the executive narrative. If only one is set it is used for both roles. The legacy single AI_MODEL env var was removed in 4.4.0; configure both batch and summary models explicitly.
        self.batch_model = (
            getattr(_config, 'ai_tagging_model', None)
            or getattr(_config, 'ai_summary_model', None)
            or 'claude-haiku-4-5'
        )
        self.summary_model = (
            getattr(_config, 'ai_summary_model', None)
            or getattr(_config, 'ai_tagging_model', None)
            or self.batch_model
        )
        # Used by single-message helpers and back-compat callers; defaults to summary.
        self.model = self.summary_model

        # Token limits from config
        self.max_tokens_per_request = getattr(_config, 'max_tokens_per_request', 4096)
        self.max_tokens_per_minute = getattr(_config, 'tokens_per_minute', 25000)
        self.max_requests_per_minute = getattr(_config, 'max_requests_per_minute', 40)
        self.use_batch_api = getattr(_config, 'use_batch_api', True)

        # Set to True the moment a batch is created on Anthropic's side. The outer analyze_messages() reads this to decide whether falling back to the synchronous path would double-bill — once a batch is in flight, never re-submit; raise so the caller can resume via --resume-batch.
        self._batch_submitted = False
        self._last_batch_id: Optional[str] = None

        # Initialize Anthropic client if credentials available
        self.client = None

        if AI_AVAILABLE and self.api_key:
            try:
                client_kwargs = {"api_key": self.api_key}

                # If an endpoint is configured, use it as base_url; otherwise force the default to prevent env vars (e.g. VS Code's ANTHROPIC_BASE_URL) from hijacking requests.
                if self.endpoint:
                    base = self.endpoint.rstrip("/")
                    client_kwargs["base_url"] = base
                else:
                    client_kwargs["base_url"] = "https://api.anthropic.com"

                self.client = Anthropic(**client_kwargs)

                # Initialize rate limiter (used in synchronous mode)
                self.rate_limiter = RateLimiter(
                    max_requests_per_minute=self.max_requests_per_minute,
                    max_tokens_per_minute=self.max_tokens_per_minute,
                )

                self.forensic.record_action(
                    "ai_analyzer_initialized",
                    f"Anthropic Claude analyzer initialized (batch={self.batch_model}, summary={self.summary_model})",
                    {
                        "model": self.model,
                        "tagging_model": self.batch_model,
                        "summary_model": self.summary_model,
                        "endpoint": _sanitize_endpoint(self.endpoint),
                        "batch_api": self.use_batch_api,
                    },
                )
            except Exception as e:
                self.forensic.record_action(
                    "ai_init_error",
                    f"Failed to initialize Anthropic Claude: {str(e)}",
                    {"error": str(e)},
                )
                self.client = None
        else:
            self.forensic.record_action(
                "ai_analyzer_disabled",
                "Claude analyzer disabled - no API key configured or anthropic package missing",
            )

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """Rough token count (~4 characters per token for English)."""
        return max(1, len(text) // 4)

    @staticmethod
    def _format_messages_for_summary(
        messages: List[Dict], max_tokens: int = 150_000
    ) -> Tuple[str, int, bool]:
        """Format messages chronologically for the executive summary prompt.

        Sorts by timestamp and formats each message as a single line. If the total exceeds *max_tokens* (estimated), applies middle-truncation: keeps the earliest and latest messages (split evenly) and inserts a marker noting how many were omitted.

        Returns:
            (formatted_text, message_count_included, was_truncated)
        """
        if not messages:
            return "", 0, False

        sorted_msgs = sorted(messages, key=lambda m: m.get('timestamp', ''))

        def _fmt(m: Dict) -> str:
            ts = m.get('timestamp', 'unknown')
            sender = m.get('sender_name', m.get('sender', 'Unknown'))
            source = m.get('source', 'unknown')
            content = m.get('content', m.get('text', ''))
            return f"[{ts}] {sender} ({source}): {content}"

        lines = [_fmt(m) for m in sorted_msgs]
        full_text = "\n".join(lines)

        est_tokens = max(1, len(full_text) // 4)
        if est_tokens <= max_tokens:
            return full_text, len(lines), False

        # Middle-truncation: keep first N and last N that fit within budget
        half_budget = max_tokens // 2
        head_lines: list[str] = []
        head_tokens = 0
        for line in lines:
            t = max(1, len(line) // 4)
            if head_tokens + t > half_budget:
                break
            head_lines.append(line)
            head_tokens += t

        tail_lines: list[str] = []
        tail_tokens = 0
        for line in reversed(lines):
            t = max(1, len(line) // 4)
            if tail_tokens + t > half_budget:
                break
            tail_lines.insert(0, line)
            tail_tokens += t

        omitted = len(lines) - len(head_lines) - len(tail_lines)
        marker = f"\n[... {omitted:,} messages omitted for context window limits ...]\n"
        truncated_text = "\n".join(head_lines) + marker + "\n".join(tail_lines)
        included = len(head_lines) + len(tail_lines)
        return truncated_text, included, True

    # ------------------------------------------------------------------
    # System prompt (shared across all analysis calls)
    # ------------------------------------------------------------------

    _SYSTEM_PROMPT = (
        "You are a forensic analyst specializing in digital communications "
        "for family law proceedings (divorce, custody, domestic relations) "
        "under Washington State law (RCW Title 26).\n\n"

        "LEGAL FRAMEWORK\n"
        "Your analysis must map findings to factors courts consider:\n"
        "- RCW 26.09.187: Best interests of the child — emotional ties, "
        "parental capacity, history of abuse, stability, cooperation in co-parenting.\n"
        "- RCW 26.09.191: Limitations on residential time — domestic violence, "
        "sexual abuse, neglect, substance abuse, withholding the child.\n"
        "- RCW 26.50 (DVPA): Domestic violence includes physical harm, bodily injury, "
        "assault, stalking, and also fear of imminent physical harm.\n\n"

        "COERCIVE CONTROL FRAMEWORK\n"
        "Analyze messages for patterns of coercive control (Evan Stark model), "
        "which courts increasingly recognize as abuse even without physical violence:\n"
        "- **Intimidation and threats**: Direct or veiled threats to safety, custody, "
        "finances, reputation, or immigration status.\n"
        "- **Isolation**: Restricting contact with family, friends, or support services; "
        "monitoring movements; controlling access to transportation or communication.\n"
        "- **Microregulation**: Dictating daily routines, appearance, parenting, "
        "spending, or social interactions to an unreasonable degree.\n"
        "- **Degradation**: Name-calling, humiliation, disparagement (especially "
        "in front of children), weaponizing insecurities.\n"
        "- **Economic abuse**: Controlling finances, withholding support, "
        "sabotaging employment, creating financial dependence.\n"
        "- **Gaslighting**: Denying documented events, rewriting history, "
        "questioning the other party's memory or sanity.\n"
        "- **Using children as instruments of control**: Parental alienation, "
        "undermining the other parent's authority, using custody or visitation "
        "as leverage, interrogating children about the other parent.\n\n"

        "BEHAVIORAL ANALYSIS\n"
        "Analyze the provided conversation with specific focus on:\n"
        "1. **Sentiment and emotional escalation**: Track emotional intensity over the batch. "
        "Note shifts from calm to hostile. Measure on 0-10 scale (0=calm, 10=crisis-level).\n"
        "2. **Threats and concerning behavior**: Direct or veiled threats to physical safety, "
        "threats regarding children/custody, financial coercion, harassment, stalking, "
        "parental alienation language. Classify each as direct, veiled, or conditional.\n"
        "3. **Temporal patterns**: Note timing indicators — late-night/early-morning "
        "message barrages, rapid-fire messaging demanding immediate responses, "
        "silence followed by escalation. Report if the batch suggests these.\n"
        "4. **Reactive vs. initiating behavior**: When someone responds aggressively, "
        "note whether they appear to be reacting to sustained provocation. "
        "Do NOT score victim responses symmetrically with initiating abuse. "
        "Flag the pattern as 'reactive' and note the provoking context.\n"
        "5. **Key topics**: Child welfare, custody arrangements, financial matters, "
        "co-parenting, protective order compliance, substance references.\n"
        "6. **Risk indicators**: Escalation trajectories, safety concerns for children "
        "or adults, evidence of parental unfitness per RCW 26.09.191.\n\n"

        "ANALYSIS GUIDELINES\n"
        "- Provide objective, fact-based analysis suitable for court proceedings.\n"
        "- Use clinically precise language. Say 'verbal aggression' not 'disagreement'; "
        "'controlling demand' not 'request'; 'threat' not 'strong statement'.\n"
        "- Clearly distinguish direct observations from interpretations.\n"
        "- Include exact quotes that support each finding.\n"
        "- Assess severity: critical, high, medium, low.\n"
        "- For each threat, specify: direct/veiled/conditional, and the target "
        "(physical safety, custody, financial, emotional).\n"
        "- Consider the family law context: best interests of children, safety of parties.\n\n"

        "FORMAT\n"
        "Respond with valid JSON (no markdown fences) using this structure:\n"
        "{\n"
        '    "sentiment": {\n'
        '        "overall": "positive/neutral/negative",\n'
        '        "shifts": [{"from": "...", "to": "...", "trigger_quote": "..."}],\n'
        '        "intensity": 0-10,\n'
        '        "escalation_detected": true/false\n'
        "    },\n"
        '    "threats": {\n'
        '        "found": true/false,\n'
        '        "severity": "none/low/medium/high/critical",\n'
        '        "details": [{\n'
        '            "type": "direct/veiled/conditional",\n'
        '            "target": "physical_safety/custody/financial/emotional/reputation",\n'
        '            "quote": "exact message text",\n'
        '            "sender": "who said it",\n'
        '            "severity": "low/medium/high/critical",\n'
        '            "rcw_relevance": "e.g. RCW 26.09.191(2)(a)(iii) — history of domestic violence",\n'
        '            "recommended_action": "..."\n'
        '        }]\n'
        "    },\n"
        '    "coercive_control": {\n'
        '        "detected": true/false,\n'
        '        "patterns": [{\n'
        '            "type": "intimidation/isolation/microregulation/degradation/economic_abuse/gaslighting/using_children",\n'
        '            "quote": "exact message text",\n'
        '            "sender": "who said it",\n'
        '            "description": "clinical description of the pattern",\n'
        '            "severity": "low/medium/high/critical"\n'
        '        }]\n'
        "    },\n"
        '    "behavioral_patterns": {\n'
        '        "patterns": [{"type": "...", "description": "...", "severity": "...", '
        '"is_reactive": false}],\n'
        '        "anomalies": [{"description": "...", "concern_level": "...", '
        '"timestamp_context": "..."}]\n'
        "    },\n"
        '    "key_topics": [],\n'
        '    "risk_indicators": [{"indicator": "...", "severity": "...", '
        '"rcw_relevance": "...", "recommended_action": "..."}],\n'
        '    "notable_quotes": [{"quote": "...", "sender": "...", "significance": "...", '
        '"forensic_relevance": "why this matters legally"}]\n'
        "}"
    )

    def _cached_system_prompt(self) -> list:
        """Return system prompt as content blocks with prompt caching enabled.

        Prompt caching avoids re-processing the identical system prompt on every request. With the Batch API, this can reduce input token costs by up to 90% for the system prompt portion across all requests in the batch.
        """
        return [{
            "type": "text",
            "text": self._SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }]

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def analyze_messages(self, messages: List[Dict], batch_size: int = 50,
                         generate_summary: bool = True,
                         state_writer=None) -> Dict[str, Any]:
        """
        Analyze messages using Claude for advanced insights.

        Uses the Batch API by default (50% cost discount + prompt caching). Falls back to synchronous processing if batch API is disabled or fails BEFORE submission. Once a batch has been created on Anthropic's side, this method will re-raise rather than fall back — re-submitting would double-bill. Use ``ForensicAnalyzer.resume_ai_batch()`` (`run.py --resume-batch`) to recover an in-flight batch.

        Args:
            messages: List of message dictionaries
            batch_size: Number of messages per analysis request (default 50).
                        Larger values reduce system prompt overhead and cost.
            generate_summary: If True, generate executive summary after batch
                              processing. Set False for pre-review batch runs
                              where summary will be generated later.
            state_writer: Optional callable invoked after batch submission with
                          a dict of {batch_id, submitted_at, total_requests,
                          status}. Used by the pipeline to persist the batch id
                          to ``pipeline_state.json`` so a sleep/disconnect can
                          be recovered via --resume-batch. Called again with
                          ``status="ended"`` after results are merged so the
                          caller can clear the in-flight marker.

        Returns:
            Dictionary containing AI analysis results
        """
        if not self.client:
            self.forensic.record_action(
                "ai_analysis_skipped",
                "AI analysis skipped - Anthropic Claude not configured",
            )
            return self._empty_analysis()

        # Reset before each invocation; batch path sets True after batches.create.
        self._batch_submitted = False
        self._last_batch_id = None

        if self.use_batch_api:
            try:
                return self._analyze_messages_batch(messages, batch_size,
                                                    generate_summary=generate_summary,
                                                    state_writer=state_writer)
            except Exception as e:
                if self._batch_submitted:
                    # Batch is already running (or completed) on Anthropic's side. NEVER fall back to sync — that re-submits the same work at full price. The batch_id is in pipeline_state.json; user recovers via `python3 run.py --resume-batch`.
                    logger.error(
                        f"Batch API failed AFTER submission (batch_id={self._last_batch_id}): {e}"
                    )
                    logger.error(
                        f"Batch is still running on Anthropic — recover with: python3 run.py --resume-batch"
                    )
                    self.forensic.record_action(
                        "batch_api_post_submit_failure",
                        f"Batch {self._last_batch_id} failed after submission — NOT falling back to sync to avoid double billing: {str(e)}",
                        {"error": str(e), "batch_id": self._last_batch_id},
                    )
                    raise
                logger.warning(f"Batch API failed (pre-submission), falling back to synchronous: {e}")
                self.forensic.record_action(
                    "batch_api_fallback",
                    f"Batch API unavailable, using synchronous mode: {str(e)}",
                    {"error": str(e)},
                )

        return self._analyze_messages_sync(messages, batch_size,
                                            generate_summary=generate_summary)

    # ------------------------------------------------------------------
    # Batch API path (50% cost discount)
    # ------------------------------------------------------------------

    def _analyze_messages_batch(self, messages: List[Dict], batch_size: int,
                                generate_summary: bool = True,
                                state_writer=None) -> Dict[str, Any]:
        """
        Submit all analysis requests via the Anthropic Message Batches API.

        Benefits:
        - 50% cost discount on all token usage
        - Prompt caching reduces system prompt costs by up to 90%
        - No client-side rate limiting needed (handled server-side)
        - Up to 100,000 requests per batch

        Processing is asynchronous: requests are submitted in bulk,
        then we poll until the batch completes (typically under 1 hour).
        """
        analysis_results = self._init_analysis_results(len(messages))

        # Build all batch requests
        batch_requests = []
        for i in range(0, len(messages), batch_size):
            batch = messages[i:i + batch_size]
            batch_text = self._prepare_batch(batch)
            batch_requests.append({
                "custom_id": f"analysis_{i // batch_size}",
                "params": {
                    "model": self.batch_model,
                    "system": self._cached_system_prompt(),
                    "messages": [{"role": "user", "content": batch_text}],
                    "max_tokens": self.max_tokens_per_request,
                },
            })

        total_requests = len(batch_requests)

        # Pre-submission cost estimate based on token estimation. Apply tokenizer overhead multiplier for models (e.g. Opus 4.7) that use a new tokenizer producing more tokens for the same text.
        batch_overhead = get_token_overhead(self.batch_model)
        system_prompt_tokens = int(self._estimate_tokens(self._SYSTEM_PROMPT) * batch_overhead)
        est_input_tokens = int(sum(self._estimate_tokens(r["params"]["messages"][0]["content"]) for r in batch_requests) * batch_overhead)
        est_input_tokens += system_prompt_tokens * total_requests
        # Based on actual run data: avg ~1,600 output tokens per batch
        # (previous estimate of 385 was from billing aggregates that didn't match per-request data)
        est_output_tokens = total_requests * 1600

        # Batch API rates — fetched from Anthropic pricing page
        bp = get_pricing(self.batch_model, batch=True)
        message_input_tokens = est_input_tokens - (system_prompt_tokens * total_requests)
        cache_creation_cost = (system_prompt_tokens / 1_000_000) * bp['cache_write']
        cache_read_cost = (system_prompt_tokens * max(0, total_requests - 1) / 1_000_000) * bp['cache_read']
        message_cost = (message_input_tokens / 1_000_000) * bp['input']
        output_cost = (est_output_tokens / 1_000_000) * bp['output']
        est_cost = cache_creation_cost + cache_read_cost + message_cost + output_cost

        # Estimated summary call — scales with message volume. Assume ~60% of messages will be confirmed in review; actual cost shown at finalize.
        summary_overhead = get_token_overhead(self.summary_model)
        sp = get_pricing(self.summary_model)
        est_confirmed_tokens = int(message_input_tokens * 0.60 * summary_overhead) + 500  # preamble
        est_summary_output = 4096
        est_sync_cost = (
            (est_confirmed_tokens / 1_000_000) * sp['input']
            + (est_summary_output / 1_000_000) * sp['output']
        )
        est_total = est_cost + est_sync_cost

        print(
            f"    Submitting {total_requests} requests via Batch API (50% cost discount)...\n"
            f"    Estimated tokens: ~{est_input_tokens:,} input + ~{est_output_tokens:,} output\n"
            f"    Estimated batch cost: ~${est_cost:.2f} (with prompt caching)\n"
            f"    Estimated sync summary: ~${est_sync_cost:.4f} (assumes ~60% confirmed; actual cost shown at finalize)\n"
            f"    Estimated total: ~${est_total:.2f}"
        )

        self.forensic.record_action(
            "batch_api_submit",
            f"Submitting {total_requests} analysis requests via Batch API",
            {
                "total_requests": total_requests,
                "batch_size": batch_size,
                "total_messages": len(messages),
            },
        )

        # Submit the batch
        message_batch = self.client.messages.batches.create(requests=batch_requests)
        batch_id = message_batch.id
        self._batch_submitted = True
        self._last_batch_id = batch_id

        self.forensic.record_action(
            "batch_api_created",
            f"Batch {batch_id} created with {total_requests} requests",
            {"batch_id": batch_id},
        )

        # Persist the batch_id to pipeline_state.json IMMEDIATELY so a sleep/disconnect during polling can be recovered. Do this before any polling — the loop is the failure-prone part.
        if state_writer is not None:
            try:
                state_writer({
                    "batch_id": batch_id,
                    "submitted_at": datetime.now().isoformat(),
                    "total_requests": total_requests,
                    "status": "in_progress",
                })
            except Exception as e:
                logger.warning(f"Failed to persist batch_id to pipeline state: {e}")

        # Poll until ended; resilient to transient network errors.
        self._poll_until_ended(batch_id, total_requests)

        analysis_results = self._collect_batch_results(
            batch_id=batch_id,
            analysis_results=analysis_results,
            total_requests=total_requests,
            generate_summary=generate_summary,
            log_message_count=len(messages),
        )

        # Mark the in-flight batch as completed in pipeline_state.json. The caller (ai_batch.py) clears the block on the next save.
        if state_writer is not None:
            try:
                state_writer({
                    "batch_id": batch_id,
                    "submitted_at": datetime.now().isoformat(),
                    "total_requests": total_requests,
                    "status": "ended",
                })
            except Exception as e:
                logger.warning(f"Failed to mark batch ended in pipeline state: {e}")

        return analysis_results

    # ------------------------------------------------------------------
    # Batch helpers — also used by resume_batch
    # ------------------------------------------------------------------

    def _poll_until_ended(self, batch_id: str, total_requests: int):
        """Poll Anthropic until the batch reaches ``processing_status='ended'``.

        Resilient to transient network errors (sleep, brief disconnect). Catches
        ``APIConnectionError``/``APITimeoutError``/``OSError`` from the SDK and
        backs off up to 60s between retries; resets the interval on success.
        Honors the existing 4-hour ``max_wait`` ceiling. The 4-hour clock counts
        only successful retrievals — time spent offline does not advance it,
        so a long sleep simply pauses progress rather than tripping the timeout.
        """
        print(f"    Polling batch {batch_id}...")
        poll_interval = 10
        max_poll_interval = 60
        max_wait = 4 * 60 * 60
        elapsed = 0
        while True:
            try:
                message_batch = self.client.messages.batches.retrieve(batch_id)
            except (APIConnectionError, APITimeoutError, OSError) as e:
                logger.warning(
                    f"Batch poll network error ({type(e).__name__}: {e}); retrying in {poll_interval}s"
                )
                self.forensic.record_action(
                    "batch_api_polling_retry",
                    f"Polling network error for {batch_id}: {type(e).__name__}",
                    {"batch_id": batch_id, "error": str(e), "next_retry_seconds": poll_interval},
                )
                time.sleep(poll_interval)
                poll_interval = min(max_poll_interval, int(poll_interval * 1.5))
                continue

            counts = message_batch.request_counts
            completed = counts.succeeded + counts.errored + counts.canceled + counts.expired
            print(
                f"\r    Progress: {completed}/{total_requests} "
                f"({counts.succeeded} succeeded, {counts.errored} errored)",
                end="", flush=True,
            )

            if message_batch.processing_status == "ended":
                print()
                return message_batch

            if elapsed >= max_wait:
                print(
                    f"\n    Batch timed out after {max_wait // 3600} hours. "
                    f"Batch ID: {batch_id} — recover later with `python3 run.py --resume-batch`."
                )
                raise TimeoutError(
                    f"Batch {batch_id} did not complete within {max_wait // 3600} hours"
                )

            # Successful retrieve — reset to fast polling.
            poll_interval = 10
            time.sleep(poll_interval)
            elapsed += poll_interval

    def _collect_batch_results(self, batch_id: str, analysis_results: Dict[str, Any],
                               total_requests: int, generate_summary: bool,
                               log_message_count: int) -> Dict[str, Any]:
        """Iterate the results of an ended batch, merge them into analysis_results, and run post-processing (cost accounting, sentiment overall, dedup, summary).

        Shared by the initial run and ``resume_batch``.
        """
        # Process results
        total_input_tokens = 0
        total_output_tokens = 0
        cache_read_tokens = 0
        cache_creation_tokens = 0
        succeeded_count = 0
        errored_count = 0
        other_count = 0

        for result in self.client.messages.batches.results(batch_id):
            if result.result.type == "succeeded":
                succeeded_count += 1
                msg = result.result.message
                # Always count tokens, even if JSON parsing fails
                total_input_tokens += msg.usage.input_tokens
                total_output_tokens += msg.usage.output_tokens
                if hasattr(msg.usage, 'cache_read_input_tokens'):
                    cache_read_tokens += msg.usage.cache_read_input_tokens or 0
                if hasattr(msg.usage, 'cache_creation_input_tokens'):
                    cache_creation_tokens += msg.usage.cache_creation_input_tokens or 0
                try:
                    batch_analysis = _extract_json(msg.content[0].text)
                    self._merge_analysis(analysis_results, batch_analysis)
                    analysis_results["processing_stats"]["batches_processed"] += 1
                except Exception as e:
                    analysis_results["processing_stats"]["errors"].append(
                        f"Parse error for {result.custom_id}: {str(e)}"
                    )
            elif result.result.type == "errored":
                errored_count += 1
                error_msg = str(getattr(result.result, 'error', 'Unknown error'))
                analysis_results["processing_stats"]["errors"].append(
                    f"API error for {result.custom_id}: {error_msg}"
                )
            else:
                # Handle expired, canceled, or other non-success results
                other_count += 1
                analysis_results["processing_stats"]["errors"].append(
                    f"Request {result.custom_id} {result.result.type} (not processed)"
                )

        analysis_results["processing_stats"]["api_calls"] = total_requests
        analysis_results["processing_stats"]["tokens_used"] = total_input_tokens + total_output_tokens
        analysis_results["processing_stats"]["input_tokens"] = total_input_tokens
        analysis_results["processing_stats"]["output_tokens"] = total_output_tokens
        analysis_results["processing_stats"]["cache_read_tokens"] = cache_read_tokens
        analysis_results["processing_stats"]["cache_creation_tokens"] = cache_creation_tokens
        analysis_results["processing_stats"]["batch_id"] = batch_id
        analysis_results["processing_stats"]["batch_api"] = True

        # Actual cost — model-aware batch pricing
        bp = get_pricing(self.batch_model, batch=True)
        # Note: cache_creation_tokens are a subset of input_tokens, so subtract them from uncached to avoid double-counting.
        uncached_input = total_input_tokens - cache_read_tokens - cache_creation_tokens
        estimated_cost = (
            (uncached_input / 1_000_000) * bp['input']
            + (cache_read_tokens / 1_000_000) * bp['cache_read']
            + (cache_creation_tokens / 1_000_000) * bp['cache_write']
            + (total_output_tokens / 1_000_000) * bp['output']
        )
        analysis_results["processing_stats"]["estimated_cost_usd"] = round(estimated_cost, 2)

        cache_info = ""
        if cache_read_tokens or cache_creation_tokens:
            cache_info = f" (cache: {cache_read_tokens:,} read, {cache_creation_tokens:,} written)"

        print(
            f"    Batch complete: {succeeded_count} succeeded, "
            f"{total_input_tokens:,} input + {total_output_tokens:,} output tokens"
            + cache_info
            + f"\n    Batch cost: ${estimated_cost:.2f}"
        )

        # Generate summary, risks, recommendations (synchronous API calls)
        # Skipped during pre-review batch runs; generated later in finalize.
        if generate_summary:
            analysis_results["conversation_summary"] = self._generate_summary(analysis_results)
            analysis_results["risk_indicators"] = self._identify_risks(analysis_results)
            analysis_results["recommendations"] = self._generate_recommendations(analysis_results)

        # Compute overall sentiment from accumulated per-batch directions
        scores = analysis_results.get("sentiment_analysis", {}).get("scores", [])
        if scores:
            # scores contains direction strings: "positive", "neutral", "negative"
            neg = sum(1 for s in scores if s == "negative")
            pos = sum(1 for s in scores if s == "positive")
            if neg > pos:
                analysis_results["sentiment_analysis"]["overall"] = "negative"
            elif pos > neg:
                analysis_results["sentiment_analysis"]["overall"] = "positive"
            else:
                analysis_results["sentiment_analysis"]["overall"] = "neutral"

        # Deduplicate key_topics
        seen_topics = set()
        unique_topics = []
        for topic in analysis_results.get("key_topics", []):
            t = str(topic).lower().strip()
            if t not in seen_topics:
                seen_topics.add(t)
                unique_topics.append(topic)
        analysis_results["key_topics"] = unique_topics

        # Deduplicate notable_quotes
        seen_quotes = set()
        unique_quotes = []
        for nq in analysis_results.get("notable_quotes", []):
            q = nq.get("quote", "").strip().lower() if isinstance(nq, dict) else str(nq).lower()
            if q and q not in seen_quotes:
                seen_quotes.add(q)
                unique_quotes.append(nq)
        analysis_results["notable_quotes"] = unique_quotes

        self.forensic.record_action(
            "batch_analysis_complete",
            f"Completed batch analysis of {log_message_count} messages",
            {
                "batch_id": batch_id,
                "total_requests": total_requests,
                "succeeded": succeeded_count,
                "errored": errored_count,
                "input_tokens": total_input_tokens,
                "output_tokens": total_output_tokens,
                "cache_read_tokens": cache_read_tokens,
                "cache_creation_tokens": cache_creation_tokens,
                "errors": len(analysis_results["processing_stats"]["errors"]),
                "risk_indicators_found": len(analysis_results["risk_indicators"]),
            },
        )

        return analysis_results

    # ------------------------------------------------------------------
    # Resume path — used when a previous run's polling was interrupted by
    # a sleep / disconnect / kill, but Anthropic kept processing the batch
    # server-side. Triggered via `python3 run.py --resume-batch`.
    # ------------------------------------------------------------------

    def resume_batch(self, batch_id: str, log_message_count: int,
                     generate_summary: bool = False,
                     state_writer=None) -> Dict[str, Any]:
        """Resume an in-flight batch by ID, poll until ended, and collect results.

        Args:
            batch_id: The Anthropic batch ID (e.g. ``msgbatch_01...``) returned
                from ``client.messages.batches.create`` in the original run.
            log_message_count: How many messages were originally submitted.
                Used only for ``analysis_results.total_messages_analyzed`` and
                forensic logging — does not affect result merging, which is
                keyed by the batch's own ``custom_id`` values.
            generate_summary: Match the original run's flag. The default
                (``False``) matches Phase 3 pre-review screening, where the
                executive summary runs later in finalize.
            state_writer: Optional callable; same shape as in
                ``analyze_messages``. Called with status="ended" after results
                are collected so the caller can clear ``ai_batch`` from
                ``pipeline_state.json``.
        """
        if not self.client:
            raise RuntimeError("AI analyzer client is not configured; cannot resume batch.")

        # Ask Anthropic for current status. retrieve() raises a 404 if the batch_id is wrong or expired (~29-day retention).
        batch_obj = self.client.messages.batches.retrieve(batch_id)
        total_requests = batch_obj.request_counts.processing + (
            batch_obj.request_counts.succeeded
            + batch_obj.request_counts.errored
            + batch_obj.request_counts.canceled
            + batch_obj.request_counts.expired
        )

        self.forensic.record_action(
            "batch_api_resumed",
            f"Resuming batch {batch_id} (status={batch_obj.processing_status})",
            {"batch_id": batch_id, "status": batch_obj.processing_status,
             "total_requests": total_requests},
        )

        if batch_obj.processing_status != "ended":
            print(f"    Batch {batch_id} still processing — resuming polling.")
            self._poll_until_ended(batch_id, total_requests)
        else:
            print(f"    Batch {batch_id} already ended — fetching results.")

        analysis_results = self._init_analysis_results(log_message_count)
        analysis_results = self._collect_batch_results(
            batch_id=batch_id,
            analysis_results=analysis_results,
            total_requests=total_requests,
            generate_summary=generate_summary,
            log_message_count=log_message_count,
        )

        if state_writer is not None:
            try:
                state_writer({
                    "batch_id": batch_id,
                    "submitted_at": datetime.now().isoformat(),
                    "total_requests": total_requests,
                    "status": "ended",
                })
            except Exception as e:
                logger.warning(f"Failed to mark batch ended in pipeline state: {e}")

        self.forensic.record_action(
            "batch_api_resume_completed",
            f"Resume completed for batch {batch_id}",
            {"batch_id": batch_id, "total_requests": total_requests},
        )

        return analysis_results

    # ------------------------------------------------------------------
    # Synchronous path (fallback / development)
    # ------------------------------------------------------------------

    def _analyze_messages_sync(self, messages: List[Dict], batch_size: int,
                               generate_summary: bool = True) -> Dict[str, Any]:
        """
        Analyze messages synchronously (one API call per batch).
        Used as fallback when Batch API is unavailable or disabled.
        """
        analysis_results = self._init_analysis_results(len(messages))

        try:
            for i in range(0, len(messages), batch_size):
                batch = messages[i:i + batch_size]

                batch_text = self._prepare_batch(batch)
                token_count = self._estimate_tokens(batch_text)

                self.rate_limiter.wait_if_needed(token_count)
                batch_analysis = self._analyze_batch(batch_text, batch)

                # Check for API errors (surfaced from _analyze_batch)
                if "_error" in batch_analysis:
                    analysis_results["processing_stats"]["errors"].append(
                        f"Batch {i // batch_size + 1}: {batch_analysis['_error']}"
                    )
                    analysis_results["processing_stats"]["api_calls"] += 1
                    continue

                self._merge_analysis(analysis_results, batch_analysis)

                # Track actual token usage from API response metadata
                metadata = batch_analysis.get("_metadata", {})
                actual_input = metadata.get("input_tokens", 0)
                actual_output = metadata.get("output_tokens", 0)

                analysis_results["processing_stats"]["batches_processed"] += 1
                analysis_results["processing_stats"]["tokens_used"] += actual_input + actual_output
                analysis_results["processing_stats"]["input_tokens"] = analysis_results["processing_stats"].get("input_tokens", 0) + actual_input
                analysis_results["processing_stats"]["output_tokens"] = analysis_results["processing_stats"].get("output_tokens", 0) + actual_output
                analysis_results["processing_stats"]["api_calls"] += 1

                self.forensic.record_action(
                    "ai_batch_analyzed",
                    f"Analyzed batch {i // batch_size + 1} of {(len(messages) + batch_size - 1) // batch_size}",
                    {
                        "batch_size": len(batch),
                        "tokens": token_count,
                        "batch_number": i // batch_size + 1,
                    },
                )

            if generate_summary:
                analysis_results["conversation_summary"] = self._generate_summary(analysis_results)
                analysis_results["risk_indicators"] = self._identify_risks(analysis_results)
                analysis_results["recommendations"] = self._generate_recommendations(analysis_results)

            # Compute overall sentiment from accumulated per-batch directions
            scores = analysis_results.get("sentiment_analysis", {}).get("scores", [])
            if scores:
                # scores contains direction strings: "positive", "neutral", "negative"
                neg = sum(1 for s in scores if s == "negative")
                pos = sum(1 for s in scores if s == "positive")
                if neg > pos:
                    analysis_results["sentiment_analysis"]["overall"] = "negative"
                elif pos > neg:
                    analysis_results["sentiment_analysis"]["overall"] = "positive"
                else:
                    analysis_results["sentiment_analysis"]["overall"] = "neutral"

            # Deduplicate key_topics
            seen_topics = set()
            unique_topics = []
            for topic in analysis_results.get("key_topics", []):
                t = str(topic).lower().strip()
                if t not in seen_topics:
                    seen_topics.add(t)
                    unique_topics.append(topic)
            analysis_results["key_topics"] = unique_topics

            # Deduplicate notable_quotes
            seen_quotes = set()
            unique_quotes = []
            for nq in analysis_results.get("notable_quotes", []):
                q = nq.get("quote", "").strip().lower() if isinstance(nq, dict) else str(nq).lower()
                if q and q not in seen_quotes:
                    seen_quotes.add(q)
                    unique_quotes.append(nq)
            analysis_results["notable_quotes"] = unique_quotes

            self.forensic.record_action(
                "ai_analysis_complete",
                f"Completed AI analysis of {len(messages)} messages",
                {
                    "total_messages": len(messages),
                    "batches": analysis_results["processing_stats"]["batches_processed"],
                    "tokens_used": analysis_results["processing_stats"]["tokens_used"],
                    "risk_indicators_found": len(analysis_results["risk_indicators"]),
                },
            )

        except Exception as e:
            self.forensic.record_action(
                "ai_analysis_error",
                f"Error during AI analysis: {str(e)}",
                {"error": str(e), "messages_processed": i if "i" in locals() else 0},
            )
            analysis_results["processing_stats"]["errors"].append(str(e))

        return analysis_results

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _init_analysis_results(self, total_messages: int) -> Dict[str, Any]:
        """Create the initial analysis results structure."""
        return {
            "generated_at": datetime.now().isoformat(),
            "total_messages": total_messages,
            "ai_model": self.model,
            "sentiment_analysis": {"scores": [], "overall": "neutral", "shifts": []},
            "threat_assessment": {"found": False, "details": []},
            "behavioral_patterns": {"patterns": [], "anomalies": []},
            "conversation_summary": "",
            "key_topics": [],
            "risk_indicators": [],
            "notable_quotes": [],
            "recommendations": [],
            "processing_stats": {
                "batches_processed": 0,
                "tokens_used": 0,
                "api_calls": 0,
                "errors": [],
            },
        }

    def _prepare_batch(self, messages: List[Dict]) -> str:
        """
        Prepare a batch of messages for AI analysis.
        Maintains forensic integrity by preserving original content.

        Args:
            messages: List of message dictionaries

        Returns:
            Formatted text for AI analysis
        """
        batch_text = "Analyze the following conversation for forensic investigation:\n\n"

        for msg in messages:
            timestamp = msg.get("timestamp", "Unknown time")
            sender = msg.get("sender", "Unknown")
            content = msg.get("content", "")
            source = msg.get("source", "")
            source_tag = f" ({source})" if source else ""

            batch_text += f"[{timestamp}] {sender}{source_tag}: {content}\n"

        return batch_text

    def _analyze_batch(self, batch_text: str, messages: List[Dict]) -> Dict[str, Any]:
        """
        Analyze a single batch of messages synchronously. Uses prompt caching on the system prompt.

        Args:
            batch_text: Formatted text of messages
            messages: Original message dictionaries

        Returns:
            Analysis results for the batch
        """
        if not self.client:
            return {}

        try:
            response = self.client.messages.create(
                model=self.model,
                system=self._cached_system_prompt(),
                messages=[{"role": "user", "content": batch_text}],
                max_tokens=self.max_tokens_per_request,
            )

            # Parse response
            result = _extract_json(response.content[0].text)

            # Add metadata for forensic tracking
            result["_metadata"] = {
                "model": self.model,
                "timestamp": datetime.now().isoformat(),
                "message_count": len(messages),
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            }

            return result

        except Exception as e:
            self.forensic.record_action(
                "ai_batch_error",
                f"Error analyzing batch: {str(e)}",
                {"error": str(e), "batch_size": len(messages)},
            )
            return {"_error": str(e)}

    def _merge_analysis(self, results: Dict, batch_analysis: Dict):
        """
        Merge batch analysis into overall results.

        Args:
            results: Overall analysis results
            batch_analysis: Analysis from a single batch
        """
        if not batch_analysis or "_error" in batch_analysis:
            return

        # Merge sentiment
        if "sentiment" in batch_analysis:
            if "sentiment_analysis" not in results:
                results["sentiment_analysis"] = {"scores": [], "overall": "neutral", "shifts": []}

            sentiment = batch_analysis["sentiment"]
            # Store the AI's overall direction (positive/neutral/negative) per batch, not just the intensity scale. Intensity (0-10) measures strength, not direction.
            batch_overall = sentiment.get("overall", "neutral")
            results["sentiment_analysis"]["scores"].append(batch_overall)

            # Track sentiment shifts
            if "shifts" in sentiment and sentiment["shifts"]:
                if "shifts" not in results["sentiment_analysis"]:
                    results["sentiment_analysis"]["shifts"] = []
                results["sentiment_analysis"]["shifts"].extend(sentiment["shifts"])

        # Merge threats
        if "threats" in batch_analysis:
            if "threat_assessment" not in results:
                results["threat_assessment"] = {"found": False, "details": []}

            if batch_analysis["threats"].get("found"):
                results["threat_assessment"]["found"] = True
                results["threat_assessment"]["details"].extend(
                    batch_analysis["threats"].get("details", [])
                )

        # Merge behavioral patterns
        if "behavioral_patterns" in batch_analysis:
            if "behavioral_patterns" not in results:
                results["behavioral_patterns"] = {"patterns": [], "anomalies": []}

            results["behavioral_patterns"]["patterns"].extend(
                batch_analysis["behavioral_patterns"].get("patterns", [])
            )
            results["behavioral_patterns"]["anomalies"].extend(
                batch_analysis["behavioral_patterns"].get("anomalies", [])
            )

        # Merge coercive control findings
        if "coercive_control" in batch_analysis:
            if "coercive_control" not in results:
                results["coercive_control"] = {"detected": False, "patterns": []}

            if batch_analysis["coercive_control"].get("detected"):
                results["coercive_control"]["detected"] = True
                results["coercive_control"]["patterns"].extend(
                    batch_analysis["coercive_control"].get("patterns", [])
                )

        # Merge key topics
        if "key_topics" in batch_analysis:
            results["key_topics"].extend(batch_analysis["key_topics"])

        # Merge risk indicators
        if "risk_indicators" in batch_analysis:
            results["risk_indicators"].extend(batch_analysis["risk_indicators"])

        # Merge notable quotes
        if "notable_quotes" in batch_analysis:
            results.setdefault("notable_quotes", []).extend(
                batch_analysis["notable_quotes"]
            )

    def generate_post_review_summary(
        self, ai_results: Dict, messages: List[Dict] = None
    ) -> Dict:
        """Generate executive summary, risks, and recommendations for existing batch results.

        Called during finalize (post-review) to add the narrative summary to AI batch results that were collected before manual review.

        Args:
            ai_results: AI analysis results from a previous batch run
                        (already stored in analysis_results['ai_analysis']).
            messages:   Optional list of message dicts to include in the
                        summary prompt. When provided, the AI receives the
                        actual conversation text for evidence-based narrative.

        Returns:
            The same dict with conversation_summary, risk_indicators,
            and recommendations populated.
        """
        ai_results["conversation_summary"] = self._generate_summary(
            ai_results, messages=messages
        )
        ai_results["risk_indicators"] = self._identify_risks(ai_results)
        ai_results["recommendations"] = self._generate_recommendations(ai_results)
        return ai_results

    def _generate_summary(self, analysis: Dict, messages: List[Dict] = None) -> str:
        """Generate an executive summary of the AI analysis.

        When *messages* is provided the full conversation text is included in the prompt so the AI can write an evidence-based narrative with quoted excerpts and a timeline. When omitted, falls back to the legacy aggregate-statistics-only prompt for backward compatibility.

        Args:
            analysis: Complete analysis results dict.
            messages: Optional list of message dicts (with timestamp, sender_name,
                      source, content keys) to embed in the prompt.

        Returns:
            Summary text for legal review.
        """
        if not self.client or not analysis.get("sentiment_analysis"):
            return "AI analysis not available."

        try:
            # --- Build the statistics preamble (always included) ---
            stats_block = (
                f"Analysis Results:\n"
                f"- Total messages analyzed: {analysis['total_messages']}\n"
                f"- Threats found: {analysis.get('threat_assessment', {}).get('found', False)}\n"
                f"- Threat severity: {analysis.get('threat_assessment', {}).get('severity', 'none')}\n"
                f"- Risk indicators: {len(analysis.get('risk_indicators', []))}\n"
                f"- Key topics: {', '.join(str(t) for t in analysis.get('key_topics', [])[:5])}\n"
                f"- Behavioral anomalies: {len(analysis.get('behavioral_patterns', {}).get('anomalies', []))}\n"
            )

            # --- Evidence block (when messages are available) ---
            if messages:
                messages_text, msg_count, was_truncated = (
                    self._format_messages_for_summary(messages)
                )
                truncation_note = ""
                if was_truncated:
                    truncation_note = (
                        "\nNOTE: The message log was truncated to fit context limits. "
                        "The earliest and most recent messages are included; some "
                        "middle messages were omitted.\n"
                    )

                prompt = (
                    "Based on the following forensic analysis of digital communications "
                    "in a family law matter, provide an executive summary suitable "
                    "for review by the legal team (attorneys and paralegals, not technicians).\n\n"
                    f"{stats_block}"
                    f"- Messages included in this summary: {msg_count}\n\n"
                    f"{truncation_note}"
                    "The following messages were analyzed and confirmed as relevant to the case. "
                    "They are presented in chronological order.\n\n"
                    "--- BEGIN MESSAGES ---\n"
                    f"{messages_text}\n"
                    "--- END MESSAGES ---\n\n"
                    "Write 3-5 paragraphs for attorneys. Structure as:\n"
                    "1. Critical safety findings — quote specific messages by timestamp\n"
                    "2. Timeline of escalation or behavioral patterns\n"
                    "3. Custody-relevant observations\n"
                    "4. Recommended immediate actions\n\n"
                    "Use plain language, avoid technical jargon. Reference specific messages "
                    "by quoting relevant excerpts with their timestamps."
                )
            else:
                # Legacy aggregate-only prompt (no message text available)
                prompt = (
                    "Based on the following forensic analysis of digital communications "
                    "in a family law matter, provide a concise executive summary suitable "
                    "for review by the legal team (attorneys and paralegals, not technicians).\n\n"
                    "Focus on:\n"
                    "- Safety concerns for any party or children\n"
                    "- Evidence of threatening, controlling, or harassing behavior\n"
                    "- Custody-relevant behavioral patterns\n"
                    "- Recommended immediate actions\n\n"
                    f"{stats_block}\n"
                    "Write 2-3 paragraphs for attorneys. Lead with the most critical findings. "
                    "Use plain language, avoid technical jargon. Reference specific message "
                    "content where possible."
                )
                msg_count = 0
                was_truncated = False

            # Respect rate limits (sync call)
            token_count = self._estimate_tokens(prompt)
            self.rate_limiter.wait_if_needed(token_count)

            response = self.client.messages.create(
                model=self.summary_model,
                system=[{
                    "type": "text",
                    "text": (
                        "You are a forensic analyst preparing evidence summaries for "
                        "family law attorneys. Write clearly for a legal audience, not "
                        "a technical one."
                    ),
                    "cache_control": {"type": "ephemeral"},
                }],
                messages=[{"role": "user", "content": prompt}],
                max_tokens=4096,
            )

            # Track tokens from this sync API call (standard rates, not batch)
            summary_input = response.usage.input_tokens
            summary_output = response.usage.output_tokens
            sp = get_pricing(self.summary_model)
            sync_cost = (summary_input / 1_000_000) * sp['input'] + (summary_output / 1_000_000) * sp['output']

            stats = analysis.get("processing_stats", {})
            stats["input_tokens"] = stats.get("input_tokens", 0) + summary_input
            stats["output_tokens"] = stats.get("output_tokens", 0) + summary_output
            stats["tokens_used"] = stats.get("tokens_used", 0) + summary_input + summary_output
            stats["api_calls"] = stats.get("api_calls", 0) + 1
            stats["summary_sync_cost_usd"] = round(sync_cost, 4)
            stats["estimated_cost_usd"] = round(
                stats.get("estimated_cost_usd", 0) + sync_cost, 4
            )

            print(f"    Summary: {summary_input:,} input + {summary_output:,} output tokens (~${sync_cost:.4f})")

            if self.forensic:
                self.forensic.record_action(
                    "summary_generated",
                    f"Executive summary generated from {msg_count} messages",
                    {
                        "messages_included": msg_count,
                        "truncated": was_truncated,
                        "input_tokens": summary_input,
                        "output_tokens": summary_output,
                        "cost_usd": round(sync_cost, 4),
                        "model": self.summary_model,
                    },
                )

            return response.content[0].text

        except Exception as e:
            self.forensic.record_action(
                "summary_generation_error",
                f"Error generating summary: {str(e)}",
                {"error": str(e)},
            )
            return "Summary generation failed. See detailed analysis results."

    def _identify_risks(self, analysis: Dict) -> List[Dict]:
        """
        Identify and prioritize risk indicators from analysis.

        Args:
            analysis: Complete analysis results

        Returns:
            List of prioritized risk indicators
        """
        risks = []

        # Check threat assessment
        if analysis.get("threat_assessment", {}).get("found"):
            risks.append(
                {
                    "type": "threat",
                    "severity": "high",
                    "description": "Potential threats or harassment detected",
                    "details": analysis["threat_assessment"].get("details", []),
                }
            )

        # Check behavioral anomalies
        anomalies = analysis.get("behavioral_patterns", {}).get("anomalies", [])
        if anomalies:
            risks.append(
                {
                    "type": "behavioral",
                    "severity": "medium",
                    "description": f"Behavioral anomalies detected ({len(anomalies)} instances)",
                    "details": anomalies[:5],
                }
            )

        # Check sentiment shifts
        shifts = analysis.get("sentiment_analysis", {}).get("shifts", [])
        if len(shifts) > 3:
            risks.append(
                {
                    "type": "emotional_volatility",
                    "severity": "low",
                    "description": f"Significant emotional volatility ({len(shifts)} shifts detected)",
                    "details": shifts,
                }
            )

        # Deduplicate and sort by severity
        risk_levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        risks.sort(key=lambda x: risk_levels.get(x["severity"], 0), reverse=True)

        return risks

    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """
        Generate actionable recommendations based on analysis.

        Args:
            analysis: Complete analysis results

        Returns:
            List of recommendations for legal team
        """
        recommendations = []

        # Based on threats
        if analysis.get("threat_assessment", {}).get("found"):
            recommendations.append(
                "Priority review recommended: Potential threats detected. "
                "Review flagged messages and consider escalation to law enforcement if warranted."
            )

        # Based on risk indicators
        risk_count = len(analysis.get("risk_indicators", []))
        if risk_count > 5:
            recommendations.append(
                f"Comprehensive review needed: {risk_count} risk indicators identified. "
                "Consider detailed manual review of all flagged content."
            )
        elif risk_count > 0:
            recommendations.append(
                f"Targeted review suggested: {risk_count} risk indicators found. "
                "Focus on messages flagged with risk indicators."
            )

        # Based on behavioral patterns
        if analysis.get("behavioral_patterns", {}).get("anomalies"):
            recommendations.append(
                "Behavioral analysis recommended: Anomalous communication patterns detected. "
                "Review timeline and context around identified anomalies."
            )

        # General recommendations
        if not recommendations:
            recommendations.append(
                "Standard review protocol: No immediate concerns identified. "
                "Proceed with standard review procedures."
            )

        recommendations.append(
            "Maintain chain of custody: Ensure all evidence handling follows "
            "documented procedures for legal admissibility."
        )

        return recommendations

    def _empty_analysis(self) -> Dict[str, Any]:
        """Return empty analysis structure when AI is not available."""
        return {
            "generated_at": datetime.now().isoformat(),
            "total_messages": 0,
            "ai_model": "Not configured",
            "sentiment_analysis": {"scores": [], "overall": "neutral", "shifts": []},
            "threat_assessment": {"found": False, "details": []},
            "behavioral_patterns": {},
            "conversation_summary": "AI analysis not available - Anthropic Claude not configured.",
            "key_topics": [],
            "risk_indicators": [],
            "notable_quotes": [],
            "recommendations": ["Configure Anthropic Claude for advanced AI-powered analysis."],
            "processing_stats": {
                "batches_processed": 0,
                "tokens_used": 0,
                "api_calls": 0,
                "errors": ["Anthropic Claude not configured"],
            },
        }

    def analyze_single_message(self, message: Dict) -> Dict[str, Any]:
        """
        Analyze a single message for immediate assessment.
        Uses synchronous API (not batch) for real-time threat detection.

        Args:
            message: Message dictionary

        Returns:
            Quick analysis results
        """
        if not self.client:
            return {"analyzed": False, "reason": "AI not configured"}

        try:
            content = message.get("content", "")
            if not content:
                return {"analyzed": False, "reason": "No content"}

            prompt = (
                f'Quickly assess this message for immediate concerns:\n'
                f'"{content[:500]}"\n\n'
                'Return valid JSON (no markdown fences): '
                '{"threat_level": "none/low/medium/high", '
                '"concerns": [], "requires_review": true/false}'
            )

            # Estimate tokens and respect limits
            token_count = self._estimate_tokens(prompt)
            self.rate_limiter.wait_if_needed(token_count)

            response = self.client.messages.create(
                model=self.model,
                system="You are a threat assessment system. Be objective and precise.",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=256,
            )

            result = _extract_json(response.content[0].text)
            result["analyzed"] = True
            result["timestamp"] = datetime.now().isoformat()

            # Log if concerns found
            if result.get("threat_level") in ["medium", "high"]:
                self.forensic.record_action(
                    "ai_threat_detected",
                    f"AI detected {result['threat_level']} threat level",
                    {"message_id": message.get("message_id"), "concerns": result.get("concerns", [])},
                )

            return result

        except Exception as e:
            self.forensic.record_action(
                "single_message_analysis_error",
                f"Error analyzing single message: {str(e)}",
                {"error": str(e)},
            )
            return {"analyzed": False, "error": str(e)}

    def generate_analysis_report(self, analysis: Dict, output_path: Optional[Path] = None) -> Path:
        """
        Generate a comprehensive AI analysis report.

        Args:
            analysis: AI analysis results
            output_path: Optional output path

        Returns:
            Path to generated report
        """
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.config.analysis_dir() / f"ai_analysis_report_{timestamp}.json"

        # Add legal metadata
        report = {
            "report_type": "AI Analysis Report",
            "generated_at": datetime.now().isoformat(),
            "generator": f"AIAnalyzer with {self.model}",
            "legal_notice": (
                f"This AI analysis was generated using Anthropic {self.model}. "
                "Results are provided as supplementary analysis and should be reviewed "
                "by qualified personnel. AI-generated insights are probabilistic and "
                "should be validated against original evidence. This analysis maintains "
                "forensic integrity through hash verification and chain of custody logging."
            ),
            "methodology": {
                "model": self.model,
                "temperature": 0.3,
                "approach": "Batch API processing with prompt caching",
                "validation": "Results cross-referenced with pattern-based analysis",
            },
            "analysis": analysis,
        }

        # Write report
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        # Hash for integrity
        report_hash = self.forensic.compute_hash(output_path)

        self.forensic.record_action(
            "ai_report_generated",
            f"Generated AI analysis report",
            {"path": str(output_path), "hash": report_hash},
        )

        return output_path


__all__ = ["AIAnalyzer", "RateLimiter"]
