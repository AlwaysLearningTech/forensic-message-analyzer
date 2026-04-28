"""Phase 4: interactive manual review."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from ..review.manual_review_manager import ManualReviewManager

logger = logging.getLogger(__name__)


def run(analyzer, analysis_results: Dict, extracted_data: Dict, resume_session_id: Optional[str] = None) -> Dict:
    """Build the review item set, open the reviewer UI, collect decisions, and persist the results."""
    logger.info("\n" + "=" * 60)
    logger.info("PHASE 4: INTERACTIVE MANUAL REVIEW")
    logger.info("=" * 60)

    manager = ManualReviewManager(
        session_id=resume_session_id,
        config=analyzer.config,
        forensic_recorder=analyzer.forensic,
    )
    analyzer._review_session_id = manager.session_id
    already_reviewed = manager.reviewed_item_ids

    items_for_review = _build_review_items(analyzer, analysis_results, extracted_data)

    logger.info(
        f"\n[*] {len(items_for_review)} items flagged for review "
        f"(local threats + AI threats + AI coercive control + emails)"
    )

    # Terminal review walks sequentially, so it needs the already-reviewed items stripped out. Web review keeps the full list (existing-review badges + auto-advance to first unreviewed handle the rest).
    items_for_terminal = items_for_review
    if already_reviewed:
        items_for_terminal = [i for i in items_for_review if i["id"] not in already_reviewed]
        skipped = len(items_for_review) - len(items_for_terminal)
        if skipped:
            logger.info(f"    Resuming: {skipped} already reviewed, {len(items_for_terminal)} remaining (terminal mode)")

    analyzer._save_pipeline_state(review_session_id=manager.session_id)

    # Only pass mapped-contact messages to the review UI, sorted chronologically
    # so multi-source corpora (iMessage + WhatsApp) interleave by real send time.
    # Extraction order (and threat_{idx} IDs) is unchanged; this is display-only.
    all_messages = extracted_data.get("messages", [])
    messages = [m for m in all_messages if _is_mapped(analyzer, m)]
    messages.sort(key=lambda m: m.get("timestamp", ""))
    screenshots = extracted_data.get("screenshots", [])

    logger.info(f"    {len(all_messages)} total messages, {len(messages)} from mapped contacts, {len(screenshots)} screenshots")
    if all_messages and not messages:
        # Every message filtered out — surface the contact config so the examiner can diagnose immediately.
        senders = {m.get("sender", "?") for m in all_messages[:200]}
        recipients = {m.get("recipient", "?") for m in all_messages[:200]}
        logger.warning(
            f"    [!] All messages filtered by contact mapping. "
            f"Senders seen: {sorted(senders)[:10]}, Recipients seen: {sorted(recipients)[:10]}, "
            f"ai_contacts: {sorted(analyzer.config.ai_contacts)[:10]}"
        )

    review_mode = analyzer.config.review_mode  # "web" (default) or "terminal" via REVIEW_MODE in .env

    if review_mode == "web" and items_for_review:
        try:
            from ..review.web_review import WebReview
            web = WebReview(manager, forensic_recorder=analyzer.forensic, config=analyzer.config)
            web.start_review(messages, items_for_review, screenshots=screenshots, port=analyzer.config.review_port)
            was_completed = getattr(web, 'was_completed', False)
            was_paused = getattr(web, 'was_paused', False)
            logger.info(f"[PIPELINE] After start_review: was_completed={was_completed}, was_paused={was_paused}")
            # DEFENSIVE: Only mark as completed if Complete button was explicitly clicked.
            # Any other exit (Pause, Ctrl+C, crash) leaves _review_completed=False → resumable.
            if was_completed:
                analyzer._review_completed = True
                logger.info("[PIPELINE] Set analyzer._review_completed = True (user clicked Complete)")
            elif was_paused:
                analyzer._review_paused = True
                logger.info("[PIPELINE] Set analyzer._review_paused = True (user clicked Pause)")
        except ImportError:
            logger.info("    Flask not installed. Falling back to terminal review.")
            from ..review.interactive_review import InteractiveReview
            InteractiveReview(manager, config=analyzer.config).review_flagged_items(messages, items_for_terminal)
    else:
        from ..review.interactive_review import InteractiveReview
        InteractiveReview(manager, config=analyzer.config).review_flagged_items(messages, items_for_terminal)

    relevant = manager.get_reviews_by_decision("relevant")
    not_relevant = manager.get_reviews_by_decision("not_relevant")
    uncertain = manager.get_reviews_by_decision("uncertain")

    review_summary = {
        "total_reviewed": len(relevant) + len(not_relevant) + len(uncertain),
        "relevant": len(relevant),
        "not_relevant": len(not_relevant),
        "uncertain": len(uncertain),
        "reviews": manager.reviews,
    }

    logger.info(f"    Relevant: {review_summary['relevant']}")
    logger.info(f"    Not Relevant: {review_summary['not_relevant']}")
    logger.info(f"    Uncertain: {review_summary['uncertain']}")
    logger.info("\n[✓] Review phase complete")

    analyzer.manifest.add_operation(
        "manual_review",
        "success",
        {
            "total_reviewed": review_summary["total_reviewed"],
            "relevant": review_summary["relevant"],
            "not_relevant": review_summary["not_relevant"],
            "uncertain": review_summary["uncertain"],
        },
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    review_output = analyzer.config.analysis_dir() / f"review_results_{timestamp}.json"
    with open(review_output, "w") as f:
        json.dump(review_summary, f, indent=2, default=str)
    analyzer._review_results_path = review_output

    return review_summary


def _is_mapped(analyzer, item: dict) -> bool:
    """True if both sender and recipient belong to mapped contacts (same filter as AI phase)."""
    sender = item.get("sender", "")
    recipient = item.get("recipient", "")
    ai_contacts = analyzer.config.ai_contacts
    ai_specified = analyzer.config.ai_contacts_specified
    if sender not in ai_contacts or recipient not in ai_contacts:
        return False
    if ai_specified is not None and sender not in ai_specified and recipient not in ai_specified:
        return False
    return True


def _build_review_items(analyzer, analysis_results: Dict, extracted_data: Dict) -> list:
    """Assemble the flat list of items presented to the reviewer.

    Every finding is stamped with a source in {pattern_matched, ai_screened, extracted} and a method label so downstream reports can distinguish deterministic pattern matches from AI flags and raw extracted content.

    Items carry a ``timestamp`` field so the queue is sorted chronologically across sources (iMessage + WhatsApp + email + ...). Without this sort, items come out in extraction order and the reviewer jumps across years between adjacent items.
    """
    import pandas as pd

    items_for_review: list = []

    # Lookup tables for resolving an item's timestamp from its source message. AI items only carry the ``quote`` text, so we need a content → message map. Pattern threats and emails carry message_id.
    msgs = extracted_data.get("messages", [])
    msg_by_id: dict = {}
    msg_by_content: dict = {}
    for m in msgs:
        mid = m.get("message_id")
        if mid is not None and str(mid) not in msg_by_id:
            msg_by_id[str(mid)] = m
        c = m.get("content")
        if c and c not in msg_by_content:
            msg_by_content[c] = m

    def _resolve_ts(*, message_id: str = "", content: str = "", direct: object = None):
        """Return the best available timestamp string for an item."""
        if direct not in (None, ""):
            return direct
        if message_id and str(message_id) in msg_by_id:
            return msg_by_id[str(message_id)].get("timestamp", "")
        if content and content in msg_by_content:
            return msg_by_content[content].get("timestamp", "")
        return ""

    # Pattern-matched threats (deterministic YAML/regex).
    if "threats" in analysis_results:
        threat_details = analysis_results["threats"].get("details", [])
        if isinstance(threat_details, list):
            for idx, item in enumerate(threat_details):
                if item.get("threat_detected") and _is_mapped(analyzer, item):
                    items_for_review.append({
                        "id": f"threat_{idx}",
                        "type": "threat",
                        "source": "pattern_matched",
                        "method": "yaml_patterns",
                        "content": item.get("content", ""),
                        "categories": item.get("threat_categories", ""),
                        "confidence": item.get("threat_confidence", 0),
                        "message_id": item.get("message_id", ""),
                        "timestamp": _resolve_ts(
                            direct=item.get("timestamp"),
                            message_id=item.get("message_id", ""),
                            content=item.get("content", ""),
                        ),
                    })

    # AI-screened threats and coercive control patterns.
    ai_analysis = analysis_results.get("ai_analysis", {})
    ai_model_name = ai_analysis.get("model") or "claude"

    ai_threats = ai_analysis.get("threat_assessment", {})
    if ai_threats.get("found"):
        for i, detail in enumerate(ai_threats.get("details", [])):
            if isinstance(detail, dict):
                quote = detail.get("quote", "")
                items_for_review.append({
                    "id": f"ai_threat_{i}",
                    "type": "ai_threat",
                    "source": "ai_screened",
                    "method": ai_model_name,
                    "content": quote,
                    "categories": f"{detail.get('type', '')} — {detail.get('target', '')}",
                    "confidence": detail.get("severity", ""),
                    "message_id": "",
                    "rcw_relevance": detail.get("rcw_relevance", ""),
                    "timestamp": _resolve_ts(content=quote),
                })

    ai_cc = ai_analysis.get("coercive_control", {})
    if ai_cc.get("detected"):
        for i, pattern in enumerate(ai_cc.get("patterns", [])):
            if isinstance(pattern, dict):
                quote = pattern.get("quote", "")
                items_for_review.append({
                    "id": f"ai_coercive_{i}",
                    "type": "ai_coercive_control",
                    "source": "ai_screened",
                    "method": ai_model_name,
                    "content": quote,
                    "categories": f"Coercive control: {pattern.get('type', '')}",
                    "confidence": pattern.get("severity", ""),
                    "message_id": "",
                    "timestamp": _resolve_ts(content=quote),
                })

    # All email messages are routed to review — emails are low-volume and each is purposeful. Third-party emails (counselors, attorneys, family) provide corroboration; mapped-person emails may need reviewer annotations.
    mapped_persons = set(analyzer.config.contact_mappings.keys())
    for msg in msgs:
        if msg.get("source") != "email":
            continue
        sender = msg.get("sender", "")
        recipient = msg.get("recipient", "")
        is_third_party = sender not in mapped_persons or recipient not in mapped_persons
        item_type = "third_party_email" if is_third_party else "email"
        subject = msg.get("subject", "")
        items_for_review.append({
            "id": f"email_{msg.get('message_id', '')}",
            "type": item_type,
            "source": "extracted",
            "method": "email_import",
            "content": msg.get("content", ""),
            "categories": f"{'Third-Party ' if is_third_party else ''}Email: {sender} → {recipient}",
            "confidence": 0.0,
            "message_id": msg.get("message_id", ""),
            "subject": subject,
            "timestamp": msg.get("timestamp", ""),
        })

    # Chronological sort across sources. Timestamps arrive as pd.Timestamp/datetime on the initial run and as ISO strings after JSON round-trip on finalize/refresh, so normalize via pd.to_datetime. Undated items pile up at the end (Timestamp.max).
    sentinel = pd.Timestamp.max.tz_localize("UTC")

    def _ts_key(it):
        raw = it.get("timestamp", "")
        if raw in (None, "", "NaT"):
            return sentinel
        parsed = pd.to_datetime(raw, utc=True, errors="coerce")
        if pd.isna(parsed):
            return sentinel
        return parsed

    items_for_review.sort(key=_ts_key)

    return items_for_review
