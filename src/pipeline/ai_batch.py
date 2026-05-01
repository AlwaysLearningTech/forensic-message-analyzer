"""Phase 3: pre-review AI screening (Anthropic Claude batch API)."""

from __future__ import annotations

import json
import logging
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict

logger = logging.getLogger(__name__)


def run(analyzer, extracted_data: Dict) -> Dict:
    """Submit mapped-contact messages to Claude for threat and coercive-control classification.

    Does NOT generate the executive summary — that runs post-review in finalize so it can incorporate the reviewer's confirmed decisions. Returns the batch results dict, or {} on skip/error.
    """
    logger.info("\n" + "=" * 60)
    logger.info("PHASE 3: PRE-REVIEW SCREENING")
    logger.info("=" * 60)

    try:
        from ..analyzers.ai_analyzer import AIAnalyzer
        ai_analyzer = AIAnalyzer(forensic_recorder=analyzer.forensic, config=analyzer.config)
        if not ai_analyzer.client:
            logger.info("    Pre-review screening skipped - AI not configured")
            return ai_analyzer._empty_analysis()

        messages = extracted_data.get("messages", [])
        ai_contacts = analyzer.config.ai_contacts
        ai_specified = analyzer.config.ai_contacts_specified
        mapped_messages = [
            m for m in messages
            if m.get("source") != "counseling"
            and m.get("sender") in ai_contacts
            and m.get("recipient") in ai_contacts
            and (
                ai_specified is None
                or m.get("sender") in ai_specified
                or m.get("recipient") in ai_specified
            )
        ]
        skipped = len(messages) - len(mapped_messages)
        if skipped:
            logger.info(f"    Filtered to {len(mapped_messages)} mapped-contact messages (skipped {skipped} unmapped)")

        # Serialize the filtered list to disk BEFORE submission so a sleep/disconnect during polling can be recovered. The resume path needs the message count to size analysis_results correctly; storing the full list also lets a future resume regenerate request prompts deterministically if Anthropic ever returns errored entries we want to retry.
        analysis_dir = analyzer.config.analysis_dir()
        analysis_dir.mkdir(parents=True, exist_ok=True)
        inflight_messages_path = analysis_dir / "ai_batch_inflight_messages.json"
        with open(inflight_messages_path, "w") as f:
            json.dump(mapped_messages, f, indent=2, default=str)

        def _state_writer(batch_info: dict):
            """Persist batch lifecycle (submitted/ended) to pipeline_state.json."""
            block = dict(batch_info)
            block["messages_path"] = str(inflight_messages_path)
            analyzer._save_pipeline_state(ai_batch=block)

        ai_results = ai_analyzer.analyze_messages(
            mapped_messages,
            batch_size=analyzer.config.batch_size,
            generate_summary=False,
            state_writer=_state_writer,
        )
        threat_count = len(ai_results.get("threat_assessment", {}).get("details", []))
        cc_count = len(ai_results.get("coercive_control", {}).get("patterns", []))
        logger.info(f"    AI batch complete - {threat_count} threats, {cc_count} coercive control patterns found")

        analyzer.manifest.add_operation(
            "ai_batch_analysis",
            "success",
            {
                "message_count": len(mapped_messages),
                "threats": threat_count,
                "coercive_control_patterns": cc_count,
            },
        )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ai_output_file = analyzer.config.analysis_dir() / f"ai_batch_results_{timestamp}.json"
        with open(ai_output_file, "w") as f:
            json.dump(ai_results, f, indent=2, default=str)
        analyzer._ai_batch_results_path = ai_output_file
        logger.info(f"    AI batch results saved to {ai_output_file.name}")

        # Results are persisted; the in-flight marker is no longer needed. Clear it so a future --resume-batch invocation cannot accidentally re-process this run.
        analyzer._save_pipeline_state(ai_batch=None)
        try:
            inflight_messages_path.unlink()
        except (FileNotFoundError, OSError):
            pass

        return ai_results
    except Exception as e:
        logger.info(f"    AI batch analysis error: {e}")
        traceback.print_exc()
        return {}
