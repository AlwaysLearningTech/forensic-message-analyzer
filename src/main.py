#!/usr/bin/env python3
"""
Main orchestration script for the forensic message analyzer.
Coordinates extraction, analysis, review, and reporting phases.
"""

import sys
import json
import copy
import logging
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import Config
from src.forensic_utils import ForensicRecorder, ForensicIntegrity
from src.third_party_registry import ThirdPartyRegistry
from src.utils.run_manifest import RunManifest


class ForensicAnalyzer:
    """Main orchestrator for the forensic analysis workflow."""
    
    def __init__(self, config: Config = None):
        """Initialize the forensic analyzer with necessary components.

        Args:
            config: Configuration instance. If None, creates a new one.
                    The caller is responsible for setting config.output_dir
                    to the desired run-specific directory (see run.py).
        """
        self.config = config if config is not None else Config()
        self.forensic = ForensicRecorder(self.config.forensic_dir(), config=self.config)
        self.integrity = ForensicIntegrity(self.forensic)
        self.manifest = RunManifest(self.forensic, config=self.config)
        self.third_party_registry = ThirdPartyRegistry(self.forensic, self.config)

        # Evidence preservation (hashing, archive, working copies, contact auto-map) is delegated to a dedicated helper so this orchestrator is not also an archive manager. The helper reads+writes the same config and forensic recorder.
        from .utils.evidence_preserver import EvidencePreserver
        self.evidence = EvidencePreserver(self.config, self.forensic, self.integrity, self.manifest)
        
        # Record session start
        self.forensic.record_action("session_start", "Forensic analysis session initialized")
        self._extracted_data_path = None
        self._analysis_results_path = None

    # ------------------------------------------------------------------
    # Source file integrity
    # ------------------------------------------------------------------

    def _hash_source_files(self):
        """Hash all source files before extraction. Delegates to EvidencePreserver."""
        self.evidence.hash_sources()

    # ------------------------------------------------------------------
    # Source file preservation (forensic archive)
    # ------------------------------------------------------------------

    def _preserve_source_files(self):
        """Archive every configured source file into preserved_sources.zip. Delegates to EvidencePreserver."""
        self.evidence.preserve_sources()

    # ------------------------------------------------------------------
    # Redaction application
    # ------------------------------------------------------------------

    def _apply_redactions_to_messages(self, data: Dict) -> Dict:
        """Return a shallow copy of ``data`` with per-message content rewritten through any active redactions.

        Loads redactions from review_dir/redactions_*.json (session_id matches the review session when available). When no redaction file exists the input is returned unchanged. The raw extracted_data JSON produced earlier in the pipeline is NOT modified — it remains available for challenge in discovery.
        """
        try:
            from .review.redaction_manager import RedactionManager
        except ImportError:
            return data

        session_id = getattr(self, "_review_session_id", None)
        if session_id:
            rm = RedactionManager(session_id=session_id, config=self.config, forensic_recorder=self.forensic)
        else:
            return data

        if not rm._records:
            return data

        new_data = dict(data)
        new_messages = []
        redacted_count = 0
        for msg in data.get("messages", []):
            msg_id = msg.get("message_id")
            if not msg_id:
                new_messages.append(msg)
                continue
            active = rm.active_for(msg_id)
            if not active:
                new_messages.append(msg)
                continue
            copy_msg = dict(msg)
            copy_msg["content"] = rm.apply(msg_id, msg.get("content") or "")
            copy_msg["_redactions_applied"] = [
                {"reason": r["reason"], "authority": r["authority"], "examiner": r["examiner"]}
                for r in active
            ]
            new_messages.append(copy_msg)
            redacted_count += 1

        new_data["messages"] = new_messages
        if redacted_count:
            logger.info(f"\n[*] Applied redactions to {redacted_count} message(s)")
            self.forensic.record_action(
                "redactions_applied_for_rendering",
                f"Redactions applied to {redacted_count} messages prior to reporting",
                {"count": redacted_count},
            )
        return new_data

    # ------------------------------------------------------------------
    # Output signing (detached Ed25519)
    # ------------------------------------------------------------------

    def _sign_artifact(self, path: Path):
        """Sign a final artifact if a signer can be built. Errors are non-fatal."""
        if path is None or not Path(path).is_file():
            return
        try:
            from .utils.signing import Signer
            key_path = getattr(self.config, "examiner_signing_key", None)
            signer = Signer(
                key_path=Path(key_path) if key_path else None,
                run_dir=Path(self.config.output_dir),
            )
            sig, pub = signer.sign_file(Path(path))
            self.forensic.record_action(
                "artifact_signed",
                f"Signed {Path(path).name} ({'ephemeral key' if signer.is_ephemeral else 'configured key'})",
                {"file": str(path), "sig": str(sig), "public_key": str(pub), "ephemeral_key": signer.is_ephemeral},
            )
        except Exception as exc:
            self.forensic.record_action(
                "artifact_sign_skipped",
                f"Could not sign {Path(path).name}: {exc}",
                {"file": str(path), "error": str(exc)},
            )

    # ------------------------------------------------------------------
    # Contact auto-mapping from vCard exports
    # ------------------------------------------------------------------

    def _apply_contact_automapping(self):
        """Merge vCard-derived contacts into config.contact_mappings. Delegates to EvidencePreserver."""
        self.evidence.apply_contact_automapping()

    # ------------------------------------------------------------------
    # Working-copy routing (FRE 1002 — Best Evidence Rule)
    # ------------------------------------------------------------------

    def _route_sources_to_working_copies(self):
        """Copy each source into run_dir/working_copies and repoint the config. Delegates to EvidencePreserver."""
        self.evidence.route_to_working_copies()

    # ------------------------------------------------------------------
    # Attachment preservation (FRE 1002 — Best Evidence Rule)
    # ------------------------------------------------------------------

    def _preserve_attachments(self, extracted_data: Dict):
        """
        Create hash-verified working copies of all attachment files.

        Copies each original attachment to sources/attachments/ and updates the message dicts to reference the preserved copy. Deduplicates within a run (same source file referenced by multiple messages) and across runs (file already preserved by a previous extraction or --refresh-attachments call). A file is re-copied only when the source has grown beyond the existing preserved copy (e.g. iCloud attachment was evicted and has since been downloaded).
        """
        messages = extracted_data.get('messages', [])
        dest_dir = self.config.sources_dir() / "attachments"
        dest_dir.mkdir(parents=True, exist_ok=True)

        preserved = {}   # {original_path_str: preserved_path}
        preserved_count = 0
        reused_count = 0
        image_count = 0
        missing_count = 0
        compressed_count = 0
        bytes_saved = 0

        IMAGE_EXTS = {'.png', '.jpg', '.jpeg', '.gif', '.heic', '.heif', '.tiff', '.bmp', '.webp'}

        logger.info("\n[*] Preserving attachment files (FRE 1002 — Best Evidence Rule)...")

        def _find_existing(src: Path) -> Optional[Path]:
            """Return an existing preserved copy of src from a prior run, or None.

            For normal copies, reuses the existing file only when the source has not grown
            beyond it (guards against iCloud-evicted placeholders being locked in). For
            compressed copies (HEIC→JPG) any existing JPEG is reused since the source is
            expected to be larger than the compressed output.
            """
            from .utils.attachment_utils import should_compress
            if not dest_dir.exists():
                return None
            if should_compress(src, self.config):
                for existing in dest_dir.glob(f"{src.stem}_*.jpg"):
                    if existing.is_file():
                        return existing
            else:
                for existing in dest_dir.glob(f"{src.stem}_*{src.suffix}"):
                    if existing.is_file() and src.stat().st_size <= existing.stat().st_size:
                        return existing
            return None

        def _preserve_one(src: Path) -> Optional[Path]:
            """Compress (if eligible) → create_working_copy. Returns the preserved path."""
            nonlocal compressed_count, bytes_saved, reused_count
            existing = _find_existing(src)
            if existing:
                reused_count += 1
                return existing
            from .utils.attachment_utils import should_compress, compress_image
            if should_compress(src, self.config):
                scratch = dest_dir / "_compress_scratch"
                scratch.mkdir(parents=True, exist_ok=True)
                temp = scratch / f"{src.stem}.jpg"
                summary = compress_image(src, temp, self.config)
                if summary and temp.exists():
                    copy_path = self.integrity.create_working_copy(temp, dest_dir)
                    try:
                        temp.unlink()
                    except OSError:
                        pass
                    if copy_path:
                        self.forensic.record_action(
                            "attachment_compressed",
                            f"Re-encoded {src.name} to JPEG (quality={summary['jpeg_quality']}, max_dim={summary['max_dimension_px']}px)",
                            {
                                "original_path": summary["original_path"],
                                "working_copy": str(copy_path),
                                "original_hash": summary["original_hash"],
                                "compressed_hash": summary["compressed_hash"],
                                "original_size": summary["original_size"],
                                "compressed_size": summary["compressed_size"],
                                "ratio": summary["ratio"],
                                "jpeg_quality": summary["jpeg_quality"],
                                "max_dimension_px": summary["max_dimension_px"],
                            },
                        )
                        compressed_count += 1
                        bytes_saved += max(0, summary["original_size"] - summary["compressed_size"])
                        return copy_path
            return self.integrity.create_working_copy(src, dest_dir)

        for msg in messages:
            # Handle primary attachment path
            att_path_str = msg.get('attachment')
            if att_path_str:
                att_path = Path(att_path_str)
                if att_path_str in preserved:
                    # Already copied — just update the reference
                    msg['attachment'] = str(preserved[att_path_str])
                elif att_path.is_file():
                    copy_path = _preserve_one(att_path)
                    if copy_path:
                        preserved[att_path_str] = copy_path
                        msg['attachment'] = str(copy_path)
                        preserved_count += 1
                        if att_path.suffix.lower() in IMAGE_EXTS:
                            image_count += 1
                else:
                    missing_count += 1
                    self.forensic.record_action(
                        "attachment_missing",
                        f"Attachment file not found: {att_path_str}",
                        {"path": att_path_str, "message_id": msg.get('message_id', '')}
                    )

            # Handle attachments list (multiple per message)
            for att in msg.get('attachments', []):
                att_list_path_str = att.get('path')
                if not att_list_path_str:
                    continue
                att_list_path = Path(att_list_path_str)
                if att_list_path_str in preserved:
                    att['path'] = str(preserved[att_list_path_str])
                elif att_list_path.is_file():
                    copy_path = _preserve_one(att_list_path)
                    if copy_path:
                        att['path'] = str(copy_path)
                        if att_list_path_str not in preserved:
                            preserved_count += 1
                            if att_list_path.suffix.lower() in IMAGE_EXTS:
                                image_count += 1
                        preserved[att_list_path_str] = copy_path
                else:
                    if att_list_path_str not in preserved:
                        missing_count += 1

        # Cleanup scratch dir if empty
        scratch = dest_dir / "_compress_scratch"
        if scratch.exists():
            try:
                scratch.rmdir()
            except OSError:
                pass

        other_count = preserved_count - image_count
        reuse_note = f", {reused_count} reused from prior run" if reused_count else ""
        logger.info(f"    Preserved {preserved_count} attachment files "
              f"({image_count} images, {other_count} other{reuse_note})")
        if compressed_count:
            logger.info(
                f"    Compressed {compressed_count} image(s), saved "
                f"{bytes_saved / (1024*1024):.1f} MB"
            )
        if missing_count:
            logger.info(f"    WARNING: {missing_count} attachment files not found on disk")

    # ------------------------------------------------------------------
    # Pipeline state (for resume after crash)
    # ------------------------------------------------------------------

    _UNSET = object()

    def _save_pipeline_state(self, review_session_id=_UNSET,
                             review_results_path=_UNSET,
                             ai_batch_results_path=_UNSET,
                             review_complete=_UNSET,
                             ai_batch=_UNSET):
        """Save pipeline state so a crashed run can resume or finalize later.

        Fields not explicitly passed are preserved from any existing state file — this lets mid-phase saves (e.g. marking the review session_id when Phase 4 starts) update one field without clobbering paths set by earlier phases. Pass the value explicitly (including None) to overwrite.
        """
        existing = self._load_pipeline_state() or {}
        state = {
            "timestamp": datetime.now().isoformat(),
            "extracted_data_path": str(self._extracted_data_path) if self._extracted_data_path else existing.get("extracted_data_path"),
            "analysis_results_path": str(self._analysis_results_path) if self._analysis_results_path else existing.get("analysis_results_path"),
            "ai_batch_results_path": existing.get("ai_batch_results_path") if ai_batch_results_path is self._UNSET else ai_batch_results_path,
            "review_results_path": existing.get("review_results_path") if review_results_path is self._UNSET else review_results_path,
            "review_session_id": existing.get("review_session_id") if review_session_id is self._UNSET else review_session_id,
            "review_complete": existing.get("review_complete", False) if review_complete is self._UNSET else review_complete,
            "ai_batch": existing.get("ai_batch") if ai_batch is self._UNSET else ai_batch,
        }
        state_path = self.config.analysis_dir() / "pipeline_state.json"
        with open(state_path, 'w') as f:
            json.dump(state, f, indent=2)
        self.forensic.record_action("pipeline_state_saved", f"Pipeline state saved for resume", {"state_path": str(state_path)})

    def _load_pipeline_state(self) -> Optional[Dict]:
        """Load pipeline state. Checks analysis/ subdir first (new layout), then root (legacy)."""
        out_dir = Path(self.config.output_dir)
        for candidate in [out_dir / "analysis" / "pipeline_state.json", out_dir / "pipeline_state.json"]:
            if candidate.exists():
                with open(candidate) as f:
                    return json.load(f)
        return None

    def _clear_pipeline_state(self):
        """Remove pipeline state file after successful completion (checks both new and legacy locations)."""
        out_dir = Path(self.config.output_dir)
        for candidate in [out_dir / "analysis" / "pipeline_state.json", out_dir / "pipeline_state.json"]:
            if candidate.exists():
                candidate.unlink()
        
    def run_extraction_phase(self, refresh_mode: bool = False) -> Dict:
        """Phase 1: data extraction. Delegates to src.pipeline.extraction."""
        from .pipeline import extraction
        return extraction.run(self, refresh_mode=refresh_mode)
    
    def run_analysis_phase(self, data: Dict) -> Dict:
        """Phase 2: automated analysis. Delegates to src.pipeline.analysis."""
        from .pipeline import analysis
        return analysis.run(self, data)

    def run_ai_batch_phase(self, extracted_data: Dict) -> Dict:
        """Phase 3: pre-review AI screening. Delegates to src.pipeline.ai_batch."""
        from .pipeline import ai_batch
        return ai_batch.run(self, extracted_data)

    def run_review_phase(self, analysis_results: Dict, extracted_data: Dict, resume_session_id: str = None) -> Dict:
        """Phase 4: manual review. Delegates to src.pipeline.review."""
        from .pipeline import review
        return review.run(self, analysis_results, extracted_data, resume_session_id)
    
    def run_behavioral_phase(self, extracted_data: Dict, analysis_results: Dict, review_results: Dict) -> Dict:
        """Phase 5: post-review behavioral analysis. Delegates to src.pipeline.behavioral."""
        from .pipeline import behavioral
        return behavioral.run(self, extracted_data, analysis_results, review_results)
    
    def _filter_analysis_by_review(self, analysis: Dict, review: Dict) -> Dict:
        """Filter analysis results to only include human-verified findings.

        Only threats and risk indicators explicitly marked 'relevant' or 'uncertain' during manual review survive into analysis reports. Unreviewed and rejected findings are cleared.

        The forensic all-messages export is NOT affected by this filtering — it uses extracted_data directly and remains a complete, unfiltered record.

        Args:
            analysis: Raw analysis results from Phase 2.
            review: Review decisions from Phase 3.

        Returns:
            Deep copy of analysis with unverified findings removed.
        """
        filtered = copy.deepcopy(analysis)

        # Build set of item IDs that were approved during review
        approved_ids = set()
        for r in review.get('reviews', []):
            if r.get('decision') in ('relevant', 'uncertain'):
                approved_ids.add(r.get('item_id', ''))

        reviewed_count = review.get('total_reviewed', 0)
        approved_count = len(approved_ids)

        # --- Filter threat details ---
        if 'threats' in filtered:
            details = filtered['threats'].get('details', [])
            cleared = 0
            for idx, item in enumerate(details):
                if item.get('threat_detected'):
                    item_id = f"threat_{idx}"
                    if item_id not in approved_ids:
                        # Not approved: clear threat annotations
                        item['threat_detected'] = False
                        item['threat_categories'] = ''
                        item['threat_confidence'] = 0
                        item['harmful_content'] = False
                        cleared += 1

            # Regenerate summary from filtered data
            confirmed = [d for d in details if d.get('threat_detected')]
            old_summary = filtered['threats'].get('summary', {})
            filtered['threats']['summary'] = {
                'total_messages': old_summary.get('total_messages', len(details)),
                'messages_with_threats': len(confirmed),
                'threat_percentage': len(confirmed) / len(details) * 100 if details else 0,
                'high_confidence_threats': sum(
                    1 for d in confirmed if d.get('threat_confidence', 0) >= 0.75
                ),
                'timestamp': old_summary.get('timestamp', ''),
            }

            if cleared:
                logger.info(f"    Filtered {cleared} unverified threats from reports")

        # --- Filter AI analysis findings ---
        # AI analysis runs post-review (Phase 5) and doesn't need filtering.

        self.forensic.record_action(
            "analysis_filtered_by_review",
            f"Filtered analysis for reports: {approved_count} approved of {reviewed_count} reviewed",
            {
                "reviewed": reviewed_count,
                "approved": approved_count,
                "approved_ids": list(approved_ids),
            },
        )

        return filtered


    def run_reporting_phase(self, data: Dict, analysis: Dict, review: Dict) -> Dict:
        """Phase 7: report generation. Delegates to src.pipeline.reporting."""
        from .pipeline import reporting
        return reporting.run(self, data, analysis, review)

    def run_documentation_phase(self, data: Dict, analysis_results: Dict = None, review_decisions: Dict = None) -> Dict:
        """Phase 8: documentation + manifest. Delegates to src.pipeline.documentation."""
        from .pipeline import documentation
        return documentation.run(self, data, analysis_results, review_decisions)
    
    def run_full_analysis(self, resume: bool = False):
        """Run extraction, analysis, AI batch, and review phases (1-4), then stop.

        After review completes, pipeline state is saved and the process exits. Run ``run_finalize()`` (via ``python3 run.py --finalize``) to continue with behavioral analysis, AI summary, reporting, and documentation (Phases 5-8).

        Args:
            resume: If True, skip extraction and analysis by loading saved state from a previous run. Resumes at the review phase.
        """
        logger.info("\n" + "="*80)
        logger.info(" FORENSIC MESSAGE ANALYZER — PHASES 1-4 ")
        logger.info("="*80)
        logger.info(f"Session started: {datetime.now()}")
        logger.info(f"Output directory: {self.config.output_dir}")

        resume_session_id = None

        if resume:
            state = self._load_pipeline_state()
            out_dir = Path(self.config.output_dir)
            # Log which location was checked (new layout first, then legacy root)
            state_path = (out_dir / "analysis" / "pipeline_state.json") if (out_dir / "analysis" / "pipeline_state.json").exists() else (out_dir / "pipeline_state.json")
            logger.info(f"\n[*] Resume requested. Looking for state in: {out_dir.name}")
            if state:
                logger.info(f"    State found: review_complete={state.get('review_complete')}, "
                            f"timestamp={state.get('timestamp', '?')}")
            else:
                logger.info(f"    No state file found in {out_dir}")

            if state and state.get("review_complete"):
                logger.info("\n[!] Review was already completed. Nothing to resume.")
                logger.info("    Run --finalize to generate reports, or delete pipeline_state.json to start fresh.")
                return
            elif state and not state.get("review_complete"):
                ext_path = state.get("extracted_data_path")
                ana_path = state.get("analysis_results_path")
                resume_session_id = state.get("review_session_id")

                ext_exists = ext_path and Path(ext_path).exists()
                ana_exists = ana_path and Path(ana_path).exists()
                logger.info(f"    extracted_data_path: {ext_path} (exists={ext_exists})")
                logger.info(f"    analysis_results_path: {ana_path} (exists={ana_exists})")

                if ext_exists and ana_exists:
                    logger.info(f"\n[*] Resuming from saved state ({state.get('timestamp', 'unknown')})")
                    logger.info(f"    Extraction: {Path(ext_path).name}")
                    logger.info(f"    Analysis:   {Path(ana_path).name}")
                    if resume_session_id:
                        logger.info(f"    Review session: {resume_session_id}")

                    with open(ext_path) as f:
                        extracted_data = json.load(f)
                    with open(ana_path) as f:
                        analysis_results = json.load(f)

                    self._extracted_data_path = Path(ext_path)
                    self._analysis_results_path = Path(ana_path)

                    logger.info("\n    Skipping Phases 1-3 (extraction, analysis, AI batch) — already completed.")
                else:
                    logger.error("\n[!] RESUME ABORTED: State file found but data files are missing or corrupt.")
                    logger.error(f"    extracted_data_path: {ext_path}")
                    logger.error(f"    analysis_results_path: {ana_path}")
                    logger.error("    Cannot resume without both files. Options:")
                    logger.error("      1. Restore the missing files from backup")
                    logger.error("      2. Start a fresh run with: python3 run.py")
                    raise RuntimeError("Resume failed: required data files missing. Refusing to start a fresh run to protect against unintended AI API costs.")
            else:
                logger.error("\n[!] RESUME ABORTED: No pipeline_state.json found in this run directory.")
                logger.error(f"    Looked in: {out_dir} (analysis/ and root)")
                logger.error("    Cannot resume a run that has no saved state. Options:")
                logger.error("      1. Use --recover-state to rebuild state from artifacts: python3 run.py --recover-state <run_dir>")
                logger.error("      2. Check that you specified the correct run directory")
                logger.error("      3. Start a fresh run with: python3 run.py")
                raise RuntimeError("Resume failed: no pipeline_state.json found. Refusing to start a fresh run to protect against unintended AI API costs.")

        try:
            if resume:
                # Resume path: skip directly to Phase 4 (review). Phases 1-3 were already completed.
                pass
            else:
                # Phase 1: Extraction
                extracted_data = self.run_extraction_phase()

                # Phase 2: Local Analysis (threat, sentiment, pattern — no AI)
                analysis_results = self.run_analysis_phase(extracted_data)

                # Phase 3: AI Batch Analysis (pre-review, no summary)
                if self.config.skip_ai_tagging:
                    logger.info("\n" + "=" * 60)
                    logger.info("PHASE 3: PRE-REVIEW SCREENING")
                    logger.info("=" * 60)
                    logger.info("    Phase 3 skipped (SKIP_AI_TAGGING=true)")
                    ai_batch_results = {}
                else:
                    ai_batch_results = self.run_ai_batch_phase(extracted_data)
                analysis_results['ai_analysis'] = ai_batch_results

                # Re-save analysis results now that AI batch data is included, so finalize can load the complete analysis from disk.
                if self._analysis_results_path:
                    with open(self._analysis_results_path, 'w') as f:
                        json.dump(analysis_results, f, indent=2, default=str)

                # Save state so review can be resumed if process dies. Stamp ai_batch_results_path now — Phase 3 produced it and a crash during Phase 4 shouldn't lose the reference.
                self._save_pipeline_state(
                    ai_batch_results_path=str(self._ai_batch_results_path) if getattr(self, '_ai_batch_results_path', None) else None,
                )

            # Phase 4: Manual Review (reviews local + AI findings)
            review_results = self.run_review_phase(analysis_results, extracted_data, resume_session_id=resume_session_id)

            # The reviewer can end the session three ways:
            # 1. Complete Review → _review_completed=True → review_complete=True
            # 2. Pause & Quit → _review_paused=True → review_complete=False
            # 3. Ctrl+C/crash → neither flag set → review_complete=False (DEFENSIVE: assume resumable)
            completed = getattr(self, '_review_completed', False)
            paused = getattr(self, '_review_paused', False)
            logger.info(f"[MAIN] After review phase: _review_completed={completed}, _review_paused={paused}, review_complete will be={completed}")

            self._save_pipeline_state(
                review_session_id=getattr(self, '_review_session_id', None),
                review_results_path=str(self._review_results_path) if getattr(self, '_review_results_path', None) else None,
                ai_batch_results_path=str(self._ai_batch_results_path) if getattr(self, '_ai_batch_results_path', None) else None,
                review_complete=completed,  # Only True if Complete button was explicitly clicked
            )

            logger.info("\n" + "="*80)
            if completed:
                logger.info(" REVIEW COMPLETE — PIPELINE PAUSED ")
                logger.info("="*80)
                logger.info(f"\nRun directory: {self.config.output_dir}")
                logger.info(f"\nTo generate reports, run:")
                logger.info(f"  python3 run.py --finalize \"{self.config.output_dir}\"")
                logger.info(f"\nOr auto-detect the latest run:")
                logger.info(f"  python3 run.py --finalize")
            else:
                # Either Pause button clicked or Ctrl+C/unexpected exit — all resumable
                logger.info(" REVIEW PAUSED — RESUMABLE ")
                logger.info("="*80)
                logger.info(f"\nRun directory: {self.config.output_dir}")
                logger.info(f"\nDecisions so far are saved. To continue the review, run:")
                logger.info(f"  python3 run.py --env <your .env> --resume")

        except Exception as e:
            logger.info(f"\n[ERROR] Workflow failed: {e}")
            import traceback
            traceback.print_exc()
            raise

    def run_finalize(self):
        """Run post-review phases (5-8) using saved pipeline state.

        Loads extraction data, analysis results (including AI batch results), and review decisions from disk. Runs behavioral analysis, AI executive summary, reporting, and documentation.
        """
        logger.info("\n" + "="*80)
        logger.info(" FORENSIC MESSAGE ANALYZER — FINALIZE (POST-REVIEW) ")
        logger.info("="*80)
        logger.info(f"Session started: {datetime.now()}")
        logger.info(f"Output directory: {self.config.output_dir}")

        state = self._load_pipeline_state()
        if not state:
            raise RuntimeError(
                "No pipeline state found. Run the full pipeline first "
                "(python3 run.py) to complete Phases 1-4."
            )
        if not state.get("review_complete"):
            raise RuntimeError(
                "Review is not yet complete. Options:\n"
                "  a) Resume and click 'Complete Review':  python3 run.py --resume\n"
                "  b) If all items are already tagged:     python3 run.py --mark-review-complete"
            )

        # Validate all required paths exist
        ext_path = state.get("extracted_data_path")
        ana_path = state.get("analysis_results_path")
        rev_path = state.get("review_results_path")

        missing = []
        for label, path in [("Extraction data", ext_path), ("Analysis results", ana_path), ("Review results", rev_path)]:
            if not path or not Path(path).exists():
                missing.append(f"{label}: {path or '(not set)'}")
        if missing:
            raise RuntimeError(
                "Pipeline state references missing files:\n  " + "\n  ".join(missing)
            )

        # Load saved data
        logger.info(f"\n[*] Loading saved pipeline data...")
        logger.info(f"    Extraction: {Path(ext_path).name}")
        logger.info(f"    Analysis:   {Path(ana_path).name}")
        logger.info(f"    Review:     {Path(rev_path).name}")

        with open(ext_path) as f:
            extracted_data = json.load(f)
        with open(ana_path) as f:
            analysis_results = json.load(f)
        with open(rev_path) as f:
            review_results = json.load(f)

        self._extracted_data_path = Path(ext_path)
        self._analysis_results_path = Path(ana_path)

        self.forensic.record_action(
            "finalize_started",
            "Post-review finalization started from saved pipeline state",
            {"state_timestamp": state.get("timestamp", "unknown")},
        )

        try:
            self._run_post_review_phases(extracted_data, analysis_results, review_results)
        except Exception as e:
            logger.info(f"\n[ERROR] Finalize failed: {e}")
            import traceback
            traceback.print_exc()
            raise

    def _run_executive_summary(self, extracted_data, analysis_results):
        """Phase 6: generate AI executive summary post-review. Factored out so refresh can skip it."""
        ai_results = analysis_results.get('ai_analysis', {})
        # Idempotency: if a summary is already on disk (from a prior finalize that crashed in Phase 7), reuse it. Prevents re-paying ~$1.30/run for the executive summary API call.
        if ai_results.get('conversation_summary'):
            logger.info("\n[*] Executive summary already generated — skipping Phase 6 (no cost)")
            return
        batch_was_skipped = getattr(self.config, 'skip_ai_tagging', False)
        if not batch_was_skipped and not (ai_results and ai_results.get('total_messages', 0) > 0):
            logger.info("\n[*] No pre-screening results found — skipping executive summary")
            return

        logger.info("\n" + "="*60)
        logger.info("PHASE 6: EXECUTIVE SUMMARY (POST-REVIEW)")
        logger.info("="*60)
        try:
            from src.analyzers.ai_analyzer import AIAnalyzer
            from src.utils.pricing import get_pricing
            ai_analyzer = AIAnalyzer(forensic_recorder=self.forensic, config=self.config)
            if not ai_analyzer.client:
                logger.info("    Executive summary skipped — AI not configured")
                return

            ai_contacts = self.config.ai_contacts
            ai_specified = self.config.ai_contacts_specified
            summary_messages = [
                m for m in extracted_data.get('messages', [])
                if m.get('source') != 'counseling'
                and m.get('sender') in ai_contacts
                and m.get('recipient') in ai_contacts
                and (ai_specified is None
                     or m.get('sender') in ai_specified
                     or m.get('recipient') in ai_specified)
            ]
            summary_messages.sort(key=lambda m: m.get('timestamp', ''))

            if summary_messages:
                sample_text, msg_count, _ = (
                    ai_analyzer._format_messages_for_summary(summary_messages)
                )
                est_input = ai_analyzer._estimate_tokens(sample_text) + 500
                est_output = 4096
                sp = get_pricing(ai_analyzer.summary_model)
                est_cost = (
                    (est_input / 1_000_000) * sp['input']
                    + (est_output / 1_000_000) * sp['output']
                )
                logger.info(
                    f"    {len(summary_messages):,} messages for executive summary "
                    f"(~{est_input:,} input tokens)"
                )
                logger.info(
                    f"    Estimated summary cost: ~${est_cost:.4f} "
                    f"({ai_analyzer.summary_model})"
                )
                if est_cost > 1.00:
                    logger.info(
                        f"    Cost exceeds $1.00 — press Ctrl+C within "
                        f"5 seconds to abort..."
                    )
                    try:
                        import time as _time
                        _time.sleep(5)
                    except KeyboardInterrupt:
                        logger.info("\n    Summary generation aborted by user.")
                        return

            if summary_messages is not None:
                updated = ai_analyzer.generate_post_review_summary(
                    ai_results, messages=summary_messages
                )
                analysis_results['ai_analysis'] = updated
                # Persist immediately so a Phase 7 crash doesn't force us to re-pay this API call on rerun. Uses the same idempotency contract the top-of-function check reads.
                if self._analysis_results_path:
                    try:
                        with open(self._analysis_results_path, 'w') as f:
                            json.dump(analysis_results, f, indent=2, default=str)
                        logger.info(f"    Executive summary generated (persisted to disk)")
                    except Exception as persist_err:
                        logger.warning(f"    Executive summary generated but failed to persist: {persist_err}")
                else:
                    logger.info(f"    Executive summary generated")
            else:
                logger.info("    Executive summary skipped (user aborted)")
        except Exception as e:
            logger.info(f"    Executive summary error (non-fatal): {e}")

    def _run_post_review_phases(self, extracted_data, analysis_results, review_results,
                                skip_ai_summary: bool = False,
                                clear_state_on_success: bool = True):
        """Shared Phase 5-8 runner used by both finalize and refresh.

        Rebuilds the enriched DataFrame from saved analysis_results, then runs
        behavioral analysis, executive summary, reporting, and documentation.

        Args:
            skip_ai_summary: When True, skip the expensive Phase 6 AI executive summary.
                             Used by --refresh-attachments to avoid re-spending AI credits.
            clear_state_on_success: When False, leave pipeline_state.json intact after completion.
                             Used by --refresh-attachments since the run may still need --finalize.
        """
        # Reconstruct enriched DataFrame for Phase 5 behavioral analysis. During the initial run, Phase 2 enriches a DataFrame with threat/sentiment/pattern columns and saves it as self._enriched_df. Since finalize/refresh runs in a new process, we must rebuild it from the saved analysis results.
        import pandas as pd
        messages = extracted_data.get('messages', [])
        if messages:
            enriched_df = pd.DataFrame(messages)
            threat_details = analysis_results.get('threats', {}).get('details', [])
            if threat_details and len(threat_details) == len(enriched_df):
                threat_df = pd.DataFrame(threat_details)
                for col in ['threat_detected', 'threat_categories', 'threat_confidence', 'harmful_content']:
                    if col in threat_df.columns and col not in enriched_df.columns:
                        enriched_df[col] = threat_df[col].values
            sentiment_data = analysis_results.get('sentiment', [])
            if sentiment_data and len(sentiment_data) == len(enriched_df):
                sentiment_df = pd.DataFrame(sentiment_data)
                for col in ['sentiment_score', 'sentiment_polarity', 'sentiment_subjectivity']:
                    if col in sentiment_df.columns and col not in enriched_df.columns:
                        enriched_df[col] = sentiment_df[col].values
            pattern_data = analysis_results.get('patterns', [])
            if pattern_data and len(pattern_data) == len(enriched_df):
                pattern_df = pd.DataFrame(pattern_data)
                for col in ['patterns_detected', 'pattern_score']:
                    if col in pattern_df.columns and col not in enriched_df.columns:
                        enriched_df[col] = pattern_df[col].values
            self._enriched_df = enriched_df

        # Phase 5: Behavioral Analysis (post-review)
        try:
            behavioral_results = self.run_behavioral_phase(extracted_data, analysis_results, review_results)
            analysis_results['behavioral'] = behavioral_results
        except Exception as e:
            logger.info(f"\n[!] Behavioral analysis failed (non-fatal): {e}")
            analysis_results['behavioral'] = {}

        # Update third-party contact data (screenshots may have added more during analysis)
        extracted_data['third_party_contacts'] = self.third_party_registry.get_all()
        tp_summary = self.third_party_registry.get_summary()
        if tp_summary['total'] > 0:
            logger.info(f"\n[*] Discovered {tp_summary['total']} third-party contacts")
            for src, count in tp_summary['by_source'].items():
                logger.info(f"    {src}: {count}")

        # Phase 6: Executive Summary (post-review). Skip when called from --refresh-attachments.
        if skip_ai_summary:
            logger.info("\n[refresh] Skipping Phase 6 executive summary (preserves existing AI spend)")
        else:
            self._run_executive_summary(extracted_data, analysis_results)

        # Phase 7: Reporting
        reports = self.run_reporting_phase(extracted_data, analysis_results, review_results)

        # Phase 8: Documentation (pass review so the events timeline can show only reviewer-confirmed findings)
        documentation = self.run_documentation_phase(extracted_data, analysis_results, review_results)

        logger.info("\n" + "="*80)
        logger.info(" WORKFLOW COMPLETE ")
        logger.info("="*80)
        logger.info(f"\nAll outputs saved to: {self.config.output_dir}")
        logger.info("\nGenerated files:")
        for report_type, path in reports.items():
            logger.info(f"  - {report_type}: {Path(path).name}")
        for doc_type, path in documentation.items():
            logger.info(f"  - {doc_type}: {Path(path).name}")

        if clear_state_on_success:
            self._clear_pipeline_state()
        else:
            logger.info("[refresh] Leaving pipeline_state.json intact (run may still need --finalize)")

    def run_refresh_attachments(self):
        """Re-run extraction only against an already-reviewed run, preserving AI batch and review decisions.

        Use case: the user has downloaded previously-evicted iCloud attachments (or enabled DOWNLOAD_ICLOUD_ATTACHMENTS) and wants the attachment files catalogued so --finalize can embed them in fresh reports.

        Safety: re-running Phase 1 produces a bit-identical message set (SQLite ROWIDs are stable; the message-skip condition is unchanged; only previously-blank attachment fields are now populated), so ``threat_{idx}`` review IDs remain valid.

        Reports are NOT regenerated here. Run --finalize after this to produce updated reports.
        """
        logger.info("\n" + "="*80)
        logger.info(" FORENSIC MESSAGE ANALYZER — REFRESH ATTACHMENTS ")
        logger.info("="*80)
        logger.info(f"Session started: {datetime.now()}")
        logger.info(f"Run directory:   {self.config.output_dir}")

        state = self._load_pipeline_state()
        if not state:
            raise RuntimeError(
                "No pipeline state found. --refresh-attachments requires a completed run. "
                "Run the full pipeline first and finish the review."
            )
        if not state.get("review_complete"):
            logger.warning(
                "[!] review_complete is not set — review may still be in progress. "
                "When review is finished, run:  python3 run.py --mark-review-complete"
            )

        ana_path = state.get("analysis_results_path")
        rev_path = state.get("review_results_path")
        missing = []
        for label, path in [("Analysis results", ana_path), ("Review results", rev_path)]:
            if not path or not Path(path).exists():
                missing.append(f"{label}: {path or '(not set)'}")
        if missing:
            raise RuntimeError(
                "Pipeline state references missing files:\n  " + "\n  ".join(missing)
            )

        logger.info(f"\n[*] Loading saved analysis + review decisions...")
        logger.info(f"    Analysis: {Path(ana_path).name}")
        logger.info(f"    Review:   {Path(rev_path).name}")

        with open(ana_path) as f:
            analysis_results = json.load(f)
        with open(rev_path) as f:
            review_results = json.load(f)

        self._analysis_results_path = Path(ana_path)

        self.forensic.record_action(
            "refresh_attachments_started",
            "Re-extracting attachments against existing review + AI batch",
            {
                "state_timestamp": state.get("timestamp", "unknown"),
                "prior_extracted_data_path": state.get("extracted_data_path"),
            },
        )

        try:
            # Phase 1 (refresh mode): re-extract, preserve fresh attachment copies to output/attachments/
            extracted_data = self.run_extraction_phase(refresh_mode=True)

            # Update pipeline_state.json so the new extracted_data_path is recorded
            self._save_pipeline_state()

            logger.info("\n[✓] Attachment refresh complete.")
            logger.info("    Run --finalize to regenerate reports with the refreshed attachments.")

        except Exception as e:
            logger.info(f"\n[ERROR] Refresh failed: {e}")
            import traceback
            traceback.print_exc()
            raise

    def mark_review_complete(self):
        """Set review_complete=True in pipeline state after verifying review results exist.

        Used when the examiner finished tagging but exited the review UI via Pause or
        browser close instead of clicking 'Complete Review'. Requires a non-empty
        review_results file; records a forensic action for the audit trail.
        """
        state = self._load_pipeline_state()
        if not state:
            raise RuntimeError("No pipeline state found.")
        if state.get("review_complete"):
            logger.info("[mark-review-complete] Already marked complete — nothing to do.")
            return

        rev_path = state.get("review_results_path")
        if not rev_path or not Path(rev_path).exists():
            raise RuntimeError(
                "No review_results file found. Resume the review before marking complete."
            )

        with open(rev_path) as f:
            rev_data = json.load(f)
        total = rev_data.get("total_reviewed", 0)
        if total == 0:
            raise RuntimeError(
                "review_results exists but has 0 reviewed items. "
                "Tag at least one item before marking complete."
            )

        self._save_pipeline_state(review_complete=True)
        self.forensic.record_action(
            "review_marked_complete",
            "Examiner manually marked review complete via --mark-review-complete",
            {"review_results_path": rev_path, "total_reviewed": total},
        )
        logger.info(
            f"[✓] Review marked complete ({total} reviewed items). "
            f"You can now run --finalize or --refresh-attachments."
        )


    def recover_pipeline_state(self):
        """Reconstruct pipeline_state.json from artifacts found in the run directory.

        Use case: --refresh-attachments or --finalize cleared the state file, but
        all artifacts (extracted_data, analysis_results, ai_batch_results, review_results)
        still exist on disk. This lets --resume work without losing forensic chain.
        """
        out_dir = Path(self.config.output_dir)
        # Write recovered state to analysis/ (new layout); also check root (legacy) for existing state
        state_path = self.config.analysis_dir() / "pipeline_state.json"
        if state_path.exists() or (out_dir / "pipeline_state.json").exists():
            raise RuntimeError("pipeline_state.json already exists in this run_dir — nothing to recover.")

        def _latest(glob_pat):
            # Check analysis/ subdir first (new layout), then root (legacy)
            hits = sorted((out_dir / "analysis").glob(glob_pat)) if (out_dir / "analysis").is_dir() else []
            if not hits:
                hits = sorted(out_dir.glob(glob_pat))
            return hits[-1] if hits else None

        ext = _latest("extracted_data_*.json")
        ana = _latest("analysis_results_*.json")
        aib = _latest("ai_batch_results_*.json")
        rev = _latest("review_results_*.json")

        missing = [name for name, p in [("extraction", ext), ("analysis", ana)] if not p]
        if missing:
            raise RuntimeError(f"Cannot recover — missing required artifacts: {', '.join(missing)}")

        def _h(p):
            return self.forensic.compute_hash(p) if p else None

        recovered = {
            "timestamp": datetime.now().isoformat(),
            "extracted_data_path": str(ext),
            "analysis_results_path": str(ana),
            "ai_batch_results_path": str(aib) if aib else None,
            "review_results_path": str(rev) if rev else None,
            "review_session_id": None,
            "review_complete": False,
        }
        state_path.write_text(json.dumps(recovered, indent=2))

        self.forensic.record_action(
            "pipeline_state_recovered",
            "Reconstructed pipeline_state.json from existing artifacts after state was cleared",
            {
                "run_dir": str(out_dir),
                "extracted_data": {"path": str(ext), "sha256": _h(ext)},
                "analysis_results": {"path": str(ana), "sha256": _h(ana)},
                "ai_batch_results": {"path": str(aib) if aib else None, "sha256": _h(aib)},
                "review_results": {"path": str(rev) if rev else None, "sha256": _h(rev)},
            },
        )
        logger.info(f"[✓] Recovered pipeline state from {out_dir.name}.")
        if rev:
            logger.info(f"    review_results found — if review is complete, run:")
            logger.info(f"      python3 run.py --mark-review-complete \"{out_dir}\"")
            logger.info(f"      python3 run.py --finalize \"{out_dir}\"")
        else:
            logger.info(f"    No review_results found — resume review with:")
            logger.info(f"      python3 run.py --resume \"{out_dir}\"")

    def resume_ai_batch(self):
        """Resume an in-flight Anthropic batch after disconnect/sleep.

        Reads ``pipeline_state.json``'s ``ai_batch`` block, polls Anthropic for the
        batch ID stored there, collects the results, merges them into
        ``analysis_results``, and clears the in-flight marker. Safe to re-run; if
        the batch has already ended, the polling step is a no-op and the results
        iteration runs immediately.
        """
        state = self._load_pipeline_state()
        if not state:
            raise RuntimeError(
                "No pipeline_state.json found in this run directory — nothing to resume."
            )
        ai_batch = state.get("ai_batch")
        if not ai_batch:
            raise RuntimeError(
                "pipeline_state.json has no ai_batch block — nothing to resume. "
                "If you believe a batch is in flight, check forensic_log_*.jsonl "
                "for batch_api_created and reconstruct the state file manually."
            )

        batch_id = ai_batch.get("batch_id")
        messages_path = ai_batch.get("messages_path")
        if not batch_id:
            raise RuntimeError("ai_batch block is missing batch_id; cannot resume.")
        if not messages_path or not Path(messages_path).exists():
            raise RuntimeError(
                f"ai_batch.messages_path is missing or unreadable: {messages_path}. "
                "The cached message list is required to size analysis_results correctly."
            )

        with open(messages_path) as f:
            mapped_messages = json.load(f)
        message_count = len(mapped_messages)

        logger.info(f"\n[*] Resuming batch {batch_id} ({message_count} messages)")

        from .analyzers.ai_analyzer import AIAnalyzer
        ai_analyzer = AIAnalyzer(forensic_recorder=self.forensic, config=self.config)
        if not ai_analyzer.client:
            raise RuntimeError(
                "AI analyzer is not configured (no API key). Cannot resume batch."
            )

        def _state_writer(batch_info: dict):
            block = dict(batch_info)
            block["messages_path"] = str(messages_path)
            self._save_pipeline_state(ai_batch=block)

        ai_results = ai_analyzer.resume_batch(
            batch_id,
            log_message_count=message_count,
            generate_summary=False,
            state_writer=_state_writer,
        )

        threat_count = len(ai_results.get("threat_assessment", {}).get("details", []))
        cc_count = len(ai_results.get("coercive_control", {}).get("patterns", []))
        logger.info(f"    Resume complete - {threat_count} threats, {cc_count} coercive control patterns found")

        # Persist the AI batch results file (same shape Phase 3 would write).
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ai_output_file = self.config.analysis_dir() / f"ai_batch_results_{timestamp}.json"
        with open(ai_output_file, "w") as f:
            json.dump(ai_results, f, indent=2, default=str)
        self._ai_batch_results_path = ai_output_file
        logger.info(f"    AI batch results saved to {ai_output_file.name}")

        # Merge into analysis_results on disk so finalize can load the complete picture.
        analysis_path = state.get("analysis_results_path")
        if analysis_path and Path(analysis_path).exists():
            with open(analysis_path) as f:
                analysis_results = json.load(f)
            analysis_results["ai_analysis"] = ai_results
            with open(analysis_path, "w") as f:
                json.dump(analysis_results, f, indent=2, default=str)
            logger.info(f"    Merged AI results into {Path(analysis_path).name}")

        # Clear the in-flight marker and stamp the new ai_batch_results_path.
        self._save_pipeline_state(
            ai_batch=None,
            ai_batch_results_path=str(ai_output_file),
        )
        try:
            Path(messages_path).unlink()
        except (FileNotFoundError, OSError):
            pass

        out_dir = Path(self.config.output_dir)
        logger.info(f"\n[✓] Batch {batch_id} resumed successfully.")
        logger.info(f"    Continue with manual review:")
        logger.info(f"      python3 run.py --resume \"{out_dir}\"")


def main(config: Config = None, resume: bool = False):
    """Main entry point for the forensic analyzer (Phases 1-4).

    Runs extraction, local analysis, and manual review, then stops.
    Use ``finalize()`` to run the remaining phases.

    Args:
        config: Configuration instance. If None, creates a new one.
        resume: If True, resume from saved pipeline state (skip extraction + analysis).

    Returns:
        bool: True if completed successfully, False otherwise.
    """
    try:
        analyzer = ForensicAnalyzer(config)
        analyzer.run_full_analysis(resume=resume)
        return True
    except Exception as e:
        logger.info(f"\n[ERROR] Analysis failed: {e}")
        return False


def refresh_attachments(config: Config = None):
    """Entry point for re-extracting attachments on an already-reviewed run.

    Preserves AI batch results and review decisions; re-runs Phase 1 against the existing working copies and then Phases 5-8. Use after downloading iCloud-evicted attachments locally.
    """
    try:
        analyzer = ForensicAnalyzer(config)
        analyzer.run_refresh_attachments()
        return True
    except Exception as e:
        logger.info(f"\n[ERROR] Refresh failed: {e}")
        return False


def mark_review_complete(config: Config = None):
    """Entry point to mark the review complete from the CLI.

    Used when the examiner finished tagging but exited the web UI via Pause or
    browser close instead of clicking 'Complete Review'. Unlocks --finalize.
    """
    try:
        analyzer = ForensicAnalyzer(config)
        analyzer.mark_review_complete()
        return True
    except Exception as e:
        logger.info(f"\n[ERROR] mark-review-complete failed: {e}")
        return False


def recover_state(config: Config = None):
    """Entry point to recover pipeline_state.json from existing run artifacts.

    Used when --refresh-attachments or --finalize cleared the state file but all
    pipeline artifacts are still on disk. Records the recovery forensically and
    prints next-step instructions.

    Args:
        config: Configuration instance. ``config.output_dir`` must point to the run directory.

    Returns:
        bool: True if recovery succeeded, False otherwise.
    """
    try:
        analyzer = ForensicAnalyzer(config)
        analyzer.recover_pipeline_state()
        return True
    except Exception as e:
        logger.info(f"\n[ERROR] Recover-state failed: {e}")
        return False


def resume_batch_cli(config: Config = None):
    """Entry point to resume an in-flight Anthropic batch after disconnect/sleep.

    Reads ``pipeline_state.json`` for the ``ai_batch`` block written by Phase 3,
    polls Anthropic for the batch by ID, collects the results, and writes
    ``ai_batch_results_*.json`` plus the merged analysis. Use after the local
    process was killed (sleep, Wi-Fi loss, Ctrl+C) while a batch was still
    polling — the batch keeps running on Anthropic's side regardless.

    Args:
        config: Configuration instance. ``config.output_dir`` must point to the
            run directory of the original (interrupted) run.
    """
    try:
        analyzer = ForensicAnalyzer(config)
        analyzer.resume_ai_batch()
        return True
    except Exception as e:
        logger.info(f"\n[ERROR] Resume-batch failed: {e}")
        logger.exception(e)
        return False


def finalize(config: Config = None):
    """Entry point for the finalize (post-review) phase (Phases 4-7).

    Loads saved pipeline state including review decisions, then runs behavioral analysis, AI analysis, reporting, and documentation.

    Args:
        config: Configuration instance. ``config.output_dir`` must point to the run directory from the original pipeline run.

    Returns:
        bool: True if completed successfully, False otherwise.
    """
    try:
        analyzer = ForensicAnalyzer(config)
        analyzer.run_finalize()
        return True
    except Exception as e:
        logger.info(f"\n[ERROR] Finalize failed: {e}")
        return False