#!/usr/bin/env python3
"""
Configuration management for the forensic message analyzer.
Loads settings from environment variables and .env file.
"""

import os
import json
from pathlib import Path
from typing import List, Dict, Optional
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Config:
    """
    Manages configuration settings for the forensic message analyzer.
    Loads from .env file and provides validated access to settings.

    Search order for .env (first hit wins):
      1. ``env_path`` argument (typically from ``run.py --env <path>``).
      2. ``DOTENV_PATH`` environment variable.
      3. ``.env`` in the project root (the default for a fresh checkout).
      4. ``.env`` in the current working directory (convenience fallback).
    """

    def __init__(self, env_path=None):
        """Initialize configuration by loading environment variables.

        Args:
            env_path: Optional explicit path to a .env file. When set, it wins over every other location — typically passed from ``run.py --env``. When ``None``, the default project-root ``.env`` is used.
        """
        env_locations = []
        if env_path:
            env_locations.append(Path(env_path).expanduser())
        dotenv_env = os.environ.get('DOTENV_PATH', '').strip()
        if dotenv_env:
            env_locations.append(Path(dotenv_env).expanduser())
        env_locations.append(_PROJECT_ROOT / '.env')
        env_locations.append(Path('.env'))

        loaded = False
        for candidate in env_locations:
            if candidate and candidate.exists() and candidate.is_file():
                load_dotenv(candidate, override=True)
                logger.info(f"Loaded .env from: {candidate}")
                loaded = True
                break

        if not loaded:
            logger.warning("No .env file found. Using system environment variables only.")
            logger.info(f"Searched locations: {[str(p) for p in env_locations]}")

        # Load configuration values
        self._load_config()
    
    def _load_config(self):
        """Load configuration from environment variables."""
        # AI / Anthropic Claude settings
        # Two-model setup:
        #   AI_TAGGING_MODEL   - cheaper model for per-message batch classification
        #   AI_SUMMARY_MODEL - higher-quality model for the executive narrative summary
        # The legacy single AI_MODEL setting has been removed; both models above are configured independently. If only one is set, it is used for both roles.
        self.ai_endpoint = os.getenv('AI_ENDPOINT')
        self.ai_api_key = os.getenv('AI_API_KEY')
        self.ai_tagging_model = os.getenv('AI_TAGGING_MODEL')      # cheaper model for batch extraction
        self.ai_summary_model = os.getenv('AI_SUMMARY_MODEL')  # model for executive summary
        
        # Contact mappings - flexible system that allows custom names
        # PERSON1_NAME defines the name used in reports (e.g., "John Doe")
        # PERSON1_MAPPING contains the list of identifiers to match (phones, emails, names)
        person1_name = os.getenv('PERSON1_NAME', 'Person1')
        person2_name = os.getenv('PERSON2_NAME', 'Person2')
        person3_name = os.getenv('PERSON3_NAME', 'Person3')
        
        # Load contact mappings and expand phone number variations
        self.person1_contacts = self._expand_contact_mappings(self._parse_json_list('PERSON1_MAPPING'))
        self.person2_contacts = self._expand_contact_mappings(self._parse_json_list('PERSON2_MAPPING'))
        self.person3_contacts = self._expand_contact_mappings(self._parse_json_list('PERSON3_MAPPING'))
        
        # Store the actual names being used (these appear in reports)
        self.person1_name = person1_name
        self.person2_name = person2_name
        self.person3_name = person3_name
        
        # Create contact_mappings using the report names
        # This maps display names to their list of identifiers
        self.contact_mappings = {
            person1_name: self.person1_contacts,
            person2_name: self.person2_contacts,
            person3_name: self.person3_contacts,
        }

        # AI analysis contacts — which mapped persons' conversations get sent to AI
        # ai_contacts_specified: the explicit names from AI_CONTACTS (e.g. {"Jane Doe"})
        # ai_contacts: the full set including Me/PERSON1 (used to validate both parties are known)
        # Filter logic: at least one party must be in ai_contacts_specified, AND both parties must be in ai_contacts. This ensures only conversations WITH the specified person(s) are analyzed, not all conversations OF the user.
        # PERSON1 (the user) is always included in ai_contacts since 'Me' and PERSON1_NAME refer to the same person across different data sources.
        ai_contacts_raw = self._parse_json_list('AI_CONTACTS')
        if ai_contacts_raw:
            self.ai_contacts_specified = set(ai_contacts_raw)
            self.ai_contacts = self.ai_contacts_specified | {person1_name}
        else:
            self.ai_contacts_specified = None  # None means "all mapped contacts"
            self.ai_contacts = set(self.contact_mappings.keys())
        
        # Date range
        self.start_date = os.getenv('START_DATE')
        self.end_date = os.getenv('END_DATE')
        
        # Analysis thresholds
        self.threat_threshold = float(os.getenv('THREAT_CONFIDENCE_THRESHOLD', '0.5'))
        self.review_threshold = float(os.getenv('MANUAL_REVIEW_THRESHOLD', '0.5'))
        
        # Analysis settings
        self.batch_size = int(os.getenv('BATCH_SIZE', '50'))
        self.max_retries = int(os.getenv('MAX_RETRIES', '3'))
        self.enable_image_analysis = os.getenv('ENABLE_IMAGE_ANALYSIS', 'true').lower() == 'true'
        self.enable_sentiment = os.getenv('ENABLE_SENTIMENT_ANALYSIS', 'true').lower() == 'true'
        self.enable_ocr = os.getenv('ENABLE_OCR', 'true').lower() == 'true'
        
        # Data sources (expand ~ to home directory)
        self.whatsapp_source_dir = self._expand_path(os.getenv('WHATSAPP_SOURCE_DIR'))
        self.screenshot_source_dir = self._expand_path(os.getenv('SCREENSHOT_SOURCE_DIR'))
        self.email_source_dir = self._expand_path(os.getenv('EMAIL_SOURCE_DIR'))
        self.teams_source_dir = self._expand_path(os.getenv('TEAMS_SOURCE_DIR'))
        self.counseling_source_dir = self._expand_path(os.getenv('COUNSELING_SOURCE_DIR'))
        self.counseling_correlation_window_hours = int(os.getenv('COUNSELING_CORRELATION_WINDOW_HOURS', '48'))
        self.messages_db_path = self._expand_path(os.getenv('MESSAGES_DB_PATH'))
        self.messages_db_wal = self._expand_path(os.getenv('MESSAGES_DB_WAL'))
        self.messages_db_shm = self._expand_path(os.getenv('MESSAGES_DB_SHM'))
        
        # Review directory
        self.review_dir = self._expand_path(
            os.getenv('REVIEW_DIR', str(_PROJECT_ROOT / 'review'))
        )

        # Port the Flask review UI binds to. Override with REVIEW_PORT in .env when 5000 is taken (macOS AirPlay Receiver uses it by default) or to run two pipelines side by side. Validated into the unprivileged range so a typo can't try to bind to port 80.
        raw_port = os.getenv('REVIEW_PORT', '5000').strip() or '5000'
        try:
            port_val = int(raw_port)
        except ValueError as exc:
            raise ValueError(f"REVIEW_PORT must be an integer, got {raw_port!r}") from exc
        if not (1024 <= port_val <= 65535):
            raise ValueError(f"REVIEW_PORT must be between 1024 and 65535, got {port_val}")
        self.review_port = port_val

        # Review interface mode. Default is "web" (Flask). Set REVIEW_MODE=terminal in .env to use the sequential terminal reviewer instead.
        self.review_mode = os.getenv('REVIEW_MODE', 'web').strip().lower()
        if self.review_mode not in ('web', 'terminal'):
            raise ValueError(f"REVIEW_MODE must be 'web' or 'terminal', got {self.review_mode!r}")

        # AI processing mode
        self.use_batch_api = os.getenv('USE_BATCH_API', 'true').lower() == 'true'
        self.skip_ai_tagging = os.getenv('SKIP_AI_TAGGING', 'false').lower() == 'true'
        # DOCX → PDF via docx2pdf drives MS Word over AppleScript; on this examiner's build it has been throwing "Message not understood" and stranding the finalize. Set SKIP_DOCX_PDF=true in .env to skip Word conversion entirely (DOCX files are still produced; methodology PDF still renders via WeasyPrint).
        self.skip_docx_pdf = os.getenv('SKIP_DOCX_PDF', 'false').lower() == 'true'

        # Rate limiting (used in synchronous mode only; batch API handles its own limits)
        self.max_requests_per_minute = int(os.getenv('MAX_REQUESTS_PER_MINUTE', '40'))
        self.tokens_per_minute = int(os.getenv('TOKENS_PER_MINUTE', '25000'))
        self.request_delay_ms = int(os.getenv('REQUEST_DELAY_MS', '1500'))
        self.max_tokens_per_request = int(os.getenv('MAX_TOKENS_PER_REQUEST', '4096'))
        
        # Output settings
        self.output_dir = self._expand_path(
            os.getenv('OUTPUT_DIR', str(_PROJECT_ROOT / 'output'))
        )
        
        # Legal compliance / case identification
        # CASE_NUMBER may be a single value (e.g. "2024-FL-12345") OR a JSON array of strings (e.g. '["2024-FL-12345","2024-FL-67890"]') for consolidated runs that span multiple matters. CASE_NUMBERS (plural) is also accepted as a JSON array.
        # case_number  - single string (joined with newlines for display)
        # case_numbers - list of strings, in input order, for per-line rendering
        self.case_numbers = self._parse_case_numbers()
        self.case_number = "\n".join(self.case_numbers) if self.case_numbers else ''
        self.examiner_name = os.getenv('EXAMINER_NAME', '')
        self.case_names = self._parse_case_names()
        self.case_name = "\n".join(self.case_names) if self.case_names else ''
        self.timezone = os.getenv('ANALYSIS_TIMEZONE', 'America/Los_Angeles')
        self.organization = os.getenv('ORGANIZATION', '')

        # Logging
        self.log_level = os.getenv('LOG_LEVEL', 'INFO')

        # Optional: directory of vCard (.vcf) exports to auto-merge into contact_mappings before extraction. Reduces the "Unknown" surface area and auto-labels third-party identifiers with their actual names.
        self.contacts_vcard_dir = self._expand_path(os.getenv('CONTACTS_VCARD_DIR'))

        # Optional: path to a long-lived examiner Ed25519 private key (PEM). When set, signed outputs chain back to the examiner's published public key. When unset, a per-run ephemeral key is generated in run_dir/keys/ — still tamper-evident within the run, but not anchored to an external identity.
        self.examiner_signing_key = self._expand_path(os.getenv('EXAMINER_SIGNING_KEY'))

        # Attachment handling
        # DOWNLOAD_ICLOUD_ATTACHMENTS: before extraction, walk ~/Library/Messages/Attachments and force-download iCloud-evicted files via `brctl download`. Default off; the user must also disable "Optimize Mac Storage" in Messages for fully-evicted files to be recoverable.
        self.download_icloud_attachments = os.getenv('DOWNLOAD_ICLOUD_ATTACHMENTS', 'false').lower() == 'true'
        # COMPRESS_ATTACHMENTS: re-encode large PNG/JPEG copies in output/attachments/ to save disk. HEIC passes through unchanged (iPhone-native; re-encoding would be a lossy derivative). Originals at ~/Library/Messages/Attachments/ are never modified.
        self.compress_attachments = os.getenv('COMPRESS_ATTACHMENTS', 'false').lower() == 'true'
        self.attachment_compress_threshold_mb = float(os.getenv('ATTACHMENT_COMPRESS_THRESHOLD_MB', '5.0'))
        self.attachment_jpeg_quality = int(os.getenv('ATTACHMENT_JPEG_QUALITY', '75'))
        self.attachment_max_dimension_px = int(os.getenv('ATTACHMENT_MAX_DIMENSION_PX', '2048'))
        
        # Ensure critical directories exist
        self._ensure_directories()
    
    def _expand_path(self, path: Optional[str]) -> Optional[str]:
        """Expand ~ in paths to actual home directory."""
        if path:
            return str(Path(path).expanduser())
        return None
    
    def _parse_json_list(self, env_var: str) -> List[str]:
        """Parse JSON list from environment variable.

        Raises ValueError when the env var is set to something non-empty that fails to parse as JSON, so malformed contact mappings fail fast instead of silently becoming an empty list. An unset or empty env var returns [] as before.
        """
        value = os.getenv(env_var, '')
        if not value or value == 'None':
            return []
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{env_var} is not valid JSON: {exc.msg}") from exc
        if not isinstance(parsed, list):
            raise ValueError(f"{env_var} must be a JSON array, got {type(parsed).__name__}")
        return parsed

    def snapshot(self) -> Dict[str, object]:
        """Return a serializable snapshot of this config for the run manifest.

        Redacts secrets (api keys) and resolves Paths to strings so downstream writers can json.dump the result directly. Every setting a reader would need to reproduce the run is included.
        """
        def _redact(value):
            if not value:
                return None
            return f"<redacted:{len(str(value))}>"

        return {
            "ai": {
                "endpoint": self.ai_endpoint,
                "api_key": _redact(self.ai_api_key),
                "tagging_model": self.ai_tagging_model,
                "summary_model": self.ai_summary_model,
                "use_batch_api": self.use_batch_api,
                "skip_ai_tagging": self.skip_ai_tagging,
                "skip_docx_pdf": self.skip_docx_pdf,
                "max_requests_per_minute": self.max_requests_per_minute,
                "tokens_per_minute": self.tokens_per_minute,
                "request_delay_ms": self.request_delay_ms,
                "max_tokens_per_request": self.max_tokens_per_request,
                "ai_contacts_specified": sorted(self.ai_contacts_specified) if self.ai_contacts_specified else None,
                "ai_contacts": sorted(self.ai_contacts),
            },
            "persons": {
                "person1_name": self.person1_name,
                "person2_name": self.person2_name,
                "person3_name": self.person3_name,
                "contact_mappings": {k: list(v) for k, v in self.contact_mappings.items()},
            },
            "sources": {
                "messages_db_path": self.messages_db_path,
                "messages_db_wal": self.messages_db_wal,
                "messages_db_shm": self.messages_db_shm,
                "whatsapp_source_dir": self.whatsapp_source_dir,
                "screenshot_source_dir": self.screenshot_source_dir,
                "email_source_dir": self.email_source_dir,
                "teams_source_dir": self.teams_source_dir,
                "counseling_source_dir": self.counseling_source_dir,
                "counseling_correlation_window_hours": self.counseling_correlation_window_hours,
            },
            "analysis": {
                "start_date": self.start_date,
                "end_date": self.end_date,
                "threat_threshold": self.threat_threshold,
                "review_threshold": self.review_threshold,
                "batch_size": self.batch_size,
                "max_retries": self.max_retries,
                "enable_image_analysis": self.enable_image_analysis,
                "enable_sentiment": self.enable_sentiment,
                "enable_ocr": self.enable_ocr,
            },
            "case": {
                "case_numbers": list(self.case_numbers),
                "case_names": list(self.case_names),
                "examiner_name": self.examiner_name,
                "organization": self.organization,
                "timezone": self.timezone,
            },
            "paths": {
                "output_dir": self.output_dir,
                "review_dir": self.review_dir,
            },
            "review_ui": {
                "port": self.review_port,
                "mode": self.review_mode,
            },
            "attachments": {
                "download_icloud_attachments": self.download_icloud_attachments,
                "compress_attachments": self.compress_attachments,
                "compress_threshold_mb": self.attachment_compress_threshold_mb,
                "jpeg_quality": self.attachment_jpeg_quality,
                "max_dimension_px": self.attachment_max_dimension_px,
            },
        }

    def _parse_case_numbers(self) -> List[str]:
        """Parse case numbers from CASE_NUMBER (string or JSON array) or CASE_NUMBERS.

        Accepts any of:
          CASE_NUMBER=2024-FL-12345                    -> ["2024-FL-12345"]
          CASE_NUMBER='["2024-FL-12345","2024-FL-67"]' -> ["2024-FL-12345","2024-FL-67"]
          CASE_NUMBERS='["2024-FL-12345","2024-FL-67"]' -> ["2024-FL-12345","2024-FL-67"]

        Returns ordered, de-duplicated list of non-empty strings.
        """
        raw_single = os.getenv('CASE_NUMBER', '').strip()
        raw_plural = os.getenv('CASE_NUMBERS', '').strip()

        candidates: List[str] = []

        for raw in (raw_single, raw_plural):
            if not raw:
                continue
            # JSON array form
            if raw.startswith('['):
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, list):
                        candidates.extend(str(x).strip() for x in parsed if str(x).strip())
                except json.JSONDecodeError:
                    logger.warning(
                        f"Could not parse case numbers as JSON; ignoring malformed value: {raw}"
                    )
                # JSON-array-shaped values never fall through to single-string treatment; otherwise a malformed '[...' would be appended verbatim as a "case number".
                continue
            # Single string form
            candidates.append(raw)

        # De-duplicate while preserving order
        seen = set()
        ordered: List[str] = []
        for c in candidates:
            if c and c not in seen:
                seen.add(c)
                ordered.append(c)
        return ordered

    def _parse_case_names(self) -> List[str]:
        """Parse case names from CASE_NAME (string or JSON array) or CASE_NAMES.

        Accepts any of:
          CASE_NAME=Smith v. Smith                        -> ["Smith v. Smith"]
          CASE_NAME='["Smith v. Smith","Jones v. Jones"]' -> ["Smith v. Smith","Jones v. Jones"]
          CASE_NAMES='["Smith v. Smith","Jones v. Jones"]' -> ["Smith v. Smith","Jones v. Jones"]

        Returns ordered, de-duplicated list of non-empty strings.
        """
        raw_single = os.getenv('CASE_NAME', '').strip()
        raw_plural = os.getenv('CASE_NAMES', '').strip()

        candidates: List[str] = []

        for raw in (raw_single, raw_plural):
            if not raw:
                continue
            if raw.startswith('['):
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, list):
                        candidates.extend(str(x).strip() for x in parsed if str(x).strip())
                except json.JSONDecodeError:
                    logger.warning(
                        f"Could not parse case names as JSON; ignoring malformed value: {raw}"
                    )
                continue
            candidates.append(raw)

        seen = set()
        ordered: List[str] = []
        for c in candidates:
            if c and c not in seen:
                seen.add(c)
                ordered.append(c)
        return ordered

    def _normalize_phone_number(self, phone: str) -> List[str]:
        """
        Generate common format variations of a phone number.
        
        Args:
            phone: Phone number in any format (e.g., "+12345678901", "234-567-8901")
            
        Returns:
            List of phone number variations including:
            - Original format
            - E.164 format (+12345678901)
            - Dashed format (234-567-8901)
            - Parentheses format ((234) 567-8901)
        """
        import re
        
        # Extract just the digits
        digits = re.sub(r'\D', '', phone)
        
        # Skip if not a valid phone number length (assuming US/Canada)
        if len(digits) < 10:
            return [phone]
        
        variations = [phone]  # Always include original
        
        # Handle different lengths
        if len(digits) == 10:
            # US/Canada number without country code
            area = digits[0:3]
            prefix = digits[3:6]
            line = digits[6:10]
            
            # Add E.164 format with +1
            variations.append(f"+1{digits}")
            # Add dashed format
            variations.append(f"{area}-{prefix}-{line}")
            # Add parentheses format
            variations.append(f"({area}) {prefix}-{line}")
            
        elif len(digits) == 11 and digits[0] == '1':
            # US/Canada number with country code
            area = digits[1:4]
            prefix = digits[4:7]
            line = digits[7:11]
            
            # Add E.164 format
            variations.append(f"+{digits}")
            # Add dashed format (without country code)
            variations.append(f"{area}-{prefix}-{line}")
            # Add parentheses format (without country code)
            variations.append(f"({area}) {prefix}-{line}")
            # Add 10-digit format
            variations.append(digits[1:])
            
        else:
            # International or non-standard format
            # Just add E.164 if not already present
            if not phone.startswith('+'):
                variations.append(f"+{digits}")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_variations = []
        for var in variations:
            if var not in seen:
                seen.add(var)
                unique_variations.append(var)
        
        return unique_variations
    
    def _expand_contact_mappings(self, contacts: List[str]) -> List[str]:
        """
        Expand contact list to include phone number variations.
        
        Args:
            contacts: List of contact identifiers (phones, emails, names)
            
        Returns:
            Expanded list with phone number variations included
        """
        import re
        
        expanded = []
        phone_pattern = re.compile(r'[\d\+\(\)\-\s]{10,}')  # Matches phone-like strings
        
        for contact in contacts:
            expanded.append(contact)  # Always include original
            
            # If it looks like a phone number, add variations
            if phone_pattern.match(contact.strip()):
                variations = self._normalize_phone_number(contact)
                expanded.extend([v for v in variations if v != contact])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_expanded = []
        for item in expanded:
            if item not in seen:
                seen.add(item)
                unique_expanded.append(item)
        
        return unique_expanded
    
    # ------------------------------------------------------------------
    # Subfolder helpers (run-directory layout)
    # ------------------------------------------------------------------

    def _subdir(self, name: str) -> Path:
        p = Path(self.output_dir) / name
        p.mkdir(parents=True, exist_ok=True)
        return p

    def reports_dir(self) -> Path:
        """Subfolder for user-facing deliverables (reports, timelines, cover sheets)."""
        return self._subdir("reports")

    def forensic_dir(self) -> Path:
        """Subfolder for audit-chain artifacts (COC, forensic log, HMAC key, manifest)."""
        return self._subdir("forensic")

    def analysis_dir(self) -> Path:
        """Subfolder for pipeline intermediates (extracted_data, analysis, ai_batch, review results, pipeline_state)."""
        return self._subdir("analysis")

    def sources_dir(self) -> Path:
        """Subfolder for preserved source inputs (working_copies, attachments, preserved_sources.zip)."""
        return self._subdir("sources")

    def _ensure_directories(self):
        """Create necessary directories if they don't exist."""
        directories = [
            self.output_dir,
            self.review_dir,
        ]

        for dir_path in directories:
            if dir_path:
                path = Path(dir_path)
                if not path.exists():
                    try:
                        path.mkdir(parents=True, exist_ok=True)
                        logger.info(f"Created directory: {path}")
                    except Exception as e:
                        logger.warning(f"Could not create directory {path}: {e}")
    
    def validate(self) -> tuple[bool, List[str]]:
        """
        Validate configuration settings.
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Check required paths
        if not self.output_dir:
            errors.append("OUTPUT_DIR not configured")
        
        # Check for at least one data source
        if not any([self.messages_db_path, self.whatsapp_source_dir, self.screenshot_source_dir, self.email_source_dir, self.teams_source_dir, self.counseling_source_dir]):
            errors.append("No data sources configured (need iMessage, WhatsApp, email, Teams, screenshots, or counseling)")
        
        # Check AI configuration if analysis is expected
        if self.ai_endpoint and not self.ai_api_key:
            errors.append("AI endpoint configured but API key missing")
        
        return len(errors) == 0, errors
    
    def get_source_info(self) -> Dict[str, str]:
        """
        Get information about configured data sources.
        
        Returns:
            Dictionary of source type to path
        """
        sources = {}
        
        if self.messages_db_path:
            sources['iMessage'] = self.messages_db_path
        if self.whatsapp_source_dir:
            sources['WhatsApp'] = self.whatsapp_source_dir
        if self.screenshot_source_dir:
            sources['Screenshots'] = self.screenshot_source_dir
        if self.email_source_dir:
            sources['Email'] = self.email_source_dir
        if self.teams_source_dir:
            sources['Teams'] = self.teams_source_dir
        if self.counseling_source_dir:
            sources['Counseling'] = self.counseling_source_dir

        return sources
