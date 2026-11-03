#!/usr/bin/env python3
"""Ghost Process: Autonomous Asymmetric Threat Intelligence Pipeline.

Ingests security RSS/Atom feeds asynchronously, deduplicates against Supabase,
distills actionable TTPs via Groq (Llama-3.1-8B-Instant), and dual-routes alerts
to Telegram (Real-time Emergencies vs. Daily Routine Digests).
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import html
import json
import logging
import os
from pathlib import Path
import random
import re
import sys
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple, TypeVar

import aiohttp
import feedparser
from groq import (
    APIConnectionError,
    APIStatusError,
    AuthenticationError,
    AsyncGroq,
    PermissionDeniedError,
    RateLimitError,
)
from supabase import Client, create_client

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stdout,
)
logger = logging.getLogger("ghost_process")

T = TypeVar("T")

# ---------------------------------------------------------------------------
# Constants & Feed Sources
# ---------------------------------------------------------------------------
GROQ_MODEL = "llama-3.1-8b-instant"
MAX_ITEMS_PER_FEED = int(os.getenv("MAX_ITEMS_PER_FEED", "6"))
LLM_CONCURRENCY_LIMIT = int(os.getenv("LLM_CONCURRENCY_LIMIT", "1"))
TELEGRAM_MAX_MESSAGE_LEN = 4000  # Safe margin below Telegram's 4096-char hard limit

DEFAULT_SECURITY_FEEDS: Dict[str, str] = {
    "Exploit-DB": "https://www.exploit-db.com/rss.xml",
    "SANS-ISC-ThreatIntel": "https://isc.sans.edu/rssfeed_full.xml",
    "The-Hacker-News-ZeroDays": "https://feeds.feedburner.com/TheHackersNews",
    "Google-Project-Zero": "https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss",
    "TrailOfBits-AI-AppSec": "https://blog.trailofbits.com/index.xml",
}

CVE_REGEX = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)
CVSS_REGEX = re.compile(
    r"(?:CVSS(?:\s*v?[234](?:\.\d)?)?[\s:=-]*|base\s+score[\s:=-]*)(10(?:\.0)?|[0-9]\.[0-9])",
    re.IGNORECASE,
)
EMERGENCY_KEYWORDS_REGEX = re.compile(
    r"\b(?:0-day|zero-day|zero\s+day|actively\s+exploited|active\s+exploitation|"
    r"exploited\s+in\s+the\s+wild|prompt\s+injection|agentic\s+ssrf)\b",
    re.IGNORECASE,
)
HTML_TAG_REGEX = re.compile(r"<[^>]+>")

SYSTEM_PROMPT = """You are an elite Principal AppSec Threat Intelligence Analyst.
Analyze the provided raw vulnerability or security advisory payload and distill it into a strict JSON object.

CRITICAL OUTPUT REQUIREMENTS:
1. You MUST respond ONLY with a valid JSON object containing EXACTLY two keys:
   - "severity_flag": String, must be either "EMERGENCY" or "ROUTINE".
   - "markdown_report": String, concise and actionable Telegram-compatible Markdown report.

2. CLASSIFICATION RULES FOR "severity_flag":
   Set "severity_flag" to "EMERGENCY" if ANY of the following conditions apply:
   - Involves a 0-day / zero-day vulnerability.
   - Indicates Active Exploitation in the wild (or CISA KEV inclusion).
   - Has a CVSS score strictly greater than 9.0 (CVSS > 9.0).
   - Involves "Prompt Injection" (direct or indirect LLM prompt injection).
   - Involves "Agentic SSRF" (or autonomous AI agent tool-use SSRF/RCE).
   Otherwise, set "severity_flag" to "ROUTINE".

3. FORMATTING RULES FOR "markdown_report":
   - Keep it stripped-down, high-signal, and immediately actionable for SecOps engineers.
   - Include:
     * **Summary & Impact**: 1-2 sentences on affected component/version and root cause.
     * **TTPs / Exploitation Vector**: MITRE ATT&CK or tactical exploitation mechanics.
     * **Remediation / Mitigations**: Concrete patches, workarounds, or detection rules.
   - Avoid filler text and avoid nested code blocks inside bullet points.
"""


def load_dotenv_if_present(dotenv_path: Optional[Path] = None) -> None:
    """Loads key=value pairs from a local .env file into os.environ without external deps."""
    target_path = dotenv_path or (Path(__file__).resolve().parent / ".env")
    if not target_path.is_file():
        return

    for raw_line in target_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = value


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Config:
    """Runtime configuration populated from environment variables."""

    supabase_url: str
    supabase_key: str
    groq_api_key: str
    telegram_bot_token: str
    telegram_chat_id: str

    @classmethod
    def from_env(cls, require_groq: bool = True) -> "Config":
        """Loads and validates environment variables (including local .env if present)."""
        load_dotenv_if_present()
        required_vars = [
            "SUPABASE_URL",
            "SUPABASE_KEY",
            "TELEGRAM_BOT_TOKEN",
            "TELEGRAM_CHAT_ID",
        ]
        if require_groq:
            required_vars.append("GROQ_API_KEY")

        missing = [var for var in required_vars if not os.getenv(var)]
        if missing:
            raise EnvironmentError(
                f"Missing required environment variables: {', '.join(missing)}"
            )

        return cls(
            supabase_url=os.environ["SUPABASE_URL"].strip(),
            supabase_key=os.environ["SUPABASE_KEY"].strip(),
            groq_api_key=os.getenv("GROQ_API_KEY", "").strip(),
            telegram_bot_token=os.environ["TELEGRAM_BOT_TOKEN"].strip(),
            telegram_chat_id=os.environ["TELEGRAM_CHAT_ID"].strip(),
        )


@dataclass(frozen=True)
class ThreatPacket:
    """Normalized representation of an ingested security feed item."""

    threat_hash: str
    cve_id: Optional[str]
    source_feed: str
    title: str
    summary: str
    source_url: str
    published_at: Optional[str]


@dataclass(frozen=True)
class DistilledThreat:
    """LLM-classified and distilled threat intelligence report."""

    severity_flag: str  # "EMERGENCY" or "ROUTINE"
    markdown_report: str


# ---------------------------------------------------------------------------
# Exponential Backoff Utility
# ---------------------------------------------------------------------------
async def retry_with_backoff(
    coro_factory: Callable[[], Coroutine[Any, Any, T]],
    *,
    operation_name: str,
    max_attempts: int = 4,
    base_delay: float = 1.5,
    max_delay: float = 30.0,
) -> T:
    """Executes an async operation with exponential backoff and full jitter."""
    last_exc: Optional[BaseException] = None
    for attempt in range(1, max_attempts + 1):
        try:
            return await coro_factory()
        except asyncio.CancelledError:
            raise
        except (AuthenticationError, PermissionDeniedError) as auth_exc:
            logger.error(
                "%s aborted immediately due to authentication error: %s",
                operation_name,
                auth_exc,
            )
            raise
        except Exception as exc:  # pylint: disable=broad-exception-caught
            last_exc = exc
            if attempt >= max_attempts:
                logger.error(
                    "%s failed permanently after %d attempts: %s",
                    operation_name,
                    max_attempts,
                    exc,
                )
                break

            sleep_window = min(max_delay, base_delay * (2 ** (attempt - 1)))
            delay = random.uniform(sleep_window * 0.5, sleep_window)
            logger.warning(
                "%s failed (attempt %d/%d): %s. Retrying in %.2fs...",
                operation_name,
                attempt,
                max_attempts,
                exc,
                delay,
            )
            await asyncio.sleep(delay)

    assert last_exc is not None
    raise last_exc


# ---------------------------------------------------------------------------
# Module 1: Ingestion & Deduplication
# ---------------------------------------------------------------------------
def clean_html(raw_text: str, max_length: int = 3500) -> str:
    """Strips HTML tags, unescapes entities, and normalizes whitespace."""
    if not raw_text:
        return ""
    unescaped = html.unescape(raw_text)
    stripped = HTML_TAG_REGEX.sub(" ", unescaped)
    normalized = " ".join(stripped.split())
    return normalized[:max_length]


def extract_cve_id(text: str) -> Optional[str]:
    """Extracts the primary CVE identifier from text if present."""
    match = CVE_REGEX.search(text)
    return match.group(1).upper() if match else None


def compute_threat_hash(
    cve_id: Optional[str],
    entry_id: str,
    link: str,
    title: str,
) -> str:
    """Computes a deterministic SHA-256 hash for deduplication."""
    if cve_id:
        canonical = f"cve:{cve_id.upper()}"
    else:
        stable_key = entry_id.strip() or link.strip() or title.strip()
        canonical = f"raw:{stable_key.lower()}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def fetch_single_feed(
    session: aiohttp.ClientSession,
    feed_name: str,
    feed_url: str,
) -> List[ThreatPacket]:
    """Fetches and parses a single RSS/Atom security feed asynchronously."""

    async def _do_fetch() -> str:
        async with session.get(feed_url) as response:
            if response.status >= 400:
                raise aiohttp.ClientResponseError(
                    request_info=response.request_info,
                    history=response.history,
                    status=response.status,
                    message=f"HTTP {response.status} from {feed_url}",
                    headers=response.headers,
                )
            return await response.text(errors="replace")

    try:
        xml_payload = await retry_with_backoff(
            _do_fetch,
            operation_name=f"Fetch RSS [{feed_name}]",
            max_attempts=3,
            base_delay=2.0,
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("Skipping feed [%s] due to fetch failure: %s", feed_name, exc)
        return []

    parsed_feed = await asyncio.to_thread(feedparser.parse, xml_payload)
    entries = getattr(parsed_feed, "entries", [])[:MAX_ITEMS_PER_FEED]

    packets: List[ThreatPacket] = []
    for entry in entries:
        title = clean_html(entry.get("title", "Untitled Threat Advisory"), max_length=300)
        summary = clean_html(
            entry.get("summary") or entry.get("description") or "",
            max_length=3500,
        )
        link = (entry.get("link") or "").strip()
        entry_id = (entry.get("id") or entry.get("guid") or link or title).strip()
        published_struct = entry.get("published_parsed") or entry.get("updated_parsed")
        published_iso: Optional[str] = None
        if published_struct:
            try:
                published_iso = datetime(
                    *published_struct[:6], tzinfo=timezone.utc
                ).isoformat()
            except (TypeError, ValueError):
                published_iso = None

        combined_text = f"{title} {summary} {entry_id}"
        cve_id = extract_cve_id(combined_text)
        threat_hash = compute_threat_hash(cve_id, entry_id, link, title)

        packets.append(
            ThreatPacket(
                threat_hash=threat_hash,
                cve_id=cve_id,
                source_feed=feed_name,
                title=title,
                summary=summary,
                source_url=link or "https://nvd.nist.gov",
                published_at=published_iso,
            )
        )

    logger.info("Ingested %d candidate packets from [%s].", len(packets), feed_name)
    return packets


async def ingest_all_feeds(
    feeds: Optional[Dict[str, str]] = None,
) -> List[ThreatPacket]:
    """Fetches all configured security RSS feeds concurrently and deduplicates in-memory."""
    active_feeds = feeds or DEFAULT_SECURITY_FEEDS
    timeout = aiohttp.ClientTimeout(total=25, connect=10)
    headers = {
        "User-Agent": "GhostProcess-ThreatIntel/1.0 (+https://github.com; Security-Automation)",
        "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
    }

    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        tasks = [
            fetch_single_feed(session, name, url)
            for name, url in active_feeds.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    unique_packets: List[ThreatPacket] = []
    seen_hashes: Set[str] = set()
    seen_cves: Set[str] = set()

    for result in results:
        if isinstance(result, BaseException):
            logger.error("Unexpected error in feed task: %s", result)
            continue
        for packet in result:
            if packet.threat_hash in seen_hashes:
                continue
            if packet.cve_id and packet.cve_id in seen_cves:
                continue
            seen_hashes.add(packet.threat_hash)
            if packet.cve_id:
                seen_cves.add(packet.cve_id)
            unique_packets.append(packet)

    logger.info(
        "Total unique candidate packets across all feeds: %d",
        len(unique_packets),
    )
    return unique_packets


async def filter_unseen_packets(
    supabase: Client,
    packets: List[ThreatPacket],
) -> List[ThreatPacket]:
    """Queries Supabase `threat_intel_cache` and drops packets whose hash or CVE exists."""
    if not packets:
        return []

    candidate_hashes = [p.threat_hash for p in packets]
    candidate_cves = [p.cve_id for p in packets if p.cve_id]

    def _query_existing() -> Tuple[Set[str], Set[str]]:
        existing_hashes: Set[str] = set()
        existing_cves: Set[str] = set()

        # Query matching threat_hash values in batches
        batch_size = 100
        for i in range(0, len(candidate_hashes), batch_size):
            batch = candidate_hashes[i : i + batch_size]
            resp = (
                supabase.table("threat_intel_cache")
                .select("threat_hash")
                .in_("threat_hash", batch)
                .execute()
            )
            for row in resp.data or []:
                if row.get("threat_hash"):
                    existing_hashes.add(row["threat_hash"])

        # Query matching cve_id values in batches
        for i in range(0, len(candidate_cves), batch_size):
            batch = candidate_cves[i : i + batch_size]
            resp = (
                supabase.table("threat_intel_cache")
                .select("cve_id")
                .in_("cve_id", batch)
                .execute()
            )
            for row in resp.data or []:
                if row.get("cve_id"):
                    existing_cves.add(row["cve_id"].upper())

        return existing_hashes, existing_cves

    existing_hashes, existing_cves = await retry_with_backoff(
        lambda: asyncio.to_thread(_query_existing),
        operation_name="Supabase deduplication lookup",
    )

    new_packets: List[ThreatPacket] = []
    dropped_count = 0
    for packet in packets:
        if packet.threat_hash in existing_hashes or (
            packet.cve_id and packet.cve_id.upper() in existing_cves
        ):
            dropped_count += 1
            continue
        new_packets.append(packet)

    logger.info(
        "Deduplication complete: %d cached packets dropped, %d new packets queued for LLM.",
        dropped_count,
        len(new_packets),
    )
    return new_packets


# ---------------------------------------------------------------------------
# Module 2: LLM Distillation & Packet Classification (Groq API)
# ---------------------------------------------------------------------------
def evaluate_emergency_heuristics(packet: ThreatPacket) -> bool:
    """Deterministic safeguard for 0-days, CVSS > 9.0, Prompt Injection, and Agentic SSRF."""
    blob = f"{packet.title}\n{packet.summary}"
    if EMERGENCY_KEYWORDS_REGEX.search(blob):
        return True

    for match in CVSS_REGEX.finditer(blob):
        try:
            score = float(match.group(1))
            if score > 9.0:
                return True
        except ValueError:
            continue

    return False


async def classify_and_distill_packet(
    groq_client: AsyncGroq,
    packet: ThreatPacket,
    semaphore: asyncio.Semaphore,
) -> DistilledThreat:
    """Sends a new threat payload to Groq (`llama-3.1-8b-instant`) and enforces JSON output."""
    user_payload = (
        f"Source Feed: {packet.source_feed}\n"
        f"CVE ID: {packet.cve_id or 'N/A'}\n"
        f"Title: {packet.title}\n"
        f"URL: {packet.source_url}\n"
        f"Raw Advisory Content:\n{packet.summary or 'No additional description provided.'}"
    )

    async def _call_groq() -> DistilledThreat:
        completion = await groq_client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_payload},
            ],
            temperature=0.1,
            max_tokens=900,
            response_format={"type": "json_object"},
        )
        raw_content = (completion.choices[0].message.content or "").strip()
        if not raw_content:
            raise ValueError("Groq returned an empty response body.")

        parsed = json.loads(raw_content)
        if not isinstance(parsed, dict):
            raise ValueError("Groq response is not a JSON object.")

        severity = str(parsed.get("severity_flag", "ROUTINE")).strip().upper()
        if severity not in {"EMERGENCY", "ROUTINE"}:
            severity = "ROUTINE"

        # Deterministic AppSec override if raw advisory explicitly meets EMERGENCY criteria
        if evaluate_emergency_heuristics(packet):
            severity = "EMERGENCY"

        raw_report = parsed.get("markdown_report", "")
        if isinstance(raw_report, dict):
            markdown_report = "\n".join(
                f"• *{k}*: {v}" for k, v in raw_report.items() if v
            ).strip()
        elif isinstance(raw_report, list):
            markdown_report = "\n".join(f"• {item}" for item in raw_report if item).strip()
        else:
            markdown_report = str(raw_report).strip()

        if not markdown_report:
            raise ValueError("Groq JSON response missing non-empty 'markdown_report'.")

        await asyncio.sleep(1.5)  # Respect Groq free-tier 30 RPM / TPM pacing
        return DistilledThreat(
            severity_flag=severity,
            markdown_report=markdown_report,
        )

    async with semaphore:
        try:
            return await retry_with_backoff(
                _call_groq,
                operation_name=f"Groq LLM Distillation [{packet.cve_id or packet.threat_hash[:10]}]",
                max_attempts=4,
                base_delay=2.0,
            )
        except (RateLimitError, APIConnectionError, APIStatusError, Exception) as exc:  # pylint: disable=broad-exception-caught
            logger.error(
                "LLM distillation failed for [%s]; applying deterministic fallback: %s",
                packet.title,
                exc,
            )
            is_emergency = evaluate_emergency_heuristics(packet)
            fallback_report = (
                f"*Summary*: {packet.title}\n"
                f"*Details*: {packet.summary[:600] or 'See advisory link.'}\n"
                f"*Mitigation*: Review vendor advisory at {packet.source_url}"
            )
            return DistilledThreat(
                severity_flag="EMERGENCY" if is_emergency else "ROUTINE",
                markdown_report=fallback_report,
            )


# ---------------------------------------------------------------------------
# Module 3: Dual-Routing Telegram Alerting & State Persistence
# ---------------------------------------------------------------------------
def chunk_telegram_message(text: str, max_len: int = TELEGRAM_MAX_MESSAGE_LEN) -> List[str]:
    """Splits a long Markdown message on paragraph/line boundaries to fit Telegram limits."""
    if len(text) <= max_len:
        return [text]

    chunks: List[str] = []
    current_lines: List[str] = []
    current_len = 0

    for line in text.splitlines(keepends=True):
        if len(line) > max_len:
            if current_lines:
                chunks.append("".join(current_lines).strip())
                current_lines = []
                current_len = 0
            for i in range(0, len(line), max_len):
                chunks.append(line[i : i + max_len])
            continue

        if current_len + len(line) > max_len and current_lines:
            chunks.append("".join(current_lines).strip())
            current_lines = [line]
            current_len = len(line)
        else:
            current_lines.append(line)
            current_len += len(line)

    if current_lines:
        chunks.append("".join(current_lines).strip())

    return [c for c in chunks if c]


async def send_telegram_message(
    session: aiohttp.ClientSession,
    bot_token: str,
    chat_id: str,
    text: str,
) -> None:
    """Sends a message via the Telegram Bot API with Markdown fallback and backoff."""
    api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    chunks = chunk_telegram_message(text)

    for idx, chunk in enumerate(chunks, start=1):

        async def _post_chunk() -> None:
            payload: Dict[str, Any] = {
                "chat_id": chat_id,
                "text": chunk,
                "parse_mode": "Markdown",
                "disable_web_page_preview": True,
            }
            async with session.post(api_url, json=payload) as resp:
                if resp.status == 400:
                    # Fallback to plain text if LLM output has unmatched Markdown entities
                    logger.warning(
                        "Telegram Markdown parse failed (HTTP 400); retrying chunk %d/%d as plain text.",
                        idx,
                        len(chunks),
                    )
                    payload.pop("parse_mode", None)
                    async with session.post(api_url, json=payload) as fallback_resp:
                        if fallback_resp.status >= 400:
                            body = await fallback_resp.text()
                            raise RuntimeError(
                                f"Telegram API HTTP {fallback_resp.status}: {body}"
                            )
                        return

                if resp.status == 429:
                    body_json = await resp.json(content_type=None)
                    retry_after = (
                        body_json.get("parameters", {}).get("retry_after", 5)
                        if isinstance(body_json, dict)
                        else 5
                    )
                    await asyncio.sleep(float(retry_after))
                    raise RuntimeError(f"Telegram rate limited (retry_after={retry_after}s)")

                if resp.status >= 400:
                    body = await resp.text()
                    raise RuntimeError(f"Telegram API HTTP {resp.status}: {body}")

        await retry_with_backoff(
            _post_chunk,
            operation_name=f"Telegram sendMessage (part {idx}/{len(chunks)})",
            max_attempts=4,
            base_delay=2.0,
        )


async def send_emergency_alert(
    session: aiohttp.ClientSession,
    config: Config,
    packet: ThreatPacket,
    distilled: DistilledThreat,
) -> None:
    """Formats and dispatches an out-of-band real-time EMERGENCY alert via Telegram."""
    cve_badge = f" ({packet.cve_id})" if packet.cve_id else ""
    message = (
        f"🚨 *[CRITICAL ZERO-DAY / EMERGENCY THREAT]*{cve_badge}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"*Title*: {packet.title}\n"
        f"*Source*: {packet.source_feed}\n"
        f"*Advisory*: {packet.source_url}\n\n"
        f"{distilled.markdown_report}"
    )
    await send_telegram_message(
        session=session,
        bot_token=config.telegram_bot_token,
        chat_id=config.telegram_chat_id,
        text=message,
    )
    logger.info(
        "EMERGENCY alert dispatched to Telegram for [%s].",
        packet.cve_id or packet.title,
    )


async def persist_threat_record(
    supabase: Client,
    packet: ThreatPacket,
    distilled: DistilledThreat,
    pending_notification: bool,
) -> None:
    """Stores the processed threat intelligence record in Supabase `threat_intel_cache`."""
    now_iso = datetime.now(timezone.utc).isoformat()
    record: Dict[str, Any] = {
        "threat_hash": packet.threat_hash,
        "cve_id": packet.cve_id,
        "source_feed": packet.source_feed,
        "title": packet.title,
        "source_url": packet.source_url,
        "published_at": packet.published_at,
        "severity_flag": distilled.severity_flag,
        "markdown_report": distilled.markdown_report,
        "pending_notification": pending_notification,
        "notified_at": None if pending_notification else now_iso,
    }

    def _upsert() -> None:
        supabase.table("threat_intel_cache").upsert(
            record,
            on_conflict="threat_hash",
        ).execute()

    await retry_with_backoff(
        lambda: asyncio.to_thread(_upsert),
        operation_name=f"Supabase upsert [{packet.cve_id or packet.threat_hash[:10]}]",
    )


async def run_recon_pipeline() -> None:
    """Executes Job 1 (Recon): Ingests feeds, deduplicates, classifies via Groq, and routes alerts."""
    config = Config.from_env(require_groq=True)
    supabase = create_client(config.supabase_url, config.supabase_key)
    groq_client = AsyncGroq(api_key=config.groq_api_key)

    candidate_packets = await ingest_all_feeds()
    new_packets = await filter_unseen_packets(supabase, candidate_packets)
    if not new_packets:
        logger.info("No new threats discovered during this recon cycle. Exiting cleanly.")
        return

    semaphore = asyncio.Semaphore(LLM_CONCURRENCY_LIMIT)
    timeout = aiohttp.ClientTimeout(total=20, connect=10)

    emergency_count = 0
    routine_count = 0

    async with aiohttp.ClientSession(timeout=timeout) as tg_session:
        for packet in new_packets:
            try:
                distilled = await classify_and_distill_packet(
                    groq_client=groq_client,
                    packet=packet,
                    semaphore=semaphore,
                )

                if distilled.severity_flag == "EMERGENCY":
                    await send_emergency_alert(
                        session=tg_session,
                        config=config,
                        packet=packet,
                        distilled=distilled,
                    )
                    await persist_threat_record(
                        supabase=supabase,
                        packet=packet,
                        distilled=distilled,
                        pending_notification=False,
                    )
                    emergency_count += 1
                else:
                    await persist_threat_record(
                        supabase=supabase,
                        packet=packet,
                        distilled=distilled,
                        pending_notification=True,
                    )
                    routine_count += 1

            except Exception as exc:  # pylint: disable=broad-exception-caught
                logger.error(
                    "Error processing packet [%s]: %s",
                    packet.cve_id or packet.title,
                    exc,
                )

    logger.info(
        "Recon cycle finished: %d EMERGENCY alerts sent, %d ROUTINE items queued for digest.",
        emergency_count,
        routine_count,
    )


async def send_daily_digest() -> None:
    """Executes Job 2 (Digest): Aggregates pending ROUTINE threats, sends digest, and clears flags."""
    config = Config.from_env(require_groq=False)
    supabase = create_client(config.supabase_url, config.supabase_key)

    def _fetch_pending() -> List[Dict[str, Any]]:
        resp = (
            supabase.table("threat_intel_cache")
            .select("id, cve_id, source_feed, title, source_url, markdown_report, created_at")
            .eq("pending_notification", True)
            .order("created_at", desc=False)
            .execute()
        )
        return list(resp.data or [])

    pending_rows = await retry_with_backoff(
        lambda: asyncio.to_thread(_fetch_pending),
        operation_name="Fetch pending digest rows from Supabase",
    )

    if not pending_rows:
        logger.info("No pending routine threats found for today's digest. Exiting.")
        return

    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    digest_sections: List[str] = [
        f"🛡️ *[GHOST PROCESS: DAILY THREAT INTEL DIGEST]*\n"
        f"📅 *Date*: {date_str} UTC | *Total Routine Advisories*: {len(pending_rows)}\n"
        f"━━━━━━━━━━━━━━━━━━━━"
    ]

    for idx, row in enumerate(pending_rows, start=1):
        cve_label = f" `{row['cve_id']}`" if row.get("cve_id") else ""
        title = row.get("title", "Untitled Advisory")
        source_feed = row.get("source_feed", "Security Feed")
        source_url = row.get("source_url", "")
        report = (row.get("markdown_report") or "").strip()

        section = (
            f"*{idx}. {title}*{cve_label}\n"
            f"📡 _Source_: {source_feed} | [Advisory Link]({source_url})\n"
            f"{report}\n"
            f"────────────────────"
        )
        digest_sections.append(section)

    full_digest_markdown = "\n\n".join(digest_sections)

    timeout = aiohttp.ClientTimeout(total=30, connect=10)
    async with aiohttp.ClientSession(timeout=timeout) as tg_session:
        await send_telegram_message(
            session=tg_session,
            bot_token=config.telegram_bot_token,
            chat_id=config.telegram_chat_id,
            text=full_digest_markdown,
        )

    delivered_ids = [row["id"] for row in pending_rows if row.get("id")]
    now_iso = datetime.now(timezone.utc).isoformat()

    def _mark_notified() -> None:
        batch_size = 100
        for i in range(0, len(delivered_ids), batch_size):
            batch = delivered_ids[i : i + batch_size]
            (
                supabase.table("threat_intel_cache")
                .update({"pending_notification": False, "notified_at": now_iso})
                .in_("id", batch)
                .execute()
            )

    await retry_with_backoff(
        lambda: asyncio.to_thread(_mark_notified),
        operation_name="Mark digest rows as notified in Supabase",
    )

    logger.info(
        "Daily digest successfully delivered (%d advisories) and marked as notified.",
        len(delivered_ids),
    )


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------
async def run_dry_run_ingestion() -> None:
    """Tests RSS feed ingestion, Supabase deduplication, and emergency heuristics."""
    load_dotenv_if_present()
    logger.info("Starting DRY-RUN mode (RSS ingestion + Supabase check + heuristics)...")
    packets = await ingest_all_feeds()

    supabase_url = os.getenv("SUPABASE_URL", "").strip()
    supabase_key = os.getenv("SUPABASE_KEY", "").strip()
    if supabase_url and supabase_key:
        supabase = create_client(supabase_url, supabase_key)
        packets = await filter_unseen_packets(supabase, packets)

    for idx, pkt in enumerate(packets[:10], start=1):
        heuristic_flag = "EMERGENCY" if evaluate_emergency_heuristics(pkt) else "ROUTINE"
        logger.info(
            "[%02d] [%s] (%s) %s -> %s",
            idx,
            pkt.source_feed,
            pkt.cve_id or pkt.threat_hash[:8],
            heuristic_flag,
            pkt.title,
        )
    logger.info("Dry-run complete. Total unseen packets ready for LLM: %d", len(packets))


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Ghost Process: Autonomous Threat Intelligence Pipeline",
    )
    parser.add_argument(
        "--mode",
        choices=("recon", "digest"),
        default="recon",
        help="Pipeline execution mode: 'recon' (4-hour feed ingestion) or 'digest' (daily routine summary).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and parse RSS feeds locally without requiring Supabase/Groq/Telegram credentials.",
    )
    return parser.parse_args(argv)


async def async_main(argv: Optional[List[str]] = None) -> None:
    """Asynchronous entrypoint dispatching to the selected pipeline mode."""
    args = parse_args(argv)
    if args.dry_run:
        await run_dry_run_ingestion()
    elif args.mode == "digest":
        await send_daily_digest()
    else:
        await run_recon_pipeline()


def main() -> None:
    """Synchronous wrapper for CLI execution."""
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        logger.info("Execution interrupted by user.")
        sys.exit(130)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.critical("Fatal unhandled error in Ghost Process: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
