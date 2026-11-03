#!/usr/bin/env python3
"""Unit tests for the Ghost Process Threat Intelligence Pipeline."""

from __future__ import annotations

import unittest

from main import (
    TELEGRAM_MAX_MESSAGE_LEN,
    ThreatPacket,
    chunk_telegram_message,
    clean_html,
    compute_threat_hash,
    evaluate_emergency_heuristics,
    extract_cve_id,
     retry_with_backoff,
)


class GhostProcessUnitTests(unittest.IsolatedAsyncioTestCase):
    """Verifies core ingestion, deduplication, heuristic, and chunking logic."""

    def test_extract_cve_id(self) -> None:
        self.assertEqual(
            extract_cve_id("Critical RCE in OpenSSH (cve-2026-48123) patched"),
            "CVE-2026-48123",
        )
        self.assertIsNone(extract_cve_id("General security advisory without CVE"))

    def test_compute_threat_hash_cve_consistency(self) -> None:
        hash_nvd = compute_threat_hash(
            "CVE-2026-9999",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-9999",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-9999",
            "NVD Title",
        )
        hash_edb = compute_threat_hash(
            "cve-2026-9999",
            "https://www.exploit-db.com/exploits/99999",
            "https://www.exploit-db.com/exploits/99999",
            "Exploit-DB PoC Title",
        )
        self.assertEqual(hash_nvd, hash_edb)

    def test_clean_html(self) -> None:
        raw = "<p>Alert: <b>Prompt &amp; Injection</b>   in   <i>Agent</i></p>"
        self.assertEqual(clean_html(raw), "Alert: Prompt & Injection in Agent")

    def test_evaluate_emergency_heuristics(self) -> None:
        pkt_prompt_inj = ThreatPacket(
            threat_hash="h1",
            cve_id=None,
            source_feed="GitHub",
            title="Indirect Prompt Injection in Autonomous Coding Agent",
            summary="Allows arbitrary tool execution.",
            source_url="https://example.com/1",
            published_at=None,
        )
        self.assertTrue(evaluate_emergency_heuristics(pkt_prompt_inj))

        pkt_ssrf = ThreatPacket(
            threat_hash="h2",
            cve_id=None,
            source_feed="GitHub",
            title="Metadata credential theft via Agentic SSRF",
            summary="Bypasses egress filter.",
            source_url="https://example.com/2",
            published_at=None,
        )
        self.assertTrue(evaluate_emergency_heuristics(pkt_ssrf))

        pkt_cvss_high = ThreatPacket(
            threat_hash="h3",
            cve_id="CVE-2026-1111",
            source_feed="NVD",
            title="Pre-auth RCE",
            summary="CVSS v3.1 Base Score: 9.8 CRITICAL",
            source_url="https://example.com/3",
            published_at=None,
        )
        self.assertTrue(evaluate_emergency_heuristics(pkt_cvss_high))

        pkt_routine = ThreatPacket(
            threat_hash="h4",
            cve_id="CVE-2026-2222",
            source_feed="NVD",
            title="Low severity log disclosure",
            summary="CVSS v3.1 Base Score: 4.3 MEDIUM",
            source_url="https://example.com/4",
            published_at=None,
        )
        self.assertFalse(evaluate_emergency_heuristics(pkt_routine))

    def test_chunk_telegram_message(self) -> None:
        long_msg = "\n".join([f"Line {i}: " + ("A" * 80) for i in range(100)])
        chunks = chunk_telegram_message(long_msg)
        self.assertGreater(len(chunks), 1)
        for chunk in chunks:
            self.assertLessEqual(len(chunk), TELEGRAM_MAX_MESSAGE_LEN)

    async def test_retry_with_backoff_recovers(self) -> None:
        attempts = 0

        async def flaky_op() -> str:
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise RuntimeError("Transient error")
            return "ok"

        result = await retry_with_backoff(
            flaky_op,
            operation_name="test_flaky",
            max_attempts=3,
            base_delay=0.05,
        )
        self.assertEqual(result, "ok")
        self.assertEqual(attempts, 2)


if __name__ == "__main__":
    unittest.main()
