#!/usr/bin/env python3
"""Standalone entrypoint for Job 2: Daily Routine Threat Intelligence Digest.

Executes `send_daily_digest()` to fetch all pending ROUTINE threat reports from
Supabase (`pending_notification = True`), deliver a consolidated Markdown digest
via Telegram, and mark the records as notified (`pending_notification = False`).
"""

from __future__ import annotations

import asyncio
import logging
import sys

from main import send_daily_digest

logger = logging.getLogger("ghost_process.digest")


def main() -> None:
    """Runs the asynchronous daily digest job."""
    try:
        asyncio.run(send_daily_digest())
    except KeyboardInterrupt:
        logger.info("Daily digest interrupted by user.")
        sys.exit(130)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.critical("Fatal error during daily digest execution: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
