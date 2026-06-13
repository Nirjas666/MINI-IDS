"""Forwarder for sending parsed log records to SIEM or console with retry/backoff."""
import requests
import logging
import time
import random
from pathlib import Path

logger = logging.getLogger(__name__)


class Forwarder:
    def __init__(self, config: dict):
        """Initialize forwarder with config.
        
        Config keys:
          - mode: "console", "http", or "disk"
          - url: (for http mode) endpoint URL
          - max_retries: (default: 3) max retry attempts for HTTP
          - initial_backoff: (default: 1) initial backoff in seconds
          - max_backoff: (default: 30) max backoff in seconds
          - jitter: (default: 0.1) jitter as fraction (0.1 = +/- 10%)
          - buffer_dir: (for disk mode) directory to store buffered records
        """
        self.mode = config.get("mode", "console")
        self.url = config.get("url")
        self.max_retries = config.get("max_retries", 3)
        self.initial_backoff = config.get("initial_backoff", 1)
        self.max_backoff = config.get("max_backoff", 30)
        self.jitter = config.get("jitter", 0.1)
        self.buffer_dir = config.get("buffer_dir", "/tmp/logcollector_buffer")
        
        if self.mode == "disk":
            Path(self.buffer_dir).mkdir(parents=True, exist_ok=True)

    def forward(self, record: dict) -> bool:
        """Forward a record to the destination. Returns True if successful."""
        if self.mode == "console":
            return self._forward_console(record)
        elif self.mode == "http":
            return self._forward_http(record)
        elif self.mode == "disk":
            return self._forward_disk(record)
        else:
            logger.warning("Unknown forwarder mode: %s", self.mode)
            return False

    def _forward_console(self, record: dict) -> bool:
        """Forward record to console."""
        try:
            print(record)
            return True
        except Exception as e:
            logger.exception("Failed to forward to console: %s", e)
            return False

    def _forward_http(self, record: dict) -> bool:
        """Forward record to HTTP endpoint with exponential backoff retry."""
        if not self.url:
            logger.error("HTTP forwarder requires 'url' in config")
            return False

        backoff = self.initial_backoff
        for attempt in range(self.max_retries + 1):
            try:
                response = requests.post(self.url, json=record, timeout=5)
                if response.status_code < 400:
                    logger.info("Successfully forwarded record to %s", self.url)
                    return True
                elif response.status_code >= 500:
                    # Server error, retry
                    logger.warning(
                        "HTTP %d from %s on attempt %d, retrying...",
                        response.status_code,
                        self.url,
                        attempt + 1,
                    )
                    if attempt < self.max_retries:
                        self._backoff_and_jitter(backoff)
                        backoff = min(backoff * 2, self.max_backoff)
                    continue
                else:
                    # Client error (4xx), don't retry
                    logger.error(
                        "HTTP %d from %s, not retrying",
                        response.status_code,
                        self.url,
                    )
                    return False
            except requests.exceptions.Timeout:
                logger.warning(
                    "Timeout from %s on attempt %d, retrying...",
                    self.url,
                    attempt + 1,
                )
                if attempt < self.max_retries:
                    self._backoff_and_jitter(backoff)
                    backoff = min(backoff * 2, self.max_backoff)
                continue
            except requests.exceptions.RequestException as e:
                logger.warning(
                    "Request failed to %s on attempt %d: %s, retrying...",
                    self.url,
                    attempt + 1,
                    e,
                )
                if attempt < self.max_retries:
                    self._backoff_and_jitter(backoff)
                    backoff = min(backoff * 2, self.max_backoff)
                continue

        logger.error("Failed to forward record to %s after %d retries", self.url, self.max_retries)
        return False

    def _forward_disk(self, record: dict) -> bool:
        """Forward record to disk buffer."""
        try:
            import json
            from datetime import datetime
            filename = f"{self.buffer_dir}/record_{datetime.utcnow().isoformat()}.json"
            with open(filename, "w") as f:
                json.dump(record, f)
            return True
        except Exception as e:
            logger.exception("Failed to forward to disk: %s", e)
            return False

    def _backoff_and_jitter(self, backoff: float):
        """Sleep with backoff and jitter."""
        jitter_factor = 1 + random.uniform(-self.jitter, self.jitter)
        sleep_duration = backoff * jitter_factor
        logger.debug("Backoff for %.2f seconds", sleep_duration)
        time.sleep(sleep_duration)
