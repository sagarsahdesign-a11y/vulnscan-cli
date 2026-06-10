"""
Shared utilities for cvemap.
Handles: logging, config loading, rich console, rate limiting, helpers.
"""

import os
import sys
import time
import logging
import threading
import io
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.theme import Theme
from rich.logging import RichHandler
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Rich console (global singleton) — force UTF-8 on Windows
# ---------------------------------------------------------------------------

def _utf8_stream(stream):
    """Wrap a stream with UTF-8 encoding if on Windows and not already UTF-8."""
    if sys.platform == "win32" and hasattr(stream, "buffer"):
        return io.TextIOWrapper(stream.buffer, encoding="utf-8", errors="replace")
    return stream

CVEMAP_THEME = Theme(
    {
        "info": "bold cyan",
        "warn": "bold yellow",
        "error": "bold red",
        "success": "bold green",
        "critical": "bold white on red",
        "high": "bold red",
        "medium": "bold yellow",
        "low": "bold blue",
        "info_sev": "bold cyan",
        "none_sev": "dim",
        "banner": "bold magenta",
        "host": "bold cyan",
        "port": "cyan",
        "version": "yellow",
        "cve": "bold red",
    }
)

console = Console(theme=CVEMAP_THEME, highlight=False, file=_utf8_stream(sys.stdout))
err_console = Console(stderr=True, theme=CVEMAP_THEME, file=_utf8_stream(sys.stderr))


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def get_logger(name: str, level: int = logging.WARNING) -> logging.Logger:
    """Return a logger that renders via RichHandler."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = RichHandler(
            console=err_console,
            show_path=False,
            rich_tracebacks=True,
            markup=True,
        )
        logger.addHandler(handler)
        logger.setLevel(level)
    return logger


logger = get_logger("cvemap.utils")


# ---------------------------------------------------------------------------
# Config / .env loader
# ---------------------------------------------------------------------------

_DEFAULT_ENV_PATHS = [
    Path(".env"),
    Path.home() / ".cvemap" / ".env",
    Path("/etc/cvemap/.env"),
]


def load_config(env_file: Optional[str] = None) -> dict:
    """
    Load configuration from .env file and environment variables.

    Priority (highest → lowest):
      1. Environment variables already set in the shell
      2. Explicit --env-file path
      3. ~/.cvemap/.env
      4. ./.env

    Returns a dict of resolved config values.
    """
    # Try explicit path first
    if env_file:
        path = Path(env_file)
        if path.exists():
            load_dotenv(path, override=False)
            logger.debug(f"Loaded config from {path}")
        else:
            logger.warning(f"Config file not found: {path}")
    else:
        for p in _DEFAULT_ENV_PATHS:
            if p.exists():
                load_dotenv(p, override=False)
                logger.debug(f"Loaded config from {p}")
                break

    return {
        "nvd_api_key": os.getenv("NVD_API_KEY", ""),
        "output_dir": os.getenv("CVEMAP_OUTPUT_DIR", "."),
        "timing": int(os.getenv("CVEMAP_TIMING", "3")),
        "max_cves_per_port": int(os.getenv("CVEMAP_MAX_CVES", "10")),
        "request_timeout": int(os.getenv("CVEMAP_REQUEST_TIMEOUT", "30")),
        "log_level": os.getenv("CVEMAP_LOG_LEVEL", "WARNING").upper(),
    }


# ---------------------------------------------------------------------------
# Thread-safe Rate Limiter (token-bucket style)
# ---------------------------------------------------------------------------

class RateLimiter:
    """
    Token-bucket rate limiter for API calls.

    NVD API limits (as of 2024):
      - Without API key : 5 requests / 30 s
      - With API key    : 50 requests / 30 s

    We use a conservative window to stay well within limits.
    """

    def __init__(self, calls: int, period: float):
        """
        Args:
            calls:  Max number of calls allowed in `period` seconds.
            period: Rolling window size in seconds.
        """
        self.calls = calls
        self.period = period
        self._lock = threading.Lock()
        self._timestamps: list[float] = []

    def acquire(self) -> None:
        """Block until a request slot is available."""
        with self._lock:
            now = time.monotonic()
            # Drop timestamps outside the rolling window
            self._timestamps = [t for t in self._timestamps if now - t < self.period]

            if len(self._timestamps) >= self.calls:
                sleep_for = self.period - (now - self._timestamps[0])
                if sleep_for > 0:
                    time.sleep(sleep_for)
                # Refresh
                now = time.monotonic()
                self._timestamps = [t for t in self._timestamps if now - t < self.period]

            self._timestamps.append(time.monotonic())


# ---------------------------------------------------------------------------
# CVSS severity helpers
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "NONE": "none_sev",
    "UNKNOWN": "dim",
}


def cvss_to_severity(score: float) -> str:
    """Convert a CVSS v3 numeric score to a severity label."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    else:
        return "NONE"


def severity_color(severity: str) -> str:
    """Map severity label to rich markup style."""
    return SEVERITY_COLORS.get(severity.upper(), "dim")


def severity_badge(severity: str) -> str:
    """Return a colored rich markup badge for a severity label."""
    style = severity_color(severity)
    return f"[{style}]{severity}[/{style}]"


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def expand_target(target: str) -> list[str]:
    """Return individual IP strings from a CIDR or single host."""
    import ipaddress

    try:
        network = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return [target]


def sanitize_filename(name: str) -> str:
    """Strip characters unsafe for filenames."""
    import re

    return re.sub(r"[^\w.\-]", "_", name)


# ---------------------------------------------------------------------------
# Timestamp helper
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return current UTC time in ISO-8601 format."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def human_duration(seconds: float) -> str:
    """Convert seconds to human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes}m {secs}s"


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
  _____ _   ______ __  __          _____  
 / ____| | / / __ \  \/  |   /\   |  __ \ 
| |    | |/ / |  | | \  / |  /  \  | |__) |
| |    |   <| |  | | |\/| | / /\ \ |  ___/ 
| |____| |\  \ |__| | |  | |/ ____ \| |     
 \_____|_| \_\____/|_|  |_/_/    \_\_|     
"""


def print_banner(version: str) -> None:
    """Print the cvemap banner with version."""
    console.print(f"[banner]{BANNER}[/banner]")
    console.print(
        f"  [dim]CVE-powered Network Vulnerability Scanner[/dim]  "
        f"[bold cyan]v{version}[/bold cyan]\n"
    )
