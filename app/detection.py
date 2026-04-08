from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

PROMPT_INJECTION_PATTERNS: list[str] = [
    r'ignore\s+previous\s+instructions',
    r'reveal\s+system\s+prompt',
    r'bypass\s+safety',
    r'disregard\s+all\s+prior\s+rules',
]

SENSITIVE_DATA_PATTERNS: list[str] = [
    r'sk-[a-zA-Z0-9]{20,}',
    r'(?i)api[_-]?key\s*[:=]\s*[^\s]+',
    r'(?i)password\s*[:=]\s*[^\s]+',
    r'(?i)token\s*[:=]\s*[^\s]+',
    r'AKIA[0-9A-Z]{16}',
]


@dataclass(slots=True)
class DetectionResult:
    matched: bool
    matches: list[str]


class AnomalyDetector:
    def __init__(self, window_size: int = 50, request_burst_threshold: int = 12) -> None:
        self.window_size = window_size
        self.request_burst_threshold = request_burst_threshold
        self.user_windows: dict[str, deque[datetime]] = defaultdict(lambda: deque(maxlen=self.window_size))

    def check(self, client_id: str, now: datetime) -> tuple[bool, str]:
        window = self.user_windows[client_id]
        window.append(now)
        if len(window) < self.request_burst_threshold:
            return False, ''

        interval = (window[-1] - window[0]).total_seconds()
        if interval <= 60:
            return True, f'request burst anomaly: {len(window)} requests in {interval:.2f}s'
        return False, ''


def _detect_with_patterns(text: str, patterns: Iterable[str]) -> DetectionResult:
    matches: list[str] = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            matches.append(pattern)
    return DetectionResult(matched=bool(matches), matches=matches)


def detect_prompt_injection(text: str) -> DetectionResult:
    return _detect_with_patterns(text, PROMPT_INJECTION_PATTERNS)


def detect_sensitive_data(text: str) -> DetectionResult:
    return _detect_with_patterns(text, SENSITIVE_DATA_PATTERNS)


def detect_regex_violation(text: str, regex: str) -> DetectionResult:
    return _detect_with_patterns(text, [regex])


def severity_from_score(score: int) -> str:
    if score >= 80:
        return 'HIGH'
    if score >= 50:
        return 'MEDIUM'
    return 'LOW'


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
