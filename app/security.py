from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Lock

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from app.config import settings
from app.detection import (
    AnomalyDetector,
    detect_prompt_injection,
    detect_regex_violation,
    detect_sensitive_data,
    now_utc,
    severity_from_score,
)
from app.logger import get_security_logger


@dataclass(slots=True)
class SecurityAssessment:
    allowed: bool
    threat_score: int
    tag: str
    severity: str
    reasons: list[str]


class SecurityEngine:
    def __init__(self) -> None:
        self.anomaly_detector = AnomalyDetector()
        self.logger = get_security_logger()
        self._storage_lock = Lock()
        Path(settings.chat_history_file).parent.mkdir(parents=True, exist_ok=True)

    def assess_input(self, text: str, client_id: str) -> SecurityAssessment:
        score = 0
        reasons: list[str] = []

        if len(text) > settings.max_input_length:
            score += 35
            reasons.append('input exceeds max length')

        injection = detect_prompt_injection(text)
        if injection.matched:
            score += 80
            reasons.append('prompt injection indicators')

        sensitive = detect_sensitive_data(text)
        if sensitive.matched:
            score += 40
            reasons.append('sensitive credential pattern')

        regex_hit = detect_regex_violation(text, settings.blocked_regex)
        if regex_hit.matched:
            score += 30
            reasons.append('blocked regex pattern')

        anomalous, anomaly_reason = self.anomaly_detector.check(client_id=client_id, now=now_utc())
        if anomalous:
            score += 25
            reasons.append(anomaly_reason)

        score = min(100, score)
        if score >= 80:
            tag = 'MALICIOUS'
            allowed = False
        elif score >= 40:
            tag = 'SUSPICIOUS'
            allowed = False
        else:
            tag = 'SAFE'
            allowed = True

        severity = severity_from_score(score)
        return SecurityAssessment(allowed=allowed, threat_score=score, tag=tag, severity=severity, reasons=reasons)

    def assess_output(self, text: str) -> SecurityAssessment:
        sensitive = detect_sensitive_data(text)
        score = 90 if sensitive.matched else 0
        reasons = ['potential sensitive data leakage in model output'] if sensitive.matched else []
        tag = 'MALICIOUS' if sensitive.matched else 'SAFE'
        severity = severity_from_score(score)
        return SecurityAssessment(allowed=not sensitive.matched, threat_score=score, tag=tag, severity=severity, reasons=reasons)

    def log_event(self, client_id: str, assessment: SecurityAssessment, direction: str) -> None:
        reason = '; '.join(assessment.reasons) if assessment.reasons else 'none'
        self.logger.info(
            f'{direction} security assessment',
            extra={
                'client_id': client_id,
                'threat_score': assessment.threat_score,
                'tag': assessment.tag,
                'severity': assessment.severity,
                'reason': reason,
            },
        )
        if assessment.tag != 'SAFE':
            print(f"[ALERT] {assessment.severity}: {direction} blocked for client={client_id} | {reason}")

    def persist_chat_record(self, payload: dict) -> None:
        with self._storage_lock:
            path = Path(settings.chat_history_file)
            data: list[dict] = []
            if path.exists():
                data = json.loads(path.read_text())
            data.append(payload)
            path.write_text(json.dumps(data, indent=2))


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, engine: SecurityEngine) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self.engine = engine

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        if request.url.path != '/chat' or request.method != 'POST':
            return await call_next(request)

        client_id = request.headers.get('X-Client-ID', 'anonymous')
        request.state.client_id = client_id
        return await call_next(request)


def blocked_response(assessment: SecurityAssessment) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={
            'error': 'request_blocked',
            'threat_score': assessment.threat_score,
            'tag': assessment.tag,
            'severity': assessment.severity,
            'reasons': assessment.reasons,
        },
    )


def to_dict(assessment: SecurityAssessment) -> dict:
    return asdict(assessment)
