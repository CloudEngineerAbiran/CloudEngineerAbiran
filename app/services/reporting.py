from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from app.services.schemas import FindingCreate
from app.utils.config import get_settings


def generate_report(findings: list[FindingCreate]) -> list[str]:
    settings = get_settings()
    out_dir = Path(settings.reports_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    json_path = out_dir / f"report_{ts}.json"
    txt_path = out_dir / f"report_{ts}.txt"

    payload = [f.model_dump() for f in findings]
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    counts = Counter(f.severity for f in findings)
    lines = [
        "Cloud Vulnerability Report",
        f"Generated UTC: {datetime.utcnow().isoformat()}",
        f"Total findings: {len(findings)}",
        "Severity summary:",
    ]
    for severity, count in sorted(counts.items()):
        lines.append(f"- {severity}: {count}")

    for finding in findings:
        lines.append(
            f"* [{finding.severity}] {finding.resource_type}:{finding.resource_id} - {finding.issue} (score={finding.score})"
        )

    txt_path.write_text("\n".join(lines), encoding="utf-8")
    return [str(json_path), str(txt_path)]
