from __future__ import annotations

import logging

from app.scanner.services import scan_ec2_security_groups, scan_iam_policies, scan_s3_public_access
from app.services.schemas import FindingCreate
from app.utils.config import get_settings

logger = logging.getLogger(__name__)


def run_all_scans() -> list[FindingCreate]:
    settings = get_settings()
    findings: list[FindingCreate] = []

    if settings.scan_s3_enabled:
        findings.extend(scan_s3_public_access())
    if settings.scan_iam_enabled:
        findings.extend(scan_iam_policies())
    if settings.scan_ec2_enabled:
        findings.extend(scan_ec2_security_groups())

    logger.info("Scan completed. findings=%s", len(findings))
    return findings
