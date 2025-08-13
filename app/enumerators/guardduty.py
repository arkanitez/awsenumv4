from __future__ import annotations

from typing import List
import boto3
from botocore.config import Config as BotoConfig

from ..graph import Graph
from ..iam_edges import mk_id

CFG = BotoConfig(
    retries={"max_attempts": 8, "mode": "adaptive"},
    read_timeout=20,
    connect_timeout=10,
)

def enumerate(session: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    gd = session.client("guardduty", region_name=region, config=CFG)
    try:
        dets = gd.list_detectors().get("DetectorIds", []) or []
    except Exception as e:
        warnings.append(f"guardduty list_detectors: {e}")
        return

    for d in dets:
        try:
            desc = gd.get_detector(DetectorId=d) or {}
        except Exception:
            desc = {}
        node_id = mk_id("guardduty", account_id, region, d)
        g.add_node(
            node_id,
            f"GuardDuty:{region}",
            "guardduty_detector",
            region,
            details={
                "DetectorId": d,
                "Status": desc.get("Status") or desc.get("status"),
                "status": desc.get("Status") or desc.get("status"),
                "FindingPublishingFrequency": desc.get("FindingPublishingFrequency"),
            },
        )
