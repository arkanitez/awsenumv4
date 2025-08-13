from __future__ import annotations

from typing import List, Dict, Any
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
    ecr = session.client("ecr", region_name=region, config=CFG)
    token = None
    # Registry scanning config (account-level)
    scan_on_push = False
    try:
        sc = ecr.get_registry_scanning_configuration()
        rules = (sc.get("scanningConfiguration") or {}).get("rules") or []
        scan_on_push = any(
            ((ru.get("scanFrequency") or "").upper() in {"SCAN_ON_PUSH", "CONTINUOUS_SCAN"}) for ru in rules
        )
    except Exception:
        pass

    while True:
        try:
            kw: Dict[str, Any] = {}
            if token:
                kw["nextToken"] = token
            resp = ecr.describe_repositories(**kw)
        except Exception as e:
            warnings.append(f"ecr describe_repositories: {e}")
            return

        for r in resp.get("repositories", []) or []:
            name = r.get("repositoryName")
            arn = r.get("repositoryArn")
            if not name:
                continue

            enc_cfg = r.get("encryptionConfiguration") or {}
            enc_type = enc_cfg.get("encryptionType") or "AES256"
            kms_key = enc_cfg.get("kmsKey")

            node_id = mk_id("ecr", account_id, region, name)
            g.add_node(
                node_id,
                name,
                "ecr_repo",
                region,
                details={
                    "repositoryName": name,
                    "Arn": arn,
                    "scanOnPush": scan_on_push,
                    "encryptionType": enc_type,
                    "kmsKey": kms_key,
                },
            )
            if kms_key:
                key_id = kms_key.split("/")[-1]
                kms_id = mk_id("kms", account_id, region, key_id)
                g.add_edge(
                    mk_id("edge", account_id, region, "ecr-kms", name, key_id),
                    node_id,
                    kms_id,
                    "encrypts with",
                    "kms",
                    "security",
                    details={},
                )

        token = resp.get("nextToken")
        if not token:
            break
