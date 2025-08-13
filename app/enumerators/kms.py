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
    kms = session.client("kms", region_name=region, config=CFG)
    marker = None
    while True:
        try:
            kw: Dict[str, Any] = {}
            if marker:
                kw["Marker"] = marker
            resp = kms.list_keys(**kw)
        except Exception as e:
            warnings.append(f"kms list_keys: {e}")
            return

        for k in resp.get("Keys", []) or []:
            key_id = k.get("KeyId")
            arn = k.get("KeyArn")
            if not key_id:
                continue
            try:
                meta = kms.describe_key(KeyId=key_id).get("KeyMetadata", {}) or {}
                rotation = False
                try:
                    rotation = bool(kms.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled", False))
                except Exception:
                    pass
                node_id = mk_id("kms", account_id, region, key_id)
                g.add_node(
                    node_id,
                    meta.get("Description") or key_id,
                    "kms_key",
                    region,
                    details={
                        "KeyId": key_id,
                        "Arn": arn,
                        "KeyState": meta.get("KeyState"),
                        "KeyManager": meta.get("KeyManager"),
                        "CustomerMasterKeySpec": meta.get("CustomerMasterKeySpec") or meta.get("KeySpec"),
                        "KeyRotationEnabled": rotation,
                    },
                )
            except Exception:
                continue

        if resp.get("Truncated"):
            marker = resp.get("NextMarker")
            continue
        break
