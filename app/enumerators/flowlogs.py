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
    ec2 = session.client("ec2", region_name=region, config=CFG)
    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", []) or []
        fls = ec2.describe_flow_logs().get("FlowLogs", []) or []
    except Exception as e:
        warnings.append(f"flowlogs describe_*: {e}")
        return

    # Ensure VPC nodes exist (lightweight)
    for v in vpcs:
        vpc_id = v.get("VpcId")
        if not vpc_id:
            continue
        g.add_node(
            mk_id("vpc", account_id, region, vpc_id),
            vpc_id,
            "vpc",
            region,
            details=v,
        )

    for f in fls:
        fid = f.get("FlowLogId")
        vpc_id = f.get("ResourceId")
        status = f.get("FlowLogStatus")
        if not fid or not vpc_id:
            continue

        node_id = mk_id("flow", account_id, region, fid)
        details = {
            "FlowLogId": fid,
            "ResourceId": vpc_id,
            "FlowLogStatus": status,
            "LogDestination": f.get("LogDestination"),
            "LogDestinationType": f.get("LogDestinationType"),
            "DeliverLogsPermissionArn": f.get("DeliverLogsPermissionArn"),
            "TrafficType": f.get("TrafficType"),
        }
        g.add_node(node_id, f"FlowLog:{vpc_id}", "vpc_flow_log", region, details=details)

        vpc_node = mk_id("vpc", account_id, region, vpc_id)
        g.add_edge(
            mk_id("edge", account_id, region, "vpc-flow", vpc_id, fid),
            vpc_node,
            node_id,
            "has flow logs",
            "flow_log",
            "logging",
            details={},
        )

        # Destination linkage (to CWL or S3)
        dst = f.get("LogDestination")
        typ = (f.get("LogDestinationType") or "").upper()
        if dst and typ == "CLOUD-WATCH-LOGS":
            # arn:aws:logs:REGION:ACCT:log-group:NAME
            parts = dst.split(":log-group:")
            lg_name = parts[-1] if len(parts) > 1 else dst
            lg_id = mk_id("cwl", account_id, region, lg_name)
            g.add_edge(
                mk_id("edge", account_id, region, "flow-cwl", fid, lg_name),
                node_id,
                lg_id,
                "logs to",
                "flow_logs",
                "logging",
                details={},
            )
        elif dst and typ == "S3":
            # arn:aws:s3:::bucket/prefix
            bucket = dst.split(":::")[-1].split("/")[0]
            s3_id = mk_id("s3", account_id, region, bucket)
            g.add_edge(
                mk_id("edge", account_id, region, "flow-s3", fid, bucket),
                node_id,
                s3_id,
                "logs to",
                "flow_logs",
                "logging",
                details={},
            )
