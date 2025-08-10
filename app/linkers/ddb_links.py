from __future__ import annotations

import re
import fnmatch
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import boto3

from ..graph import Graph

# Heuristic action classification
READ_ACTIONS = {
    "GetItem", "BatchGetItem", "Query", "Scan",
    "DescribeTable", "DescribeTimeToLive", "DescribeContinuousBackups",
    "DescribeContributorInsights", "DescribeStream",
    "ListTables", "ListTagsOfResource", "ListStreams", "DescribeKinesisStreamingDestination"
}
WRITE_ACTIONS = {
    "PutItem", "UpdateItem", "DeleteItem", "BatchWriteItem",
    "CreateTable", "UpdateTable", "DeleteTable", "TagResource", "UntagResource",
    "EnableKinesisStreamingDestination", "DisableKinesisStreamingDestination"
}

LAMBDA_ARN_RE = re.compile(r"(arn:aws:lambda:[^:]+:\d+:function:[A-Za-z0-9-_]+)(?::\d+)?$")

def _s(name: Optional[str]) -> str:
    return (name or "").strip()

def _extract_lambda_arn(node_id: str, details: Dict[str, Any]) -> Optional[str]:
    """Get Lambda function ARN from node details or parse from id."""
    arn = _s(details.get("arn"))
    if arn.startswith("arn:aws:lambda:"):
        return arn
    # try to find first arn substring in id
    m = LAMBDA_ARN_RE.search(node_id)
    if m:
        return m.group(1)
    return None

def _extract_lambda_name_from_arn(fn_arn: str) -> Optional[str]:
    # arn:aws:lambda:region:acct:function:FuncName[:version]
    try:
        return fn_arn.split(":function:")[1].split(":")[0]
    except Exception:
        return None

def _collect_policy_statements(iam: boto3.client, role_name: str, warnings: List[str]) -> List[Dict[str, Any]]:
    """Collect identity policy statements (attached managed + inline) for a role."""
    stmts: List[Dict[str, Any]] = []

    # Inline policies
    try:
        inline = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
        for pol_name in inline:
            try:
                pol = iam.get_role_policy(RoleName=role_name, PolicyName=pol_name)
                doc = pol.get("PolicyDocument") or {}
                stmts.extend(doc.get("Statement", []) if isinstance(doc.get("Statement", []), list)
                             else [doc.get("Statement", {})])
            except Exception as e:
                warnings.append(f"iam get_role_policy {role_name}/{pol_name} failed: {e}")
    except Exception as e:
        warnings.append(f"iam list_role_policies {role_name} failed: {e}")

    # Attached managed policies
    try:
        attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
        for ap in attached:
            arn = ap.get("PolicyArn")
            if not arn:
                continue
            try:
                meta = iam.get_policy(PolicyArn=arn).get("Policy", {})
                ver_id = meta.get("DefaultVersionId")
                if not ver_id:
                    continue
                ver = iam.get_policy_version(PolicyArn=arn, VersionId=ver_id).get("PolicyVersion", {})
                doc = ver.get("Document") or {}
                stmts.extend(doc.get("Statement", []) if isinstance(doc.get("Statement", []), list)
                             else [doc.get("Statement", {})])
            except Exception as e:
                warnings.append(f"iam get_policy_version {arn} failed: {e}")
    except Exception as e:
        warnings.append(f"iam list_attached_role_policies {role_name} failed: {e}")

    # Normalize: flatten and filter only Allow effects
    norm: List[Dict[str, Any]] = []
    for s in stmts:
        if not isinstance(s, dict):
            continue
        if _s(s.get("Effect")).lower() != "allow":
            continue
        acts = s.get("Action") or s.get("NotAction")
        res = s.get("Resource") or s.get("NotResource")
        # Keep original so we can show evidence; we match only when 'Action' exists
        s_norm = {
            "Action": acts, "Resource": res, "Condition": s.get("Condition"), "Sid": s.get("Sid")
        }
        norm.append(s_norm)
    return norm

def _action_names(actions: Any) -> Set[str]:
    """Return set of DynamoDB action names without the 'dynamodb:' prefix;
       supports string or list, with wildcards."""
    out: Set[str] = set()
    if not actions:
        return out
    if isinstance(actions, str):
        actions = [actions]
    for a in actions:
        a = _s(a)
        if not a:
            continue
        if a == "*" or a.lower() == "dynamodb:*":
            out.add("*")
        elif ":" in a:
            svc, name = a.split(":", 1)
            if svc.lower() == "dynamodb":
                out.add(name)
        else:
            # If someone wrote bare action name (rare)
            out.add(a)
    return out

def _resources_list(resources: Any) -> List[str]:
    if not resources:
        return []
    if isinstance(resources, str):
        return [resources]
    return [r for r in resources if isinstance(r, str)]

def _classify_rw(action_names: Set[str]) -> Tuple[bool, bool]:
    """Return (reads, writes) booleans."""
    if "*" in action_names:
        return True, True
    read = any(any(fnmatch.fnmatchcase(a, pat) for pat in READ_ACTIONS) or a.startswith("Describe") or a.startswith("List")
               for a in action_names)
    write = any(any(fnmatch.fnmatchcase(a, pat) for pat in WRITE_ACTIONS)
                for a in action_names)
    return read, write

def _match_table_arns(res_patterns: List[str], table_arn: str) -> bool:
    """Does any policy Resource pattern match table ARN? Supports '*' wildcards."""
    for pat in res_patterns:
        pat = _s(pat)
        if not pat:
            continue
        if pat == "*" or pat.endswith(":*"):
            # broad wildcard; treat as match
            return True
        # Normalize index forms to still match table ARNs
        # e.g., arn:aws:dynamodb:region:acct:table/MyTable/index/*
        if fnmatch.fnmatchcase(table_arn, pat):
            return True
        # If the pattern is a table-only ARN and our table_arn has index ARN, it's still fine
    return False

def _collect_tables_from_graph(g: Graph) -> List[Dict[str, Any]]:
    """Extract DDB table nodes from Graph elements."""
    tables: List[Dict[str, Any]] = []
    for el in g.elements():
        if not isinstance(el, dict):
            continue
        data = el.get("data") or {}
        if el.get("group") == "nodes" and data.get("type") == "dynamodb_table":
            tables.append({
                "node_id": data.get("id"),
                "name": (data.get("details") or {}).get("name") or data.get("label") or "",
                "arn": (data.get("details") or {}).get("arn") or "",
                "region": data.get("region") or "",
            })
    return tables

def _collect_lambdas_from_graph(g: Graph) -> List[Dict[str, Any]]:
    lambdas: List[Dict[str, Any]] = []
    for el in g.elements():
        if not isinstance(el, dict):
            continue
        data = el.get("data") or {}
        if el.get("group") == "nodes" and data.get("type") == "lambda":
            lambdas.append({
                "node_id": data.get("id"),
                "details": data.get("details") or {},
                "region": data.get("region") or "",
                "label": data.get("label") or "",
            })
    return lambdas

def _edge_id(lambda_node_id: str, table_node_id: str, kind: str) -> str:
    return f"lambda-ddb:{kind}:{lambda_node_id}->{table_node_id}"

def _add_edge(g: Graph, lam_node_id: str, tab_node_id: str, label: str, details: Dict[str, Any]) -> None:
    g.add_edge(
        id_=_edge_id(lam_node_id, tab_node_id, details.get("source", "iam")),
        src=lam_node_id,
        tgt=tab_node_id,
        label=label,
        type_="ddb",
        category="data",
        derived=True,
        details=details,
    )

def link_lambda_to_dynamodb(sess: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    """Derive Lambda -> DynamoDB table edges from IAM and env vars."""
    lambda_client = sess.client("lambda", region_name=region)
    iam = sess.client("iam")
    tables = _collect_tables_from_graph(g)
    table_arns = [t["arn"] for t in tables if t.get("arn")]
    tables_by_arn = {t["arn"]: t for t in tables if t.get("arn")}
    tables_by_name = {t["name"]: t for t in tables if t.get("name")}
    lambdas = _collect_lambdas_from_graph(g)

    for lam in lambdas:
        lam_node_id = lam["node_id"]
        # resolve Lambda ARN and name
        lam_arn = _extract_lambda_arn(lam_node_id, lam["details"])
        lam_name = None
        if lam_arn:
            lam_name = _extract_lambda_name_from_arn(lam_arn)

        # fetch function configuration (role + env)
        role_arn = None
        env_vars: Dict[str, str] = {}
        try:
            # Prefer ARN when available; else name; else label
            fn_id = lam_arn or lam_name or lam["label"]
            cfg = lambda_client.get_function_configuration(FunctionName=fn_id)
            role_arn = cfg.get("Role")
            env_vars = (cfg.get("Environment") or {}).get("Variables") or {}
        except Exception as e:
            warnings.append(f"lambda get_function_configuration {lam.get('label')} failed: {e}")

        # ---- ENV INFERENCE ----
        # Look for env var values that exactly match table names
        if env_vars and tables_by_name:
            for k, v in env_vars.items():
                val = _s(v)
                if not val:
                    continue
                # common variable name hints; we still do exact name match to reduce noise
                if any(hint in k.upper() for hint in ("TABLE", "DDB", "DYNAMO")):
                    tab = tables_by_name.get(val)
                    if tab:
                        _add_edge(g, lam_node_id, tab["node_id"], f"ENV: {k}", {
                            "source": "env",
                            "env_key": k,
                            "env_value": val
                        })

        # ---- IAM INFERENCE ----
        # From the execution role policies, find DDB actions & match resources to table ARNs
        if role_arn:
            # arn:aws:iam::acct:role/ROLE_NAME
            try:
                role_name = role_arn.split("/")[-1]
                stmts = _collect_policy_statements(iam, role_name, warnings)
                # aggregate actions and resources
                for s in stmts:
                    acts = _action_names(s.get("Action"))
                    if not acts:
                        continue
                    if not any(a == "*" or a.startswith("dynamodb") or a in READ_ACTIONS or a in WRITE_ACTIONS for a in acts):
                        # if user specified NotAction or non-ddb, skip
                        if not any(a for a in acts if ":" in a and a.split(":", 1)[0].lower() == "dynamodb"):
                            continue

                    res_list = _resources_list(s.get("Resource"))
                    # No resource means implicitly all (rare) — skip to avoid blast radius
                    if not res_list:
                        continue

                    reads, writes = _classify_rw(acts)
                    label = "IAM: "
                    if reads and writes:
                        label += "read+write"
                    elif reads:
                        label += "read"
                    elif writes:
                        label += "write"
                    else:
                        label += "dynamodb"

                    matched_any = False
                    for tab_arn in table_arns:
                        if _match_table_arns(res_list, tab_arn):
                            tab = tables_by_arn.get(tab_arn)
                            if tab:
                                matched_any = True
                                _add_edge(g, lam_node_id, tab["node_id"], label, {
                                    "source": "iam",
                                    "role": role_arn,
                                    "actions": sorted(list(acts)),
                                    "resources": res_list
                                })
                    # If patterns are too broad and matched nothing (e.g., table/* in a different region),
                    # do nothing — avoids spamming edges to all tables.
                    if not matched_any and any(p == "*" for p in res_list):
                        # very broad policy; not connecting to everything — just warn once
                        warnings.append(f"lambda {lam.get('label')} role policy allows DynamoDB on '*' but no table ARNs matched in {region}")
            except Exception as e:
                warnings.append(f"iam policy scan for role {role_arn} failed: {e}")
