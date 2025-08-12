from __future__ import annotations

from typing import Any, Dict, List, Tuple, Set
import re

# Sensitive ports to flag if exposed to 0.0.0.0/0
SENSITIVE_PORTS: Set[int] = {
    22,    # SSH
    3389,  # RDP
    3306,  # MySQL
    5432,  # PostgreSQL
    1433,  # MSSQL
    1521,  # Oracle
    27017, # MongoDB
    6379,  # Redis
    11211, # Memcached
    9200,  # Elasticsearch/OpenSearch
    25,    # SMTP
}

def _index_nodes(elements: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {el["data"]["id"]: el for el in elements if isinstance(el, dict) and el.get("group") == "nodes" and el.get("data", {}).get("id")}

def _mark_issue(el: Dict[str, Any], severity: str = "high"):
    if not el or "data" not in el: return
    el["data"]["severity"] = severity
    cls = (el.get("classes") or "").strip()
    classes = set(cls.split()) if cls else set()
    classes.add("issue")
    classes.add(severity.lower())
    el["classes"] = " ".join(sorted(classes))

def _parse_ports_from_label(label: str) -> Tuple[bool, Set[int]]:
    """
    Parses a label like:
      'tcp: 80,443; udp: 53'
      'tcp: 0-65535'
      'all'
      'any'
    Returns (all_ports, specific_ports)
    """
    if not label:
        return (False, set())

    s = label.strip().lower()
    if "all" == s or s.startswith("all ") or "any" == s:
        return (True, set())

    # Look for "0-65535"
    if "0-65535" in s or "1-65535" in s or "tcp: any" in s or "udp: any" in s:
        return (True, set())

    ports: Set[int] = set()
    # extract after 'tcp:' or 'udp:' sequences
    for proto in ("tcp", "udp", "all"):
        m = re.search(rf"{proto}\s*:\s*([0-9,\s\-]+|any|all)", s)
        if not m:
            continue
        chunk = m.group(1)
        if chunk in ("any", "all"):
            return (True, set())
        # Split lists like "80,443, 22"
        for token in re.split(r"[,\s;]+", chunk):
            token = token.strip()
            if not token:
                continue
            if "-" in token:
                try:
                    a, b = token.split("-", 1)
                    a = int(a); b = int(b)
                    if a <= b:
                        # If wide range, treat as all for our purposes
                        if a <= 1 and b >= 65535:
                            return (True, set())
                        # Add only sensitive ports within range
                        for p in SENSITIVE_PORTS:
                            if a <= p <= b:
                                ports.add(p)
                except Exception:
                    pass
            else:
                try:
                    ports.add(int(token))
                except Exception:
                    pass
    return (False, ports)

def _edge_from_world(edge: Dict[str, Any], nodes_by_id: Dict[str, Dict[str, Any]]) -> bool:
    """True if edge source is a 0.0.0.0/0 CIDR or explicit 'external' node."""
    if not edge or edge.get("group") != "edges": return False
    d = edge.get("data") or {}
    src_id = d.get("source")
    if not src_id: return False
    src = nodes_by_id.get(src_id)
    if not src: return False
    stype = (src.get("data") or {}).get("type") or ""
    if stype == "external":
        return True
    if stype == "cidr":
        cidr = ((src.get("data") or {}).get("details") or {}).get("cidr") or ""
        if str(cidr).strip() == "0.0.0.0/0":
            return True
    # Some graphs may encode world as label of the src node
    label = (src.get("data") or {}).get("label") or ""
    if label.lower().strip() in {"internet", "0.0.0.0/0", "any", "world"}:
        return True
    return False

def _is_network_edge(edge: Dict[str, Any]) -> bool:
    return (edge.get("data") or {}).get("category") == "network"

def _add_finding(findings: List[Dict[str, Any]], el: Dict[str, Any], title: str, detail: str, severity: str = "HIGH"):
    data = el.get("data") or {}
    findings.append({
        "id": data.get("id"),
        "type": data.get("type"),
        "severity": severity,
        "title": title,
        "detail": detail,
        "region": data.get("region"),
        "label": data.get("label")
    })

def _truthy(details: Dict[str, Any], *keys: str) -> bool:
    for k in keys:
        v = details.get(k)
        if isinstance(v, bool) and v:
            return True
        if isinstance(v, str) and v.lower() in {"true", "yes", "public", "internet-facing", "enabled"}:
            return True
    return False

def analyze(elements: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Inspect nodes/edges and:
      - add data.severity='high' and class 'issue' to risky elements
      - return a list of findings dicts
    """
    findings: List[Dict[str, Any]] = []

    nodes_by_id = _index_nodes(elements)

    # --- 1) Network exposure: 0.0.0.0/0 to sensitive ports or all ports
    for el in elements:
        if el.get("group") != "edges": 
            continue
        if not _is_network_edge(el):
            continue
        if not _edge_from_world(el, nodes_by_id):
            continue

        d = el.get("data") or {}
        label = (d.get("label") or "")
        all_ports, ports = _parse_ports_from_label(label)

        risky = False
        reason = None
        if all_ports:
            risky = True
            reason = "All ports exposed to the Internet (0.0.0.0/0)."
        elif ports & SENSITIVE_PORTS:
            risky = True
            common = sorted(ports & SENSITIVE_PORTS)
            reason = f"Sensitive ports {', '.join(map(str, common))} exposed to the Internet (0.0.0.0/0)."

        if risky:
            # Mark the edge and the target node
            _mark_issue(el, "high")
            tgt_id = d.get("target")
            tgt = nodes_by_id.get(tgt_id)
            if tgt: _mark_issue(tgt, "high")
            # Create a finding against the target (asset) and reference the edge id in detail
            target_label = (tgt.get("data") or {}).get("label") if tgt else d.get("target")
            edge_id = d.get("id") or f"{d.get('source')}->{d.get('target')}"
            _add_finding(findings, tgt or el, "Public network exposure", f"{reason} Edge: {edge_id}; Target: {target_label}", "HIGH")

    # --- 2) Node-level posture
    for n in elements:
        if n.get("group") != "nodes":
            continue
        nd = n.get("data") or {}
        t = (nd.get("type") or "").lower()
        details = nd.get("details") or {}

        # EC2: public IP
        if t in {"instance", "ec2", "ec2_instance"}:
            pub = details.get("public_ip") or details.get("PublicIpAddress") or details.get("PublicIp") or False
            if pub:
                _mark_issue(n, "high")
                _add_finding(findings, n, "EC2 instance has public IP", f"Instance is publicly reachable via {pub}", "HIGH")

        # ELB/ALB: internet-facing
        if t in {"load_balancer", "elb", "alb", "nlb"}:
            scheme = (details.get("scheme") or details.get("Scheme") or "").lower()
            if scheme == "internet-facing":
                _mark_issue(n, "high")
                _add_finding(findings, n, "Internet-facing load balancer", "Scheme is internet-facing", "HIGH")

        # RDS: publicly accessible
        if t in {"rds", "rds_instance", "aurora", "rds_cluster_instance"}:
            if bool(details.get("PubliclyAccessible")):
                _mark_issue(n, "high")
                _add_finding(findings, n, "RDS publicly accessible", "RDS instance is PubliclyAccessible=true", "HIGH")

        # EKS: endpoint public
        if t in {"eks", "eks_cluster"}:
            if _truthy(details, "endpointPublicAccess", "EndpointPublicAccess"):
                _mark_issue(n, "high")
                _add_finding(findings, n, "EKS public endpoint", "Cluster endpointPublicAccess is enabled", "HIGH")

        # Lambda Function URL: public (AuthType NONE)
        if t == "lambda":
            # common places to stash this from enumeration
            auth = (details.get("FunctionUrlAuthType") or details.get("function_url_auth_type") or "").upper()
            if auth == "NONE":
                _mark_issue(n, "high")
                _add_finding(findings, n, "Lambda Function URL is public", "Function URL AuthType = NONE", "HIGH")

        # S3: public
        if t in {"s3_bucket", "s3"}:
            acl = (details.get("acl") or "").lower()
            policy_public = bool(details.get("policy_allows_public"))
            bucket_public = bool(details.get("public"))
            acl_public = any(x in acl for x in ["public-read", "public-read-write"])
            if bucket_public or policy_public or acl_public:
                _mark_issue(n, "high")
                why = []
                if bucket_public:   why.append("bucket marked public")
                if policy_public:   why.append("policy allows public")
                if acl_public:      why.append(f"acl={acl}")
                _add_finding(findings, n, "S3 bucket is public", "; ".join(why) or "public access detected", "HIGH")

    return findings
