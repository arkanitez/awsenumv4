from __future__ import annotations

from typing import Any, Dict, List, Tuple, Set, Iterable
import re

# ===== Port model =====

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
    9200,  # ES/OpenSearch
    25,    # SMTP
    389, 636,  # LDAP/LDAPS
    23, 21,    # Telnet / FTP
}
HTTP_PORTS = {80, 8080, 8000, 8081}

# Common weak TLS policy IDs/versions (ELB/CloudFront, etc.)
TLS_WEAK_VERSIONS = {"SSLv3", "TLSv1", "TLSv1_0", "TLSv1.0", "TLSv1_1", "TLSv1.1"}
TLS_WEAK_PATTERNS = re.compile(r"(TLS[-_]?1(\.0|_0|[-_]0)|SSL)", re.IGNORECASE)

# ===== Utilities =====

def _index_nodes(elements: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {
        el["data"]["id"]: el
        for el in elements
        if isinstance(el, dict) and el.get("group") == "nodes" and el.get("data", {}).get("id")
    }

def _mark_issue(el: Dict[str, Any], severity: str = "high"):
    if not el or "data" not in el: return
    el["data"]["severity"] = severity
    cls = (el.get("classes") or "").strip()
    classes = set(cls.split()) if cls else set()
    classes.add("issue")
    classes.add(severity.lower())
    el["classes"] = " ".join(sorted(classes))

def _add_finding(findings: List[Dict[str, Any]], el: Dict[str, Any], title: str, detail: str, severity: str = "HIGH"):
    data = (el.get("data") or {}) if isinstance(el, dict) else {}
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
        if isinstance(v, bool) and v: return True
        if isinstance(v, (int, float)) and v != 0: return True
        if isinstance(v, str) and v.strip().lower() in {"true","yes","enabled","public","internet-facing","open"}:
            return True
    return False

def _safe_str(v: Any) -> str:
    try: return str(v)
    except Exception: return ""

def _coalesce(d: Dict[str, Any], *keys: str, default: Any=None) -> Any:
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default

# ===== Policy checks (Cloudsplaining-like) =====

def _iter_policy_docs(obj: Any) -> Iterable[Dict[str, Any]]:
    if not obj: return
    if isinstance(obj, dict) and ("Statement" in obj or "statement" in obj):
        yield obj; return
    if isinstance(obj, list):
        yield {"Statement": obj}; return
    if isinstance(obj, dict):
        for key in ("policy","policy_document","resource_policy","Policy","AssumeRolePolicyDocument"):
            doc = obj.get(key)
            if isinstance(doc, dict) and ("Statement" in doc or "statement" in doc):
                yield doc

def _wild(v: Any) -> bool:
    if isinstance(v, str):
        s = v.strip()
        return s == "*" or s.lower() == "arn:*" or s.lower().endswith(":*")
    if isinstance(v, list):
        return any(_wild(x) for x in v)
    return False

def _principal_public(p: Any) -> bool:
    if isinstance(p, str): return p == "*" or p.lower() == "anonymous"
    if isinstance(p, dict):
        for _, vv in p.items():
            if _wild(vv): return True
    if isinstance(p, list):
        return any(_principal_public(x) for x in p)
    return False

def _policy_allows_overbroad(policy_doc: Dict[str, Any]) -> Tuple[bool, bool, bool]:
    try:
        stmts = policy_doc.get("Statement") or policy_doc.get("statement") or []
        if isinstance(stmts, dict): stmts = [stmts]
        a_wild = r_wild = p_pub = False
        for s in stmts:
            if (s.get("Effect") or s.get("effect") or "").lower() != "allow": continue
            action = s.get("Action") or s.get("action")
            resource = s.get("Resource") or s.get("resource")
            principal = s.get("Principal") or s.get("principal")
            a_wild = a_wild or _wild(action)
            r_wild = r_wild or _wild(resource)
            p_pub = p_pub or _principal_public(principal)
        return (a_wild, r_wild, p_pub)
    except Exception:
        return (False, False, False)

# ===== Edge / ports parsing =====

def _parse_ports_from_label(label: str) -> Tuple[bool, Set[int], Set[int]]:
    """
    Parse ports from labels like 'tcp: 80,443; udp: 53', '0-65535', 'any'.
    Returns (all_ports, ports, http_ports_found)
    """
    if not label: return (False, set(), set())
    s = label.strip().lower()
    if s in {"all","any"} or "0-65535" in s or "1-65535" in s:
        return (True, set(), set())

    ports: Set[int] = set(); http_found: Set[int] = set()
    tokens = re.findall(r'(\d{1,5})(?:-(\d{1,5}))?', s)
    for (a, b) in tokens:
        try:
            a = int(a)
            if b:
                b = int(b)
                if a <= 1 and b >= 65535: return (True, set(), http_found)
                for p in range(a, min(b, 65535) + 1):
                    ports.add(p); 
                    if p in HTTP_PORTS: http_found.add(p)
            else:
                ports.add(a); 
                if a in HTTP_PORTS: http_found.add(a)
        except Exception:
            pass
    return (False, ports, http_found)

def _edge_from_world(edge: Dict[str, Any], nodes_by_id: Dict[str, Dict[str, Any]]) -> bool:
    if not edge or edge.get("group") != "edges": return False
    d = edge.get("data") or {}; src_id = d.get("source")
    if not src_id: return False
    src = nodes_by_id.get(src_id); 
    if not src: return False
    stype = (src.get("data") or {}).get("type") or ""
    if stype == "external": return True
    if stype == "cidr":
        cidr = ((src.get("data") or {}).get("details") or {}).get("cidr") or ""
        if str(cidr).strip() == "0.0.0.0/0": return True
    label = (src.get("data") or {}).get("label") or ""
    return label.lower().strip() in {"internet", "0.0.0.0/0", "any", "world"}

def _is_network_edge(edge: Dict[str, Any]) -> bool:
    return (edge.get("data") or {}).get("category") == "network"

# ===== Main analyzer =====

def analyze(elements: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    nodes_by_id = _index_nodes(elements)

    # 1) Network exposure (0.0.0.0/0 edges) — sensitive ports, all ports, http-only
    for el in elements:
        if el.get("group") != "edges" or not _is_network_edge(el): 
            continue
        if not _edge_from_world(el, nodes_by_id): 
            continue

        d = el.get("data") or {}
        label = (d.get("label") or "")
        all_ports, ports, http_ports = _parse_ports_from_label(label)

        if all_ports:
            _mark_issue(el, "high")
            tgt = nodes_by_id.get(d.get("target"))
            if tgt: _mark_issue(tgt, "high")
            _add_finding(findings, tgt or el, "Public network exposure", "All ports exposed to the Internet (0.0.0.0/0).", "HIGH")
            continue

        sens = ports & SENSITIVE_PORTS
        if sens:
            _mark_issue(el, "high")
            tgt = nodes_by_id.get(d.get("target"))
            if tgt: _mark_issue(tgt, "high")
            _add_finding(findings, tgt or el, "Public network exposure",
                         f"Sensitive ports {', '.join(map(str, sorted(sens)))} exposed to 0.0.0.0/0.", "HIGH")

        if http_ports:
            _mark_issue(el, "high")
            tgt = nodes_by_id.get(d.get("target"))
            if tgt: _mark_issue(tgt, "high")
            _add_finding(findings, tgt or el, "HTTP listener exposed to Internet",
                         f"HTTP port(s) {', '.join(map(str, sorted(http_ports)))} reachable from 0.0.0.0/0.", "HIGH")

    # 2) Node posture checks (service-focused)
    for n in elements:
        if n.get("group") != "nodes": continue
        nd = n.get("data") or {}
        t = (nd.get("type") or "").lower()
        details = nd.get("details") or {}

        # ---- EC2 / EBS / AMI / Snapshots
        if t in {"instance", "ec2", "ec2_instance"}:
            if _coalesce(details, "PublicIpAddress","PublicIp","public_ip", default=None):
                _mark_issue(n, "high")
                _add_finding(findings, n, "EC2 instance has public IP",
                             f"Instance public IP: {_safe_str(_coalesce(details,'PublicIpAddress','PublicIp','public_ip'))}", "HIGH")
            ht = (_coalesce(details, "HttpTokens","httpTokens", default="optional") or "").lower()
            if ht and ht != "required":
                _mark_issue(n, "high")
                _add_finding(findings, n, "EC2 IMDSv2 not enforced", f"Instance metadata HttpTokens={ht}", "HIGH")

        if t in {"ebs_volume","volume"}:
            if not bool(_coalesce(details, "Encrypted","encrypted", default=False)):
                _mark_issue(n, "high")
                _add_finding(findings, n, "EBS volume is unencrypted", "Encrypted=false", "HIGH")

        if t in {"ebs_snapshot","snapshot"}:
            if _truthy(details, "public","Public"):
                _mark_issue(n, "high")
                _add_finding(findings, n, "EBS snapshot is public", "Snapshot is publicly accessible", "HIGH")

        if t in {"ami","image"}:
            if _truthy(details, "public","Public"):
                _mark_issue(n, "high")
                _add_finding(findings, n, "AMI is public", "Image is publicly accessible", "HIGH")

        # ---- ELB/ALB/NLB
        if t in {"load_balancer","elb","alb","nlb"}:
            scheme = (_coalesce(details,"scheme","Scheme", default="") or "").lower()
            if scheme == "internet-facing":
                _mark_issue(n, "high")
                _add_finding(findings, n, "Internet-facing load balancer", "Scheme is internet-facing", "HIGH")
            # Weak TLS on listeners
            listeners = details.get("listeners") or []
            for lst in listeners:
                proto = _safe_str(lst.get("Protocol") or lst.get("protocol")).upper()
                port = lst.get("Port") or lst.get("port")
                pol  = _safe_str(lst.get("SslPolicy") or lst.get("ssl_policy"))
                if proto in {"TLS","SSL","HTTPS"} and (pol in TLS_WEAK_VERSIONS or TLS_WEAK_PATTERNS.search(pol)):
                    _mark_issue(n, "high")
                    _add_finding(findings, n, "ELB weak TLS policy",
                                 f"Listener {proto}/{port} uses weak policy '{pol}'", "HIGH")
                # HTTP listener without https/redirect hint (if enumerator provided)
                if proto == "HTTP" and not _truthy(lst, "RedirectToHTTPS","redirect_to_https") and not _truthy(details, "httpRedirectToHttps"):
                    _mark_issue(n, "high")
                    _add_finding(findings, n, "HTTP listener without HTTPS redirect",
                                 f"Listener HTTP/{port} does not indicate redirect to HTTPS", "HIGH")

        # ---- RDS / Aurora
        if t in {"rds","rds_instance","rds_cluster_instance","aurora"}:
            if bool(details.get("PubliclyAccessible")):
                _mark_issue(n, "high")
                _add_finding(findings, n, "RDS publicly accessible", "PubliclyAccessible=true", "HIGH")
            if not bool(details.get("StorageEncrypted", True)):
                _mark_issue(n, "high")
                _add_finding(findings, n, "RDS storage not encrypted", "StorageEncrypted=false", "HIGH")
            brp = details.get("BackupRetentionPeriod")
            if isinstance(brp, int) and brp <= 0:
                _mark_issue(n, "high")
                _add_finding(findings, n, "RDS backups disabled", "BackupRetentionPeriod<=0", "HIGH")
            if details.get("MultiAZ") is False:
                _mark_issue(n, "high")
                _add_finding(findings, n, "RDS not Multi-AZ", "MultiAZ=false", "HIGH")

        # ---- EKS
        if t in {"eks","eks_cluster"}:
            if _truthy(details, "endpointPublicAccess","EndpointPublicAccess"):
                _mark_issue(n, "high")
                _add_finding(findings, n, "EKS public endpoint", "endpointPublicAccess enabled", "HIGH")
            cidrs = details.get("publicAccessCidrs") or details.get("PublicAccessCidrs") or []
            try: cidrs = [c.strip() for c in cidrs if isinstance(c, str)]
            except Exception: cidrs = []
            if "0.0.0.0/0" in cidrs:
                _mark_issue(n, "high")
                _add_finding(findings, n, "EKS endpoint open to world", "publicAccessCidrs includes 0.0.0.0/0", "HIGH")
            logs = details.get("clusterLogging") or details.get("ClusterLogging") or {}
            enabled_logs = []
            try:
                for ct in logs.get("types", []) or []:
                    if ct in ("api","audit","authenticator","controllerManager","scheduler"):
                        enabled_logs.append(ct)
            except Exception: pass
            if not enabled_logs:
                _mark_issue(n, "high")
                _add_finding(findings, n, "EKS control plane logging disabled", "No log types enabled", "HIGH")

        # ---- ECS
        if t in {"ecs_service"}:
            if _truthy(details, "internetFacing","publicLoadBalancer"):
                _mark_issue(n, "high")
                _add_finding(findings, n, "ECS service internet-facing", "Public LB or internetFacing=true", "HIGH")

        # ---- Lambda
        if t == "lambda":
            auth = (_coalesce(details, "FunctionUrlAuthType","function_url_auth_type", default="") or "").upper()
            if auth == "NONE":
                _mark_issue(n, "high")
                _add_finding(findings, n, "Lambda Function URL is public", "Function URL AuthType=NONE", "HIGH")
            if _truthy(details, "resource_policy_public","ResourcePolicyPublic"):
                _mark_issue(n, "high")
                _add_finding(findings, n, "Lambda resource policy allows public", "Invoke permission to '*'", "HIGH")

        # ---- S3
        if t in {"s3_bucket","s3"}:
            acl = (_safe_str(details.get("acl")).lower())
            policy_public = bool(details.get("policy_allows_public") or details.get("PolicyAllowsPublic"))
            bucket_public = bool(details.get("public") or details.get("Public"))
            pab = details.get("public_access_block") or details.get("PublicAccessBlock") or {}
            pab_disabled = any(v is False for v in [
                pab.get("BlockPublicAcls"),
                pab.get("IgnorePublicAcls"),
                pab.get("BlockPublicPolicy"),
                pab.get("RestrictPublicBuckets"),
            ])
            if bucket_public or policy_public or "public-read" in acl or "public-read-write" in acl or pab_disabled:
                _mark_issue(n, "high")
                why = []
                if bucket_public:   why.append("bucket marked public")
                if policy_public:   why.append("policy allows public")
                if "public-read" in acl or "public-read-write" in acl: why.append(f"acl={acl}")
                if pab_disabled:    why.append("PublicAccessBlock disabled")
                _add_finding(findings, n, "S3 bucket is public", "; ".join(why) or "public access detected", "HIGH")
            enc_conf = details.get("ServerSideEncryptionConfiguration")
                if not enc_conf:
                    enc_resp = details.get("encryption")
                    if isinstance(enc_resp, dict):
                        enc_conf = enc_resp.get("ServerSideEncryptionConfiguration") or enc_resp.get("Rules")
                if not enc_conf:
                    _mark_issue(n, "high")
                _add_finding(findings, n, "S3 default encryption not enabled", "No default SSE configuration", "HIGH")
            ver = details.get("Versioning") or details.get("versioning") or {}
            if not bool(ver.get("Status") == "Enabled" or ver.get("enabled") is True):
                _mark_issue(n, "high")
                _add_finding(findings, n, "S3 versioning disabled", "Versioning not enabled", "HIGH")
            log = details.get("Logging") or details.get("logging") or {}
            logging_enabled = bool(
                log.get("Enabled") or log.get("enabled") or
                log.get("LoggingEnabled") or log.get("TargetBucket")
            )
            if not logging_enabled:
                _mark_issue(n, "high")
                _add_finding(findings, n, "S3 server access logging disabled", "No logging target", "HIGH")

        # ---- CloudFront
        if t in {"cloudfront"}:
            min_tls = _safe_str(_coalesce(details, "MinimumProtocolVersion","ViewerCertificateMinimumProtocolVersion"))
            if min_tls and (min_tls in TLS_WEAK_VERSIONS or min_tls.upper() in TLS_WEAK_VERSIONS or TLS_WEAK_PATTERNS.search(min_tls)):
                _mark_issue(n, "high")
                _add_finding(findings, n, "CloudFront weak TLS", f"MinimumProtocolVersion={min_tls}", "HIGH")
            vpp = _safe_str(_coalesce(details, "ViewerProtocolPolicy","viewer_protocol_policy")).lower()
            if vpp == "allow-all":
                _mark_issue(n, "high")
                _add_finding(findings, n, "CloudFront allows HTTP", "ViewerProtocolPolicy=allow-all", "HIGH")
            if _safe_str(details.get("origin_access")).lower() in {"none","public"}:
                _mark_issue(n, "high")
                _add_finding(findings, n, "CloudFront S3 origin not protected", "No OAI/OAC configured", "HIGH")

        # ---- IAM-like (policies, trust, resource policies)
        if t in {"iam_role","iam_policy"}:
            for doc in _iter_policy_docs(details):
                a_w, r_w, p_pub = _policy_allows_overbroad(doc)
                if a_w and r_w:
                    _mark_issue(n, "high")
                    _add_finding(findings, n, "IAM policy allows * on *", "Action='*' and Resource='*'", "HIGH")
                elif a_w:
                    _mark_issue(n, "high")
                    _add_finding(findings, n, "IAM policy action wildcard", "Action='*'", "HIGH")
                elif r_w:
                    _mark_issue(n, "high")
                    _add_finding(findings, n, "IAM policy resource wildcard", "Resource='*'", "HIGH")
                if p_pub:
                    _mark_issue(n, "high")
                    _add_finding(findings, n, "IAM policy has public principal", "Principal='*'", "HIGH")
            if "AssumeRolePolicyDocument" in details:
                a_w, r_w, p_pub = _policy_allows_overbroad(details["AssumeRolePolicyDocument"])
                if p_pub:
                    _mark_issue(n, "high")
                    _add_finding(findings, n, "IAM trust policy allows anyone to assume", "Principal='*' in trust", "HIGH")

        if t in {"sqs_queue","sns_topic","opensearch_domain","kinesis_stream"}:
            for doc in _iter_policy_docs(details):
                a_w, r_w, p_pub = _policy_allows_overbroad(doc)
                if p_pub:
                    _mark_issue(n, "high")
                    _add_finding(findings, n, f"{nd.get('type','Resource')} policy allows public access",
                                 "Principal='*' in resource policy", "HIGH")

        if t in {"kms_key","kms"}:
            rot = details.get("KeyRotationEnabled")
            if rot is False:
                _mark_issue(n, "high")
                _add_finding(findings, n, "KMS key rotation disabled", "KeyRotationEnabled=false", "HIGH")

        if t in {"secret","secrets_manager"}:
            if not bool(details.get("RotationEnabled")):
                _mark_issue(n, "high")
                _add_finding(findings, n, "Secrets Manager rotation disabled", "RotationEnabled=false", "HIGH")

        if t in {"cloudwatch_log_group"}:
            r = details.get("retentionInDays") or details.get("RetentionInDays")
            if not isinstance(r, int) or r <= 0:
                _mark_issue(n, "high")
                _add_finding(findings, n, "CloudWatch log group has no retention", f"retentionInDays={r}", "HIGH")

        # ---- Default Security Group usage
        if t in {"security_group"}:
            name = _safe_str(_coalesce(details, "GroupName","groupName","name","Name"))
            if name.lower() == "default":
                _mark_issue(n, "high")
                _add_finding(findings, n, "Default Security Group in use", "Security Group name is 'default'", "HIGH")

    return findings


# ===== Minimal self-tests =====
if __name__ == "__main__":
    assert _parse_ports_from_label("tcp: 80,443; udp: 53") == (False, {80,443,53}, {80})
    assert _parse_ports_from_label("all") == (True, set(), set())
    assert _parse_ports_from_label("tcp: 0-65535") == (True, set(), set())
    doc = {"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Allow","Action":["s3:Get*"],"Resource":"*","Principal":"*"}]}
    assert _policy_allows_overbroad(doc) == (True, True, True)
    print("findings.py self-tests passed")
