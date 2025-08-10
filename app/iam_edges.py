from __future__ import annotations
from typing import List, Dict, Any, Iterable, Tuple, Optional
import re
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from .graph import Graph

CFG = BotoConfig(retries={'max_attempts': 8, 'mode': 'adaptive'}, read_timeout=20, connect_timeout=10)
def mk_id(*parts: str) -> str: return ":".join([p for p in parts if p])

# ---- Helpers ----
def _flatten(x: Any) -> Iterable[str]:
    if not x: return []
    if isinstance(x, str): return [x]
    if isinstance(x, list): return [str(i) for i in x]
    return []

def _table_from_arn(arn: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    m = re.match(r'^arn:aws:dynamodb:([a-z0-9-]+):(\d+):table/([^/]+)', arn)
    if not m: return (None, None, None)
    return (m.group(1), m.group(2), m.group(3))

def _s3_bucket_from_arn(arn: str) -> Optional[str]:
    # s3 arns: arn:aws:s3:::bucket or arn:aws:s3:::bucket/key
    m = re.match(r'^arn:aws:s3:::([^/]+)', arn)
    return m.group(1) if m else None

def _sqs_from_arn(arn: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    m = re.match(r'^arn:aws:sqs:([a-z0-9-]+):(\d+):(.+)$', arn)
    return (m.group(1), m.group(2), m.group(3)) if m else (None, None, None)

def _sns_from_arn(arn: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    m = re.match(r'^arn:aws:sns:([a-z0-9-]+):(\d+):(.+)$', arn)
    return (m.group(1), m.group(2), m.group(3)) if m else (None, None, None)

def _kinesis_from_arn(arn: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    m = re.match(r'^arn:aws:kinesis:([a-z0-9-]+):(\d+):stream/([^/]+)$', arn)
    return (m.group(1), m.group(2), m.group(3)) if m else (None, None, None)

def _kms_from_arn(arn: str) -> Tuple[Optional[str], Optional[str]]:
    m = re.match(r'^arn:aws:kms:([a-z0-9-]*):(\d+):key/[a-f0-9-]+$', arn)
    return (m.group(1), m.group(2)) if m else (None, None)

def _secrets_from_arn(arn: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    m = re.match(r'^arn:aws:secretsmanager:([a-z0-9-]+):(\d+):secret:([^:]+)', arn)
    return (m.group(1), m.group(2), m.group(3)) if m else (None, None, None)

def _ssm_from_arn(arn: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    m = re.match(r'^arn:aws:ssm:([a-z0-9-]+):(\d+):parameter/(.+)$', arn)
    return (m.group(1), m.group(2), m.group(3)) if m else (None, None, None)

# ---- Read/write/action classification per service ----
DDB_READ = {'GetItem','BatchGetItem','Query','Scan','Describe*','List*'}
DDB_WRITE = {'PutItem','UpdateItem','DeleteItem','BatchWriteItem','CreateTable','UpdateTable','DeleteTable','TagResource','UntagResource'}
S3_READ = {'GetObject','ListBucket','GetBucket*','List*'}
S3_WRITE = {'PutObject','DeleteObject','PutBucket*','DeleteBucket*'}
SQS_READ = {'ReceiveMessage','GetQueue*','List*'}
SQS_WRITE = {'SendMessage','DeleteMessage','PurgeQueue','SetQueue*','CreateQueue'}
SNS_READ = {'GetTopic*','List*'}
SNS_WRITE = {'Publish','Subscribe','Unsubscribe','SetTopic*','CreateTopic','DeleteTopic'}
KIN_READ = {'Get*','Describe*','List*'}
KIN_WRITE = {'PutRecord','PutRecords','MergeShards','SplitShard','Start*','Add*','Remove*'}
KMS_READ = {'Decrypt','Describe*','List*','GetPublicKey'}
KMS_WRITE = {'Encrypt','ReEncrypt*','GenerateDataKey*','Sign','Verify'}
SEC_READ = {'GetSecretValue','Describe*','List*'}
SEC_WRITE = {'PutSecretValue','RotateSecret','CreateSecret','UpdateSecret','RestoreSecret','DeleteSecret'}
SSM_READ = {'GetParameter','GetParameters','Describe*','List*'}
SSM_WRITE = {'PutParameter','LabelParameterVersion','DeleteParameter','SendCommand'}

def _match_action(service: str, action: str) -> Tuple[bool, bool]:
    """Returns (read, write) for a single action like 'dynamodb:PutItem'."""
    a = action.lower()
    if a == '*': return True, True
    if ':' in a:
        svc, act = a.split(':', 1)
    else:
        return False, False
    act_norm = act.replace('.', '').replace('-', '')
    def any_match(act_set):
        return any(
            x.lower().rstrip('*') in act_norm
            for x in act_set
        )
    if svc == 'dynamodb':
        return any_match(DDB_READ), any_match(DDB_WRITE)
    if svc == 's3':
        return any_match(S3_READ), any_match(S3_WRITE)
    if svc == 'sqs':
        return any_match(SQS_READ), any_match(SQS_WRITE)
    if svc == 'sns':
        return any_match(SNS_READ), any_match(SNS_WRITE)
    if svc == 'kinesis':
        return any_match(KIN_READ), any_match(KIN_WRITE)
    if svc == 'kms':
        return any_match(KMS_READ), any_match(KMS_WRITE)
    if svc == 'secretsmanager':
        return any_match(SEC_READ), any_match(SEC_WRITE)
    if svc == 'ssm':
        return any_match(SSM_READ), any_match(SSM_WRITE)
    return False, False

def _label(read: bool, write: bool, svc_hint: str) -> str:
    if read and write: return f'perm: {svc_hint} read+write'
    if write: return f'perm: {svc_hint} write'
    if read: return f'perm: {svc_hint} read'
    return f'perm: {svc_hint}'

# ---- Ensure nodes exist (lightweight) ----
def ensure_node(g: Graph, type_: str, account: str, region: str, key: str, label: str, details: Dict[str, Any] | None = None) -> str:
    nid = mk_id(type_, account, region, key)
    g.add_node(nid, label, type_, region, details=details or {})
    return nid

# ---- IAM policy collection ----
def collect_role_statements(sess: boto3.Session, role_arn: str, warnings: List[str]) -> List[Dict[str, Any]]:
    iam = sess.client('iam', config=CFG)
    out: List[Dict[str, Any]] = []
    role_name = role_arn.split('/')[-1] if '/' in role_arn else role_arn
    try:
        for ap in iam.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', []) or []:
            parn = ap['PolicyArn']
            try:
                ver = iam.get_policy(PolicyArn=parn)['Policy']['DefaultVersionId']
                doc = iam.get_policy_version(PolicyArn=parn, VersionId=ver)['PolicyVersion']['Document']
                stmts = doc.get('Statement')
                if isinstance(stmts, dict): stmts = [stmts]
                for st in (stmts or []): out.append(st)
            except ClientError as e:
                warnings.append(f'iam get_policy_version {parn}: {e.response["Error"]["Code"]}')
    except ClientError as e:
        warnings.append(f'iam list_attached_role_policies: {e.response["Error"]["Code"]}')
    try:
        for name in iam.list_role_policies(RoleName=role_name).get('PolicyNames', []) or []:
            try:
                doc = iam.get_role_policy(RoleName=role_name, PolicyName=name)['PolicyDocument']
                stmts = doc.get('Statement')
                if isinstance(stmts, dict): stmts = [stmts]
                for st in (stmts or []): out.append(st)
            except ClientError as e:
                warnings.append(f'iam get_role_policy {name}: {e.response["Error"]["Code"]}')
    except ClientError as e:
        warnings.append(f'iam list_role_policies: {e.response["Error"]["Code"]}')
    return out

# ---- Build edges from IAM statements for a given "caller" node (Lambda/EC2/ECS task) ----
def add_edges_from_role_policies(
    sess: boto3.Session,
    role_arn: str,
    caller_node: str,
    caller_label: str,
    account_id: str,
    region: str,
    g: Graph,
    warnings: List[str]
) -> None:
    try:
        stmts = collect_role_statements(sess, role_arn, warnings)
    except Exception as e:
        warnings.append(f'iam policy read failed for {role_arn}: {e}')
        return

    for st in stmts:
        if (st.get('Effect') or '').lower() != 'allow':
            continue
        actions = _flatten(st.get('Action'))
        resources = _flatten(st.get('Resource'))
        if not actions or not resources:
            continue

        # Precompute aggregate read/write for label
        svc_hint = (actions[0].split(':',1)[0] if ':' in actions[0] else 'svc')
        agg_read = False; agg_write = False
        for a in actions:
            r,w = _match_action(svc_hint, a)
            agg_read |= r; agg_write |= w

        for r in resources:
            if r == '*':
                # Skip universal "*" to avoid spaghetti.
                continue

            # DynamoDB table
            tr, ta, tname = _table_from_arn(r)
            if tname:
                tregion = tr or region; taccount = ta or account_id
                table_node = ensure_node(g, 'dynamodb', taccount, tregion, tname, tname, {'name': tname})
                g.add_edge(
                    mk_id('edge', account_id, region, 'iam', role_arn, 'ddb', taccount, tregion, tname),
                    caller_node,
                    table_node,
                    _label(agg_read, agg_write, 'dynamodb'),
                    'iam-perm',
                    'data',
                    derived=False,
                    details={'actions': actions, 'source': 'iam'}
                )
                continue

            # S3 bucket
            b = _s3_bucket_from_arn(r)
            if b:
                # S3 is regionless in ARN; we won't guess, use current region for node id consistency
                bnode = ensure_node(g, 's3', account_id, region, b, b, {'name': b})
                g.add_edge(
                    mk_id('edge', account_id, region, 'iam', role_arn, 's3', b),
                    caller_node,
                    bnode,
                    _label(agg_read, agg_write, 's3'),
                    'iam-perm',
                    'data',
                    derived=False,
                    details={'actions': actions, 'source': 'iam'}
                )
                continue

            # SQS queue
            qr, qa, qn = _sqs_from_arn(r)
            if qn:
                qnode = ensure_node(g, 'sqs', qa or account_id, qr or region, qn, qn)
                g.add_edge(
                    mk_id('edge', account_id, region, 'iam', role_arn, 'sqs', qa or account_id, qr or region, qn),
                    caller_node,
                    qnode,
                    _label(agg_read, agg_write, 'sqs'),
                    'iam-perm',
                    'data',
                    derived=False,
                    details={'actions': actions, 'source': 'iam'}
                )
                continue

            # SNS topic
            sr, sa, sn = _sns_from_arn(r)
            if sn:
                snode = ensure_node(g, 'sns', sa or account_id, sr or region, sn, sn)
                g.add_edge(
                    mk_id('edge', account_id, region, 'iam', role_arn, 'sns', sa or account_id, sr or region, sn),
                    caller_node,
                    snode,
                    _label(agg_read, agg_write, 'sns'),
                    'iam-perm',
                    'data',
                    derived=False,
                    details={'actions': actions, 'source': 'iam'}
                )
                continue

            # Kinesis stream
            kr, ka, ks = _kinesis_from_arn(r)
            if ks:
                knode = ensure_node(g, 'kinesis', ka or account_id, kr or region, ks, ks)
                g.add_edge(
                    mk_id('edge', account_id, region, 'iam', role_arn, 'kin', ka or account_id, kr or region, ks),
                    caller_node,
                    knode,
                    _label(agg_read, agg_write, 'kinesis'),
                    'iam-perm',
                    'data',
                    derived=False,
                    details={'actions': actions, 'source': 'iam'}
                )
                continue

            # KMS key
            krgn, kacc = _kms_from_arn(r)
            if krgn is not None:
                knode = ensure_node(g, 'kms', kacc or account_id, krgn or region, r.split('/')[-1], 'KMS Key', {'key_arn': r})
                g.add_edge(
                    mk_id('edge', account_id, region, 'iam', role_arn, 'kms', r),
                    caller_node,
                    knode,
                    _label(agg_read, agg_write, 'kms'),
                    'iam-perm',
                    'data',
                    derived=False,
                    details={'actions': actions, 'source': 'iam'}
                )
                continue

            # Secrets Manager
            segr, seacc, sename = _secrets_from_arn(r)
            if sename:
                snode = ensure_node(g, 'secret', seacc or account_id, segr or region, sename, sename)
                g.add_edge(
                    mk_id('edge', account_id, region, 'iam', role_arn, 'secret', seacc or account_id, segr or region, sename),
                    caller_node,
                    snode,
                    _label(agg_read, agg_write, 'secret'),
                    'iam-perm',
                    'data',
                    derived=False,
                    details={'actions': actions, 'source': 'iam'}
                )
                continue

            # SSM Parameter
            pr, pa, pname = _ssm_from_arn(r)
            if pname:
                pnode = ensure_node(g, 'ssmparam', pa or account_id, pr or region, pname, pname)
                g.add_edge(
                    mk_id('edge', account_id, region, 'iam', role_arn, 'ssm', pa or account_id, pr or region, pname),
                    caller_node,
                    pnode,
                    _label(agg_read, agg_write, 'ssm'),
                    'iam-perm',
                    'data',
                    derived=False,
                    details={'actions': actions, 'source': 'iam'}
                )
                continue
