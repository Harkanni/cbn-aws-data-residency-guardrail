"""Public probe API for the region-lock demo. Whitelisted actions only, no user-supplied commands.
Runs as a dedicated least-privilege role that has the region-lock and no-replication deny policies
attached, so every result is a REAL AWS authorization decision for that role."""
import base64
import collections
import datetime as dt
import json
import os
import secrets
import time
from concurrent.futures import ThreadPoolExecutor

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

R, B, K = os.environ['APPROVED_REGION'], os.environ['BUCKET'], os.environ['KEY_ARN']
P, T, ACCT = os.environ['PREFIX'], os.environ['TOPIC_ARN'], os.environ['ACCOUNT_ID']
REGIONS = {'us-east-1', 'eu-west-1', 'ap-southeast-1', R}
SIDS = {'DenyReplicationChanges', 'DenyNonTLS', 'DenyNonKmsEncryption', 'DenyWrongKmsKey'}
CFG = Config(retries={'max_attempts': 1}, connect_timeout=5, read_timeout=20)
HITS = collections.deque(maxlen=60)


def cl(svc, region=R, **kw):
    return boto3.client(svc, region_name=region, config=CFG, **kw)


def res(verdict, cmd, detail):
    return {'verdict': verdict, 'who': 'public probe role', 'cmd': cmd, 'detail': str(detail).replace(ACCT, '************')[:600]}


def attempt(cmd, fn, ok='Request succeeded.'):
    try:
        fn()
        return res('allowed', cmd, ok)
    except ClientError as e:
        c = e.response.get('Error', {})
        code, msg = c.get('Code', ''), c.get('Message', '')
        if code == 'DryRunOperation':
            return res('allowed', cmd, 'DryRunOperation: the request would have succeeded (nothing was created).')
        denied = code in ('AccessDenied', 'UnauthorizedOperation', 'AccessDeniedException') or 'explicit deny' in msg
        return res('denied' if denied else 'error', cmd, f'{code}: {msg}')
    except Exception as e:  # network, validation, etc.
        return res('error', cmd, f'{type(e).__name__}: {e}')


def probe(p):
    s, r = p.get('service'), p.get('region')
    if r not in REGIONS:
        raise ValueError('unknown region')
    if s == 'ec2':
        return attempt(f'ec2:CreateVpc (dry run) in {r}', lambda: cl('ec2', r).create_vpc(CidrBlock='10.99.0.0/16', DryRun=True))
    if s == 'kms':
        return attempt(f'kms:ListKeys in {r}', lambda: cl('kms', r).list_keys(Limit=1))
    if s == 'lambda':
        return attempt(f'lambda:ListFunctions in {r}', lambda: cl('lambda', r).list_functions(MaxItems=1))
    if s == 'rds':
        return attempt(f'rds:DescribeDBInstances in {r}', lambda: cl('rds', r).describe_db_instances(MaxRecords=20))
    if s == 's3':
        name = f'{P}-probe-{ACCT}-{secrets.token_hex(3)}'
        kw = {} if r == 'us-east-1' else {'CreateBucketConfiguration': {'LocationConstraint': r}}
        c = cl('s3', r)
        out = attempt(f's3:CreateBucket in {r}', lambda: c.create_bucket(Bucket=name, **kw))
        if out['verdict'] == 'allowed':
            attempt('s3:DeleteBucket', lambda: c.delete_bucket(Bucket=name))
            out['detail'] = 'Bucket created, then deleted again.'
        return out
    raise ValueError('unknown service')


def act(p):
    a = p.get('action')
    if a == 'probe':
        return probe(p)
    key = f'tests/{a}-{int(time.time())}.json'
    body = json.dumps({'receipt_id': a, 'note': 'SIMULATED DATA'}).encode()
    s3 = cl('s3')

    def put(client=s3, **kw):
        return lambda: client.put_object(Bucket=B, Key=key, Body=body, **kw)

    if a == 'upOk':
        return attempt('s3:PutObject, SSE-KMS with our key', put(ServerSideEncryption='aws:kms', SSEKMSKeyId=K))
    if a == 'upS3':
        return attempt('s3:PutObject, SSE-S3 (AES256)', put(ServerSideEncryption='AES256'))
    if a == 'upKey':
        return attempt('s3:PutObject, SSE-KMS with the AWS-managed key', put(ServerSideEncryption='aws:kms', SSEKMSKeyId='alias/aws/s3'))
    if a == 'upHttp':
        http = boto3.client('s3', region_name=R, config=CFG, endpoint_url=f'http://s3.{R}.amazonaws.com')
        return attempt('s3:PutObject over plain HTTP', put(http, ServerSideEncryption='aws:kms', SSEKMSKeyId=K))
    if a == 'repl':
        rc = {'Role': f'arn:aws:iam::{ACCT}:role/dummy-replication-role', 'Rules': [{
            'ID': 'offshore', 'Status': 'Enabled', 'Priority': 1, 'Filter': {},
            'DeleteMarkerReplication': {'Status': 'Disabled'},
            'Destination': {'Bucket': 'arn:aws:s3:::dummy-destination-bucket'}}]}
        return attempt('s3:PutBucketReplication to another bucket', lambda: s3.put_bucket_replication(Bucket=B, ReplicationConfiguration=rc))
    if a == 'mrk':
        return attempt('kms:CreateKey (multi-Region)', lambda: cl('kms').create_key(MultiRegion=True))
    raise ValueError('unknown action')


def status():
    now = dt.datetime.now(dt.timezone.utc)

    def metric(rule):
        d = cl('cloudwatch').get_metric_statistics(
            Namespace='AWS/Events', MetricName='Invocations', Dimensions=[{'Name': 'RuleName', 'Value': rule}],
            StartTime=now - dt.timedelta(hours=24), EndTime=now, Period=86400, Statistics=['Sum'])
        return int(sum(x['Sum'] for x in d.get('Datapoints', [])))

    jobs = {
        'rules': lambda: cl('config').describe_compliance_by_config_rule(),
        'sns': lambda: cl('sns').list_subscriptions_by_topic(TopicArn=T),
        'enc': lambda: cl('s3').get_bucket_encryption(Bucket=B),
        'bpa': lambda: cl('s3').get_public_access_block(Bucket=B),
        'pol': lambda: cl('s3').get_bucket_policy(Bucket=B),
        'rot': lambda: cl('kms').get_key_rotation_status(KeyId=K),
        'key': lambda: cl('kms').describe_key(KeyId=K),
        'm1': lambda: metric(P + '-replication-change'),
        'm2': lambda: metric(P + '-config-noncompliant')}

    def safe(f):
        try:
            return f()
        except Exception:
            return None

    with ThreadPoolExecutor(9) as ex:
        futs = {k: ex.submit(safe, f) for k, f in jobs.items()}
        r = {k: f.result() for k, f in futs.items()}

    rules = [{'name': x['ConfigRuleName'], 'status': x.get('Compliance', {}).get('ComplianceType', 'UNKNOWN')}
             for x in (r['rules'] or {}).get('ComplianceByConfigRules', []) if x['ConfigRuleName'].startswith(P)]
    try:
        d = r['enc']['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']
    except (TypeError, KeyError, IndexError):
        d = {}
    algo, ekey = d.get('SSEAlgorithm', 'unknown'), d.get('KMSMasterKeyID')
    bpa = (r['bpa'] or {}).get('PublicAccessBlockConfiguration', {})
    try:
        sids = {s.get('Sid') for s in json.loads(r['pol']['Policy'])['Statement']}
    except (TypeError, KeyError, ValueError):
        sids = set()
    multi = (r['key'] or {}).get('KeyMetadata', {}).get('MultiRegion')
    rot = (r['rot'] or {}).get('KeyRotationEnabled')
    config = [
        {'label': 'Default encryption', 'value': algo + (' with our key' if ekey == K else ''), 'ok': algo == 'aws:kms' and ekey == K},
        {'label': 'Block Public Access', 'value': 'all four on' if bpa and all(bpa.values()) else 'not fully on', 'ok': bool(bpa) and all(bpa.values())},
        {'label': 'Bucket policy', 'value': f'{len(SIDS & sids)} of 4 deny statements', 'ok': SIDS <= sids},
        {'label': 'Key rotation', 'value': 'enabled' if rot else 'disabled', 'ok': bool(rot)},
        {'label': 'KMS key scope', 'value': 'multi-Region' if multi else 'single-Region', 'ok': multi is False}]

    def hide(e):  # never publish the subscriber's address
        return e[:1] + '***' + e[e.find('@'):] if '@' in e else '***'

    subs = [{'endpoint': hide(s['Endpoint']), 'confirmed': s['SubscriptionArn'] != 'PendingConfirmation'}
            for s in (r['sns'] or {}).get('Subscriptions', [])]
    return {'mode': 'public', 'account': '********' + ACCT[-4:], 'region': R, 'bucket': 'payments bucket (name hidden)',
            'rules': rules, 'config': config, 'subs': subs, 'fired': {'replication': r['m1'] or 0, 'config': r['m2'] or 0}}


def out(code, body):
    return {'statusCode': code, 'headers': {'Content-Type': 'application/json', 'Cache-Control': 'no-store'}, 'body': json.dumps(body)}


def handler(event, context):
    now = time.time()
    HITS.append(now)
    if sum(1 for h in HITS if now - h < 60) >= 40:
        return out(429, {'error': 'Too many requests, slow down.'})
    path, method = event.get('rawPath', ''), event['requestContext']['http']['method']
    try:
        if method == 'GET' and path.endswith('/status'):
            return out(200, status())
        if method == 'POST' and path.endswith('/run'):
            raw = event.get('body') or '{}'
            if event.get('isBase64Encoded'):
                raw = base64.b64decode(raw).decode()
            return out(200, act(json.loads(raw)))
        return out(404, {'error': 'not found'})
    except Exception as e:
        return out(400, {'error': str(e)[:200]})
