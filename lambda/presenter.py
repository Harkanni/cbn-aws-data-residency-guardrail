"""Presenter API: migration, drift and admin-identity tests, running in AWS. Whitelisted actions only,
and every request needs the demo key. Runs as a role that carries the inbound-only migration policy,
so reads from the legacy region are allowed and every write must target the approved region."""
import base64
import hmac
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

E = os.environ
R, B, K, P, ACCT = E['APPROVED_REGION'], E['BUCKET'], E['KEY_ARN'], E['PREFIX'], E['ACCOUNT_ID']
LR, LT, DT, LAMI = E['LEGACY_REGION'], E['LEGACY_TABLE'], E['DEST_TABLE'], E['LEGACY_AMI']
KEY, STATE, PARAM, FN = E['DEMO_KEY'], E['STATE_TABLE'], E['POLICY_PARAM'], E.get('AWS_LAMBDA_FUNCTION_NAME', '')
EC2_NAME = 'migrated-payments-app'
CFG = Config(retries={'max_attempts': 2}, connect_timeout=5, read_timeout=25)


def cl(svc, region=R):
    return boto3.client(svc, region_name=region, config=CFG)


def res(verdict, cmd, detail):
    return {'verdict': verdict, 'who': 'presenter role', 'cmd': cmd, 'detail': str(detail).replace(ACCT, '************')[:600]}


def attempt(cmd, fn, ok='Request succeeded.'):
    try:
        fn()
        return res('allowed', cmd, ok)
    except ClientError as e:
        c = e.response.get('Error', {})
        code, msg = c.get('Code', ''), c.get('Message', '')
        denied = code in ('AccessDenied', 'UnauthorizedOperation', 'AccessDeniedException') or 'explicit deny' in msg
        return res('denied' if denied else 'error', cmd, f'{code}: {msg}')
    except Exception as e:
        return res('error', cmd, f'{type(e).__name__}: {e}')


# ---- job state: one DynamoDB item per job, each written only by its own job -----------------
def put(job, d):
    cl('dynamodb').put_item(TableName=STATE, Item={'id': {'S': job}, 'v': {'S': json.dumps(d)}})


def get(job):
    it = cl('dynamodb').get_item(TableName=STATE, Key={'id': {'S': job}}).get('Item')
    return json.loads(it['v']['S']) if it else {'state': 'idle'}


def job_db():
    try:
        items = cl('dynamodb', LR).scan(TableName=LT)['Items']  # read from legacy: allowed
        total, moved, dd = len(items), 0, cl('dynamodb')
        put('db', {'state': 'running', 'moved': 0, 'total': total})
        for i in range(0, total, 5):
            chunk = items[i:i + 5]
            dd.batch_write_item(RequestItems={DT: [{'PutRequest': {'Item': it}} for it in chunk]})  # write: approved only
            moved += len(chunk)
            put('db', {'state': 'running', 'moved': moved, 'total': total})
            time.sleep(0.8)  # slow enough to watch
        put('db', {'state': 'done', 'moved': moved, 'total': total})
    except Exception as e:
        put('db', {'state': 'error', 'error': str(e)[:300]})


def job_ec2(ev, ctx):
    e = cl('ec2')
    try:
        ami = ev.get('ami')
        if not ami:
            put('ec2', {'state': 'copying'})
            ami = e.copy_image(Name=f'{P}-{EC2_NAME}', SourceImageId=LAMI, SourceRegion=LR, Encrypted=True, KmsKeyId=K)['ImageId']
        put('ec2', {'state': 'copying', 'ami': ami})
        while True:
            s = e.describe_images(ImageIds=[ami])['Images'][0]['State']
            if s == 'available':
                break
            if s in ('failed', 'error'):
                raise RuntimeError('image copy failed')
            if ctx.get_remaining_time_in_millis() < 40000:  # hand over to a fresh invocation
                cl('lambda').invoke(FunctionName=FN, InvocationType='Event', Payload=json.dumps({'job': 'ec2', 'ami': ami}).encode())
                return
            time.sleep(10)
        put('ec2', {'state': 'launching', 'ami': ami})
        inst = e.run_instances(ImageId=ami, InstanceType='t3.micro', MinCount=1, MaxCount=1,
                               TagSpecifications=[{'ResourceType': 'instance', 'Tags': [{'Key': 'Name', 'Value': EC2_NAME}]}])['Instances'][0]['InstanceId']
        e.get_waiter('instance_running').wait(InstanceIds=[inst], WaiterConfig={'Delay': 5, 'MaxAttempts': 40})
        put('ec2', {'state': 'done', 'ami': ami, 'instance': inst})
    except Exception as ex:
        put('ec2', {'state': 'error', 'error': str(ex)[:300]})


def run_job(ev, ctx):
    job_db() if ev['job'] == 'db' else job_ec2(ev, ctx)
    return {'ok': True}


def start(job):
    cl('lambda').invoke(FunctionName=FN, InvocationType='Event', Payload=json.dumps({'job': job}).encode())


# ---- migration status and reset -------------------------------------------------------------
def mig_status():
    def count(t, r):
        try:
            return cl('dynamodb', r).scan(TableName=t, Select='COUNT')['Count']
        except Exception:
            return None

    def image(r, **kw):
        try:
            imgs = cl('ec2', r).describe_images(**kw)['Images']
            return imgs[0]['State'] if imgs else 'none'
        except Exception:
            return 'none'

    def instance():
        try:
            d = cl('ec2').describe_instances(Filters=[{'Name': 'tag:Name', 'Values': [EC2_NAME]},
                                                      {'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']}])
            ins = [i for r in d['Reservations'] for i in r['Instances']]
            return ins[0]['State']['Name'] if ins else 'none'
        except Exception:
            return 'none'

    jobs = {'lrows': lambda: count(LT, LR), 'drows': lambda: count(DT, R), 'limg': lambda: image(LR, ImageIds=[LAMI]),
            'dimg': lambda: image(R, Owners=['self'], Filters=[{'Name': 'name', 'Values': [f'{P}-{EC2_NAME}']}]),
            'dins': instance, 'db': lambda: get('db'), 'ec2': lambda: get('ec2')}
    with ThreadPoolExecutor(7) as ex:
        futs = {k: ex.submit(f) for k, f in jobs.items()}
        r = {k: f.result() for k, f in futs.items()}
    db, ec = r['db'], r['ec2']
    return {'enabled': True, 'legacy_region': LR, 'region': R, 'legacy': {'rows': r['lrows'], 'image': r['limg']},
            'dest': {'rows': r['drows'], 'image': r['dimg'], 'instance': r['dins']},
            'job': {'db': db.get('state'), 'moved': db.get('moved', 0), 'total': db.get('total', 0), 'ec2': ec.get('state'),
                    'ami': ec.get('ami'), 'instance': ec.get('instance'), 'error': db.get('error') or ec.get('error')}}


def reset():
    if get('db').get('state') == 'running' or get('ec2').get('state') in ('copying', 'launching'):
        raise RuntimeError('a migration is still running')
    e = cl('ec2')
    d = e.describe_instances(Filters=[{'Name': 'tag:Name', 'Values': [EC2_NAME]},
                                      {'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']}])
    ids = [i['InstanceId'] for r in d['Reservations'] for i in r['Instances']]
    if ids:
        e.terminate_instances(InstanceIds=ids)
    for im in e.describe_images(Owners=['self'], Filters=[{'Name': 'name', 'Values': [f'{P}-{EC2_NAME}']}])['Images']:
        e.deregister_image(ImageId=im['ImageId'])
        for b in im.get('BlockDeviceMappings', []):
            sid = b.get('Ebs', {}).get('SnapshotId')
            if sid:
                try:
                    e.delete_snapshot(SnapshotId=sid)
                except ClientError:
                    pass
    dd = cl('dynamodb')
    items = dd.scan(TableName=DT, ProjectionExpression='payment_id')['Items']
    for i in range(0, len(items), 25):
        dd.batch_write_item(RequestItems={DT: [{'DeleteRequest': {'Key': it}} for it in items[i:i + 25]]})
    put('db', {'state': 'idle'})
    put('ec2', {'state': 'idle'})


def fix():
    s3 = cl('s3')
    s3.put_bucket_encryption(Bucket=B, ServerSideEncryptionConfiguration={'Rules': [{
        'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'aws:kms', 'KMSMasterKeyID': K}, 'BucketKeyEnabled': True}]})
    s3.put_bucket_policy(Bucket=B, Policy=cl('ssm').get_parameter(Name=PARAM)['Parameter']['Value'])
    s3.put_public_access_block(Bucket=B, PublicAccessBlockConfiguration={
        'BlockPublicAcls': True, 'IgnorePublicAcls': True, 'BlockPublicPolicy': True, 'RestrictPublicBuckets': True})
    cl('kms').enable_key_rotation(KeyId=K)


def act(p):
    a = p.get('action')
    s3 = cl('s3')
    if a == 'migDb':
        if get('db').get('state') != 'running':
            put('db', {'state': 'running', 'moved': 0, 'total': 0})
            start('db')
        return res('allowed', 'dynamodb scan (legacy) -> batch-write-item (approved region)', 'Database migration started.')
    if a == 'migEc2':
        if get('ec2').get('state') not in ('copying', 'launching'):
            put('ec2', {'state': 'copying'})
            start('ec2')
        return res('allowed', 'ec2 copy-image (legacy -> approved, re-encrypted) then run-instances', 'Server migration started; the image copy takes several minutes.')
    if a == 'migReset':
        reset()
        return res('allowed', 'terminate instance, deregister image, clear migrated table', 'Migration reset. The legacy side is untouched.')
    if a == 'migOutDb':
        return attempt('dynamodb:PutItem into us-east-1', lambda: cl('dynamodb', 'us-east-1').put_item(TableName=DT, Item={'payment_id': {'S': 'PAY-OUT'}}))
    if a == 'migOutEc2':
        return attempt('ec2:CopyImage into us-east-1', lambda: cl('ec2', 'us-east-1').copy_image(Name='exfil', SourceImageId='ami-00000000000000000', SourceRegion=R))
    if a == 'replAdmin':
        rc = {'Role': f'arn:aws:iam::{ACCT}:role/dummy-replication-role', 'Rules': [{
            'ID': 'offshore', 'Status': 'Enabled', 'Priority': 1, 'Filter': {}, 'DeleteMarkerReplication': {'Status': 'Disabled'},
            'Destination': {'Bucket': 'arn:aws:s3:::dummy-destination-bucket'}}]}
        return attempt('s3:PutBucketReplication as an admin-level role', lambda: s3.put_bucket_replication(Bucket=B, ReplicationConfiguration=rc))
    drift = {
        'enc': ('s3:DeleteBucketEncryption', lambda: s3.delete_bucket_encryption(Bucket=B)),
        'ssl': ('s3:DeleteBucketPolicy', lambda: s3.delete_bucket_policy(Bucket=B)),
        'pub': ('s3:PutPublicAccessBlock (all off)', lambda: s3.put_public_access_block(Bucket=B, PublicAccessBlockConfiguration={
            'BlockPublicAcls': False, 'IgnorePublicAcls': False, 'BlockPublicPolicy': False, 'RestrictPublicBuckets': False})),
        'rot': ('kms:DisableKeyRotation', lambda: cl('kms').disable_key_rotation(KeyId=K))}
    if a in drift:
        return attempt(*drift[a])
    if a == 'fix':
        return attempt('restore encryption, bucket policy, Block Public Access and rotation', fix,
                       'Encryption, bucket policy, Block Public Access and key rotation restored.')
    raise ValueError('unknown action')


def out(code, body):
    return {'statusCode': code, 'headers': {'Content-Type': 'application/json', 'Cache-Control': 'no-store'}, 'body': json.dumps(body)}


_WATCH = {'at': 0.0, 'body': None}


def watch():
    """Read-only migration status for anyone with the link. Cached briefly so many viewers
    polling at once do not multiply the AWS calls."""
    now = time.time()
    if _WATCH['body'] is None or now - _WATCH['at'] > 2:
        s = mig_status()
        if s['job'].get('error'):
            s['job']['error'] = str(s['job']['error']).replace(ACCT, '************')
        _WATCH.update(at=now, body=s)
    return _WATCH['body']


def handler(event, context):
    if 'job' in event:  # asynchronous job started by act()
        return run_job(event, context)
    path, method = event.get('rawPath', ''), event['requestContext']['http']['method']
    # Public, read-only: watch the migration live. Starting, pushing out, drift and reset need the key.
    if method == 'GET' and path.rstrip('/') == '/api/migration':
        try:
            return out(200, watch())
        except Exception as e:
            return out(503, {'error': str(e).replace(ACCT, '************')[:200]})
    h = {k.lower(): v for k, v in (event.get('headers') or {}).items()}
    if not hmac.compare_digest(h.get('x-demo-key', '').encode(), KEY.encode()):
        return out(401, {'error': 'Presenter key required'})
    try:
        if path.endswith('/unlock'):
            return out(200, {'ok': True})
        if method == 'GET' and path.endswith('/migration'):
            return out(200, mig_status())
        if method == 'POST' and path.endswith('/run'):
            raw = event.get('body') or '{}'
            if event.get('isBase64Encoded'):
                raw = base64.b64decode(raw).decode()
            return out(200, act(json.loads(raw)))
        return out(404, {'error': 'not found'})
    except Exception as e:
        return out(400, {'error': str(e).replace(ACCT, '************')[:200]})
