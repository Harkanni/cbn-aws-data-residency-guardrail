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

from codeview import Call

E = os.environ
R, B, K, P, ACCT = E['APPROVED_REGION'], E['BUCKET'], E['KEY_ARN'], E['PREFIX'], E['ACCOUNT_ID']
LR, LT, DT, LAMI = E['LEGACY_REGION'], E['LEGACY_TABLE'], E['DEST_TABLE'], E['LEGACY_AMI']
LINST = E.get('LEGACY_INSTANCE', '')
KEY, STATE, PARAM, FN = E['DEMO_KEY'], E['STATE_TABLE'], E['POLICY_PARAM'], E.get('AWS_LAMBDA_FUNCTION_NAME', '')
EC2_NAME = 'migrated-payments-app'
CFG = Config(retries={'max_attempts': 2}, connect_timeout=5, read_timeout=25)


def cl(svc, region=R):
    return boto3.client(svc, region_name=region, config=CFG)


def mask(s):
    return str(s).replace(ACCT, '************')


def res(verdict, cmd, detail, code=None, cli=None):
    r = {'verdict': verdict, 'who': 'presenter role', 'cmd': cmd, 'detail': mask(detail)[:600],
         'role': f'{P}-presenter-lambda', 'source': 'lambda/presenter.py'}
    if code:  # the exact code that ran, as Python and as the AWS CLI equivalent
        r['code'], r['cli'] = mask(code), mask(cli or '')
    return r


def attempt(cmd, call, ok='Request succeeded.'):
    """Run one Call (or a (fn, code, cli) tuple) and report AWS's own answer with the code that ran."""
    fn, code, cli = (call, call.code(), call.cli()) if isinstance(call, Call) else call
    try:
        fn()
        return res('allowed', cmd, ok, code, cli)
    except ClientError as e:
        c = e.response.get('Error', {})
        ec, msg = c.get('Code', ''), c.get('Message', '')
        denied = ec in ('AccessDenied', 'UnauthorizedOperation', 'AccessDeniedException') or 'explicit deny' in msg
        return res('denied' if denied else 'error', cmd, f'{ec}: {msg}', code, cli)
    except Exception as e:
        return res('error', cmd, f'{type(e).__name__}: {e}', code, cli)


def C(svc, op, region=R, **kw):
    return Call(svc, region, op, config=CFG, **kw)


# What the background jobs run (job_db and job_ec2 below), shown in the console's code panel.
def code_db():
    return (f"""legacy = boto3.client('dynamodb', region_name={LR!r})   # offshore: read only
items = legacy.scan(TableName={LT!r})['Items']
dest = boto3.client('dynamodb', region_name={R!r})     # approved region: writes allowed
for i in range(0, len(items), 5):
    dest.batch_write_item(RequestItems={{{DT!r}: [{{'PutRequest': {{'Item': it}}}} for it in items[i:i + 5]]}})""",
            f"""aws dynamodb scan --table-name {LT} --region {LR}
# then, 5 records at a time, into the approved region:
aws dynamodb batch-write-item --request-items file://batch.json --region {R}""")


def code_ec2():
    return (f"""ec2 = boto3.client('ec2', region_name={R!r})   # called IN the approved region
ami = ec2.copy_image(Name={P + '-' + EC2_NAME!r}, SourceImageId={LAMI!r}, SourceRegion={LR!r},
                     Encrypted=True, KmsKeyId={K!r})['ImageId']   # re-encrypted with the bank's key
# wait until the copy is 'available', then launch it:
ec2.run_instances(ImageId=ami, InstanceType='t3.micro', MinCount=1, MaxCount=1,
                  TagSpecifications=[{{'ResourceType': 'instance', 'Tags': [{{'Key': 'Name', 'Value': {EC2_NAME!r}}}]}}])""",
            f"""aws ec2 copy-image --name {P}-{EC2_NAME} --source-image-id {LAMI} --source-region {LR} --encrypted --kms-key-id {K} --region {R}
aws ec2 wait image-available --image-ids <new-ami> --region {R}
aws ec2 run-instances --image-id <new-ami> --instance-type t3.micro --count 1 --tag-specifications 'ResourceType=instance,Tags=[{{Key=Name,Value={EC2_NAME}}}]' --region {R}""")


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
def legacy_table_state():
    try:
        return cl('dynamodb', LR).describe_table(TableName=LT)['Table']['TableStatus'].lower()  # active / deleting
    except ClientError as e:
        return 'deleted' if e.response['Error']['Code'] == 'ResourceNotFoundException' else 'unknown'
    except Exception:
        return 'unknown'


def legacy_instance_state():
    if not LINST:
        return 'unknown'
    try:
        ins = [i for r in cl('ec2', LR).describe_instances(InstanceIds=[LINST])['Reservations'] for i in r['Instances']]
        return ins[0]['State']['Name'] if ins else 'none'
    except ClientError as e:
        return 'none' if 'NotFound' in e.response['Error']['Code'] else 'unknown'
    except Exception:
        return 'unknown'


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
            'dins': instance, 'db': lambda: get('db'), 'ec2': lambda: get('ec2'),
            'ltab': legacy_table_state, 'lins': legacy_instance_state}
    with ThreadPoolExecutor(9) as ex:
        futs = {k: ex.submit(f) for k, f in jobs.items()}
        r = {k: f.result() for k, f in futs.items()}
    db, ec = r['db'], r['ec2']
    return {'enabled': True, 'legacy_region': LR, 'region': R, 'legacy_table': LT, 'dest_table': DT,
            'legacy': {'rows': r['lrows'], 'image': r['limg'], 'table': r['ltab'], 'instance': r['lins']},
            'dest': {'rows': r['drows'], 'image': r['dimg'], 'instance': r['dins']},
            'job': {'db': db.get('state'), 'moved': db.get('moved', 0), 'total': db.get('total', 0), 'ec2': ec.get('state'),
                    'ami': ec.get('ami'), 'instance': ec.get('instance'), 'error': db.get('error') or ec.get('error')}}


def reset():
    if legacy_table_state() == 'deleted':
        raise RuntimeError('The offshore copies are decommissioned, so the migrated data is now the only copy. '
                           'Rebuild the legacy side first (./deploy.sh fix), then reset.')
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


def fix_parts():
    """The four restore calls, in order. The bucket policy is read back from the copy kept in SSM."""
    enc = C('s3', 'put_bucket_encryption', Bucket=B, ServerSideEncryptionConfiguration={'Rules': [{
        'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'aws:kms', 'KMSMasterKeyID': K}, 'BucketKeyEnabled': True}]})
    pab = C('s3', 'put_public_access_block', Bucket=B, PublicAccessBlockConfiguration={
        'BlockPublicAcls': True, 'IgnorePublicAcls': True, 'BlockPublicPolicy': True, 'RestrictPublicBuckets': True})
    rot = C('kms', 'enable_key_rotation', KeyId=K)
    pol_py = (f"ssm = boto3.client('ssm', region_name={R!r})\n"
              f"s3.put_bucket_policy(Bucket={B!r}, Policy=ssm.get_parameter(Name={PARAM!r})['Parameter']['Value'])")
    pol_cli = (f'aws s3api put-bucket-policy --bucket {B} --region {R} --policy '
               f'"$(aws ssm get-parameter --name {PARAM} --query Parameter.Value --output text --region {R})"')
    code = '\n'.join([enc.code(), pol_py, pab.code().split('\n', 1)[1], rot.code()])
    cli = '\n'.join([enc.cli(), pol_cli, pab.cli(), rot.cli()])
    return enc, pab, rot, code, cli


def fix():
    enc, pab, rot, _, _ = fix_parts()
    enc()
    C('s3', 'put_bucket_policy', Bucket=B, Policy=cl('ssm').get_parameter(Name=PARAM)['Parameter']['Value'])()
    pab()
    rot()


def decommission():
    """Delete the offshore originals, but only the parts whose copy in the approved region is verified."""
    if legacy_table_state() == 'deleted' and legacy_instance_state() in ('none', 'terminated', 'shutting-down'):
        return res('allowed', f'decommission offshore copies in {LR}', f'Already decommissioned: nothing of the bank is left in {LR}.')
    counts = {}
    for t, r in ((LT, LR), (DT, R)):
        try:
            counts[t] = cl('dynamodb', r).scan(TableName=t, Select='COUNT')['Count']
        except Exception:
            counts[t] = None
    db_ok = counts[LT] is not None and counts[DT] is not None and counts[DT] >= counts[LT] > 0
    imgs = cl('ec2').describe_images(Owners=['self'], Filters=[{'Name': 'name', 'Values': [f'{P}-{EC2_NAME}']}])['Images']
    ec2_ok = any(i['State'] == 'available' for i in imgs)
    if not (db_ok or ec2_ok):
        return res('error', 'decommission offshore copies',
                   f'Nothing verified yet: the migrated table has {counts[DT]} of {counts[LT]} records and no migrated image '
                   'is available. Migrate first; the offshore originals are only deleted once their copy is verified.')
    steps, notes = [], []
    if db_ok:
        notes.append(f'database verified: {counts[DT]} of {counts[LT]} records in {R}')
        steps.append(C('dynamodb', 'delete_table', LR, TableName=LT))
    else:
        notes.append(f'database NOT deleted: only {counts[DT]} of {counts[LT]} records copied')
    if ec2_ok:
        notes.append(f'server image verified in {R}')
        if LINST:
            steps.append(C('ec2', 'terminate_instances', LR, InstanceIds=[LINST]))
        try:
            old = cl('ec2', LR).describe_images(ImageIds=[LAMI])['Images']
        except ClientError:
            old = []
        snaps = [b['Ebs']['SnapshotId'] for i in old for b in i.get('BlockDeviceMappings', []) if b.get('Ebs', {}).get('SnapshotId')]
        if old:
            steps.append(C('ec2', 'deregister_image', LR, ImageId=LAMI))
        steps += [C('ec2', 'delete_snapshot', LR, SnapshotId=sid) for sid in snaps]
    else:
        notes.append('server NOT deleted: no migrated image available yet')
    results, verdict = [], 'allowed'
    for c in steps:
        r = attempt(c.op, c)
        results.append(f"{c.op}: {r['verdict']}")
        if r['verdict'] != 'allowed':
            verdict = r['verdict']
            results[-1] += f" ({r['detail'][:120]})"
    vtext = (f"# verified first: {counts[DT]} of {counts[LT]} records and the server image are in {R}\n" if db_ok and ec2_ok
             else '# verified first: ' + '; '.join(notes) + '\n')
    seen, py = set(), []
    for c in steps:  # one client line per service, then each call
        head, body = c.code().split('\n', 1)
        if (c.svc, c.region) not in seen:
            seen.add((c.svc, c.region))
            py.append(head)
        py.append(body)
    code = vtext + '\n'.join(py)
    cli = vtext + '\n'.join(c.cli() for c in steps)
    return res(verdict, f'decommission offshore copies in {LR}', '. '.join(notes + results) + '.', code, cli)


RESET_PY = """ec2 = boto3.client('ec2', region_name={R!r})
ec2.terminate_instances(InstanceIds=[...])            # the migrated server
ec2.deregister_image(ImageId=...)                     # the copied image
ec2.delete_snapshot(SnapshotId=...)                   # and its snapshot
dest = boto3.client('dynamodb', region_name={R!r})
dest.batch_write_item(RequestItems={{{DT!r}: [{{'DeleteRequest': ...}}]}})   # empty the migrated table"""
RESET_CLI = """aws ec2 terminate-instances --instance-ids <migrated-server> --region {R}
aws ec2 deregister-image --image-id <copied-ami> --region {R}
aws ec2 delete-snapshot --snapshot-id <its-snapshot> --region {R}
aws dynamodb batch-write-item --request-items file://delete-all.json --region {R}"""


def act(p):
    a = p.get('action')
    if a == 'migDb':
        if get('db').get('state') != 'running':
            put('db', {'state': 'running', 'moved': 0, 'total': 0})
            start('db')
        return res('allowed', 'dynamodb scan (legacy) -> batch-write-item (approved region)', 'Database migration started.', *code_db())
    if a == 'migEc2':
        if get('ec2').get('state') not in ('copying', 'launching'):
            put('ec2', {'state': 'copying'})
            start('ec2')
        return res('allowed', 'ec2 copy-image (legacy -> approved, re-encrypted) then run-instances',
                   'Server migration started; the image copy takes several minutes.', *code_ec2())
    if a == 'migReset':
        reset()
        return res('allowed', 'terminate instance, deregister image, clear migrated table', 'Migration reset. The legacy side is untouched.',
                   RESET_PY.format(R=R, DT=DT), RESET_CLI.format(R=R))
    if a == 'migClean':
        return decommission()
    if a == 'migOutDb':
        return attempt('dynamodb:PutItem into us-east-1', C('dynamodb', 'put_item', 'us-east-1', TableName=DT, Item={'payment_id': {'S': 'PAY-OUT'}}))
    if a == 'migOutEc2':
        return attempt('ec2:CopyImage into us-east-1', C('ec2', 'copy_image', 'us-east-1', Name='exfil', SourceImageId='ami-00000000000000000', SourceRegion=R))
    if a == 'replAdmin':
        rc = {'Role': f'arn:aws:iam::{ACCT}:role/dummy-replication-role', 'Rules': [{
            'ID': 'offshore', 'Status': 'Enabled', 'Priority': 1, 'Filter': {}, 'DeleteMarkerReplication': {'Status': 'Disabled'},
            'Destination': {'Bucket': 'arn:aws:s3:::dummy-destination-bucket'}}]}
        return attempt('s3:PutBucketReplication as an admin-level role', C('s3', 'put_bucket_replication', Bucket=B, ReplicationConfiguration=rc))
    drift = {
        'enc': ('s3:DeleteBucketEncryption', C('s3', 'delete_bucket_encryption', Bucket=B)),
        'ssl': ('s3:DeleteBucketPolicy', C('s3', 'delete_bucket_policy', Bucket=B)),
        'pub': ('s3:PutPublicAccessBlock (all off)', C('s3', 'put_public_access_block', Bucket=B, PublicAccessBlockConfiguration={
            'BlockPublicAcls': False, 'IgnorePublicAcls': False, 'BlockPublicPolicy': False, 'RestrictPublicBuckets': False})),
        'rot': ('kms:DisableKeyRotation', C('kms', 'disable_key_rotation', KeyId=K))}
    if a in drift:
        return attempt(*drift[a])
    if a == 'fix':
        _, _, _, code, cli = fix_parts()
        return attempt('restore encryption, bucket policy, Block Public Access and rotation', (fix, code, cli),
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
