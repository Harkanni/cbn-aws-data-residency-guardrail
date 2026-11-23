#!/usr/bin/env python3
"""Real region-lock console. A tiny local server: every button runs a whitelisted AWS CLI call
against YOUR account and returns AWS's own response. Nothing is simulated.

Needs: Python 3.8+, AWS CLI v2, IAM admin credentials (not root), and the Terraform already applied.
Run:   python3 server.py        (then open the printed URL; it is bound to 127.0.0.1 only)
"""
import datetime as dt
import json
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
REGION = os.environ.get('APPROVED_REGION', 'af-south-1')
PREFIX = os.environ.get('NAME_PREFIX', 'region-lock-demo')
PORT = int(os.environ.get('PORT', '8765'))
TOKEN = secrets.token_urlsafe(16)
REGIONS = {'us-east-1', 'eu-west-1', 'ap-southeast-1', REGION}
DENIED = ('AccessDenied', 'UnauthorizedOperation', 'explicit deny')
SIDS = {'DenyReplicationChanges', 'DenyNonTLS', 'DenyNonKmsEncryption', 'DenyWrongKmsKey'}
CFG, OP = {}, {}


def aws(args, env=None, timeout=90):
    e = dict(os.environ, AWS_PAGER='')
    if env:
        e.pop('AWS_PROFILE', None)
        e.update(env)
    try:
        p = subprocess.run(['aws'] + args + ['--no-cli-pager'], capture_output=True, text=True, env=e, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        sys.exit('AWS CLI not found on PATH')
    except subprocess.TimeoutExpired:
        return 124, '', 'timed out'


def role_env(name):
    """Credentials for a demo role: 'operator' (region lock) or 'migrator' (inbound-only migration)."""
    c = OP.get(name)
    if c and time.time() < c['exp']:
        return c['env']
    role = f"arn:aws:iam::{CFG['acct']}:role/{PREFIX}-{name}"
    err = ''
    for _ in range(3):
        rc, o, err = aws(['sts', 'assume-role', '--role-arn', role, '--role-session-name', 'console', '--output', 'json'])
        if rc == 0:
            k = json.loads(o)['Credentials']
            env = {'AWS_ACCESS_KEY_ID': k['AccessKeyId'], 'AWS_SECRET_ACCESS_KEY': k['SecretAccessKey'],
                   'AWS_SESSION_TOKEN': k['SessionToken']}
            OP[name] = {'env': env, 'exp': time.time() + 3000}
            return env
        time.sleep(3)
    raise RuntimeError(f'cannot assume {role}: {err.strip()[:200]}')


def operator():
    return role_env('operator')


def probe(args, who='operator'):
    rc, o, e = aws(args, None if who == 'admin' else role_env(who))
    text = (e or o).strip()
    if rc == 0:
        verdict = 'allowed'
    elif 'DryRunOperation' in text:
        verdict, text = 'allowed', 'DryRunOperation: the request would have succeeded (nothing was created).'
    elif any(d in text for d in DENIED):
        verdict = 'denied'
    else:
        verdict = 'error'
    return {'verdict': verdict, 'who': who, 'cmd': 'aws ' + ' '.join(args), 'detail': text[:600] or 'OK'}


def probe_service(p):
    s, r = p.get('service'), p.get('region')
    if r not in REGIONS:
        raise ValueError('unknown region')
    if s == 'ec2':
        return probe(['ec2', 'create-vpc', '--cidr-block', '10.99.0.0/16', '--dry-run', '--region', r])
    if s == 'kms':
        return probe(['kms', 'list-keys', '--region', r])
    if s == 'lambda':
        return probe(['lambda', 'list-functions', '--region', r])
    if s == 'rds':
        return probe(['rds', 'describe-db-instances', '--region', r])
    if s == 's3':
        name = f"{PREFIX}-probe-{CFG['acct']}-{secrets.token_hex(3)}"
        args = ['s3api', 'create-bucket', '--bucket', name, '--region', r]
        if r != 'us-east-1':
            args += ['--create-bucket-configuration', 'LocationConstraint=' + r]
        res = probe(args)
        if res['verdict'] == 'allowed':
            probe(['s3api', 'delete-bucket', '--bucket', name, '--region', r])
            res['detail'] = 'Bucket created, then deleted again.'
        return res
    raise ValueError('unknown service')


def terraform_apply():
    e = dict(os.environ, TF_VAR_approved_region=REGION, TF_VAR_name_prefix=PREFIX)
    if os.environ.get('ALERT_EMAIL'):
        e['TF_VAR_alert_email'] = os.environ['ALERT_EMAIL']
    meta = {'who': 'admin', 'cmd': 'terraform apply -auto-approve'}
    try:
        p = subprocess.run(['terraform', 'apply', '-auto-approve', '-input=false', '-no-color'], cwd=HERE,
                           capture_output=True, text=True, env=e, timeout=420)
    except FileNotFoundError:
        return dict(meta, verdict='error', detail='terraform not found on this machine; run ./deploy.sh fix instead.')
    tail = '\n'.join((p.stdout + p.stderr).strip().splitlines()[-6:])
    return dict(meta, verdict='allowed' if p.returncode == 0 else 'error', detail=tail)


# ----------------------------- Migration engine ------------------------------
MIG = {'ec2': 'idle', 'db': 'idle', 'moved': 0, 'total': 0, 'ami': None, 'instance': None, 'error': None}
EC2_NAME = 'migrated-payments-app'


def mj(args, region, timeout=120):
    """Run an AWS CLI call as the inbound-only migrator role and return parsed JSON."""
    rc, o, e = aws(args + ['--region', region, '--output', 'json'], role_env('migrator'), timeout)
    if rc:
        raise RuntimeError((e or o).strip()[:300])
    return json.loads(o) if o.strip() else {}


def mig_db():
    m = CFG['mig']
    try:
        MIG.update(db='running', error=None, moved=0, total=0)
        items = mj(['dynamodb', 'scan', '--table-name', m['legacy_table']], m['legacy_region'])['Items']
        MIG['total'] = len(items)
        for i in range(0, len(items), 5):
            chunk = items[i:i + 5]
            f = Path(tempfile.mkdtemp()) / 'batch.json'
            f.write_text(json.dumps({m['dest_table']: [{'PutRequest': {'Item': it}} for it in chunk]}))
            mj(['dynamodb', 'batch-write-item', '--request-items', 'file://' + f.as_posix()], REGION)
            MIG['moved'] += len(chunk)
            time.sleep(0.8)  # slow enough to watch
        MIG['db'] = 'done'
    except Exception as e:
        MIG.update(db='error', error=str(e))


def mig_ec2():
    m = CFG['mig']
    try:
        MIG.update(ec2='copying', error=None, ami=None, instance=None)
        r = mj(['ec2', 'copy-image', '--name', f'{PREFIX}-{EC2_NAME}', '--source-image-id', m['legacy_ami'],
                '--source-region', m['legacy_region'], '--encrypted', '--kms-key-id', CFG['key']], REGION)
        MIG['ami'] = r['ImageId']
        for _ in range(180):  # up to 45 minutes
            st = mj(['ec2', 'describe-images', '--image-ids', MIG['ami']], REGION)['Images'][0]['State']
            if st == 'available':
                break
            if st in ('failed', 'error'):
                raise RuntimeError('image copy failed')
            time.sleep(15)
        else:
            raise RuntimeError('image copy timed out')
        MIG['ec2'] = 'launching'
        r = mj(['ec2', 'run-instances', '--image-id', MIG['ami'], '--instance-type', 't3.micro', '--count', '1',
                '--tag-specifications', f'ResourceType=instance,Tags=[{{Key=Name,Value={EC2_NAME}}}]'], REGION)
        MIG['instance'] = r['Instances'][0]['InstanceId']
        for _ in range(60):
            d = mj(['ec2', 'describe-instances', '--instance-ids', MIG['instance']], REGION)
            if d['Reservations'][0]['Instances'][0]['State']['Name'] == 'running':
                MIG['ec2'] = 'done'
                return
            time.sleep(5)
        raise RuntimeError('instance did not reach running')
    except Exception as e:
        MIG.update(ec2='error', error=str(e))


def mig_status():
    m = CFG.get('mig')
    if not m:
        return {'enabled': False}
    R = REGION

    def count(table, region):
        try:
            return mj(['dynamodb', 'scan', '--table-name', table, '--select', 'COUNT'], region)['Count']
        except Exception:
            return None

    def image(region, **kw):
        try:
            args = ['ec2', 'describe-images'] + (['--image-ids', kw['id']] if 'id' in kw else
                                                 ['--owners', 'self', '--filters', f"Name=name,Values={PREFIX}-{EC2_NAME}"])
            imgs = mj(args, region)['Images']
            return imgs[0]['State'] if imgs else 'none'
        except Exception:
            return 'none'

    def instance():
        try:
            d = mj(['ec2', 'describe-instances', '--filters', f'Name=tag:Name,Values={EC2_NAME}',
                    'Name=instance-state-name,Values=pending,running,stopping,stopped'], R)
            ins = [i for r in d['Reservations'] for i in r['Instances']]
            return ins[0]['State']['Name'] if ins else 'none'
        except Exception:
            return 'none'

    jobs = {'lrows': lambda: count(m['legacy_table'], m['legacy_region']), 'drows': lambda: count(m['dest_table'], R),
            'limg': lambda: image(m['legacy_region'], id=m['legacy_ami']), 'dimg': lambda: image(R), 'dins': instance}
    with ThreadPoolExecutor(5) as ex:
        futs = {k: ex.submit(f) for k, f in jobs.items()}
        r = {k: f.result() for k, f in futs.items()}
    return {'enabled': True, 'legacy_region': m['legacy_region'], 'region': R,
            'legacy': {'rows': r['lrows'], 'image': r['limg']},
            'dest': {'rows': r['drows'], 'image': r['dimg'], 'instance': r['dins']}, 'job': dict(MIG)}


def mig_reset():
    m = CFG['mig']
    if MIG['db'] == 'running' or MIG['ec2'] in ('copying', 'launching'):
        raise RuntimeError('a migration is still running')
    d = mj(['ec2', 'describe-instances', '--filters', f'Name=tag:Name,Values={EC2_NAME}',
            'Name=instance-state-name,Values=pending,running,stopping,stopped'], REGION)
    ids = [i['InstanceId'] for r in d['Reservations'] for i in r['Instances']]
    if ids:
        mj(['ec2', 'terminate-instances', '--instance-ids'] + ids, REGION)
    for im in mj(['ec2', 'describe-images', '--owners', 'self', '--filters', f'Name=name,Values={PREFIX}-{EC2_NAME}'], REGION)['Images']:
        mj(['ec2', 'deregister-image', '--image-id', im['ImageId']], REGION)
        for b in im.get('BlockDeviceMappings', []):
            sid = b.get('Ebs', {}).get('SnapshotId')
            if sid:
                try:
                    mj(['ec2', 'delete-snapshot', '--snapshot-id', sid], REGION)
                except RuntimeError:
                    pass
    items = mj(['dynamodb', 'scan', '--table-name', m['dest_table'], '--projection-expression', 'payment_id'], REGION)['Items']
    for i in range(0, len(items), 25):
        f = Path(tempfile.mkdtemp()) / 'del.json'
        f.write_text(json.dumps({m['dest_table']: [{'DeleteRequest': {'Key': it}} for it in items[i:i + 25]]}))
        mj(['dynamodb', 'batch-write-item', '--request-items', 'file://' + f.as_posix()], REGION)
    MIG.update(ec2='idle', db='idle', moved=0, total=0, ami=None, instance=None, error=None)


def mig_act(a):
    m = CFG.get('mig')
    if not m:
        raise ValueError('migration resources not deployed (add migration.tf and run ./deploy.sh up)')
    meta = {'who': 'migrator', 'verdict': 'allowed'}
    if a == 'migDb':
        if MIG['db'] != 'running':
            threading.Thread(target=mig_db, daemon=True).start()
        return dict(meta, cmd='dynamodb scan (legacy) -> batch-write-item (approved region)', detail='Database migration started.')
    if a == 'migEc2':
        if MIG['ec2'] not in ('copying', 'launching'):
            threading.Thread(target=mig_ec2, daemon=True).start()
        return dict(meta, cmd='ec2 copy-image (legacy -> approved, re-encrypted) then run-instances', detail='Server migration started; the image copy takes several minutes.')
    if a == 'migReset':
        mig_reset()
        return dict(meta, cmd='terminate instance, deregister image, clear migrated table', detail='Migration reset. The legacy side is untouched.')
    if a == 'migOutDb':
        f = Path(tempfile.mkdtemp()) / 'item.json'
        f.write_text(json.dumps({'payment_id': {'S': 'PAY-OUT'}}))
        return probe(['dynamodb', 'put-item', '--table-name', m['dest_table'], '--item', 'file://' + f.as_posix(), '--region', 'us-east-1'], 'migrator')
    if a == 'migOutEc2':
        return probe(['ec2', 'copy-image', '--name', 'exfil', '--source-image-id', 'ami-00000000000000000',
                      '--source-region', REGION, '--region', 'us-east-1'], 'migrator')
    raise ValueError('unknown action')


def act(a, p):
    B, K, R = CFG['bucket'], CFG['key'], REGION
    if a.startswith('mig'):
        return mig_act(a)
    if a == 'probe':
        return probe_service(p)
    tmp = Path(tempfile.mkdtemp())
    body = tmp / 'receipt.json'
    body.write_text(json.dumps({'receipt_id': a, 'note': 'SIMULATED DATA'}))
    put = ['s3api', 'put-object', '--bucket', B, '--key', f'tests/{a}-{int(time.time())}.json',
           '--body', str(body), '--region', R]
    kms = ['--server-side-encryption', 'aws:kms', '--ssekms-key-id']
    if a == 'upOk':
        return probe(put + kms + [K])
    if a == 'upS3':
        return probe(put + ['--server-side-encryption', 'AES256'])
    if a == 'upKey':
        return probe(put + kms + ['alias/aws/s3'])
    if a == 'upHttp':
        return probe(put + kms + [K, '--endpoint-url', f'http://s3.{R}.amazonaws.com'])
    if a in ('repl', 'replAdmin'):
        cfg = tmp / 'repl.json'
        cfg.write_text(json.dumps({'Role': f"arn:aws:iam::{CFG['acct']}:role/dummy-replication-role", 'Rules': [{
            'ID': 'offshore', 'Status': 'Enabled', 'Priority': 1, 'Filter': {},
            'DeleteMarkerReplication': {'Status': 'Disabled'},
            'Destination': {'Bucket': 'arn:aws:s3:::dummy-destination-bucket'}}]}))
        return probe(['s3api', 'put-bucket-replication', '--bucket', B, '--region', R,
                      '--replication-configuration', 'file://' + cfg.as_posix()],
                     'operator' if a == 'repl' else 'admin')
    if a == 'mrk':
        return probe(['kms', 'create-key', '--multi-region', '--region', R])
    drift = {
        'enc': ['s3api', 'delete-bucket-encryption', '--bucket', B, '--region', R],
        'ssl': ['s3api', 'delete-bucket-policy', '--bucket', B, '--region', R],
        'pub': ['s3api', 'put-public-access-block', '--bucket', B, '--region', R, '--public-access-block-configuration',
                'BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false'],
        'rot': ['kms', 'disable-key-rotation', '--key-id', K, '--region', R]}
    if a in drift:
        return probe(drift[a], 'admin')
    if a == 'fix':
        return terraform_apply()
    raise ValueError('unknown action')


def status():
    B, K, R, T = CFG['bucket'], CFG['key'], REGION, CFG['topic']
    now = dt.datetime.now(dt.timezone.utc)
    iso = lambda t: t.strftime('%Y-%m-%dT%H:%M:%SZ')

    def j(args):
        rc, o, _ = aws(args + ['--output', 'json'])
        try:
            return json.loads(o) if rc == 0 and o.strip() else None
        except ValueError:
            return None

    def metric(rule):
        d = j(['cloudwatch', 'get-metric-statistics', '--region', R, '--namespace', 'AWS/Events',
               '--metric-name', 'Invocations', '--dimensions', 'Name=RuleName,Value=' + rule,
               '--start-time', iso(now - dt.timedelta(hours=24)), '--end-time', iso(now),
               '--period', '86400', '--statistics', 'Sum'])
        return int(sum(x['Sum'] for x in (d or {}).get('Datapoints', [])))

    jobs = {
        'rules': lambda: j(['configservice', 'describe-compliance-by-config-rule', '--region', R]),
        'sns': lambda: j(['sns', 'list-subscriptions-by-topic', '--topic-arn', T, '--region', R]),
        'enc': lambda: j(['s3api', 'get-bucket-encryption', '--bucket', B, '--region', R]),
        'bpa': lambda: j(['s3api', 'get-public-access-block', '--bucket', B, '--region', R]),
        'pol': lambda: j(['s3api', 'get-bucket-policy', '--bucket', B, '--region', R]),
        'rot': lambda: j(['kms', 'get-key-rotation-status', '--key-id', K, '--region', R]),
        'key': lambda: j(['kms', 'describe-key', '--key-id', K, '--region', R]),
        'm1': lambda: metric(PREFIX + '-replication-change'),
        'm2': lambda: metric(PREFIX + '-config-noncompliant')}
    with ThreadPoolExecutor(9) as ex:
        futs = {k: ex.submit(f) for k, f in jobs.items()}
        r = {k: f.result() for k, f in futs.items()}

    rules = [{'name': x['ConfigRuleName'], 'status': x.get('Compliance', {}).get('ComplianceType', 'UNKNOWN')}
             for x in (r['rules'] or {}).get('ComplianceByConfigRules', []) if x['ConfigRuleName'].startswith(PREFIX)]
    d = None
    try:
        d = r['enc']['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']
    except (TypeError, KeyError, IndexError):
        pass
    algo, ekey = (d or {}).get('SSEAlgorithm', 'unknown'), (d or {}).get('KMSMasterKeyID')
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
    subs = [{'endpoint': s['Endpoint'], 'confirmed': s['SubscriptionArn'] != 'PendingConfirmation'}
            for s in (r['sns'] or {}).get('Subscriptions', [])]
    return {'account': CFG['acct'], 'region': R, 'bucket': B, 'rules': rules, 'config': config, 'subs': subs,
            'fired': {'replication': r['m1'], 'config': r['m2']}}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype='application/json'):
        b = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def allowed(self):
        if self.headers.get('Host', '').split(':')[0] not in ('127.0.0.1', 'localhost'):
            self.send(403, {'error': 'bad host'})
            return False
        return True

    def authed(self):
        return secrets.compare_digest(self.headers.get('X-Token', ''), TOKEN)

    def do_GET(self):
        if not self.allowed():
            return
        path = urlparse(self.path).path
        if path == '/':
            return self.send(200, (HERE / 'console.html').read_bytes(), 'text/html; charset=utf-8')
        if path == '/api/migration' and self.authed():
            try:
                return self.send(200, mig_status())
            except Exception as e:
                return self.send(500, {'error': str(e)})
        if path == '/api/status' and self.authed():
            try:
                return self.send(200, status())
            except Exception as e:
                return self.send(500, {'error': str(e)})
        self.send(401 if path.startswith('/api') else 404, {'error': 'not available'})

    def do_POST(self):
        if not self.allowed():
            return
        if urlparse(self.path).path != '/api/run' or not self.authed():
            return self.send(401, {'error': 'bad token'})
        try:
            p = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))) or b'{}')
            self.send(200, act(p.get('action', ''), p))
        except Exception as e:
            self.send(400, {'error': str(e)})


def main():
    rc, o, e = aws(['sts', 'get-caller-identity', '--output', 'json'])
    if rc:
        sys.exit('No working AWS credentials: ' + e.strip())
    me = json.loads(o)
    if me['Arn'].endswith(':root'):
        sys.exit('You are using the root user. Use an IAM admin user or role instead.')
    CFG['acct'] = me['Account']
    out = {}
    try:
        out = json.loads(subprocess.run(['terraform', 'output', '-json'], cwd=HERE, capture_output=True, text=True).stdout or '{}')
    except (FileNotFoundError, ValueError):
        pass
    for k, tf, env in (('bucket', 'payments_bucket', 'BUCKET'), ('key', 'kms_key_arn', 'KEY_ARN'), ('topic', 'alerts_topic_arn', 'TOPIC_ARN')):
        CFG[k] = out.get(tf, {}).get('value') or os.environ.get(env)
    if not all(CFG.get(k) for k in ('bucket', 'key', 'topic')):
        sys.exit('Resources not found. Run ./deploy.sh up first (or set BUCKET, KEY_ARN, TOPIC_ARN).')
    t = {k: out.get(k, {}).get('value') for k in ('mig_legacy_region', 'mig_legacy_table', 'mig_dest_table', 'mig_legacy_ami')}
    if all(t.values()):
        CFG['mig'] = {k[4:]: v for k, v in t.items()}
    operator()
    url = f'http://127.0.0.1:{PORT}/?t={TOKEN}'
    print(f'Account {CFG["acct"]} | region {REGION} | bucket {CFG["bucket"]}\nOpen: {url}\nCtrl+C to stop.')
    if not os.environ.get('NO_BROWSER'):
        webbrowser.open(url)
    ThreadingHTTPServer(('127.0.0.1', PORT), H).serve_forever()


if __name__ == '__main__':
    main()
