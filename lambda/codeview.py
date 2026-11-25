"""Shows the console exactly what runs: each AWS call is described once (service, region, operation,
parameters) and the same description is used to make the call, to print it as Python (boto3) and to
print the equivalent AWS CLI command. Nothing here talks to AWS except Call.__call__."""
import json
import shlex

import boto3
from botocore import xform_name

CLI_SERVICE = {'s3': 's3api'}  # the AWS CLI names the low-level S3 API "s3api"


def _py(v, level=1):
    """Python literal for v, broken over indented lines when it is long (valid Python either way)."""
    if isinstance(v, (bytes, bytearray)):
        return repr(bytes(v))
    flat = repr(v)
    if not isinstance(v, (dict, list)) or len(flat) <= 60:
        return flat
    pad, end = '    ' * (level + 1), '    ' * level
    if isinstance(v, dict):
        inner = ''.join(f'{pad}{k!r}: {_py(x, level + 1)},\n' for k, x in v.items())
        return '{\n' + inner + end + '}'
    inner = ''.join(f'{pad}{_py(x, level + 1)},\n' for x in v)
    return '[\n' + inner + end + ']'


class Call:
    """One AWS API call: run it with call(), show it with .code() and .cli()."""

    def __init__(self, svc, region, op, endpoint=None, config=None, **kw):
        self.svc, self.region, self.op, self.endpoint, self.config, self.kw = svc, region, op, endpoint, config, kw
        self._client = None

    def client(self):
        if self._client is None:
            extra = {'endpoint_url': self.endpoint} if self.endpoint else {}
            self._client = boto3.client(self.svc, region_name=self.region, config=self.config, **extra)
        return self._client

    def __call__(self):
        return getattr(self.client(), self.op)(**self.kw)

    def code(self, var=None):
        v = var or self.svc.replace('-', '_')
        ep = f', endpoint_url={self.endpoint!r}' if self.endpoint else ''
        head = f'{v} = boto3.client({self.svc!r}, region_name={self.region!r}{ep})'
        args = [f'{k}={_py(x)}' for k, x in self.kw.items()]
        one = f'{v}.{self.op}({", ".join(args)})'
        body = one if len(one) <= 88 and '\n' not in one else f'{v}.{self.op}(\n' + ''.join(f'    {a},\n' for a in args) + ')'
        return head + '\n' + body

    def cli(self):
        c = self.client()
        api = c.meta.method_to_api_mapping[self.op]
        shape = c.meta.service_model.operation_model(api).input_shape
        members = shape.members if shape else {}
        parts = ['aws', CLI_SERVICE.get(self.svc, self.svc), xform_name(api, '-')]
        for k, x in self.kw.items():
            flag = '--' + xform_name(k, '-')
            t = members[k].type_name if k in members else ''
            if t == 'boolean':
                parts.append(flag if x else '--no-' + flag[2:])
            elif t == 'blob':
                parts += [flag, 'receipt.json']  # the CLI reads the body from a file
            elif isinstance(x, (dict, list)):
                parts += [flag, shlex.quote(json.dumps(x, separators=(',', ':')))]
            else:
                parts += [flag, shlex.quote(str(x))]
        parts += ['--region', self.region]
        if self.endpoint:
            parts += ['--endpoint-url', self.endpoint]
        return ' '.join(parts)

