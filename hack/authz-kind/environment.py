#!/usr/bin/env python3
"""Isolated test-infra kind environment for real Milo authorization requests."""
import argparse
import base64
import contextlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.tmp/authz'
MILO = Path(os.environ.get('MILO_DIR', str(ROOT.parent / 'milo'))).resolve()
CLUSTER = os.environ.get('AUTHZ_CLUSTER_NAME', 'openfga-subresources')
NS = 'authz-e2e'
PORT = int(os.environ.get('AUTHZ_PORT', '16443'))
ADMIN = 'local-authz-admin-token'
USER = 'local-authz-user-token'
TIMEOUT = int(os.environ.get('AUTHZ_TIMEOUT', '240'))
CTX = ssl._create_unverified_context()  # ephemeral local test certificates only


def run(*args, input=None, capture=False, check=True, **kwargs):
    return subprocess.run([str(a) for a in args], input=input, text=True,
                          capture_output=capture, check=check, **kwargs)


def kube(*args, **kwargs):
    return run('kubectl', '--kubeconfig', STATE / 'kind.kubeconfig',
               '--context', 'kind-' + CLUSTER, *args, **kwargs)


def apply(*objects):
    kube('apply', '-f', '-', input=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': objects}))


def obj(kind, name, spec=None, api='v1'):
    result = {'apiVersion': api, 'kind': kind, 'metadata': {'name': name, 'namespace': NS}}
    if spec is not None:
        result['spec'] = spec
    return result


def deployment(name, image, args=None, env=None, volumes=None, mounts=None):
    container = {'name': name, 'image': image, 'imagePullPolicy': 'IfNotPresent',
                 'resources': {'requests': {'cpu': '50m', 'memory': '64Mi'},
                               'limits': {'memory': '1Gi'}}}
    if args is not None:
        container['args'] = args
    if env:
        container['env'] = [{'name': k, 'value': v} for k, v in env.items()]
    if mounts:
        container['volumeMounts'] = mounts
    template_metadata = {'labels': {'app': name}}
    if image in ('milo:authz', 'openfga-provider:authz'):
        image_id = run('docker', 'image', 'inspect', '--format', '{{.Id}}', image, capture=True).stdout.strip()
        template_metadata['annotations'] = {'authz-e2e.miloapis.com/image-id': image_id}
    return obj('Deployment', name, {'replicas': 1, 'strategy': {'type': 'Recreate'},
               'selector': {'matchLabels': {'app': name}},
               'template': {'metadata': template_metadata,
                            'spec': {'serviceAccountName': 'provider', 'containers': [container],
                                     'volumes': volumes or []}}}, 'apps/v1')


def service(name, ports):
    return obj('Service', name, {'selector': {'app': name},
               'ports': [{'name': 'p' + str(p), 'port': p, 'targetPort': p} for p in ports]})


def wait_deployment(name):
    kube('-n', NS, 'rollout', 'status', 'deployment/' + name, '--timeout=' + str(TIMEOUT) + 's')


def request(path, method='GET', data=None, token=ADMIN, port=PORT):
    raw = None if data is None else json.dumps(data).encode()
    headers = {'Authorization': 'Bearer ' + token,
               'Content-Type': 'application/merge-patch+json' if method == 'PATCH' else 'application/json'}
    req = urllib.request.Request('https://127.0.0.1:' + str(port) + path, data=raw, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=15) as res:
            payload = res.read().decode()
            return res.status, json.loads(payload) if payload.startswith('{') else payload
    except urllib.error.HTTPError as e:
        payload = e.read().decode()
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            pass
        return e.code, payload


def wait(description, fn):
    deadline = time.monotonic() + TIMEOUT
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
            if last:
                return last
        except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
            last = str(e)
        time.sleep(1)
    raise RuntimeError('Timed out waiting for ' + description + ': ' + str(last))


@contextlib.contextmanager
def forward(service_name='milo', local_port=PORT, remote_port=6443):
    STATE.mkdir(parents=True, exist_ok=True)
    with (STATE / (service_name + '-forward.log')).open('w') as log:
        proc = subprocess.Popen(['kubectl', '--kubeconfig', str(STATE / 'kind.kubeconfig'),
                                 '--context', 'kind-' + CLUSTER, '-n', NS, 'port-forward',
                                 'service/' + service_name, str(local_port) + ':' + str(remote_port)],
                                stdout=log, stderr=log)
        try:
            wait('port-forward', lambda: 'Forwarding from' in (STATE / (service_name + '-forward.log')).read_text())
            if proc.poll() is not None:
                raise RuntimeError('port-forward exited; see ' + log.name)
            yield
        finally:
            proc.terminate()
            proc.wait(timeout=15)


def kubeconfig(server, token=ADMIN):
    return json.dumps({'apiVersion': 'v1', 'kind': 'Config', 'current-context': 'local-authz',
                      'clusters': [{'name': 'local-authz', 'cluster': {'server': server, 'insecure-skip-tls-verify': True}}],
                      'contexts': [{'name': 'local-authz', 'context': {'cluster': 'local-authz', 'user': 'local-authz'}}],
                      'users': [{'name': 'local-authz', 'user': {'token': token}}]})


def tokens(uid='authz-user'):
    secret = obj('Secret', 'auth-config')
    secret['stringData'] = {
        'tokens.csv': ADMIN + ',admin,admin,"system:masters"\n' + USER + ',authz-user,' + uid + ',"system:authenticated"\n',
        'kubeconfig': kubeconfig('https://milo.' + NS + '.svc:6443'),
        'webhook': kubeconfig('https://provider-webhook.' + NS + '.svc:8090/apis/authorization.k8s.io/v1/subjectaccessreviews', '')}
    apply(secret)


def flag(enabled):
    for name in ['provider-manager', 'provider-webhook']:
        kube('-n', NS, 'set', 'env', 'deployment/' + name, 'ENABLE_SUBRESOURCE_AUTHORIZATION=' + str(enabled).lower())
        wait_deployment(name)


def build():
    image_dir = STATE / 'images'
    image_dir.mkdir(parents=True, exist_ok=True)
    architecture = run('docker', 'info', '--format', '{{.Architecture}}', capture=True).stdout.strip()
    arch = {'aarch64': 'arm64', 'x86_64': 'amd64'}.get(architecture, architecture)
    # A temporary workspace consumes the checked-out Milo API without modifying either go.mod.
    workspace = STATE / 'go.work'
    workspace.write_text('go 1.26.0\nuse (\n' + str(ROOT) + '\n' + str(MILO) + '\n)\n')
    env = dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH=arch, GOWORK=str(workspace))
    for directory, target, binary in [(MILO, './cmd/milo', 'milo'), (ROOT, './cmd', 'auth-provider-openfga')]:
        flags = ['-s', '-w']
        if binary == 'milo':
            version = run('go', 'list', '-m', '-f', '{{.Version}}', 'k8s.io/component-base', cwd=MILO, env=env, capture=True).stdout.strip()
            minor = version.split('.')[1]
            flags += ['-X', 'k8s.io/component-base/version.gitVersion=v1.' + minor + '.0-milo.dev',
                      '-X', 'k8s.io/component-base/version.gitMajor=1', '-X', 'k8s.io/component-base/version.gitMinor=' + minor]
        run('go', 'build', '-p', '4', '-trimpath', '-ldflags=' + ' '.join(flags), '-o', image_dir / binary, target, cwd=directory, env=env)
    for binary, image in [('milo', 'milo:authz'), ('auth-provider-openfga', 'openfga-provider:authz')]:
        dockerfile = 'FROM gcr.io/distroless/static:nonroot\nCOPY ' + binary + ' /app\nENTRYPOINT ["/app"]\n'
        run('docker', 'build', '-t', image, '-f', '-', image_dir, input=dockerfile)


def up():
    STATE.mkdir(parents=True, exist_ok=True)
    config = STATE / 'kind.yaml'
    config.write_text('kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n- role: control-plane\n')
    # Reuse the pinned shared infrastructure tasks; no ambient kubectl context is used.
    vars_ = ['CLUSTER_NAME=' + CLUSTER, 'KIND_CFG=' + str(config),
             'KUBECONFIG_FILE=' + str(STATE / 'kind.kubeconfig')]
    run('task', '--yes', 'test-infra:ensure-repo', *vars_, cwd=ROOT)
    # Recover the dedicated kubeconfig before shared bootstrap checks an
    # existing cluster (for example after removing local generated state).
    if CLUSTER in run('kind', 'get', 'clusters', capture=True).stdout.splitlines():
        run('kind', 'export', 'kubeconfig', '--name', CLUSTER, '--kubeconfig', STATE / 'kind.kubeconfig')
    infra_env = dict(os.environ, KUBECONFIG=str(STATE / 'kind.kubeconfig'))
    run('task', '--yes', 'create-kind', *vars_, cwd=ROOT / '.test-infra', env=infra_env)
    run('kind', 'export', 'kubeconfig', '--name', CLUSTER, '--kubeconfig', STATE / 'kind.kubeconfig')
    if os.environ.get('AUTHZ_SKIP_BUILD') != 'true':
        build()
    run('kind', 'load', 'docker-image', 'milo:authz', 'openfga-provider:authz', '--name', CLUSTER)
    apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NS}}, obj('ServiceAccount', 'provider'))
    role = {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRole', 'metadata': {'name': 'authz-e2e-model-config'},
            'rules': [{'apiGroups': [''], 'resources': ['configmaps'], 'verbs': ['get', 'list', 'watch', 'create', 'update', 'patch']}]}
    binding = {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRoleBinding', 'metadata': {'name': 'authz-e2e-model-config'},
               'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': 'authz-e2e-model-config'},
               'subjects': [{'kind': 'ServiceAccount', 'name': 'provider', 'namespace': NS}]}
    apply(role, binding)
    cert, key = STATE / 'tls.crt', STATE / 'tls.key'
    if not cert.exists():
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
            '-out', cert, '-days', '30', '-subj', '/CN=local-authz', capture=True)
    tls = obj('Secret', 'tls')
    tls['data'] = {'tls.crt': base64.b64encode(cert.read_bytes()).decode(), 'tls.key': base64.b64encode(key.read_bytes()).decode()}
    apply(tls)
    tokens()
    apply(deployment('etcd', 'registry.k8s.io/etcd:3.5.16-0',
                     ['etcd', '--listen-client-urls=http://0.0.0.0:2379', '--advertise-client-urls=http://etcd:2379', '--data-dir=/data']),
          service('etcd', [2379]),
          deployment('openfga', 'openfga/openfga:v1.8.16', ['run'], {'OPENFGA_DATASTORE_ENGINE': 'memory'}),
          service('openfga', [8080, 8081]))
    wait_deployment('etcd')
    wait_deployment('openfga')
    with forward('openfga', 18080, 8080):
        def create_store():
            req = urllib.request.Request('http://127.0.0.1:18080/stores', data=b'{"name":"subresources"}', headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req) as res:
                return json.load(res)['id']
        store = wait('OpenFGA store', create_store)
    (STATE / 'store-id').write_text(store)
    volumes = [{'name': 'tls', 'secret': {'secretName': 'tls'}}, {'name': 'auth', 'secret': {'secretName': 'auth-config'}}]
    mounts = [{'name': 'tls', 'mountPath': '/etc/tls', 'readOnly': True}, {'name': 'auth', 'mountPath': '/etc/milo', 'readOnly': True}]
    apply(deployment('milo', 'milo:authz', ['apiserver', '--etcd-servers=http://etcd:2379', '--etcd-prefix=/authz-e2e',
          '--bind-address=0.0.0.0', '--secure-port=6443', '--tls-cert-file=/etc/tls/tls.crt', '--tls-private-key-file=/etc/tls/tls.key',
          '--service-account-key-file=/etc/tls/tls.crt', '--service-account-issuer=https://milo.authz-e2e.svc',
          '--token-auth-file=/etc/milo/tokens.csv', '--authorization-mode=RBAC,Webhook',
          '--authorization-webhook-config-file=/etc/milo/webhook', '--authorization-webhook-version=v1',
          '--authorization-webhook-cache-authorized-ttl=0s', '--authorization-webhook-cache-unauthorized-ttl=0s'],
          volumes=volumes, mounts=mounts), service('milo', [6443]))
    wait_deployment('milo')
    with forward():
        wait('Milo ready', lambda: request('/readyz')[0] == 200)
        code, user = request('/apis/iam.miloapis.com/v1alpha1/users', 'POST', {'apiVersion': 'iam.miloapis.com/v1alpha1', 'kind': 'User', 'metadata': {'name': 'authz-user'}, 'spec': {'email': 'authz@example.com'}})
        if code == 409:
            code, user = request('/apis/iam.miloapis.com/v1alpha1/users/authz-user')
        if code not in (200, 201):
            raise RuntimeError(user)
        wait('IAM storage ready', lambda: request('/apis/iam.miloapis.com/v1alpha1/protectedresources')[0] == 200)
    # User principal IDs are resource names, so the static token is valid from startup.
    common = ['--openfga-api-url=openfga:8081', '--openfga-store-id=' + store,
              '--configmap-name=openfga-authorization-model', '--configmap-namespace=' + NS,
              '--enable-subresource-authorization=$(ENABLE_SUBRESOURCE_AUTHORIZATION)', '--health-probe-bind-address=:8082', '--metrics-bind-address=0']
    env = {'KUBECONFIG': '/etc/milo/kubeconfig', 'POD_NAMESPACE': NS,
           'ENABLE_SUBRESOURCE_AUTHORIZATION': os.environ.get('ENABLE_SUBRESOURCE_AUTHORIZATION', 'false')}
    apply(deployment('provider-manager', 'openfga-provider:authz', ['manager'] + common,
                     env, volumes, mounts),
          deployment('provider-webhook', 'openfga-provider:authz', ['authz-webhook', '--webhook-port=8090', '--cert-dir=/etc/tls'] + common,
                     env, volumes, mounts), service('provider-webhook', [8090]))
    wait_deployment('provider-manager')
    wait_deployment('provider-webhook')
    (STATE / 'milo.kubeconfig').write_text(kubeconfig('https://127.0.0.1:' + str(PORT)))
    print('Ready. Run task test:e2e:subresources. Local credentials stay in .tmp/authz.')


def diagnostics():
    for args in [('get', 'pods', '-A', '-o', 'wide'), ('-n', NS, 'get', 'events', '--sort-by=.lastTimestamp')]:
        kube(*args, check=False)
    for name in ['milo', 'provider-manager', 'provider-webhook', 'openfga']:
        result = kube('-n', NS, 'logs', 'deployment/' + name, '--tail=200', capture=True, check=False)
        (STATE / (name + '.log')).write_text(result.stdout + result.stderr)
    print('Diagnostics saved in ' + str(STATE))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['up', 'down', 'build', 'diagnostics'])
    args = parser.parse_args()
    os.chdir(ROOT)
    try:
        if args.command == 'down':
            run('kind', 'delete', 'cluster', '--name', CLUSTER,
                '--kubeconfig', STATE / 'kind.kubeconfig')
        else:
            globals()[args.command]()
    except Exception:
        if (STATE / 'kind.kubeconfig').exists():
            diagnostics()
        raise


if __name__ == '__main__':
    main()
