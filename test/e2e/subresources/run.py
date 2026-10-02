#!/usr/bin/env python3
"""Real HTTP regression suite: end-user writes traverse Milo and its authz webhook."""
import importlib.util
import json
import sys
from pathlib import Path

# Keep importing the shared harness from creating artifacts beside tracked code.
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('environment', Path(__file__).resolve().parents[3] / 'hack/authz-kind/environment.py')
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)
IAM = '/apis/iam.miloapis.com/v1alpha1'
RM = '/apis/resourcemanager.miloapis.com/v1alpha1'
GROUP = 'authz-test.miloapis.com'
WIDGETS = '/apis/' + GROUP + '/v1/widgets'
NS = 'authz-subresources'
ROLE = IAM + '/namespaces/' + NS + '/roles/'
BINDING = IAM + '/namespaces/' + NS + '/policybindings/'
PR = IAM + '/protectedresources/'


def api(path, method='GET', data=None):
    code, body = e.request(path, method, data)
    if code not in (200, 201, 202):
        raise AssertionError((method, path, code, body))
    return body


def ensure(path, body):
    name = body['metadata']['name']
    code, old = e.request(path + '/' + name)
    if code == 404:
        return api(path, 'POST', body)
    assert code == 200, old
    return api(path + '/' + name, 'PATCH', body)


def ready(path):
    def check():
        resource = api(path)
        generation = resource['metadata'].get('generation', 0)
        conditions = resource.get('status', {}).get('conditions', [])
        return resource if any(c['type'] == 'Ready' and c['status'] == 'True' and
                               c.get('observedGeneration', resource.get('status', {}).get('observedGeneration', -1)) >= generation
                               for c in conditions) else None
    return e.wait(path + ' Ready at current generation', check)


def role(name, permissions, inherited=None):
    body = {'apiVersion': 'iam.miloapis.com/v1alpha1', 'kind': 'Role', 'metadata': {'name': name, 'namespace': NS},
            'spec': {'launchStage': 'Beta', 'includedPermissions': permissions, 'inheritedRoles': inherited or []}}
    ensure(ROLE.rstrip('/'), body)
    return ready(ROLE + name)


def binding(name, role_name, target, user):
    body = {'apiVersion': 'iam.miloapis.com/v1alpha1', 'kind': 'PolicyBinding', 'metadata': {'name': name, 'namespace': NS},
            'spec': {'roleRef': {'name': role_name, 'namespace': NS},
                     'subjects': [{'kind': 'User', 'name': user['metadata']['name'], 'uid': user['metadata']['uid']}],
                     'resourceSelector': target}}
    ensure(BINDING.rstrip('/'), body)
    return ready(BINDING + name)


def registration(name, group, kind, plural, subresources=None, parents=None):
    body = {'apiVersion': 'iam.miloapis.com/v1alpha1', 'kind': 'ProtectedResource', 'metadata': {'name': name},
            'spec': {'serviceRef': {'name': group}, 'kind': kind, 'plural': plural, 'singular': kind.lower(),
                     'permissions': ['get', 'patch', 'update'], 'subresources': subresources or [],
                     'parentResources': parents or []}}
    ensure(PR.rstrip('/'), body)
    return ready(PR + name)


def assert_request(label, path, expected, body=None, method='PATCH', converge=False):
    def check():
        code, response = e.request(path, method, body, token=e.USER)
        if code != expected:
            if converge:
                return None
            raise AssertionError((label, expected, code, response))
        return response
    result = e.wait(label, check) if converge else check()
    with (e.STATE / 'results.jsonl').open('a') as report:
        report.write(json.dumps({'test': label, 'method': method, 'path': path, 'status': expected, 'response': result}) + '\n')
    print('PASS:', label, 'HTTP', expected, flush=True)
    return result


def status_patch(label, expected, marker, converge=False, name='one'):
    path = WIDGETS + '/' + name
    before = api(path).get('status', {})
    result = assert_request(label, path + '/status', expected, {'status': {'marker': marker}}, converge=converge)
    after = api(path).get('status', {})
    if expected == 200:
        assert after['marker'] == marker, after
    elif not converge:
        assert after == before, (before, after)
    return result


def setup():
    ensure('/api/v1/namespaces', {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NS}})
    schema = {'type': 'object', 'properties': {
        'spec': {'type': 'object', 'properties': {'marker': {'type': 'string'}, 'replicas': {'type': 'integer'}}},
        'status': {'type': 'object', 'properties': {'marker': {'type': 'string'}, 'replicas': {'type': 'integer'}}}}}
    crd = {'apiVersion': 'apiextensions.k8s.io/v1', 'kind': 'CustomResourceDefinition', 'metadata': {'name': 'widgets.' + GROUP},
           'spec': {'group': GROUP, 'scope': 'Cluster', 'names': {'kind': 'Widget', 'plural': 'widgets', 'singular': 'widget'},
                    'versions': [{'name': 'v1', 'served': True, 'storage': True, 'schema': {'openAPIV3Schema': schema},
                                  'subresources': {'status': {}, 'scale': {'specReplicasPath': '.spec.replicas', 'statusReplicasPath': '.status.replicas'}}}]}}
    ensure('/apis/apiextensions.k8s.io/v1/customresourcedefinitions', crd)
    e.wait('Widget CRD established', lambda: e.request(WIDGETS)[0] == 200)
    for name in ['one', 'two']:
        ensure(WIDGETS, {'apiVersion': GROUP + '/v1', 'kind': 'Widget', 'metadata': {'name': name}, 'spec': {'marker': 'initial', 'replicas': 1}})
    registration('authz-widgets', GROUP, 'Widget', 'widgets', [{'name': 'status', 'permissions': ['get', 'patch', 'update']}])
    for existing in api(BINDING.rstrip('/')).get('items', []):
        api(BINDING + existing['metadata']['name'], 'DELETE')
    e.wait('prior test PolicyBindings deleted', lambda: not api(BINDING.rstrip('/')).get('items'))
    user = api(IAM + '/users/authz-user')
    widget = api(WIDGETS + '/one')
    target = {'resourceRef': {'apiGroup': GROUP, 'kind': 'Widget', 'name': 'one', 'uid': widget['metadata']['uid']}}
    return user, target


def feature_argument(omit):
    for name in ['provider-manager', 'provider-webhook']:
        deployment = json.loads(e.kube('-n', e.NS, 'get', 'deployment/' + name, '-o', 'json', capture=True).stdout)
        args = deployment['spec']['template']['spec']['containers'][0]['args']
        args = [a for a in args if not a.startswith('--enable-subresource-authorization')]
        if not omit:
            args.append('--enable-subresource-authorization=$(ENABLE_SUBRESOURCE_AUTHORIZATION)')
        patch = [{'op': 'replace', 'path': '/spec/template/spec/containers/0/args', 'value': args}]
        e.kube('-n', e.NS, 'patch', 'deployment/' + name, '--type=json', '-p', json.dumps(patch))
        e.wait_deployment(name)


def suite():
    # Omission must preserve compatibility, even with subresource declarations.
    e.STATE.mkdir(parents=True, exist_ok=True)
    (e.STATE / 'results.jsonl').write_text('')
    feature_argument(omit=True)
    with e.forward():
        user, target = setup()
        # Refresh discovery after installing the synthetic CRD, before issuing grants.
        e.kube('-n', e.NS, 'rollout', 'restart', 'deployment/provider-manager')
        e.wait_deployment('provider-manager')
        assert_request('non-admin user has no RBAC authorization bypass', WIDGETS + '/one', 403, {'spec': {'marker': 'forbidden'}}, converge=True)
        perm = GROUP + '/widgets'
        role('writer', [perm + '.get', perm + '.patch', perm + '.update'])
        binding('writer', 'writer', target, user)
        assert_request('disabled: base PATCH', WIDGETS + '/one', 200, {'spec': {'marker': 'base'}}, converge=True)
        status_patch('disabled: legacy base PATCH permits status PATCH', 200, 'legacy', converge=True)
    feature_argument(omit=False)
    e.flag(True)
    with e.forward():
        e.wait('Milo ready after flag switch', lambda: e.request('/readyz')[0] == 200)
        ready(PR + 'authz-widgets')
        status_patch('enabled: base grant denies status PATCH', 403, 'forbidden', converge=True)
        status_patch('enabled: denial preserves stored status', 403, 'forbidden')
        assert_request('enabled: base PATCH still allowed', WIDGETS + '/one', 200, {'spec': {'marker': 'base-enabled'}})
        assert_request('base grant cannot authorize undeclared scale subresource', WIDGETS + '/one/scale', 403, {'spec': {'replicas': 2}})
        role('writer', [perm + '.get', perm + '.patch', perm + '/status.update'])
        ready(BINDING + 'writer')
        status_patch('status.update does not authorize status PATCH', 403, 'wrong-verb')
        current = api(WIDGETS + '/one')
        current['status'] = {'marker': 'put-allowed'}
        assert_request('status.update permits actual PUT', WIDGETS + '/one/status', 200, current, method='PUT', converge=True)
        role('writer', [perm + '/status.patch'])
        ready(BINDING + 'writer')
        status_patch('status.patch permits PATCH and persists state', 200, 'explicit', converge=True)
        current = api(WIDGETS + '/one')
        current['status'] = {'marker': 'forbidden-put'}
        assert_request('status.patch does not authorize actual PUT', WIDGETS + '/one/status', 403, current, method='PUT', converge=True)
        assert api(WIDGETS + '/one')['status']['marker'] == 'explicit'
        assert_request('status-only grant denies base PATCH', WIDGETS + '/one', 403, {'spec': {'marker': 'forbidden'}}, converge=True)
        status_patch('instance grant cannot patch another instance', 403, 'forbidden', name='two')
        assert_request('unregistered scale subresource denies PATCH', WIDGETS + '/one/scale', 403, {'spec': {'replicas': 2}})
        role('writer', [perm + '/status.get'])
        ready(BINDING + 'writer')
        status_patch('Role permission revocation denies PATCH', 403, 'revoked', converge=True)
        role('leaf', [perm + '/status.patch'])
        role('writer', [], [{'name': 'leaf', 'namespace': NS}])
        ready(BINDING + 'writer')
        status_patch('inherited Role grants status PATCH', 200, 'inherited', converge=True)
        role('leaf', [perm + '/status.get'])
        status_patch('inherited Role permission revocation denies PATCH', 403, 'revoked', converge=True)
        role('writer', [perm + '/status.patch'])
        api(BINDING + 'writer', 'DELETE')
        e.wait('instance binding deleted', lambda: e.request(BINDING + 'writer')[0] == 404)
        binding('root-writer', 'writer', {'resourceKind': {'apiGroup': GROUP, 'kind': 'Widget'}}, user)
        status_patch('Root grant permits another instance status PATCH', 200, 'root', converge=True, name='two')
        registration('authz-widgets', GROUP, 'Widget', 'widgets', [{'name': 'status', 'permissions': ['get', 'update']}])
        status_patch('registration verb removal denies PATCH', 403, 'removed', converge=True, name='two')
        registration('authz-widgets', GROUP, 'Widget', 'widgets', [{'name': 'status', 'permissions': ['get', 'patch', 'update']}])
        role('writer', [perm + '/status.patch'])
        status_patch('restored registration restores declared grant', 200, 'restored', converge=True, name='two')
        registration('authz-widgets', GROUP, 'Widget', 'widgets')
        status_patch('subresource declaration removal denies PATCH', 403, 'unregistered', converge=True, name='two')
        registration('authz-widgets', GROUP, 'Widget', 'widgets', [{'name': 'status', 'permissions': ['get', 'patch', 'update']}])
        status_patch('restored subresource restores declared grant', 200, 'reregistered', converge=True, name='two')
        api(BINDING + 'root-writer', 'DELETE')
        status_patch('PolicyBinding deletion revokes Root grant', 403, 'deleted', converge=True, name='two')
        hierarchy(user)
    print('All real HTTP subresource authorization checks passed.', flush=True)


def hierarchy(user):
    # Test-only declarations for existing hierarchy objects; no service configuration is changed.
    registration('authz-organizations', 'resourcemanager.miloapis.com', 'Organization', 'organizations')
    registration('authz-projects', 'resourcemanager.miloapis.com', 'Project', 'projects',
                 [{'name': 'status', 'permissions': ['patch']}], [{'apiGroup': 'resourcemanager.miloapis.com', 'kind': 'Organization'}])
    org = ensure(RM + '/organizations', {'apiVersion': 'resourcemanager.miloapis.com/v1alpha1', 'kind': 'Organization',
                                       'metadata': {'name': 'authz-parent'}, 'spec': {'type': 'Standard'}})
    ensure(RM + '/projects', {'apiVersion': 'resourcemanager.miloapis.com/v1alpha1', 'kind': 'Project',
           'metadata': {'name': 'authz-child', 'ownerReferences': [{'apiVersion': 'resourcemanager.miloapis.com/v1alpha1',
                        'kind': 'Organization', 'name': org['metadata']['name'], 'uid': org['metadata']['uid']}]},
           'spec': {'ownerRef': {'apiGroup': 'resourcemanager.miloapis.com', 'kind': 'Organization', 'name': org['metadata']['name'], 'uid': org['metadata']['uid']}}})
    role('parent-writer', ['resourcemanager.miloapis.com/projects/status.patch'])
    binding('parent-writer', 'parent-writer', {'resourceRef': {'apiGroup': 'resourcemanager.miloapis.com', 'kind': 'Organization',
            'name': org['metadata']['name'], 'uid': org['metadata']['uid']}}, user)
    body = {'status': {'conditions': [{'type': 'AuthzTest', 'status': 'True', 'reason': 'EndToEnd',
                                     'message': 'Authorized through parent', 'lastTransitionTime': '2026-01-01T00:00:00Z'}]}}
    assert_request('parent hierarchy grant permits actual Project status PATCH', RM + '/projects/authz-child/status', 200, body, converge=True)
    stored = api(RM + '/projects/authz-child')
    assert any(c['type'] == 'AuthzTest' for c in stored['status']['conditions'])
    api(BINDING + 'parent-writer', 'DELETE')
    assert_request('parent binding deletion revokes status PATCH', RM + '/projects/authz-child/status', 403, body, converge=True)


if __name__ == '__main__':
    try:
        suite()
    except Exception:
        e.diagnostics()
        with e.forward():
            for path in [PR.rstrip('/'), ROLE.rstrip('/'), BINDING.rstrip('/')]:
                code, body = e.request(path)
                (e.STATE / (path.rsplit('/', 1)[-1] + '.json')).write_text(json.dumps(body, indent=2))
        raise
