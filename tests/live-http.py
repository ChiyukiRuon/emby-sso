"""Exercise the plugin in an isolated Emby instance with the TEST ONLY harness loaded."""
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

base = os.environ.get('EMBY_SSO_BASE', 'http://127.0.0.1:18996')
public = os.environ.get('EMBY_SSO_PUBLIC_URL', 'https://localhost:18997')
public_host = urllib.parse.urlparse(public).netloc

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

def request(path, data=None, cookie='', origin=public, headers=None):
    h = {'Host': public_host, 'Origin': origin, 'Cookie': cookie}
    h.update(headers or {})
    body = None if data is None else urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(base + path, body, headers=h)
    try:
        response = opener.open(req)
    except urllib.error.HTTPError as error:
        response = error
    return response.code, response.headers, response.read().decode()

def bootstrap(html):
    return json.loads(re.search(r'<script id="bootstrap" type="application/json">(.*?)</script>', html, re.S)[1])

status, _, _ = request('/sso-test/setup', {}, headers={'X-Test-Secret': os.environ['EMBY_SSO_TEST_SECRET']})
assert status == 200, status

def login(subject, action='login', username='', password=''):
    token_headers = {}
    if action == 'link':
        status, _, body = request('/emby/Users/AuthenticateByName', {'Username': username, 'Pw': password}, headers={
            'X-Emby-Authorization': 'MediaBrowser Client="SsoTest", Device="Test", DeviceId="profile-test", Version="1.0"'
        })
        assert status == 200, (status, body)
        local = json.loads(body)
        token_headers = {'X-Emby-Token': local['AccessToken']}
    status, headers, html = request('/sso/profile' if action == 'link' else '/sso', headers=token_headers)
    assert status == 200, (status, html)
    cookie_header = headers['Set-Cookie']
    cookie = cookie_header.split(';')[0]
    assert 'HttpOnly' in cookie_header
    assert ('Secure' in cookie_header) == public.startswith('https://')
    csrf = (json.loads(html) if action == 'link' else bootstrap(html))['csrf']
    data = {'Csrf': csrf, 'Action': action, 'Username': username, 'Password': password}
    route = '/sso/profile' if action == 'link' else '/sso/start'
    status, _, _ = request(route, data, cookie, origin='https://evil.test', headers=token_headers)
    assert status == 400
    status, headers, body = request(route, data, cookie, headers=token_headers)
    assert status == 200 if action == 'link' else status in (302, 303), (status, body)
    auth = urllib.parse.parse_qs(urllib.parse.urlparse(json.loads(body)['url'] if action == 'link' else headers['Location']).query)
    assert auth['code_challenge_method'] == ['S256']
    callback = '/sso/callback?' + urllib.parse.urlencode({'State': auth['state'][0], 'Code': subject + '|' + auth['nonce'][0]})
    status, _, _ = request(callback, cookie='__Secure-EmbySso=' + 'x' * 43)
    assert status == 400
    status, _, html = request(callback, cookie=cookie)
    if action == 'link':
        assert status in (302, 303), (status, html)
        return login(subject)
    assert status == 200, (status, html)
    status, _, _ = request(callback, cookie=cookie)
    assert status == 400
    ticket = bootstrap(html)['ticket']
    status, _, body = request('/sso/session', {'Ticket': ticket}, cookie)
    assert status == 200, (status, body)
    result = json.loads(body)
    assert result['AccessToken'] and result['User']['Id']
    status, _, _ = request('/sso/session', {'Ticket': ticket}, cookie)
    assert status == 400
    status, _, body = request('/emby/Users/' + result['User']['Id'], headers={'X-Emby-Token': result['AccessToken']})
    assert status == 200, (status, body)
    return result, json.loads(body)

result, user = login('new-sso-user')
assert not user['Policy']['IsAdministrator'] and not user['Policy']['EnableAllFolders']
assert not user['Policy']['EnableContentDeletion']
repeat, _ = login('new-sso-user')
assert result['User']['Id'] == repeat['User']['Id']
linked, user = login('external-subject', 'link', 'existing-user', 'ExistingPassword123!')
assert user['Name'] == 'existing-user'
again, _ = login('external-subject')
assert linked['User']['Id'] == again['User']['Id']
admin, admin_user = login('admin-subject', 'link', 'sso-admin', 'SsoAdminPassword123!')
assert admin_user['Policy']['IsAdministrator']
admin_again, _ = login('admin-subject')
assert admin['User']['Id'] == admin_again['User']['Id']
print('PASS live Emby 4.10.2.0: registration, repeat login, explicit binding, bound login, admin binding/login, remote API session, CSRF, cross-browser callback, replay, restricted policy')

# Profile management requires an authenticated user, ignores submitted usernames, and checks passwords.
status, _, _ = request('/sso/profile')
assert status in (401, 403), status
headers = {'X-Emby-Token': linked['AccessToken']}
for password, expected in [('wrong-password', 400), ('ExistingPassword123!', 200)]:
    status, response_headers, body = request('/sso/profile', headers=headers)
    assert status == 200, (status, body)
    profile = json.loads(body)
    assert profile['username'] == 'existing-user' and profile['bound']
    cookie = response_headers['Set-Cookie'].split(';')[0]
    status, _, body = request('/sso/profile', {
        'Csrf': profile['csrf'], 'Action': 'unlink', 'Password': password,
        'Username': 'sso-admin'
    }, cookie, headers=headers)
    assert status == expected, (status, body)
status, _, body = request('/sso/profile', headers=headers)
assert not json.loads(body)['bound']
status, _, body = request('/sso/profile', headers={'X-Emby-Token': admin['AccessToken']})
assert json.loads(body)['bound']
print('PASS profile: authentication, password verification, session-derived account, unlink isolation')
