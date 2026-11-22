#!/usr/bin/env python3
"""Mock API for README screenshots (see screenshots.sh).

Serves internal/web/static plus fake /api responses with example data.
Usage: mock.py <static-dir> [port]   (listens on 127.0.0.1 only)
"""
import json, sys, time, os
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

STATIC = sys.argv[1]
HERE = os.path.dirname(os.path.abspath(__file__))
NOW = int(time.time())

def proxy(host, port, scheme='http', cert='*.home.example.org', **kw):
    p = dict(enabled=True, forwardScheme=scheme, forwardHost=host, forwardPort=port,
             certificate=cert, sslForced=bool(cert), http2=bool(cert), hsts=False,
             websocket=True, blockExploits=True, caching=False, accessList='')
    p.update(kw)
    return p

T = '192.168.10.5'
ENTRIES = [
    dict(domain='cloud.home.example.org', dnsIps=[T], pointsToNpm=True, proxy=proxy('192.168.10.20', 11000, hsts=True)),
    dict(domain='grafana.home.example.org', dnsIps=[T], pointsToNpm=True, proxy=proxy('192.168.10.31', 3000, accessList='LAN only')),
    dict(domain='ha.home.example.org', dnsIps=[T], pointsToNpm=True, proxy=proxy('192.168.10.40', 8123)),
    dict(domain='jellyfin.home.example.org', dnsIps=[T], pointsToNpm=True, proxy=proxy('192.168.10.21', 8096, caching=True)),
    dict(domain='nas.home.example.org', dnsIps=['192.168.10.10'], pointsToNpm=False, proxy=proxy('192.168.10.10', 5001, scheme='https')),
    dict(domain='paperless.home.example.org', dnsIps=[T], pointsToNpm=True, proxy=proxy('192.168.10.22', 8000, accessList='LAN only')),
    dict(domain='printer.home.example.org', dnsIps=['192.168.10.60'], pointsToNpm=False, proxy=None),
    dict(domain='vault.home.example.org', dnsIps=[T], pointsToNpm=True, proxy=proxy('192.168.10.23', 8080, hsts=True, http2=True)),
    dict(domain='wiki.home.example.org', dnsIps=[], pointsToNpm=False, proxy=proxy('192.168.10.24', 3000, cert='', websocket=False)),
]

OPTIONS = dict(
    allowedDomains=['home.example.org'], targetIp=T, canAdvanced=True,
    certificates=[dict(id=1, name='*.home.example.org', expires='2027-02-14 08:00:00'),
                  dict(id=2, name='status.example.org', expires='2027-01-03 10:12:00')],
    accessLists=[dict(id=1, name='LAN only'), dict(id=2, name='Admins')],
)

SETTINGS = dict(
    piholeUrl='https://pi.hole', piholePasswordSet=True, piholeCaPem='',
    npmUrl='https://npm.home.example.org', npmEmail='proxydns@home.example.org', npmPasswordSet=True,
    npmCaPem='', npmTargetIp=T, allowedDomains='home.example.org',
    oidcAvailable=True, oidcEnabled=False, oidcIssuer='', oidcClientId='', oidcClientSecretSet=False,
    oidcRedirectUrl='', oidcButtonLabel='',
)

USER = dict(id=1, username='admin', role='admin', email='admin@home.example.org', totpEnabled=True)

def det(fwd, cert=1, acl=0, **kw):
    d = dict(dns=T, forward=fwd, certificate=cert, accessList=acl, sslForced=True, http2=True, hsts=False,
             websocket=True, blockExpl=True, caching=False, locations=0, advanced=False)
    d.update(kw)
    return json.dumps(d, separators=(',', ':'))

A = [
    (60, 'admin', 'entry_create', 'vault.home.example.org', True, det('http://192.168.10.23:8080', hsts=True)),
    (420, 'admin', 'entry_create', 'paperless.home.example.org', True, det('http://192.168.10.22:8000', acl=1)),
    (900, 'maria', 'entry_create', 'git.home.example.org', False, 'npm: certificate not found; DNS record rolled back'),
    (1500, 'maria', 'login', 'maria', True, 'password + TOTP'),
    (3600, 'admin', 'settings_test', 'npm', True, ''),
    (3700, 'admin', 'settings_update', '', True, ''),
    (7200, 'admin', 'user_create', 'maria', True, 'role=user'),
    (7300, '', 'login', 'root', False, 'unknown user or no password'),
    (7400, 'admin', 'totp_enable', 'admin', True, ''),
    (7500, 'admin', 'login', 'admin', True, 'password'),
    (7600, 'admin', 'setup', 'admin', True, 'first admin created'),
]
AUDIT = [dict(id=len(A) - i, ts=NOW - a[0], username=a[1], ip='192.168.10.' + ('77' if a[1] == 'maria' else '50'),
              action=a[2], target=a[3], success=a[4], details=a[5]) for i, a in enumerate(A)]

ROUTES = {
    '/api/info': dict(mode='server', version='0.0.1-alpha', setupRequired=False, setupNeedsCode=False, oidc=dict(enabled=False)),
    '/api/auth/me': dict(user=USER, configured=True, csrf='x'),
    '/api/entries': dict(entries=ENTRIES, targetIp=T, errors={}),
    '/api/entries/options': OPTIONS,
    '/api/settings': SETTINGS,
    '/api/users': [],
    '/api/audit': dict(entries=AUDIT, total=len(AUDIT)),
    '/api/audit/verify': dict(ok=True, checked=len(AUDIT)),
}

class H(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=STATIC, **kw)

    def log_message(self, *a):
        pass

    def send(self, body, ctype='application/json'):
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split('?')[0]
        if path in ROUTES:
            return self.send(json.dumps(ROUTES[path]).encode())
        if path in ('/', '/index.html'):
            html = open(os.path.join(STATIC, 'index.html'), encoding='utf-8').read()
            html = html.replace('</head>', '<script src="/_shot.js" defer></script></head>')
            return self.send(html.encode(), 'text/html; charset=utf-8')
        if path == '/_shot.js':
            return self.send(open(os.path.join(HERE, 'shot.js'), 'rb').read(), 'text/javascript')
        return super().do_GET()

PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8765
ThreadingHTTPServer(('127.0.0.1', PORT), H).serve_forever()
