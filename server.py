"""
Zero Trust Architecture Server — Desktop GUI
Run: python server_gui.py
Opens a tkinter control panel; Flask runs in a background thread on port 5000.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading, datetime, queue, sys, io, time, json
import jwt, uuid, datetime as dt, logging
from collections import deque
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

# ── PALETTE ───────────────────────────────────────────────────────────────────
C = {
    'bg':      '#060a14', 'surface': '#0b1120', 'surface2': '#111827',
    'surface3':'#1c2840', 'border':  '#1f3050', 'text':     '#e2eaf8',
    'muted':   '#4a6080', 'green':   '#00e5a0', 'red':      '#ff4d6d',
    'amber':   '#ffb547', 'blue':    '#4da6ff', 'purple':   '#a78bfa',
    'cyan':    '#22d3ee',
}

# ── SHARED STATE (populated once Flask initialises) ───────────────────────────
_flask_app   = None
_users_db    = {}
_active_sessions = {}
_blacklisted = set()
_access_log  = deque(maxlen=300)
_device_trust= {}
_log_queue   = queue.Queue()   # GUI log messages
_server_running = False

# ── FLASK SETUP ───────────────────────────────────────────────────────────────
def build_flask():
    global _flask_app, _users_db, _active_sessions, _blacklisted
    global _access_log, _device_trust

    from flask import Flask, request, jsonify, g, render_template_string

    _flask_app = Flask(__name__)
    _flask_app.config['SECRET_KEY'] = 'zta-demo-key-change-in-production'

    _users_db = {
        'alice':   {'password': generate_password_hash('alice_pass'),   'role': 'admin',     'department': 'IT Security',  'device_id': None, 'failed': 0, 'locked': False},
        'bob':     {'password': generate_password_hash('bob_pass'),     'role': 'manager',   'department': 'Finance',      'device_id': None, 'failed': 0, 'locked': False},
        'charlie': {'password': generate_password_hash('charlie_pass'), 'role': 'analyst',   'department': 'Finance',      'device_id': None, 'failed': 0, 'locked': False},
        'diana':   {'password': generate_password_hash('diana_pass'),   'role': 'developer', 'department': 'Engineering',  'device_id': None, 'failed': 0, 'locked': False},
        'eve':     {'password': generate_password_hash('eve_pass'),     'role': 'viewer',    'department': 'HR',           'device_id': None, 'failed': 0, 'locked': False},
        'frank':   {'password': generate_password_hash('frank_pass'),   'role': 'guest',     'department': 'External',     'device_id': None, 'failed': 0, 'locked': False},
    }

    zones = {
        'system_zone':      {'name': 'System Zone',      'description': 'System administration & config', 'permission': 'system_admin',      'sensitivity': 'critical', 'color': '#ef4444'},
        'finance_zone':     {'name': 'Finance Zone',     'description': 'Financial data & transactions',  'permission': 'finance_access',     'sensitivity': 'high',     'color': '#f59e0b'},
        'engineering_zone': {'name': 'Engineering Zone', 'description': 'Code repos & deployments',       'permission': 'engineering_access', 'sensitivity': 'high',     'color': '#8b5cf6'},
        'hr_zone':          {'name': 'HR Zone',          'description': 'Employee data & payroll',        'permission': 'hr_access',          'sensitivity': 'high',     'color': '#06b6d4'},
        'reports_zone':     {'name': 'Reports Zone',     'description': 'Business reports & analytics',   'permission': 'reports_access',     'sensitivity': 'medium',   'color': '#22c55e'},
        'public_zone':      {'name': 'Public Zone',      'description': 'Public info & announcements',    'permission': 'public_access',      'sensitivity': 'low',      'color': '#94a3b8'},
    }

    role_permissions = {
        'admin':     ['system_admin', 'finance_access', 'engineering_access', 'hr_access', 'reports_access', 'public_access', 'manage_users'],
        'manager':   ['finance_access', 'hr_access', 'reports_access', 'public_access'],
        'analyst':   ['finance_access', 'reports_access', 'public_access'],
        'developer': ['engineering_access', 'reports_access', 'public_access'],
        'viewer':    ['reports_access', 'public_access'],
        'guest':     ['public_access'],
    }

    sensitivity_threshold = {'critical': 40, 'high': 55, 'medium': 70, 'low': 85}

    # ── HELPERS ───────────────────────────────────────────────────────────────
    def log_access(username, action, resource, status, risk=None, reason=''):
        entry = {
            'id':         str(uuid.uuid4())[:8],
            'timestamp':  dt.datetime.now().isoformat(),
            'username':   username or 'anon',
            'action':     action,
            'resource':   resource,
            'status':     status,
            'risk_score': risk,
            'reason':     reason,
            'ip':         request.remote_addr if request else 'internal',
        }
        _access_log.appendleft(entry)
        color = 'fail' if status == 'denied' else ('ok' if status == 'allowed' else 'info')
        ts    = dt.datetime.now().strftime('%H:%M:%S')
        msg   = f'[{ts}] [{status.upper():7}] {username or "anon":10} | {action:22} | {resource:18} risk={risk} {reason}'
        _log_queue.put((msg, color))

    def get_device_trust(device_id):
        if not device_id or device_id == 'unknown':
            return 'untrusted'
        return _device_trust.get(device_id, 'low')

    def calculate_risk(username, device_id, permission):
        role   = _users_db.get(username, {}).get('role', 'guest')
        trust  = get_device_trust(device_id)
        hour   = dt.datetime.now().hour
        failed = _users_db.get(username, {}).get('failed', 0)
        role_risk  = {'admin': 15, 'manager': 20, 'analyst': 25, 'developer': 25, 'viewer': 15, 'guest': 45}.get(role, 50)
        trust_risk = {'high': 5, 'medium': 20, 'low': 40, 'untrusted': 65}.get(trust, 65)
        perm_risk  = {'system_admin': 75, 'manage_users': 65, 'finance_access': 45,
                      'hr_access': 45, 'engineering_access': 40, 'reports_access': 20, 'public_access': 5}.get(permission, 35)
        time_risk  = 0 if 8 <= hour <= 18 else (15 if 6 <= hour < 8 or 18 < hour <= 22 else 35)
        fail_risk  = min(failed * 10, 30)
        return round(min((role_risk + trust_risk + perm_risk + time_risk + fail_risk) / 5, 100), 1)

    def make_token(username, device_id):
        jti = str(uuid.uuid4())
        payload = {
            'sub': username, 'device_id': device_id, 'jti': jti,
            'role': _users_db[username]['role'],
            'iat': dt.datetime.utcnow(),
            'exp': dt.datetime.utcnow() + dt.timedelta(hours=1),
        }
        token = jwt.encode(payload, _flask_app.config['SECRET_KEY'], algorithm='HS256')
        _active_sessions[jti] = {
            'username':      username,
            'device_id':     device_id,
            'role':          _users_db[username]['role'],
            'department':    _users_db[username]['department'],
            'login_time':    dt.datetime.now().isoformat(),
            'last_verified': dt.datetime.now().isoformat(),
            'ip':            request.remote_addr,
            'verify_count':  0,
        }
        return token, jti

    # ── AUTH DECORATOR ────────────────────────────────────────────────────────
    def token_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth  = request.headers.get('Authorization', '')
            token = auth.split(' ')[1] if auth.startswith('Bearer ') else None
            if not token:
                log_access(None, 'access', request.path, 'denied', reason='No token')
                return jsonify({'message': 'Token missing'}), 401
            try:
                data = jwt.decode(token, _flask_app.config['SECRET_KEY'], algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Invalid token'}), 401

            jti      = data.get('jti')
            username = data.get('sub')
            device   = data.get('device_id', 'unknown')

            if jti in _blacklisted:
                return jsonify({'message': 'Session revoked'}), 401
            if username not in _users_db:
                return jsonify({'message': 'User not found'}), 401
            if _users_db[username].get('locked'):
                return jsonify({'message': 'Account locked'}), 403

            stored = _users_db[username].get('device_id')
            if stored and stored != device:
                log_access(username, 'access', request.path, 'denied', reason='Device mismatch')
                return jsonify({'message': 'Unauthorized device'}), 403

            if jti in _active_sessions:
                _active_sessions[jti]['last_verified'] = dt.datetime.now().isoformat()
                _active_sessions[jti]['verify_count'] += 1

            g.user, g.role, g.device_id, g.jti = username, _users_db[username]['role'], device, jti
            return f(*args, **kwargs)
        return decorated

    def authorize(permission):
        def decorator(f):
            @wraps(f)
            def inner(*args, **kwargs):
                if permission not in role_permissions.get(g.role, []):
                    log_access(g.user, permission, request.path, 'denied',
                               reason=f'Role "{g.role}" lacks permission')
                    return jsonify({'message': f'Access denied — your role ({g.role}) does not have {permission}'}), 403
                risk  = calculate_risk(g.user, g.device_id, permission)
                zone  = next((z for z, d in zones.items() if d['permission'] == permission), None)
                sens  = zones.get(zone, {}).get('sensitivity', 'medium')
                threshold = sensitivity_threshold.get(sens, 70)
                if risk > threshold:
                    log_access(g.user, permission, request.path, 'denied', risk=risk,
                               reason=f'Risk {risk} > threshold {threshold}')
                    return jsonify({'message': f'Access blocked by risk policy (score {risk} > {threshold})',
                                    'risk_score': risk, 'threshold': threshold}), 403
                log_access(g.user, permission, request.path, 'allowed', risk=risk)
                g.risk = risk
                return f(*args, **kwargs)
            return inner
        return decorator

    # ── ROUTES ────────────────────────────────────────────────────────────────
    @_flask_app.route('/login', methods=['POST'])
    def login():
        body      = request.json or {}
        username  = body.get('username', '').strip().lower()
        password  = body.get('password', '')
        device_id = body.get('device_id', 'unknown')
        if not username or not password:
            return jsonify({'message': 'Credentials required'}), 400
        user = _users_db.get(username)
        if not user:
            log_access(username, 'login', '/login', 'denied', reason='Unknown user')
            return jsonify({'message': 'Invalid credentials'}), 401
        if user.get('locked'):
            return jsonify({'message': 'Account locked — contact admin'}), 403
        if not check_password_hash(user['password'], password):
            user['failed'] += 1
            if user['failed'] >= 5:
                user['locked'] = True
                return jsonify({'message': 'Account locked after too many failed attempts'}), 403
            log_access(username, 'login', '/login', 'denied', reason='Wrong password')
            return jsonify({'message': 'Invalid credentials'}), 401
        user['failed'] = 0
        if device_id != 'unknown':
            user['device_id'] = device_id
            _device_trust.setdefault(device_id, 'medium')
        token, jti = make_token(username, device_id)
        perms      = role_permissions.get(user['role'], [])
        accessible = {z: d for z, d in zones.items() if d['permission'] in perms}
        log_access(username, 'login', '/login', 'allowed', reason=f'Login from {request.remote_addr}')
        return jsonify({
            'token': token, 'jti': jti,
            'username': username, 'role': user['role'], 'department': user['department'],
            'permissions': perms, 'accessible_zones': accessible,
        })

    @_flask_app.route('/logout', methods=['POST'])
    @token_required
    def logout():
        _blacklisted.add(g.jti)
        _active_sessions.pop(g.jti, None)
        log_access(g.user, 'logout', '/logout', 'info', reason='User logged out')
        return jsonify({'message': 'Logged out'})

    @_flask_app.route('/verify', methods=['GET'])
    @token_required
    def verify():
        risk = calculate_risk(g.user, g.device_id, 'public_access')
        return jsonify({'valid': True, 'username': g.user, 'role': g.role,
                        'risk_score': risk, 'ts': dt.datetime.now().isoformat()})

    @_flask_app.route('/zone/system', methods=['GET'])
    @token_required
    @authorize('system_admin')
    def zone_system():
        return jsonify({'zone': 'System Zone', 'accessed_by': g.user, 'risk_score': g.risk,
                        'data': {'cpu_usage': '34%', 'memory': '12.4 GB / 32 GB',
                                 'active_users': len(_users_db), 'active_sessions': len(_active_sessions),
                                 'uptime': '14d 7h 22m', 'threat_level': 'LOW'}})

    @_flask_app.route('/zone/finance', methods=['GET'])
    @token_required
    @authorize('finance_access')
    def zone_finance():
        return jsonify({'zone': 'Finance Zone', 'accessed_by': g.user, 'risk_score': g.risk,
                        'data': {'q1_revenue': '$4.2M', 'expenses': '$2.8M', 'net': '$1.4M',
                                 'budget_used': '67%', 'pending_invoices': 23, 'open_audits': 2}})

    @_flask_app.route('/zone/engineering', methods=['GET'])
    @token_required
    @authorize('engineering_access')
    def zone_engineering():
        return jsonify({'zone': 'Engineering Zone', 'accessed_by': g.user, 'risk_score': g.risk,
                        'data': {'active_repos': 42, 'open_prs': 7, 'builds_today': 19,
                                 'deployments': 3, 'test_coverage': '83%', 'incidents_open': 1}})

    @_flask_app.route('/zone/hr', methods=['GET'])
    @token_required
    @authorize('hr_access')
    def zone_hr():
        return jsonify({'zone': 'HR Zone', 'accessed_by': g.user, 'risk_score': g.risk,
                        'data': {'total_employees': 145, 'open_positions': 8,
                                 'pending_reviews': 12, 'new_hires_q1': 9, 'attrition_rate': '4.2%'}})

    @_flask_app.route('/zone/reports', methods=['GET'])
    @token_required
    @authorize('reports_access')
    def zone_reports():
        return jsonify({'zone': 'Reports Zone', 'accessed_by': g.user, 'risk_score': g.risk,
                        'data': {'latest_report': 'Q1 2026 Summary', 'kpi_status': 'On Track',
                                 'dashboards': 8, 'scheduled_reports': 14, 'data_sources': 6}})

    @_flask_app.route('/zone/public', methods=['GET'])
    @token_required
    @authorize('public_access')
    def zone_public():
        return jsonify({'zone': 'Public Zone', 'accessed_by': g.user, 'risk_score': g.risk,
                        'data': {'announcements': 3, 'latest_news': 'Company All-Hands: Apr 15',
                                 'upcoming_events': 2, 'policy_updates': 1}})

    @_flask_app.route('/api/stats')
    def api_stats():
        logs    = list(_access_log)
        allowed = sum(1 for l in logs if l['status'] == 'allowed')
        denied  = sum(1 for l in logs if l['status'] == 'denied')
        return jsonify({
            'active_sessions': len(_active_sessions), 'total_users': len(_users_db),
            'locked_users': sum(1 for u in _users_db.values() if u.get('locked')),
            'allowed': allowed, 'denied': denied,
            'total_requests': len(logs),
            'denial_rate': round(denied / max(len(logs), 1) * 100, 1),
        })

    @_flask_app.route('/api/users')
    def api_users():
        active_names = {s['username'] for s in _active_sessions.values()}
        return jsonify([{
            'username': u, 'role': d['role'], 'department': d['department'],
            'locked': d.get('locked', False), 'failed': d.get('failed', 0),
            'active': u in active_names,
            'permissions': role_permissions.get(d['role'], []),
            'device_trust': get_device_trust(d.get('device_id')),
        } for u, d in _users_db.items()])

    @_flask_app.route('/api/sessions')
    def api_sessions():
        return jsonify(list(_active_sessions.values()))

    @_flask_app.route('/api/logs')
    def api_logs():
        return jsonify(list(_access_log)[:int(request.args.get('limit', 60))])

    @_flask_app.route('/api/zones')
    def api_zones():
        return jsonify([{**d, 'zone_id': z,
            'authorized_roles': [r for r, p in role_permissions.items() if d['permission'] in p]
        } for z, d in zones.items()])

    @_flask_app.route('/api/revoke/<username>', methods=['POST'])
    def api_revoke(username):
        jtis = [j for j, s in _active_sessions.items() if s['username'] == username]
        for j in jtis:
            _blacklisted.add(j)
            _active_sessions.pop(j, None)
        log_access('dashboard', 'revoke', f'/{username}', 'info', reason=f'Revoked {len(jtis)} sessions')
        return jsonify({'revoked': len(jtis)})

    @_flask_app.route('/api/unlock/<username>', methods=['POST'])
    def api_unlock(username):
        if username in _users_db:
            _users_db[username]['locked'] = False
            _users_db[username]['failed'] = 0
            return jsonify({'message': f'Unlocked {username}'})
        return jsonify({'message': 'Not found'}), 404

    @_flask_app.route('/health')
    def health():
        return jsonify({'status': 'healthy', 'ts': dt.datetime.now().isoformat()})

    return _flask_app

# ── SERVER THREAD ─────────────────────────────────────────────────────────────
_server_thread = None

def start_server():
    global _server_running, _server_thread
    if _server_running:
        return
    flask_app = build_flask()

    import logging as lg
    log = lg.getLogger('werkzeug')
    log.setLevel(lg.ERROR)        # silence werkzeug to stdout

    def run():
        global _server_running
        _server_running = True
        _log_queue.put(('Server started on http://127.0.0.1:5000', 'ok'))
        flask_app.run(debug=False, host='127.0.0.1', port=5000, use_reloader=False)

    _server_thread = threading.Thread(target=run, daemon=True)
    _server_thread.start()


# ── GUI ────────────────────────────────────────────────────────────────────────
class ServerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Zero Trust Server — Control Panel')
        self.geometry('1060x680')
        self.configure(bg=C['bg'])
        self.minsize(800, 520)
        self._apply_style()
        self._build()
        self._poll_logs()
        self._refresh_stats()
        self.protocol('WM_DELETE_WINDOW', self._quit)

    def _quit(self):
        self.destroy()
        sys.exit(0)

    def _apply_style(self):
        s = ttk.Style(self)
        s.theme_use('clam')
        s.configure('TNotebook',        background=C['surface'],  borderwidth=0)
        s.configure('TNotebook.Tab',    background=C['surface2'], foreground=C['muted'],
                    padding=[14, 6],   font=('Courier', 9, 'bold'))
        s.map('TNotebook.Tab',
              background=[('selected', C['surface3'])],
              foreground=[('selected', C['green'])])
        s.configure('TSeparator', background=C['border'])

    # ── LAYOUT ────────────────────────────────────────────────────────────────
    def _build(self):
        self._topbar()
        body = tk.Frame(self, bg=C['bg'])
        body.pack(fill='both', expand=True, padx=12, pady=(0, 12))

        # Left: stat cards + users table
        left = tk.Frame(body, bg=C['bg'])
        left.pack(side='left', fill='both', expand=True, padx=(0, 10))

        self._stat_cards(left)
        self._users_section(left)

        # Right: log console
        self._log_section(body)

        self._statusbar()

    # ── TOP BAR ───────────────────────────────────────────────────────────────
    def _topbar(self):
        bar = tk.Frame(self, bg=C['surface'])
        bar.pack(fill='x')
        tk.Frame(bar, bg=C['green'], height=3).pack(fill='x')

        inner = tk.Frame(bar, bg=C['surface'])
        inner.pack(fill='x', padx=18, pady=10)

        tk.Label(inner, text='🛡  ZERO TRUST SERVER', font=('Courier', 13, 'bold'),
                 bg=C['surface'], fg=C['green']).pack(side='left')

        right = tk.Frame(inner, bg=C['surface'])
        right.pack(side='right')

        self.status_dot = tk.Label(right, text='●', font=('Courier', 14),
                                   bg=C['surface'], fg=C['red'])
        self.status_dot.pack(side='left', padx=(0, 4))

        self.status_lbl = tk.Label(right, text='STOPPED', font=('Courier', 10, 'bold'),
                                   bg=C['surface'], fg=C['red'])
        self.status_lbl.pack(side='left', padx=(0, 18))

        self.start_btn = tk.Button(right, text='▶  START SERVER',
                                   font=('Courier', 10, 'bold'),
                                   bg=C['green'], fg=C['bg'], relief='flat',
                                   padx=18, pady=7, cursor='hand2',
                                   activebackground='#00c489',
                                   command=self._start_server)
        self.start_btn.pack(side='left', padx=(0, 8))

        tk.Label(right, text='port 5000', font=('Courier', 9),
                 bg=C['surface'], fg=C['muted']).pack(side='left')

    # ── STAT CARDS ────────────────────────────────────────────────────────────
    def _stat_cards(self, parent):
        row = tk.Frame(parent, bg=C['bg'])
        row.pack(fill='x', pady=(10, 10))

        specs = [
            ('SESSIONS',  '0', C['cyan'],   'v_sessions'),
            ('USERS',     '6', C['blue'],   'v_users'),
            ('ALLOWED',   '0', C['green'],  'v_allowed'),
            ('DENIED',    '0', C['red'],    'v_denied'),
            ('LOCKED',    '0', C['amber'],  'v_locked'),
            ('DENY RATE', '0%',C['purple'], 'v_rate'),
        ]
        for label, default, color, attr in specs:
            card = tk.Frame(row, bg=C['surface2'],
                            highlightbackground=C['border'], highlightthickness=1)
            card.pack(side='left', expand=True, fill='x', padx=4)
            tk.Frame(card, bg=color, height=2).pack(fill='x')
            tk.Label(card, text=label, font=('Courier', 8, 'bold'),
                     bg=C['surface2'], fg=C['muted']).pack(pady=(8, 2))
            v = tk.StringVar(value=default)
            setattr(self, attr, v)
            tk.Label(card, textvariable=v, font=('Courier', 20, 'bold'),
                     bg=C['surface2'], fg=color).pack(pady=(0, 10))

    # ── USERS TABLE ───────────────────────────────────────────────────────────
    def _users_section(self, parent):
        panel = tk.Frame(parent, bg=C['surface'],
                         highlightbackground=C['border'], highlightthickness=1)
        panel.pack(fill='both', expand=True)

        hdr = tk.Frame(panel, bg=C['surface2'])
        hdr.pack(fill='x')
        tk.Label(hdr, text='USER ACCOUNTS', font=('Courier', 10, 'bold'),
                 bg=C['surface2'], fg=C['text']).pack(side='left', padx=14, pady=10)
        self.refresh_lbl = tk.Label(hdr, text='', font=('Courier', 8),
                                    bg=C['surface2'], fg=C['muted'])
        self.refresh_lbl.pack(side='right', padx=14)
        tk.Frame(panel, bg=C['border'], height=1).pack(fill='x')

        # Treeview
        cols = ('user', 'role', 'dept', 'status', 'fails', 'trust')
        self.tree = ttk.Treeview(panel, columns=cols, show='headings', height=9)
        headers = [('user', 'USERNAME', 110), ('role', 'ROLE', 90),
                   ('dept', 'DEPARTMENT', 120), ('status', 'STATUS', 80),
                   ('fails', 'FAILS', 50), ('trust', 'TRUST', 70)]
        for cid, txt, w in headers:
            self.tree.heading(cid, text=txt)
            self.tree.column(cid, width=w, anchor='w')

        style = ttk.Style()
        style.configure('Treeview', background=C['surface2'], foreground=C['text'],
                        fieldbackground=C['surface2'], rowheight=26,
                        font=('Helvetica', 10), borderwidth=0)
        style.configure('Treeview.Heading', background=C['surface3'],
                        foreground=C['muted'], font=('Courier', 8, 'bold'),
                        borderwidth=0, relief='flat')
        style.map('Treeview', background=[('selected', C['surface3'])],
                  foreground=[('selected', C['cyan'])])

        self.tree.tag_configure('active', foreground=C['green'])
        self.tree.tag_configure('locked', foreground=C['red'])
        self.tree.tag_configure('offline', foreground=C['muted'])

        sb = ttk.Scrollbar(panel, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side='left', fill='both', expand=True)
        sb.pack(side='right', fill='y')

        # Action bar
        act = tk.Frame(panel, bg=C['surface'])
        act.pack(fill='x')
        tk.Frame(act, bg=C['border'], height=1).pack(fill='x')
        btn_row = tk.Frame(act, bg=C['surface'])
        btn_row.pack(fill='x', padx=10, pady=8)
        tk.Button(btn_row, text='Revoke Session', font=('Courier', 9, 'bold'),
                  bg='#3d1a24', fg=C['red'], relief='flat', padx=12, pady=5,
                  cursor='hand2', activebackground='#5a2030',
                  command=self._revoke_selected).pack(side='left', padx=4)
        tk.Button(btn_row, text='Unlock Account', font=('Courier', 9, 'bold'),
                  bg='#0d2d20', fg=C['green'], relief='flat', padx=12, pady=5,
                  cursor='hand2', activebackground='#1a4030',
                  command=self._unlock_selected).pack(side='left', padx=4)
        tk.Label(btn_row, text='Select a user then click an action',
                 font=('Courier', 8), bg=C['surface'], fg=C['muted']).pack(side='right', padx=8)

    # ── LOG CONSOLE ───────────────────────────────────────────────────────────
    def _log_section(self, parent):
        panel = tk.Frame(parent, bg=C['surface'],
                         highlightbackground=C['border'], highlightthickness=1,
                         width=360)
        panel.pack(side='right', fill='y')
        panel.pack_propagate(False)

        hdr = tk.Frame(panel, bg=C['surface2'])
        hdr.pack(fill='x')
        tk.Label(hdr, text='LIVE LOG', font=('Courier', 10, 'bold'),
                 bg=C['surface2'], fg=C['text']).pack(side='left', padx=14, pady=10)
        tk.Button(hdr, text='Clear', font=('Courier', 8), bg=C['surface3'],
                  fg=C['muted'], relief='flat', padx=8, pady=2,
                  cursor='hand2', command=self._clear_log).pack(side='right', padx=10, pady=8)
        tk.Frame(panel, bg=C['border'], height=1).pack(fill='x')

        self.log_box = scrolledtext.ScrolledText(
            panel, font=('Courier', 9), bg='#040810', fg=C['muted'],
            relief='flat', padx=8, pady=8, state='disabled', wrap='word',
        )
        self.log_box.pack(fill='both', expand=True)
        self.log_box.tag_configure('ok',   foreground=C['green'])
        self.log_box.tag_configure('fail', foreground=C['red'])
        self.log_box.tag_configure('info', foreground=C['cyan'])
        self.log_box.tag_configure('warn', foreground=C['amber'])
        self.log_box.tag_configure('dim',  foreground=C['muted'])

    # ── STATUS BAR ────────────────────────────────────────────────────────────
    def _statusbar(self):
        bar = tk.Frame(self, bg=C['surface2'])
        bar.pack(fill='x', side='bottom')
        self.clock_var = tk.StringVar()
        tk.Label(bar, textvariable=self.clock_var, font=('Courier', 8),
                 bg=C['surface2'], fg=C['muted']).pack(side='right', padx=12, pady=4)
        tk.Label(bar, text='  http://127.0.0.1:5000  |  dashboard → /dashboard',
                 font=('Courier', 8), bg=C['surface2'], fg=C['muted']).pack(side='left', pady=4)
        self._tick_clock()

    def _tick_clock(self):
        self.clock_var.set(dt.datetime.now().strftime('%Y-%m-%d  %H:%M:%S'))
        self.after(1000, self._tick_clock)

    # ── ACTIONS ───────────────────────────────────────────────────────────────
    def _start_server(self):
        self.start_btn.config(state='disabled', text='Starting…')
        self._log('Starting Flask server on port 5000…', 'info')
        threading.Thread(target=self._do_start, daemon=True).start()

    def _do_start(self):
        start_server()
        time.sleep(0.8)
        self.after(0, self._on_started)

    def _on_started(self):
        self.status_dot.config(fg=C['green'])
        self.status_lbl.config(text='RUNNING', fg=C['green'])
        self.start_btn.config(text='● RUNNING', bg=C['surface3'], fg=C['green'],
                              state='disabled')
        self._log('Server is live at http://127.0.0.1:5000', 'ok')

    def _log(self, msg, tag='dim'):
        self.log_box.config(state='normal')
        self.log_box.insert('end', msg + '\n', tag)
        self.log_box.see('end')
        self.log_box.config(state='disabled')

    def _clear_log(self):
        self.log_box.config(state='normal')
        self.log_box.delete('1.0', 'end')
        self.log_box.config(state='disabled')

    def _poll_logs(self):
        try:
            while True:
                msg, tag = _log_queue.get_nowait()
                self._log(msg, tag)
        except queue.Empty:
            pass
        self.after(200, self._poll_logs)

    def _refresh_stats(self):
        if _server_running:
            logs    = list(_access_log)
            allowed = sum(1 for l in logs if l['status'] == 'allowed')
            denied  = sum(1 for l in logs if l['status'] == 'denied')
            total   = max(len(logs), 1)
            locked  = sum(1 for u in _users_db.values() if u.get('locked'))
            self.v_sessions.set(str(len(_active_sessions)))
            self.v_users.set(str(len(_users_db)))
            self.v_allowed.set(str(allowed))
            self.v_denied.set(str(denied))
            self.v_locked.set(str(locked))
            self.v_rate.set(f'{round(denied/total*100,1)}%')
            self._refresh_table()
            ts = dt.datetime.now().strftime('%H:%M:%S')
            self.refresh_lbl.config(text=f'updated {ts}')
        self.after(2000, self._refresh_stats)

    def _refresh_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        active_names = {s['username'] for s in _active_sessions.values()}
        for uname, d in _users_db.items():
            if d.get('locked'):
                status, tag = '🔒 Locked', 'locked'
            elif uname in active_names:
                status, tag = '● Active', 'active'
            else:
                status, tag = '○ Offline', 'offline'
            trust = _device_trust.get(d.get('device_id'), 'untrusted') if d.get('device_id') else 'none'
            self.tree.insert('', 'end', iid=uname,
                             values=(uname, d['role'], d['department'],
                                     status, d.get('failed', 0), trust),
                             tags=(tag,))

    def _revoke_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        username = sel[0]
        jtis = [j for j, s in list(_active_sessions.items()) if s['username'] == username]
        for j in jtis:
            _blacklisted.add(j)
            _active_sessions.pop(j, None)
        self._log(f'Revoked {len(jtis)} session(s) for {username}', 'warn')

    def _unlock_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        username = sel[0]
        if username in _users_db:
            _users_db[username]['locked'] = False
            _users_db[username]['failed'] = 0
            self._log(f'Unlocked account: {username}', 'ok')


if __name__ == '__main__':
    app = ServerGUI()
    app.mainloop()