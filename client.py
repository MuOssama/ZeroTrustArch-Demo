"""
Zero Trust Client — GUI Application
Run: python client_gui.py   (server_gui.py must be running first)

Users & passwords:
  alice / alice_pass    → admin      (all zones)
  bob / bob_pass        → manager    (finance, hr, reports, public)
  charlie / charlie_pass→ analyst    (finance, reports, public)
  diana / diana_pass    → developer  (engineering, reports, public)
  eve / eve_pass        → viewer     (reports, public)
  frank / frank_pass    → guest      (public only)
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests, uuid, platform, socket, datetime, threading, json, time

BASE_URL = "http://127.0.0.1:5000"

# ── PALETTE ───────────────────────────────────────────────────────────────────
C = {
    'bg':      '#060a14',  'surface': '#0b1120',  'surface2': '#111827',
    'border':  '#1f3050',  'text':    '#e2eaf8',   'muted':    '#4a6080',
    'green':   '#00e5a0',  'red':     '#ff4d6d',   'amber':    '#ffb547',
    'blue':    '#4da6ff',  'purple':  '#a78bfa',   'cyan':     '#22d3ee',
}

ROLE_COLORS = {
    'admin': C['blue'], 'manager': C['amber'], 'analyst': C['green'],
    'developer': C['purple'], 'viewer': C['cyan'], 'guest': C['muted'],
}

ZONES = {
    'system_zone':      {'name': 'System Zone',      'icon': '*',  'color': C['red'],    'endpoint': '/zone/system'},
    'finance_zone':     {'name': 'Finance Zone',     'icon': '$',  'color': C['amber'],  'endpoint': '/zone/finance'},
    'engineering_zone': {'name': 'Engineering Zone', 'icon': '#',  'color': C['purple'], 'endpoint': '/zone/engineering'},
    'hr_zone':          {'name': 'HR Zone',          'icon': '+',  'color': C['cyan'],   'endpoint': '/zone/hr'},
    'reports_zone':     {'name': 'Reports Zone',     'icon': '@',  'color': C['green'],  'endpoint': '/zone/reports'},
    'public_zone':      {'name': 'Public Zone',      'icon': 'o',  'color': C['muted'],  'endpoint': '/zone/public'},
}

# ── DEVICE ID ─────────────────────────────────────────────────────────────────
def get_device_id():
    parts = [socket.gethostname(),
             ':'.join(f'{(uuid.getnode()>>e)&0xff:02x}' for e in range(0,48,8)),
             platform.system()]
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, '-'.join(parts)))

DEVICE_ID = get_device_id()

# ── SAFE JSON HELPER ──────────────────────────────────────────────────────────
def safe_json(response):
    """Parse JSON safely; return dict with 'message' on failure."""
    try:
        return response.json()
    except Exception:
        return {'message': f'Server returned non-JSON response (HTTP {response.status_code})'}

# ── MAIN APP ──────────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Zero Trust Client")
        self.geometry("1180x720")
        self.configure(bg=C['bg'])
        self.minsize(900, 600)

        self.token     = None
        self.user_info = None
        self.running   = True

        self._apply_style()
        self._show_login()
        self.protocol("WM_DELETE_WINDOW", self._quit)

    def _quit(self):
        self.running = False
        if self.token:
            try: requests.post(f"{BASE_URL}/logout", headers=self._h(), timeout=2)
            except: pass
        self.destroy()

    def _apply_style(self):
        s = ttk.Style(self)
        s.theme_use('clam')
        s.configure('TEntry', fieldbackground=C['surface2'], foreground=C['text'],
                    insertcolor=C['text'], borderwidth=0)

    def _clear(self):
        for w in self.winfo_children(): w.destroy()

    def _show_login(self):
        self._clear()
        LoginFrame(self).pack(fill='both', expand=True)

    def _show_dashboard(self):
        self._clear()
        DashboardFrame(self).pack(fill='both', expand=True)

    def _h(self):
        return {'Authorization': f'Bearer {self.token}', 'X-Device-ID': DEVICE_ID}

    def do_login(self, username, password, callback):
        def run():
            try:
                r = requests.post(f"{BASE_URL}/login", json={
                    'username': username, 'password': password, 'device_id': DEVICE_ID
                }, timeout=6)
                data = safe_json(r)
                if r.status_code == 200:
                    self.token     = data['token']
                    self.user_info = data
                    self.after(0, self._show_dashboard)
                else:
                    msg = data.get('message', 'Login failed')
                    self.after(0, lambda m=msg: callback(False, m))
            except requests.exceptions.ConnectionError:
                self.after(0, lambda: callback(False, 'Cannot connect — is server_gui.py running?'))
            except Exception as e:
                self.after(0, lambda err=str(e): callback(False, err))
        threading.Thread(target=run, daemon=True).start()

    def do_logout(self):
        if self.token:
            try: requests.post(f"{BASE_URL}/logout", headers=self._h(), timeout=3)
            except: pass
        self.token, self.user_info = None, None
        self._show_login()

    def access_zone(self, endpoint, on_done):
        def run():
            try:
                r = requests.get(f"{BASE_URL}{endpoint}", headers=self._h(), timeout=6)
                data = safe_json(r)
                self.after(0, lambda: on_done(r.status_code, data))
            except Exception as e:
                self.after(0, lambda err=str(e): on_done(0, {'message': err}))
        threading.Thread(target=run, daemon=True).start()

    def verify(self, on_done):
        def run():
            try:
                r = requests.get(f"{BASE_URL}/verify", headers=self._h(), timeout=5)
                data = safe_json(r)
                self.after(0, lambda: on_done(r.status_code, data))
            except Exception as e:
                self.after(0, lambda err=str(e): on_done(0, {'message': err}))
        threading.Thread(target=run, daemon=True).start()

# ── REUSABLE WIDGETS ──────────────────────────────────────────────────────────
def label(parent, text, size=11, weight='normal', color=None, mono=False, **kw):
    font_family = 'Courier' if mono else 'Helvetica'
    lbl = tk.Label(parent, text=text,
                   font=(font_family, size, weight),
                   bg=kw.pop('bg', parent.cget('bg')),
                   fg=color or C['text'], **kw)
    return lbl

def frame(parent, bg=None, **kw):
    return tk.Frame(parent, bg=bg or C['surface'], **kw)

def hline(parent, color=None):
    return tk.Frame(parent, bg=color or C['border'], height=1)

# ── LOGIN FRAME ───────────────────────────────────────────────────────────────
class LoginFrame(tk.Frame):
    def __init__(self, app):
        super().__init__(app, bg=C['bg'])
        self.app = app
        self._build()

    def _build(self):
        card = frame(self, bg=C['surface'],
                     highlightbackground=C['border'], highlightthickness=1)
        card.place(relx=0.5, rely=0.5, anchor='center', width=420)

        tk.Frame(card, bg=C['green'], height=3).pack(fill='x')

        inner = frame(card, bg=C['surface'])
        inner.pack(fill='both', padx=40, pady=36)

        label(inner, '[shield]', size=32, color=C['green'], bg=C['surface'],
              mono=True).pack()
        label(inner, 'ZERO TRUST CLIENT', size=14, weight='bold',
              color=C['text'], bg=C['surface'], mono=True).pack(pady=(6, 2))
        label(inner, 'Authenticate to enter protected zones', size=9,
              color=C['muted'], bg=C['surface']).pack(pady=(0, 28))

        hline(inner).pack(fill='x', pady=(0, 24))

        self.u_var = tk.StringVar()
        self.p_var = tk.StringVar()
        self._field(inner, 'USERNAME', self.u_var)
        # FIX: use ASCII '*' for show — avoids multi-byte char parse errors on some platforms
        self._field(inner, 'PASSWORD', self.p_var, show='*')

        f = frame(inner, bg=C['surface'])
        f.pack(fill='x', pady=(4, 20))
        label(f, 'DEVICE ID', size=8, weight='bold', color=C['muted'],
              bg=C['surface'], mono=True).pack(anchor='w')
        tk.Label(f, text=DEVICE_ID, font=('Courier', 9), bg='#0d1829',
                 fg=C['muted'], padx=8, pady=6, anchor='w').pack(fill='x', pady=(3, 0))

        self.btn = tk.Button(inner, text='AUTHENTICATE  >',
                             font=('Helvetica', 11, 'bold'),
                             bg=C['green'], fg=C['bg'], relief='flat',
                             padx=0, pady=12, cursor='hand2',
                             activebackground='#00c489', activeforeground=C['bg'],
                             command=self._login)
        self.btn.pack(fill='x')

        self.status_var = tk.StringVar()
        tk.Label(inner, textvariable=self.status_var, font=('Helvetica', 9),
                 bg=C['surface'], fg=C['red'], wraplength=340,
                 justify='center').pack(pady=(10, 0))

        hline(inner).pack(fill='x', pady=(20, 12))
        hint = ('alice  bob  charlie  diana  eve  frank\n'
                'passwords: <name>_pass  |  server on localhost:5000')
        label(inner, hint, size=8, color=C['muted'], bg=C['surface'],
              justify='center').pack()

        self.bind_all('<Return>', lambda e: self._login())

    def _field(self, parent, label_text, var, show=None):
        f = frame(parent, bg=C['surface'])
        f.pack(fill='x', pady=5)
        tk.Label(f, text=label_text, font=('Courier', 9, 'bold'),
                 bg=C['surface'], fg=C['muted']).pack(anchor='w')
        e = tk.Entry(f, textvariable=var, font=('Helvetica', 12),
                     bg=C['surface2'], fg=C['text'], relief='flat',
                     insertbackground=C['green'],
                     show=show if show else '',
                     highlightbackground=C['border'], highlightthickness=1)
        e.pack(fill='x', ipady=8, pady=(3, 0))
        return e

    def _login(self):
        u, p = self.u_var.get().strip(), self.p_var.get()
        if not u or not p:
            self.status_var.set('Enter username and password')
            return
        self.btn.config(state='disabled', text='Connecting...')
        self.status_var.set('')
        def on_fail(ok, msg):
            self.status_var.set(f'x  {msg}')
            self.btn.config(state='normal', text='AUTHENTICATE  >')
        self.app.do_login(u, p, on_fail)

# ── DASHBOARD FRAME ───────────────────────────────────────────────────────────
class DashboardFrame(tk.Frame):
    def __init__(self, app):
        super().__init__(app, bg=C['bg'])
        self.app  = app
        self.info = app.user_info
        self._build()
        self._start_verify_loop()

    def _build(self):
        self._topbar()

        body = frame(self, bg=C['bg'])
        body.pack(fill='both', expand=True, padx=14, pady=(0, 14))

        self._zone_panel(body)
        self._data_panel(body)
        self._log_panel(body)

        self._statusbar()

    # ── TOP BAR ───────────────────────────────────────────────────────────────
    def _topbar(self):
        bar = frame(self, bg=C['surface'])
        bar.pack(fill='x')
        tk.Frame(bar, bg=C['green'], height=2).pack(fill='x')

        inner = frame(bar, bg=C['surface'])
        inner.pack(fill='x', padx=20, pady=10)

        left = frame(inner, bg=C['surface'])
        left.pack(side='left')
        label(left, '[shield]  Zero Trust Client', size=13, weight='bold',
              color=C['text'], bg=C['surface'], mono=True).pack(side='left')

        right = frame(inner, bg=C['surface'])
        right.pack(side='right')

        role  = self.info.get('role', '?')
        rc    = ROLE_COLORS.get(role, C['muted'])
        uname = self.info.get('username', '')
        dept  = self.info.get('department', '')

        label(right, f'[u] {uname}', size=10, weight='bold',
              color=C['text'], bg=C['surface']).pack(side='left')
        label(right, f'  [{role.upper()}]', size=10, weight='bold',
              color=rc, bg=C['surface']).pack(side='left')
        label(right, f'  {dept}', size=9, color=C['muted'],
              bg=C['surface']).pack(side='left', padx=(0, 20))

        self.risk_var = tk.StringVar(value='Risk --')
        label(right, '', size=9, color=C['muted'], bg=C['surface'],
              textvariable=self.risk_var).pack(side='left', padx=(0, 20))

        logout_btn = tk.Button(right, text='Logout', font=('Helvetica', 9, 'bold'),
                               bg=C['red'], fg='white', relief='flat',
                               padx=14, pady=5, cursor='hand2',
                               activebackground='#cc3355',
                               command=self.app.do_logout)
        logout_btn.pack(side='left')

    # ── ZONE PANEL (left) ─────────────────────────────────────────────────────
    def _zone_panel(self, parent):
        panel = frame(parent, bg=C['surface'],
                      highlightbackground=C['border'], highlightthickness=1)
        panel.pack(side='left', fill='y', padx=(0, 10), pady=10)

        hdr = frame(panel, bg=C['surface2'])
        hdr.pack(fill='x')
        label(hdr, 'ZONE ACCESS', size=10, weight='bold', color=C['green'],
              bg=C['surface2'], mono=True).pack(padx=14, pady=10, anchor='w')
        hline(panel).pack(fill='x')

        accessible = self.info.get('accessible_zones', {})

        for zone_id, zdata in ZONES.items():
            can = zone_id in accessible
            self._zone_btn(panel, zone_id, zdata, can)

        hline(panel).pack(fill='x', pady=(8, 0))
        leg = frame(panel, bg=C['surface'])
        leg.pack(fill='x', padx=12, pady=8)
        label(leg, 'o', size=9, color=C['green'], bg=C['surface']).pack(side='left')
        label(leg, ' Accessible', size=8, color=C['muted'], bg=C['surface']).pack(side='left', padx=(0,10))
        label(leg, 'o', size=9, color=C['red'], bg=C['surface']).pack(side='left')
        label(leg, ' Denied', size=8, color=C['muted'], bg=C['surface']).pack(side='left')

    def _zone_btn(self, parent, zone_id, zdata, can_access):
        color = zdata['color'] if can_access else C['muted']
        ind   = '[+]' if can_access else '[-]'

        f = frame(parent, bg=C['surface'])
        f.pack(fill='x', padx=8, pady=3)

        btn = tk.Button(
            f,
            text=f"{ind}  {zdata['icon']}  {zdata['name']}",
            font=('Courier', 9, 'bold' if can_access else 'normal'),
            bg=C['surface2'] if can_access else C['surface'],
            fg=color,
            relief='flat', anchor='w',
            padx=14, pady=8,
            cursor='hand2',
            activebackground=C['surface2'],
            activeforeground=color,
            command=lambda z=zone_id: self._try_zone(z),
            width=22,
        )
        btn.pack(fill='x')

        accent = tk.Frame(f, bg=color, width=3)
        accent.place(x=0, y=0, relheight=1)

    # ── DATA PANEL (center) ───────────────────────────────────────────────────
    def _data_panel(self, parent):
        panel = frame(parent, bg=C['surface'],
                      highlightbackground=C['border'], highlightthickness=1)
        panel.pack(side='left', fill='both', expand=True, pady=10, padx=(0, 10))

        hdr = frame(panel, bg=C['surface2'])
        hdr.pack(fill='x')
        label(hdr, 'ZONE DATA', size=10, weight='bold', color=C['text'],
              bg=C['surface2'], mono=True).pack(padx=14, pady=10, anchor='w')
        hline(panel).pack(fill='x')

        self.data_text = scrolledtext.ScrolledText(
            panel, font=('Courier', 11), bg=C['bg'], fg=C['text'],
            relief='flat', padx=18, pady=18, state='disabled', wrap='word',
            insertbackground=C['text'],
        )
        self.data_text.pack(fill='both', expand=True)
        self.data_text.tag_configure('header',  foreground=C['green'], font=('Courier', 12, 'bold'))
        self.data_text.tag_configure('label',   foreground=C['muted'])
        self.data_text.tag_configure('value',   foreground=C['cyan'])
        self.data_text.tag_configure('denied',  foreground=C['red'],   font=('Courier', 12, 'bold'))
        self.data_text.tag_configure('key',     foreground=C['amber'])

        self._write_data([
            ('header',  '  Select a zone from the left panel\n\n'),
            ('label',   '  [+]  Accessible zones will return live data\n'),
            ('label',   '  [-]  Denied zones show the rejection reason\n\n'),
            ('label',   '  Continuous verification runs every 30 seconds.\n'),
            ('label',   '  Risk scoring is re-evaluated on every request.\n'),
        ])

    def _write_data(self, segments):
        self.data_text.config(state='normal')
        self.data_text.delete('1.0', 'end')
        for tag, text in segments:
            self.data_text.insert('end', text, tag)
        self.data_text.config(state='disabled')

    # ── LOG PANEL (right) ─────────────────────────────────────────────────────
    def _log_panel(self, parent):
        panel = frame(parent, bg=C['surface'],
                      highlightbackground=C['border'], highlightthickness=1)
        panel.pack(side='right', fill='y', pady=10)
        panel.configure(width=280)
        panel.pack_propagate(False)

        hdr = frame(panel, bg=C['surface2'])
        hdr.pack(fill='x')
        label(hdr, 'ACTIVITY LOG', size=10, weight='bold', color=C['text'],
              bg=C['surface2'], mono=True).pack(padx=14, pady=10, anchor='w')
        hline(panel).pack(fill='x')

        self.log_text = scrolledtext.ScrolledText(
            panel, font=('Courier', 9), bg='#040810', fg=C['muted'],
            relief='flat', padx=8, pady=8, state='disabled', wrap='word',
        )
        self.log_text.pack(fill='both', expand=True)
        self.log_text.tag_configure('ts',   foreground='#2a3f5f')
        self.log_text.tag_configure('ok',   foreground=C['green'])
        self.log_text.tag_configure('fail', foreground=C['red'])
        self.log_text.tag_configure('info', foreground=C['cyan'])
        self.log_text.tag_configure('warn', foreground=C['amber'])
        self.log_text.tag_configure('dim',  foreground=C['muted'])

    # ── STATUS BAR ────────────────────────────────────────────────────────────
    def _statusbar(self):
        bar = frame(self, bg=C['surface2'])
        bar.pack(fill='x', side='bottom')

        label(bar, f'  Device: {DEVICE_ID[:28]}...', size=8, color=C['muted'],
              bg=C['surface2'], mono=True).pack(side='left', pady=5)

        self.verify_var = tk.StringVar(value='  o Initializing...')
        label(bar, '', size=8, color=C['green'], bg=C['surface2'],
              textvariable=self.verify_var, mono=True).pack(side='right', padx=12, pady=5)

    # ── ACTIONS ───────────────────────────────────────────────────────────────
    def _log(self, msg, tag='info'):
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        self.log_text.config(state='normal')
        self.log_text.insert('end', f'[{ts}] ', 'ts')
        self.log_text.insert('end', msg + '\n', tag)
        self.log_text.see('end')
        self.log_text.config(state='disabled')

    def _try_zone(self, zone_id):
        zdata = ZONES[zone_id]
        self._log(f'-> {zdata["name"]}', 'info')

        def on_done(status, data):
            if status == 200:
                risk = data.get('risk_score', '?')
                self._log(f'[OK] GRANTED  risk={risk}', 'ok')
                segs = [
                    ('header', f'  [OK]  {data["zone"]}\n\n'),
                    ('label',  f'  Accessed by:  '), ('value',  f'{data["accessed_by"]}\n'),
                    ('label',  f'  Risk Score:   '), ('value',  f'{risk}\n\n'),
                    ('label',  '  ' + '-'*38 + '\n\n'),
                ]
                for k, v in data.get('data', {}).items():
                    segs.append(('key',   f'  {k:<22}'))
                    segs.append(('value', f'{v}\n'))
                self._write_data(segs)
            else:
                msg  = data.get('message', 'Unknown error')
                risk = data.get('risk_score')
                thr  = data.get('threshold')
                self._log(f'[X] DENIED -- {msg}', 'fail')
                segs = [
                    ('denied', f'  [X]  ACCESS DENIED\n\n'),
                    ('label',  f'  Zone:    '), ('value', f'{zdata["name"]}\n'),
                    ('label',  f'  Reason:  '), ('fail',  f'{msg}\n'),
                ]
                if risk is not None:
                    segs += [
                        ('label', f'  Risk:    '), ('warn', f'{risk}  (threshold {thr})\n'),
                    ]
                segs += [('label', f'\n  HTTP {status}')]
                self._write_data(segs)

        self.app.access_zone(zdata['endpoint'], on_done)

    def _start_verify_loop(self):
        self._log('Session active. Verification every 30s.', 'info')

        def loop():
            while self.app.running and self.app.token:
                time.sleep(30)
                if not self.app.running or not self.app.token:
                    break

                def on_verify(status, data):
                    if not self.app.token:
                        return
                    if status == 200:
                        risk = data.get('risk_score', '?')
                        ts   = datetime.datetime.now().strftime('%H:%M:%S')
                        self.risk_var.set(f'Risk {risk}')
                        self.verify_var.set(f'  o Verified {ts}')
                        self._log(f'[~] Session verified  risk={risk}', 'info')
                    else:
                        self.verify_var.set('  ! Verification failed')
                        self._log('[!] Session verification failed!', 'fail')

                self.app.verify(on_verify)

        threading.Thread(target=loop, daemon=True).start()
        self.verify_var.set(f'  o Active since {datetime.datetime.now().strftime("%H:%M:%S")}')

# ── ENTRY POINT ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    app = App()
    app.mainloop()