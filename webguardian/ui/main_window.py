import customtkinter as ctk
import threading
import os
import time
from datetime import timedelta
from ..scanner import Scanner

THREAT = {
    'critical': {'fg': '#ef4444', 'bg': '#2d0a0a', 'icon': '!'},
    'high':     {'fg': '#f59e0b', 'bg': '#2d1f00', 'icon': '▲'},
    'medium':   {'fg': '#3b82f6', 'bg': '#001a3d', 'icon': '●'},
    'low':      {'fg': '#6b7280', 'bg': '#1a1f2e', 'icon': '○'},
    'info':     {'fg': '#4b5563', 'bg': '#1a1f2e', 'icon': '·'},
}
THREAT_LIGHT = {
    'critical': {'fg': '#dc2626', 'bg': '#fef2f2', 'icon': '!'},
    'high':     {'fg': '#d97706', 'bg': '#fffbeb', 'icon': '▲'},
    'medium':   {'fg': '#2563eb', 'bg': '#eff6ff', 'icon': '●'},
    'low':      {'fg': '#6b7280', 'bg': '#f9fafb', 'icon': '○'},
    'info':     {'fg': '#9ca3af', 'bg': '#f9fafb', 'icon': '·'},
}


class ThreatCard(ctk.CTkScrollableFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color='transparent')
        self.grid_columnconfigure(0, weight=1)
        self._items = []

    def clear(self):
        for w in self._items:
            w.destroy()
        self._items.clear()

    def load(self, findings):
        self.clear()
        order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        findings.sort(key=lambda f: (order.get(f['severity'], 4), f.get('file', '')))

        if not findings:
            lbl = ctk.CTkLabel(self, text='✓  No threats detected',
                                font=ctk.CTkFont(size=13))
            lbl.grid(row=0, column=0, pady=50)
            self._items.append(lbl)
            return

        for i, f in enumerate(findings):
            self._items.append(self._build(i, f))

    def _palette(self, sev):
        dark = ctk.get_appearance_mode() == 'Dark'
        p = THREAT if dark else THREAT_LIGHT
        return p.get(sev, p['info'])

    def _build(self, idx, f):
        sev = f.get('severity', 'info')
        pal = self._palette(sev)

        card = ctk.CTkFrame(self, fg_color=pal['bg'], corner_radius=4)
        card.grid(row=idx, column=0, sticky='ew', pady=(0, 2))
        card.grid_columnconfigure(2, weight=1)

        icon_lbl = ctk.CTkLabel(card, text=f' {pal["icon"]} ',
                                 font=ctk.CTkFont(size=13, weight='bold'),
                                 text_color=pal['fg'])
        icon_lbl.grid(row=0, column=0, rowspan=2, padx=(8, 2), pady=6)

        badge = ctk.CTkLabel(card, text=sev.upper(),
                              font=ctk.CTkFont(size=9, weight='bold'),
                              text_color=pal['fg'])
        badge.grid(row=0, column=1, sticky='nw', padx=(0, 6), pady=(6, 0))

        msg = ctk.CTkLabel(card, text=f['message'], font=ctk.CTkFont(size=12),
                            wraplength=660, justify='left', anchor='w')
        msg.grid(row=0, column=2, sticky='ew', padx=(0, 10), pady=(6, 1))

        if f.get('file'):
            loc = f['file']
            if f.get('line'):
                loc += f'  :{f["line"]}'
            flbl = ctk.CTkLabel(card, text=loc, font=ctk.CTkFont(size=9, family='Consolas'),
                                 anchor='w')
            flbl.grid(row=1, column=1, columnspan=2, sticky='ew', padx=(0, 10), pady=(0, 6))

        return card


class MainWindow(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color='transparent')
        self.parent = parent
        self.scanner = None
        self._thread = None
        self._running = False
        self._t0 = 0.0

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        self._header()
        self._scan_bar()
        self._progress_area()
        self._results()

        self._show_scan_ui(False)

    # ─── Header ────────────────────────────────────────────

    def _header(self):
        h = ctk.CTkFrame(self, fg_color='transparent', height=44)
        h.grid(row=0, column=0, sticky='ew', padx=24, pady=(14, 0))
        h.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(h, text='🛡️', font=ctk.CTkFont(size=22)).grid(row=0, column=0, padx=(0, 6))
        ctk.CTkLabel(h, text='WebGuardian', font=ctk.CTkFont(size=17, weight='bold')).grid(row=0, column=1)

        self._badge = ctk.CTkLabel(h, text='  ●  Ready  ',
                                    font=ctk.CTkFont(size=10, weight='bold'),
                                    corner_radius=8)
        self._badge.grid(row=0, column=2, sticky='e')

        self._theme_btn = ctk.CTkButton(h, text='☀', width=32, height=26,
                                         font=ctk.CTkFont(size=13), command=self._toggle_theme)
        self._theme_btn.grid(row=0, column=3, padx=(6, 0))
        self._sync_theme_btn()

    def _toggle_theme(self):
        m = 'Light' if ctk.get_appearance_mode() == 'Dark' else 'Dark'
        ctk.set_appearance_mode(m)
        self._sync_theme_btn()

    def _sync_theme_btn(self):
        self._theme_btn.configure(text='☾' if ctk.get_appearance_mode() == 'Dark' else '☀')

    # ─── Scan Bar ──────────────────────────────────────────

    def _scan_bar(self):
        bar = ctk.CTkFrame(self, corner_radius=6)
        bar.grid(row=1, column=0, sticky='ew', padx=24, pady=(12, 6))
        bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(bar, text='Location', font=ctk.CTkFont(size=11)).grid(row=0, column=0, padx=(12, 4), pady=10)

        self._path_var = ctk.StringVar()
        ctk.CTkEntry(bar, textvariable=self._path_var,
                      placeholder_text='C:\\xampp\\htdocs\\project  |  /var/www/project',
                      font=ctk.CTkFont(size=12)).grid(row=0, column=1, sticky='ew', padx=4, pady=10)

        ctk.CTkButton(bar, text='Browse', width=68, font=ctk.CTkFont(size=11),
                       command=self._browse).grid(row=0, column=2, padx=(2, 6), pady=10)

        self._go_btn = ctk.CTkButton(bar, text='▶  Scan Now', width=110, height=32,
                                       font=ctk.CTkFont(size=12, weight='bold'),
                                       command=self._start)
        self._go_btn.grid(row=0, column=3, padx=(0, 10), pady=10)

        ctk.CTkCheckBox(bar, text='Check permissions', variable=ctk.BooleanVar(value=True),
                         font=ctk.CTkFont(size=11)).grid(row=0, column=4, padx=(0, 10), pady=10)

    # ─── Progress Area ─────────────────────────────────────

    def _progress_area(self):
        self._prog = ctk.CTkFrame(self, corner_radius=6)

        # Progress bar
        self._pbar = ctk.CTkProgressBar(self._prog, height=5, corner_radius=2)
        self._pbar.grid(row=0, column=0, columnspan=4, sticky='ew', padx=16, pady=(14, 4))
        self._pbar.set(0)

        # Stats cards
        row = ctk.CTkFrame(self._prog, fg_color='transparent')
        row.grid(row=1, column=0, columnspan=4, sticky='ew', padx=16, pady=(0, 6))
        row.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self._stats = {}
        for i, (k, c) in enumerate([('Files', '#3b82f6'), ('Threats', '#ef4444'),
                                      ('Skipped', '#6b7280'), ('Time', '#6b7280')]):
            f = ctk.CTkFrame(row, corner_radius=4, height=56)
            f.grid(row=0, column=i, sticky='ew', padx=2)
            f.grid_propagate(False)
            lbl = ctk.CTkLabel(f, text='0', font=ctk.CTkFont(size=22, weight='bold'), text_color=c)
            lbl.pack(expand=True, pady=(2, 0))
            ctk.CTkLabel(f, text=k, font=ctk.CTkFont(size=9)).pack()
            self._stats[k] = lbl

        # Phase
        self._phase_lbl = ctk.CTkLabel(self._prog, text='Preparing…',
                                        font=ctk.CTkFont(size=11))
        self._phase_lbl.grid(row=2, column=0, columnspan=4, sticky='w', padx=18, pady=(0, 2))

        # Current file – prominent display
        file_frame = ctk.CTkFrame(self._prog, corner_radius=4)
        file_frame.grid(row=3, column=0, columnspan=4, sticky='ew', padx=16, pady=(0, 12))
        file_frame.grid_columnconfigure(1, weight=1)
        file_frame.grid_rowconfigure(0, weight=1)

        self._file_icon = ctk.CTkLabel(file_frame, text='📄', font=ctk.CTkFont(size=14))
        self._file_icon.grid(row=0, column=0, padx=(10, 4), pady=8)

        self._file_lbl = ctk.CTkLabel(file_frame, text='',
                                       font=ctk.CTkFont(size=11, family='Consolas'),
                                       anchor='w')
        self._file_lbl.grid(row=0, column=1, sticky='ew', padx=(0, 10), pady=8)

    # ─── Results ───────────────────────────────────────────

    def _results(self):
        self._tabs = ctk.CTkTabview(self, corner_radius=6)
        self._tabs.grid(row=4, column=0, sticky='nsew', padx=24, pady=(8, 16))

        self._summary_frame = ctk.CTkScrollableFrame(self._tabs.add('Summary'), fg_color='transparent')
        self._summary_frame.grid_columnconfigure(0, weight=1)

        th_tab = self._tabs.add('Threats')
        th_tab.grid_columnconfigure(0, weight=1)
        self._threats = ThreatCard(th_tab)
        self._threats.grid(row=0, column=0, sticky='nsew')

    # ─── Summary ───────────────────────────────────────────

    def _render_summary(self, results):
        for w in self._summary_frame.winfo_children():
            w.destroy()

        stats = results.get('stats', {})
        summary = results.get('summary', {})
        total = summary.get('total', 0)
        elapsed = stats.get('elapsed_ms', 0)
        files = stats.get('files_scanned', 0)

        bar_frame = ctk.CTkFrame(self._summary_frame, fg_color='transparent')
        bar_frame.grid(row=0, column=0, sticky='ew', pady=(10, 0))
        bar_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(bar_frame, text='Threat Summary',
                      font=ctk.CTkFont(size=13, weight='bold')).pack(anchor='w', pady=(0, 6))

        if total > 0:
            bar = ctk.CTkFrame(bar_frame, height=24, corner_radius=3)
            bar.pack(fill='x')
            bar.pack_propagate(False)

            segs = [(summary.get(s, 0), s) for s in ('critical', 'high', 'medium', 'low', 'info') if summary.get(s, 0)]
            t = sum(s[0] for s in segs)
            for cnt, sev in segs:
                pct = cnt / t
                if pct > 0.01:
                    is_dark = ctk.get_appearance_mode() == 'Dark'
                    p = THREAT if is_dark else THREAT_LIGHT
                    color = p[sev]['fg']
                    seg = ctk.CTkFrame(bar, fg_color=color, corner_radius=0, height=24)
                    seg.pack(side='left', fill='both', expand=True)
                    ctk.CTkLabel(seg, text=str(cnt), font=ctk.CTkFont(size=9, weight='bold'),
                                  text_color='#ffffff').pack(expand=True)

            leg = ctk.CTkFrame(bar_frame, fg_color='transparent')
            leg.pack(fill='x', pady=(4, 0))
            for sev in ('critical', 'high', 'medium', 'low', 'info'):
                cnt = summary.get(sev, 0)
                if cnt:
                    is_dark = ctk.get_appearance_mode() == 'Dark'
                    p = THREAT if is_dark else THREAT_LIGHT
                    ctk.CTkLabel(leg, text=f'{p["icon"]}  {sev.title()}: {cnt}',
                                  font=ctk.CTkFont(size=11), text_color=p['fg']).pack(side='left', padx=(0, 14))
        else:
            ctk.CTkLabel(bar_frame, text='✓  Clean  —  no threats detected',
                          font=ctk.CTkFont(size=13)).pack(anchor='w', pady=8)

        meta = ctk.CTkFrame(self._summary_frame, fg_color='transparent')
        meta.grid(row=1, column=0, sticky='ew', pady=(14, 0))
        ctk.CTkLabel(meta, text='Scan Details', font=ctk.CTkFont(size=13, weight='bold')).pack(anchor='w')

        details = [
            ('Files scanned', str(files)),
            ('Files skipped', str(stats.get('files_skipped', 0))),
            ('Duration', f'{elapsed // 1000}s'),
            ('CMS type', results.get('cms_type', '—').title()),
            ('Path', results.get('scanned_path', '')),
        ]
        for label, value in details:
            r = ctk.CTkFrame(meta, fg_color='transparent')
            r.pack(fill='x', pady=1)
            ctk.CTkLabel(r, text=label, font=ctk.CTkFont(size=11), width=110, anchor='w').pack(side='left')
            ctk.CTkLabel(r, text=value, font=ctk.CTkFont(size=11, family='Consolas' if label == 'Path' else 'default'),
                          anchor='w').pack(side='left', fill='x', expand=True)

    # ─── Actions ───────────────────────────────────────────

    def _browse(self):
        p = ctk.filedialog.askdirectory(title='Select directory')
        if p:
            self._path_var.set(p)

    def _show_scan_ui(self, active):
        if active:
            self._prog.grid(row=2, column=0, sticky='ew', padx=24, pady=(0, 4))
        else:
            self._prog.grid_remove()

    def _stat(self, key, val, color=None):
        if key in self._stats:
            self._stats[key].configure(text=str(val))
            if color:
                self._stats[key].configure(text_color=color)

    def _start(self):
        path = self._path_var.get().strip()
        if not path or not os.path.isdir(path):
            return

        self._running = True
        self._go_btn.configure(state='disabled', text='Scanning…')
        self._badge.configure(text='  ●  Scanning  ')
        self._show_scan_ui(True)
        self._pbar.configure(mode='indeterminate')
        self._pbar.start()
        self._phase_lbl.configure(text='Preparing…')
        self._file_lbl.configure(text='')
        self._file_icon.configure(text='⚙')

        for k in ('Files', 'Threats', 'Skipped'):
            self._stat(k, '0', '#3b82f6' if k == 'Files' else '#ef4444' if k == 'Threats' else '#6b7280')
        self._stat('Time', '0s')
        self._threats.clear()
        self._tabs.set('Summary')

        self.scanner = Scanner(path, progress_callback=self._on_progress)
        self._t0 = time.time()
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()
        self.after(250, self._tick)

    def _worker(self):
        try:
            r = self.scanner.run()
            self.after(0, lambda: self._done(r))
        except Exception as e:
            self.after(0, lambda: self._fail(str(e)))
        finally:
            self._running = False

    def _tick(self):
        if self._running:
            s = int(time.time() - self._t0)
            self._stat('Time', f'{s}s' if s < 60 else str(timedelta(seconds=s)).lstrip('0').lstrip(':'))
            self.after(250, self._tick)

    def _on_progress(self, data):
        def upd():
            self._phase_lbl.configure(text=data.get('phase', '').replace('_', ' ').title())
            self._stat('Files', data.get('files_scanned', 0))
            self._stat('Threats', data.get('findings_count', 0))
            self._stat('Skipped', data.get('files_skipped', 0))

            f = data.get('current_file', '')
            if f:
                self._file_lbl.configure(text=f)
                self._file_icon.configure(text='📄')
        self.after(0, upd)

    def _done(self, results):
        self._pbar.stop()
        self._pbar.configure(mode='determinate')
        self._pbar.set(1)
        self._go_btn.configure(state='normal', text='▶  Scan Now')
        self._badge.configure(text='  ●  Complete  ')
        self._phase_lbl.configure(text='Scan completed')
        self._file_lbl.configure(text='')
        self._file_icon.configure(text='✅')

        t = results.get('summary', {}).get('total', 0)
        self._stat('Threats', t, '#ef4444' if t > 0 else '#16a34a')
        self._stat('Time', f'{results["stats"]["elapsed_ms"] // 1000}s')

        self._render_summary(results)
        self._threats.load(results.get('findings', []))
        self._tabs.set('Summary')

    def _fail(self, err):
        self._pbar.stop()
        self._pbar.configure(mode='determinate')
        self._pbar.set(0)
        self._go_btn.configure(state='normal', text='▶  Scan Now')
        self._badge.configure(text='  ●  Error  ')
        self._phase_lbl.configure(text='Scan failed')
        self._file_lbl.configure(text=err)
        self._file_icon.configure(text='❌')
