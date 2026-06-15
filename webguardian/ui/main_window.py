import customtkinter as ctk
import threading
import os
import time
from datetime import timedelta
from ..scanner import Scanner

SEVERITY = {
    'critical': {'color': ['#dc2626', '#ef4444'], 'bg': ['#fef2f2', '#2d0a0a'], 'icon': '!'},
    'high':     {'color': ['#d97706', '#f59e0b'], 'bg': ['#fffbeb', '#2d1f00'], 'icon': '▲'},
    'medium':   {'color': ['#2563eb', '#60a5fa'], 'bg': ['#eff6ff', '#001a3d'], 'icon': '●'},
    'low':      {'color': ['#6b7280', '#9ca3af'], 'bg': ['#f9fafb', '#1a1d23'], 'icon': '○'},
    'info':     {'color': ['#9ca3af', '#6b7280'], 'bg': ['#f9fafb', '#1a1d23'], 'icon': '·'},
}


class FindingsList(ctk.CTkScrollableFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color='transparent')
        self.grid_columnconfigure(0, weight=1)
        self._cards = []

    def clear(self):
        for c in self._cards:
            c.destroy()
        self._cards.clear()

    def load(self, findings):
        self.clear()
        order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        findings.sort(key=lambda f: (order.get(f['severity'], 4), f.get('file', '')))

        if not findings:
            lbl = ctk.CTkLabel(self, text='✓  No issues found', font=ctk.CTkFont(size=13))
            lbl.grid(row=0, column=0, pady=40)
            self._cards.append(lbl)
            return

        for i, f in enumerate(findings):
            self._cards.append(self._card(i, f))

    def _card(self, idx, f):
        sev = f.get('severity', 'info')
        s = SEVERITY.get(sev, SEVERITY['info'])
        is_dark = ctk.get_appearance_mode() == 'Dark'
        color = s['color'][1] if is_dark else s['color'][0]
        bg = s['bg'][1] if is_dark else s['bg'][0]

        card = ctk.CTkFrame(self, fg_color=bg, corner_radius=4)
        card.grid(row=idx, column=0, sticky='ew', pady=(0, 3), padx=0)
        card.grid_columnconfigure(1, weight=1)

        badge = ctk.CTkLabel(card, text=f' {s["icon"]} {sev.upper()} ',
                              font=ctk.CTkFont(size=10, weight='bold'),
                              text_color=color)
        badge.grid(row=0, column=0, sticky='nw', padx=(10, 4), pady=7)

        msg = ctk.CTkLabel(card, text=f['message'], font=ctk.CTkFont(size=12),
                            wraplength=680, justify='left', anchor='w')
        msg.grid(row=0, column=1, sticky='ew', padx=(0, 10), pady=(7, 2))

        if f.get('file'):
            loc = f['file']
            if f.get('line'):
                loc += f' :{f["line"]}'
            flbl = ctk.CTkLabel(card, text=loc, font=ctk.CTkFont(size=10, family='Consolas'),
                                 anchor='w')
            flbl.grid(row=1, column=1, sticky='ew', padx=(0, 10), pady=(0, 7))

        return card

    def refresh_colors(self):
        self.load([])


class SummaryPane(ctk.CTkScrollableFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color='transparent')
        self.grid_columnconfigure(0, weight=1)
        self._current = None

    def display(self, results):
        self._current = results
        for w in self.winfo_children():
            w.destroy()

        stats = results.get('stats', {})
        summary = results.get('summary', {})
        total = summary.get('total', 0)
        elapsed = stats.get('elapsed_ms', 0)
        files = stats.get('files_scanned', 0)

        # Metric cards row
        row = ctk.CTkFrame(self, fg_color='transparent')
        row.grid(row=0, column=0, sticky='ew', pady=(8, 12))
        row.grid_columnconfigure((0, 1, 2, 3), weight=1)

        metrics = [
            ('Files Scanned', str(files), '#2563eb'),
            ('Findings', str(total), '#dc2626' if total > 0 else '#16a34a'),
            ('Duration', f'{elapsed // 1000}s', '#6b7280'),
            ('CMS', results.get('cms_type', '—').title(), '#6b7280'),
        ]
        for i, (label, value, color) in enumerate(metrics):
            c = ctk.CTkFrame(row, corner_radius=4)
            c.grid(row=0, column=i, sticky='nsew', padx=3, ipady=8)
            ctk.CTkLabel(c, text=value, font=ctk.CTkFont(size=22, weight='bold'),
                          text_color=color).pack(pady=(6, 0))
            ctk.CTkLabel(c, text=label, font=ctk.CTkFont(size=10)).pack(pady=(0, 4))

        # Severity bar
        if total > 0:
            bar_frame = ctk.CTkFrame(self, fg_color='transparent')
            bar_frame.grid(row=1, column=0, sticky='ew', pady=(0, 10))

            bar = ctk.CTkFrame(bar_frame, height=22, corner_radius=2)
            bar.pack(fill='x')
            bar.pack_propagate(False)

            segments = [(summary.get(s, 0), s) for s in ('critical', 'high', 'medium', 'low', 'info') if summary.get(s, 0)]
            total_cnt = sum(s[0] for s in segments)

            for cnt, sev in segments:
                pct = cnt / total_cnt
                if pct > 0.01:
                    s = SEVERITY[sev]
                    is_dark = ctk.get_appearance_mode() == 'Dark'
                    color = s['color'][1] if is_dark else s['color'][0]
                    f = ctk.CTkFrame(bar, fg_color=color, corner_radius=0, height=22)
                    f.pack(side='left', fill='both', expand=True)
                    ctk.CTkLabel(f, text=str(cnt), font=ctk.CTkFont(size=9, weight='bold'),
                                  text_color='#ffffff').pack(expand=True)

            legend = ctk.CTkFrame(bar_frame, fg_color='transparent')
            legend.pack(fill='x', pady=(4, 0))
            for sev in ('critical', 'high', 'medium', 'low', 'info'):
                cnt = summary.get(sev, 0)
                if cnt:
                    s = SEVERITY[sev]
                    is_dark = ctk.get_appearance_mode() == 'Dark'
                    ctk.CTkLabel(legend, text=f'{s["icon"]}  {sev.title()}: {cnt}',
                                  font=ctk.CTkFont(size=11),
                                  text_color=s['color'][1] if is_dark else s['color'][0]).pack(side='left', padx=(0, 14))

        # Path
        path_frame = ctk.CTkFrame(self, fg_color='transparent')
        path_frame.grid(row=2, column=0, sticky='ew', pady=(6, 0))
        ctk.CTkLabel(path_frame, text='Path:', font=ctk.CTkFont(size=10)).pack(anchor='w')
        ctk.CTkLabel(path_frame, text=results.get('scanned_path', ''),
                      font=ctk.CTkFont(size=10, family='Consolas')).pack(anchor='w', fill='x')


class MainWindow(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color='transparent')
        self.parent = parent
        self.scanner = None
        self.thread = None
        self.running = False
        self.start_time = 0.0

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._header()
        self._toolbar()
        self._main()

    def _header(self):
        h = ctk.CTkFrame(self, fg_color='transparent', height=44)
        h.grid(row=0, column=0, sticky='ew', padx=20, pady=(14, 4))
        h.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(h, text='WebGuardian', font=ctk.CTkFont(size=18, weight='bold')).grid(row=0, column=0)
        ctk.CTkLabel(h, text='Security Scanner', font=ctk.CTkFont(size=11)).grid(row=0, column=1, padx=(4, 0))

        self.badge = ctk.CTkLabel(h, text='  ●  Ready  ', font=ctk.CTkFont(size=10, weight='bold'),
                                   corner_radius=8)
        self.badge.grid(row=0, column=2, sticky='e')

        self.theme_btn = ctk.CTkButton(h, text='☀', width=36, height=28,
                                        font=ctk.CTkFont(size=14), command=self._toggle_theme)
        self.theme_btn.grid(row=0, column=3, padx=(8, 0))
        self._update_theme_btn()

    def _toolbar(self):
        t = ctk.CTkFrame(self, corner_radius=4)
        t.grid(row=1, column=0, sticky='ew', padx=20, pady=(4, 10))
        t.grid_columnconfigure(1, weight=1)

        self.path_var = ctk.StringVar()
        entry = ctk.CTkEntry(t, textvariable=self.path_var,
                              placeholder_text='C:\\project  or  /var/www/project',
                              font=ctk.CTkFont(size=12))
        entry.grid(row=0, column=0, columnspan=2, sticky='ew', padx=10, pady=10)

        browse_btn = ctk.CTkButton(t, text='Browse', width=72,
                                    font=ctk.CTkFont(size=11), command=self._browse)
        browse_btn.grid(row=0, column=2, padx=(0, 6), pady=10)

        self.go_btn = ctk.CTkButton(t, text='Scan', width=90, height=32,
                                     font=ctk.CTkFont(size=12, weight='bold'),
                                     command=self._start)
        self.go_btn.grid(row=0, column=3, padx=(0, 10), pady=10)

        self.perm_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(t, text='Permissions', variable=self.perm_var,
                         font=ctk.CTkFont(size=11)).grid(row=0, column=4, padx=(0, 10), pady=10)

    def _main(self):
        self.prog = ctk.CTkFrame(self, corner_radius=4)
        self.prog.grid(row=2, column=0, sticky='nsew', padx=20, pady=(0, 14))
        self.prog.grid_columnconfigure(0, weight=1)
        self.prog.grid_rowconfigure(3, weight=1)

        # Progress bar + stats row
        self.pbar = ctk.CTkProgressBar(self.prog, height=4, corner_radius=2)
        self.pbar.grid(row=0, column=0, sticky='ew', padx=14, pady=(12, 2))
        self.pbar.set(0)

        stats = ctk.CTkFrame(self.prog, fg_color='transparent')
        stats.grid(row=1, column=0, sticky='ew', padx=14, pady=(2, 4))
        stats.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self._stat_labels = {}
        for i, (k, v, c) in enumerate([('Files', '0', None), ('Findings', '0', None),
                                         ('Skipped', '0', None), ('Time', '0s', None)]):
            f = ctk.CTkFrame(stats, corner_radius=3, height=48)
            f.grid(row=0, column=i, sticky='ew', padx=2)
            f.grid_propagate(False)
            lbl = ctk.CTkLabel(f, text=v, font=ctk.CTkFont(size=16, weight='bold'), anchor='center')
            lbl.pack(expand=True, pady=(2, 0))
            ctk.CTkLabel(f, text=k, font=ctk.CTkFont(size=9), anchor='center').pack()
            self._stat_labels[k] = lbl

        self.phase_lbl = ctk.CTkLabel(self.prog, text='', font=ctk.CTkFont(size=11))
        self.phase_lbl.grid(row=2, column=0, sticky='w', padx=14, pady=(0, 6))

        self.prog.grid_remove()

        # Tab view
        self.tabs = ctk.CTkTabview(self.prog, corner_radius=4)
        self.tabs.grid(row=3, column=0, sticky='nsew', pady=(0, 2))

        self.summary = SummaryPane(self.tabs.add('Summary'))
        self.summary.grid(row=0, column=0, sticky='nsew')

        self.findings = FindingsList(self.tabs.add('Findings'))
        self.findings.grid(row=0, column=0, sticky='nsew')

    def _toggle_theme(self):
        mode = 'Light' if ctk.get_appearance_mode() == 'Dark' else 'Dark'
        ctk.set_appearance_mode(mode)
        self._update_theme_btn()
        self.findings.refresh_colors()

    def _update_theme_btn(self):
        is_dark = ctk.get_appearance_mode() == 'Dark'
        self.theme_btn.configure(text='☾' if is_dark else '☀')

    def _browse(self):
        p = ctk.filedialog.askdirectory(title='Select Directory')
        if p:
            self.path_var.set(p)

    def _stat(self, key, val, color=None):
        if key in self._stat_labels:
            self._stat_labels[key].configure(text=str(val))
            if color:
                self._stat_labels[key].configure(text_color=color)

    def _start(self):
        path = self.path_var.get().strip()
        if not path:
            return
        if not os.path.isdir(path):
            return

        self.running = True
        self.go_btn.configure(state='disabled', text='Scanning…')
        self.prog.grid()
        self.pbar.configure(mode='indeterminate')
        self.pbar.start()
        self.badge.configure(text='  ●  Scanning  ')

        for k in ('Files', 'Findings', 'Skipped'):
            self._stat(k, '0')
        self._stat('Time', '0s')
        self.phase_lbl.configure(text='Initialising…')
        self.findings.clear()
        self.tabs.set('Summary')

        self.scanner = Scanner(path, progress_callback=self._on_progress)
        self.start_time = time.time()
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()
        self.after(250, self._tick)

    def _worker(self):
        try:
            r = self.scanner.run()
            self.after(0, lambda: self._done(r))
        except Exception as e:
            self.after(0, lambda: self._fail(str(e)))
        finally:
            self.running = False

    def _tick(self):
        if self.running:
            s = int(time.time() - self.start_time)
            self._stat('Time', f'{s}s' if s < 60 else str(timedelta(seconds=s)).lstrip('0').lstrip(':'))
            self.after(250, self._tick)

    def _on_progress(self, data):
        def upd():
            self.phase_lbl.configure(text=data.get('phase', '').replace('_', ' ').title())
            self._stat('Files', data.get('files_scanned', 0))
            self._stat('Findings', data.get('findings_count', 0))
            self._stat('Skipped', data.get('files_skipped', 0))
        self.after(0, upd)

    def _done(self, results):
        self.pbar.stop()
        self.pbar.configure(mode='determinate')
        self.pbar.set(1)
        self.go_btn.configure(state='normal', text='Scan')
        self.badge.configure(text='  ●  Complete  ')
        self.phase_lbl.configure(text='Scan Complete')

        t = results.get('summary', {}).get('total', 0)
        self._stat('Findings', t, '#dc2626' if t > 0 else '#16a34a')
        self._stat('Time', f'{results["stats"]["elapsed_ms"] // 1000}s')

        self.summary.display(results)
        self.findings.load(results.get('findings', []))
        self.tabs.set('Summary')

    def _fail(self, err):
        self.pbar.stop()
        self.pbar.configure(mode='determinate')
        self.pbar.set(0)
        self.go_btn.configure(state='normal', text='Scan')
        self.badge.configure(text='  ●  Error  ')
        self.phase_lbl.configure(text=f'Error: {err}')
