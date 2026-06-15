import customtkinter as ctk
import threading
import os
import time
from datetime import timedelta
from ..scanner import Scanner

SEVERITY_COLORS = {
    'critical': '#f85149',
    'high': '#d29922',
    'medium': '#58a6ff',
    'low': '#8b949e',
    'info': '#6e7681',
}
SEVERITY_BG = {
    'critical': '#490202',
    'high': '#3d2e00',
    'medium': '#002d4a',
    'low': '#161b22',
    'info': '#161b22',
}
SEVERITY_ICON = {
    'critical': '⬡',
    'high': '▲',
    'medium': '◆',
    'low': '○',
    'info': '·',
}


class FindingsTab(ctk.CTkScrollableFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color='transparent')
        self.grid_columnconfigure(0, weight=1)
        self.findings = []
        self.widgets = []

    def clear(self):
        for w in self.widgets:
            w.destroy()
        self.widgets.clear()
        self.findings.clear()

    def display(self, findings):
        self.clear()
        self.findings = findings
        sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        findings.sort(key=lambda f: (sev_order.get(f['severity'], 4), f.get('file', '')))

        if not findings:
            lbl = ctk.CTkLabel(self, text='✓  No issues found — your project looks clean.',
                                font=ctk.CTkFont(size=13), text_color='#7ee787')
            lbl.grid(row=0, column=0, pady=40, sticky='n')
            self.widgets.append(lbl)
            return

        for i, f in enumerate(findings):
            self.widgets.append(self._build_card(i, f))

    def _build_card(self, idx, f):
        sev = f.get('severity', 'info')
        color = SEVERITY_COLORS.get(sev, '#8b949e')
        bg = SEVERITY_BG.get(sev, '#161b22')
        icon = SEVERITY_ICON.get(sev, '·')

        card = ctk.CTkFrame(self, fg_color=bg, corner_radius=6)
        card.grid_columnconfigure(1, weight=1)
        card.grid(row=idx, column=0, sticky='ew', pady=(0, 4), padx=2)

        badge = ctk.CTkLabel(card, text=f' {icon} {sev.upper()} ', font=ctk.CTkFont(size=10, weight='bold'),
                              text_color=color, fg_color=bg, corner_radius=3)
        badge.grid(row=0, column=0, sticky='nw', padx=(10, 6), pady=8)

        msg = ctk.CTkLabel(card, text=f['message'], font=ctk.CTkFont(size=12),
                            text_color='#e6edf3', wraplength=700, justify='left', anchor='w')
        msg.grid(row=0, column=1, sticky='ew', padx=(0, 10), pady=(8, 2))

        if f.get('file'):
            loc = f['file']
            if f.get('line'):
                loc += f' :{f["line"]}'
            flbl = ctk.CTkLabel(card, text=loc, font=ctk.CTkFont(size=11, family='Consolas'),
                                 text_color='#8b949e', anchor='w')
            flbl.grid(row=1, column=1, sticky='ew', padx=(0, 10), pady=(0, 8))

        return card


class SummaryTab(ctk.CTkScrollableFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color='transparent')
        self.grid_columnconfigure(0, weight=1)

    def display(self, results):
        for w in self.winfo_children():
            w.destroy()

        stats = results.get('stats', {})
        summary = results.get('summary', {})
        cms = results.get('cms_type', 'unknown')
        path = results.get('scanned_path', '')
        total = summary.get('total', 0)
        elapsed = stats.get('elapsed_ms', 0)

        # Stats grid
        grid = ctk.CTkFrame(self, fg_color='transparent')
        grid.grid(row=0, column=0, sticky='ew', pady=(10, 5))
        for i in range(6):
            grid.grid_columnconfigure(i, weight=1)

        metrics = [
            ('Files Scanned', str(stats.get('files_scanned', 0)), '#58a6ff'),
            ('Findings', str(total), '#f85149' if total > 0 else '#7ee787'),
            ('CMS Type', cms.title(), '#e6edf3'),
            ('Duration', f'{elapsed // 1000}s', '#e6edf3'),
            ('Severity', 'Count', '#8b949e'),
        ]

        for i, (label, value, color) in enumerate(metrics):
            c = ctk.CTkFrame(grid, fg_color='#161b22', corner_radius=8)
            c.grid(row=0, column=i, sticky='nsew', padx=3, ipady=6)
            ctk.CTkLabel(c, text=label, font=ctk.CTkFont(size=10), text_color='#8b949e').pack(pady=(6, 0))
            ctk.CTkLabel(c, text=value, font=ctk.CTkFont(size=20, weight='bold'),
                          text_color=color).pack(pady=(0, 6))

        # Severity breakdown bar
        if total > 0:
            bar_frame = ctk.CTkFrame(self, fg_color='transparent')
            bar_frame.grid(row=1, column=0, sticky='ew', pady=(15, 5))
            bar_frame.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(bar_frame, text='Severity Breakdown', font=ctk.CTkFont(size=12, weight='bold'),
                          text_color='#e6edf3').pack(anchor='w', padx=3, pady=(0, 6))

            bar = ctk.CTkFrame(bar_frame, fg_color='#21262d', corner_radius=4, height=24)
            bar.pack(fill='x', padx=3)
            bar.pack_propagate(False)

            segments = []
            for sev in ('critical', 'high', 'medium', 'low', 'info'):
                cnt = summary.get(sev, 0)
                if cnt:
                    segments.append((cnt, sev, SEVERITY_COLORS.get(sev, '#6e7681')))

            if segments:
                total_cnt = sum(s[0] for s in segments)
                for cnt, sev, color in segments:
                    pct = cnt / total_cnt
                    if pct > 0.01:
                        f = ctk.CTkFrame(bar, fg_color=color, corner_radius=0)
                        f.pack(side='left', fill='both', expand=True)
                        ctk.CTkLabel(f, text=f'{cnt}', font=ctk.CTkFont(size=10, weight='bold'),
                                      text_color='#ffffff').pack(expand=True)

            # Legend
            legend = ctk.CTkFrame(bar_frame, fg_color='transparent')
            legend.pack(fill='x', padx=3, pady=(6, 0))
            for sev in ('critical', 'high', 'medium', 'low', 'info'):
                cnt = summary.get(sev, 0)
                if cnt:
                    lbl = ctk.CTkLabel(legend, text=f'{SEVERITY_ICON[sev]}  {sev.title()}: {cnt}',
                                        font=ctk.CTkFont(size=11),
                                        text_color=SEVERITY_COLORS.get(sev, '#8b949e'))
                    lbl.pack(side='left', padx=(0, 16))

        # Path info
        info = ctk.CTkFrame(self, fg_color='transparent')
        info.grid(row=2, column=0, sticky='ew', pady=(15, 0))
        ctk.CTkLabel(info, text='Scanned Path:', font=ctk.CTkFont(size=11), text_color='#8b949e').pack(anchor='w')
        ctk.CTkLabel(info, text=path, font=ctk.CTkFont(size=11, family='Consolas'),
                      text_color='#58a6ff', anchor='w').pack(anchor='w', fill='x')


class MainWindow(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color='#0d1117')
        self.parent = parent
        self.scanner = None
        self.scan_thread = None
        self.running = False
        self.scan_start = 0.0

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._build_header()
        self._build_controls()
        self._build_content()

    def _build_header(self):
        hdr = ctk.CTkFrame(self, fg_color='transparent', height=48)
        hdr.grid(row=0, column=0, sticky='ew', padx=24, pady=(16, 8))
        hdr.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(hdr, text='◈', font=ctk.CTkFont(size=26, weight='bold'),
                      text_color='#2ea043').grid(row=0, column=0, padx=(0, 8))

        ctk.CTkLabel(hdr, text='WebGuardian', font=ctk.CTkFont(size=20, weight='bold'),
                      text_color='#e6edf3').grid(row=0, column=1, padx=(0, 6))

        ctk.CTkLabel(hdr, text='Security Scanner', font=ctk.CTkFont(size=12),
                      text_color='#8b949e').grid(row=0, column=2, sticky='w')

        self.status_badge = ctk.CTkLabel(hdr, text='  ●  Ready  ',
                                           font=ctk.CTkFont(size=11, weight='bold'),
                                           text_color='#7ee787', fg_color='#093423',
                                           corner_radius=10)
        self.status_badge.grid(row=0, column=3, sticky='e', padx=(0, 4))

        ctk.CTkLabel(hdr, text='v1.0', font=ctk.CTkFont(size=10), text_color='#484f58').grid(row=0, column=4, padx=(2, 0))

    def _build_controls(self):
        ctrl = ctk.CTkFrame(self, fg_color='#161b22', corner_radius=10)
        ctrl.grid(row=1, column=0, sticky='ew', padx=24, pady=(4, 12))
        ctrl.grid_columnconfigure(1, weight=1)

        icon_lbl = ctk.CTkLabel(ctrl, text='📁', font=ctk.CTkFont(size=16))
        icon_lbl.grid(row=0, column=0, padx=(14, 6), pady=12)

        self.path_var = ctk.StringVar()
        entry = ctk.CTkEntry(ctrl, textvariable=self.path_var,
                              placeholder_text='C:\\wamp\\www\\project  or  /var/www/project',
                              font=ctk.CTkFont(size=12))
        entry.grid(row=0, column=1, sticky='ew', padx=4, pady=12)

        browse_btn = ctk.CTkButton(ctrl, text='Browse', width=80, command=self._browse,
                                    font=ctk.CTkFont(size=11), fg_color='#21262d',
                                    hover_color='#30363d', text_color='#e6edf3')
        browse_btn.grid(row=0, column=2, padx=(4, 8), pady=12)

        self.scan_btn = ctk.CTkButton(ctrl, text='Start Scan', width=120, height=32,
                                       font=ctk.CTkFont(size=12, weight='bold'),
                                       fg_color='#238636', hover_color='#2ea043',
                                       command=self._start_scan)
        self.scan_btn.grid(row=0, column=3, padx=4, pady=12)

        sep = ctk.CTkFrame(ctrl, width=1, fg_color='#30363d')
        sep.grid(row=0, column=4, sticky='ns', padx=8, pady=10)

        self.check_perms = ctk.BooleanVar(value=True)
        perm_cb = ctk.CTkCheckBox(ctrl, text='Permissions', variable=self.check_perms,
                                    font=ctk.CTkFont(size=11), checkbox_width=18, checkbox_height=18)
        perm_cb.grid(row=0, column=5, padx=(4, 12), pady=12)

    def _build_content(self):
        content = ctk.CTkFrame(self, fg_color='transparent')
        content.grid(row=2, column=0, sticky='nsew', padx=24, pady=(0, 16))
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(1, weight=1)

        # Progress section
        self.prog_frame = ctk.CTkFrame(content, fg_color='#161b22', corner_radius=10)
        self.prog_frame.grid(row=0, column=0, sticky='ew', pady=(0, 12))
        self.prog_frame.grid_columnconfigure(1, weight=1)

        self.progress_bar = ctk.CTkProgressBar(self.prog_frame, height=6, corner_radius=3)
        self.progress_bar.grid(row=0, column=0, columnspan=4, sticky='ew', padx=16, pady=(14, 2))
        self.progress_bar.set(0)
        self.progress_bar.configure(mode='determinate')

        # Progress stats
        for i in range(4):
            self.prog_frame.grid_columnconfigure(i, weight=1)

        self.lbl_phase = ctk.CTkLabel(self.prog_frame, text='', font=ctk.CTkFont(size=11),
                                       text_color='#8b949e')
        self.lbl_phase.grid(row=1, column=0, sticky='w', padx=16, pady=(6, 2))

        self.lbl_current = ctk.CTkLabel(self.prog_frame, text='', font=ctk.CTkFont(size=10, family='Consolas'),
                                         text_color='#484f58')
        self.lbl_current.grid(row=2, column=0, columnspan=4, sticky='ew', padx=16, pady=(0, 2))

        stats_row = ctk.CTkFrame(self.prog_frame, fg_color='transparent')
        stats_row.grid(row=3, column=0, columnspan=4, sticky='ew', padx=16, pady=(4, 12))
        for i in range(4):
            stats_row.grid_columnconfigure(i, weight=1)

        self.stat_frames = {}
        stat_defs = [('Files', '0', '#58a6ff'), ('Findings', '0', '#e6edf3'),
                     ('Skipped', '0', '#8b949e'), ('Time', '0s', '#8b949e')]
        for i, (label, value, color) in enumerate(stat_defs):
            frame = ctk.CTkFrame(stats_row, fg_color='#0d1117', corner_radius=6)
            frame.grid(row=0, column=i, sticky='ew', padx=2, ipady=4)
            ctk.CTkLabel(frame, text=value, font=ctk.CTkFont(size=18, weight='bold'),
                          text_color=color).pack(pady=(2, 0))
            ctk.CTkLabel(frame, text=label, font=ctk.CTkFont(size=9), text_color='#484f58').pack()
            self.stat_frames[label] = frame

        self.prog_frame.grid_remove()

        # Results tabs
        self.tabview = ctk.CTkTabview(content, corner_radius=8)
        self.tabview.grid(row=1, column=0, sticky='nsew')

        self.summary_tab = self.tabview.add('Summary')
        self.summary_tab.grid_columnconfigure(0, weight=1)
        self.summary_view = SummaryTab(self.summary_tab)
        self.summary_view.grid(row=0, column=0, sticky='nsew')

        self.findings_tab = self.tabview.add('Findings')
        self.findings_tab.grid_columnconfigure(0, weight=1)
        self.findings_view = FindingsTab(self.findings_tab)
        self.findings_view.grid(row=0, column=0, sticky='nsew')

    def _browse(self):
        path = ctk.filedialog.askdirectory(title='Select Directory to Scan')
        if path:
            self.path_var.set(path)

    def _update_stat(self, label, value, color=None):
        if label in self.stat_frames:
            child = self.stat_frames[label].winfo_children()[0]
            child.configure(text=str(value))
            if color:
                child.configure(text_color=color)

    def _start_scan(self):
        path = self.path_var.get().strip()
        if not path:
            self._show_results_text('Please select a directory to scan.\n')
            return
        if not os.path.isdir(path):
            self._show_results_text(f'Directory does not exist:\n{path}\n')
            return

        self.running = True
        self.scan_btn.configure(state='disabled', text='Scanning…')
        self.prog_frame.grid()
        self.progress_bar.set(0)
        self.progress_bar.configure(mode='indeterminate')
        self.progress_bar.start()
        self.status_badge.configure(text='  ●  Scanning  ', text_color='#d29922', fg_color='#3d2e00')

        self.lbl_phase.configure(text='Initialising…')
        self.lbl_current.configure(text='')
        self._update_stat('Files', '0')
        self._update_stat('Findings', '0')
        self._update_stat('Skipped', '0')
        self._update_stat('Time', '0s')

        self.findings_view.clear()
        self.tabview.set('Summary')

        self.scanner = Scanner(path, progress_callback=self._on_progress)
        self.scan_start = time.time()
        self.scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
        self.scan_thread.start()
        self.after(250, self._poll_time)

    def _scan_worker(self):
        try:
            results = self.scanner.run()
            self.after(0, lambda: self._scan_done(results))
        except Exception as e:
            self.after(0, lambda: self._scan_error(str(e)))
        finally:
            self.running = False

    def _poll_time(self):
        if self.running:
            elapsed = int(time.time() - self.scan_start)
            if elapsed < 60:
                self._update_stat('Time', f'{elapsed}s')
            else:
                self._update_stat('Time', str(timedelta(seconds=elapsed)).lstrip('0').lstrip(':'))
            self.after(250, self._poll_time)

    def _on_progress(self, data):
        def update():
            phase = data.get('phase', '')
            phase_label = phase.replace('_', ' ').title()
            self.lbl_phase.configure(text=phase_label)
            self._update_stat('Files', data.get('files_scanned', 0))
            self._update_stat('Findings', data.get('findings_count', 0))
            self._update_stat('Skipped', data.get('files_skipped', 0))
            if data.get('current_file'):
                f = data['current_file']
                if len(f) > 80:
                    f = '…' + f[-77:]
                self.lbl_current.configure(text=f)
        self.after(0, update)

    def _scan_done(self, results):
        self.progress_bar.stop()
        self.progress_bar.configure(mode='determinate')
        self.progress_bar.set(1)
        self.scan_btn.configure(state='normal', text='Start Scan')
        self.status_badge.configure(text='  ●  Complete  ', text_color='#7ee787', fg_color='#093423')

        total = results.get('summary', {}).get('total', 0)
        elapsed = results.get('stats', {}).get('elapsed_ms', 0)
        self._update_stat('Time', f'{elapsed // 1000}s')
        self.lbl_phase.configure(text='Scan Complete')
        self.lbl_current.configure(text='')
        self._update_stat('Findings', total, '#f85149' if total > 0 else '#7ee787')

        self.summary_view.display(results)
        self.findings_view.display(results.get('findings', []))
        self.tabview.set('Summary')

    def _scan_error(self, err):
        self.progress_bar.stop()
        self.progress_bar.configure(mode='determinate')
        self.progress_bar.set(0)
        self.scan_btn.configure(state='normal', text='Start Scan')
        self.status_badge.configure(text='  ●  Error  ', text_color='#f85149', fg_color='#490202')
        self.lbl_phase.configure(text='Error')
        self._show_results_text(f'Scan failed:\n{err}\n')

    def _show_results_text(self, text):
        self.summary_view.display({
            'stats': {'files_scanned': 0, 'files_skipped': 0, 'elapsed_ms': 0},
            'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0},
            'cms_type': '—',
            'scanned_path': '',
            'findings': [],
        })
        self.tabview.set('Summary')
