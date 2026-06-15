import customtkinter as ctk
import threading
import os
import time

from ..scanner import Scanner


class MainWindow(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.scanner = None
        self.scan_thread = None
        self.running = False

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._build_header()
        self._build_scan_config()
        self._build_progress()
        self._build_results()

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color='transparent')
        header.grid(row=0, column=0, sticky='ew', padx=20, pady=(15, 5))
        header.grid_columnconfigure(1, weight=1)

        title = ctk.CTkLabel(header, text='WebGuardian', font=ctk.CTkFont(size=26, weight='bold'))
        title.grid(row=0, column=0, sticky='w')

        subtitle = ctk.CTkLabel(header, text='Security Scanner', font=ctk.CTkFont(size=13),
                                 text_color='gray')
        subtitle.grid(row=0, column=1, sticky='w', padx=(8, 0))

        self.status_label = ctk.CTkLabel(header, text='Ready', font=ctk.CTkFont(size=12),
                                          text_color='green')
        self.status_label.grid(row=0, column=2, sticky='e')

    def _build_scan_config(self):
        config = ctk.CTkFrame(self)
        config.grid(row=1, column=0, sticky='ew', padx=20, pady=(5, 10))
        config.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(config, text='Scan Path:', font=ctk.CTkFont(size=13)).grid(row=0, column=0, padx=(10, 5), pady=10, sticky='w')

        self.path_var = ctk.StringVar()
        self.path_entry = ctk.CTkEntry(config, textvariable=self.path_var, placeholder_text='C:\\wamp\\www\\project or /var/www/project')
        self.path_entry.grid(row=0, column=1, sticky='ew', padx=5, pady=10)

        browse_btn = ctk.CTkButton(config, text='Browse', width=80, command=self._browse)
        browse_btn.grid(row=0, column=2, padx=5, pady=10)

        self.scan_btn = ctk.CTkButton(config, text='Start Scan', width=120,
                                       fg_color='#2ea043', hover_color='#238636',
                                       command=self._start_scan)
        self.scan_btn.grid(row=0, column=3, padx=5, pady=10)

        scan_opts = ctk.CTkFrame(config, fg_color='transparent')
        scan_opts.grid(row=0, column=4, padx=5, pady=10)
        self.check_perms = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(scan_opts, text='Check Permissions', variable=self.check_perms,
                         font=ctk.CTkFont(size=12)).pack(side='left', padx=5)

    def _build_progress(self):
        progress_frame = ctk.CTkFrame(self)
        progress_frame.grid(row=2, column=0, sticky='ew', padx=20, pady=(0, 5))
        progress_frame.grid_columnconfigure(0, weight=1)
        progress_frame.grid_rowconfigure(2, weight=1)

        self.progress_bar = ctk.CTkProgressBar(progress_frame, mode='indeterminate')
        self.progress_bar.grid(row=0, column=0, sticky='ew', padx=10, pady=(10, 2))
        self.progress_bar.configure(progress_color='#2ea043')
        self.progress_bar.set(0)

        info_frame = ctk.CTkFrame(progress_frame, fg_color='transparent')
        info_frame.grid(row=1, column=0, sticky='ew', padx=10, pady=(2, 5))
        info_frame.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        self.lbl_phase = ctk.CTkLabel(info_frame, text='', font=ctk.CTkFont(size=11), text_color='gray')
        self.lbl_phase.grid(row=0, column=0, sticky='w')

        self.lbl_files = ctk.CTkLabel(info_frame, text='Files: 0', font=ctk.CTkFont(size=11))
        self.lbl_files.grid(row=0, column=1, sticky='w')

        self.lbl_findings = ctk.CTkLabel(info_frame, text='Findings: 0', font=ctk.CTkFont(size=11))
        self.lbl_findings.grid(row=0, column=2, sticky='w')

        self.lbl_time = ctk.CTkLabel(info_frame, text='Time: 0s', font=ctk.CTkFont(size=11), text_color='gray')
        self.lbl_time.grid(row=0, column=3, sticky='e')

        self.lbl_current = ctk.CTkLabel(progress_frame, text='', font=ctk.CTkFont(size=11),
                                          text_color='gray', wraplength=900)
        self.lbl_current.grid(row=2, column=0, sticky='ew', padx=10, pady=(0, 5))

    def _build_results(self):
        results_frame = ctk.CTkFrame(self)
        results_frame.grid(row=3, column=0, sticky='nsew', padx=20, pady=(0, 15))
        results_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_rowconfigure(0, weight=1)

        self.results_text = ctk.CTkTextbox(results_frame, wrap='word', font=ctk.CTkFont(size=12))
        self.results_text.grid(row=0, column=0, sticky='nsew')
        self.results_text.configure(state='disabled')

    def _browse(self):
        path = ctk.filedialog.askdirectory(title='Select Directory to Scan')
        if path:
            self.path_var.set(path)

    def _start_scan(self):
        path = self.path_var.get().strip()
        if not path:
            self._log('Please select a directory to scan.\n')
            return
        if not os.path.isdir(path):
            self._log(f'Directory does not exist: {path}\n')
            return

        self.running = True
        self.scan_btn.configure(state='disabled', text='Scanning...')
        self.results_text.configure(state='normal')
        self.results_text.delete('0.0', 'end')
        self.results_text.configure(state='disabled')
        self.progress_bar.start()
        self.status_label.configure(text='Scanning...', text_color='#2ea043')
        self.lbl_phase.configure(text='Starting...')

        self.scanner = Scanner(path, progress_callback=self._on_progress)
        self.scan_start = time.time()
        self.scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
        self.scan_thread.start()
        self.after(100, self._poll_time)

    def _scan_worker(self):
        try:
            self.scanner.run()
        finally:
            self.running = False
            self.after(0, self._scan_done)

    def _poll_time(self):
        if self.running:
            elapsed = int(time.time() - self.scan_start)
            self.lbl_time.configure(text=f'Time: {elapsed}s')
            self.after(500, self._poll_time)

    def _on_progress(self, data):
        def update():
            self.lbl_phase.configure(text=data.get('phase', '').replace('_', ' ').title())
            self.lbl_files.configure(text=f"Files: {data.get('files_scanned', 0)}")
            self.lbl_findings.configure(text=f"Findings: {data.get('findings_count', 0)}")
            if data.get('current_file'):
                self.lbl_current.configure(text=data['current_file'])
        self.after(0, update)

    def _scan_done(self):
        self.progress_bar.stop()
        self.progress_bar.set(1)
        self.scan_btn.configure(state='normal', text='Start Scan')
        self.status_label.configure(text='Complete', text_color='green')

        results = self.scanner.results if self.scanner else {}
        elapsed = results.get('stats', {}).get('elapsed_ms', 0)
        self.lbl_time.configure(text=f'Time: {elapsed // 1000}s')
        self.lbl_phase.configure(text='Completed')
        self.lbl_current.configure(text='')

        self._display_results(results)

    def _display_results(self, results):
        self.results_text.configure(state='normal')
        self.results_text.delete('0.0', 'end')

        stats = results.get('stats', {})
        summary = results.get('summary', {})
        findings = results.get('findings', [])
        cms = results.get('cms_type', 'unknown')
        path = results.get('scanned_path', '')

        tag_configs = {
            'h1': ('white', 18, 'bold'),
            'h2': ('#cccccc', 14, 'bold'),
            'critical': ('#ff4444', 12, 'bold'),
            'high': ('#ff8800', 12, 'normal'),
            'medium': ('#ffcc00', 12, 'normal'),
            'low': ('#4488ff', 12, 'normal'),
            'info': ('#888888', 12, 'normal'),
            'normal': ('#cccccc', 12, 'normal'),
            'file': ('#44cc44', 11, 'normal'),
            'label': ('#888888', 11, 'normal'),
        }
        for tag, (color, size, weight) in tag_configs.items():
            self.results_text.tag_config(tag, foreground=color, font=ctk.CTkFont(size=size, weight=weight))

        self.results_text.insert('end', 'Scan Results\n', 'h1')
        self.results_text.insert('end', f'Path: {path}\n', 'normal')
        self.results_text.insert('end', f'CMS Type: {cms}\n', 'normal')
        self.results_text.insert('end', f'Files Scanned: {stats.get("files_scanned", 0)}\n', 'normal')
        self.results_text.insert('end', f'Elapsed: {stats.get("elapsed_ms", 0) // 1000}s\n\n', 'normal')

        sev_map = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        findings.sort(key=lambda x: sev_map.get(x['severity'], 4))

        self.results_text.insert('end', f'Summary: {summary.get("total", 0)} total findings\n', 'h2')
        for sev in ('critical', 'high', 'medium', 'low', 'info'):
            count = summary.get(sev, 0)
            if count:
                self.results_text.insert('end', f'  {sev.title()}: {count}\n', sev)
        self.results_text.insert('end', '\n')

        if findings:
            self.results_text.insert('end', 'Findings\n', 'h2')
            for i, f in enumerate(findings[:200], 1):
                sev = f.get('severity', 'info')
                self.results_text.insert('end', f'{i}. [{sev.upper()}] ', sev)
                self.results_text.insert('end', f'{f["message"]}\n', 'normal')
                if f.get('file'):
                    self.results_text.insert('end', f'   File: {f["file"]}', 'file')
                    if f.get('line'):
                        self.results_text.insert('end', f' :{f["line"]}', 'file')
                    self.results_text.insert('end', '\n', 'file')
            if len(findings) > 200:
                self.results_text.insert('end', f'\n... and {len(findings) - 200} more findings.\n', 'label')
        else:
            self.results_text.insert('end', 'No findings — your project looks clean!\n', 'normal')

        self.results_text.configure(state='disabled')

    def _log(self, text):
        self.results_text.configure(state='normal')
        self.results_text.insert('end', text, 'normal')
        self.results_text.configure(state='disabled')
