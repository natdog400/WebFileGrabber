import asyncio
import os
import re
import threading
import urllib.parse
import urllib.parse
import tkinter as tk
from tkinter import ttk, filedialog
from tkinter.scrolledtext import ScrolledText
import subprocess
import shutil
import sys
import signal
import time
import json
import winreg

def sanitize_name(name):
    return re.sub(r'[<>:"/\\|?*]', '_', name)

class SwfDownloaderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SWF Downloader")
        try:
            style = ttk.Style()
            for theme in ("vista", "xpnative", "clam"):
                try:
                    style.theme_use(theme)
                    break
                except Exception:
                    continue
            style.configure("TButton", padding=6)
            style.configure("TLabel", padding=2)
            style.configure("TEntry", padding=4)
            style.configure("TLabelframe", padding=8)
        except Exception:
            pass
        self.url_var = tk.StringVar()
        self.dir_var = tk.StringVar()
        self.running = False
        self.stop_event = threading.Event()
        self.thread = None
        nb = ttk.Notebook(root)
        nb.grid(sticky="nsew")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        frm = ttk.Frame(nb, padding=10)
        nb.add(frm, text="Main")
        logs_tab = ttk.Frame(nb)
        nb.add(logs_tab, text="Logs")
        sub_nb = ttk.Notebook(frm)
        sub_nb.grid(row=0, column=0, columnspan=3, sticky="nsew")
        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(0, weight=1)
        capture_tab = ttk.Frame(sub_nb, padding=8)
        filters_tab = ttk.Frame(sub_nb, padding=8)
        advanced_tab = ttk.Frame(sub_nb, padding=8)
        sub_nb.add(capture_tab, text="Capture")
        sub_nb.add(filters_tab, text="Filters")
        sub_nb.add(advanced_tab, text="Advanced")
        ttk.Label(capture_tab, text="URL").grid(row=0, column=0, sticky="w")
        url_entry = ttk.Entry(capture_tab, textvariable=self.url_var)
        url_entry.grid(row=1, column=0, columnspan=3, sticky="ew")
        capture_tab.columnconfigure(0, weight=1)
        ttk.Label(capture_tab, text="Save to").grid(row=2, column=0, sticky="w")
        dir_entry = ttk.Entry(capture_tab, textvariable=self.dir_var)
        dir_entry.grid(row=3, column=0, sticky="ew")
        ttk.Button(capture_tab, text="Browse", command=self.choose_dir).grid(row=3, column=1, sticky="ew")
        self.domain_only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(capture_tab, text="Restrict to entered domain", variable=self.domain_only_var).grid(row=4, column=0, sticky="w")
        ttk.Label(capture_tab, text="Capture mode").grid(row=4, column=1, sticky="w")
        self.capture_mode = tk.StringVar(value="playwright")
        ttk.Radiobutton(capture_tab, text="Browser", variable=self.capture_mode, value="playwright").grid(row=5, column=0, sticky="w")
        ttk.Radiobutton(capture_tab, text="Proxy (system Edge)", variable=self.capture_mode, value="proxy").grid(row=5, column=1, sticky="w")
        ttk.Radiobutton(capture_tab, text="Connect (Edge CDP)", variable=self.capture_mode, value="cdp").grid(row=5, column=2, sticky="w")
        ttk.Label(capture_tab, text="Browser engine").grid(row=6, column=0, sticky="w")
        self.browser_engine = tk.StringVar(value="edge")
        ttk.Radiobutton(capture_tab, text="Chromium", variable=self.browser_engine, value="chromium").grid(row=6, column=1, sticky="w")
        ttk.Radiobutton(capture_tab, text="Edge (msedge)", variable=self.browser_engine, value="edge").grid(row=6, column=2, sticky="w")
        ttk.Radiobutton(capture_tab, text="Pale Moon", variable=self.browser_engine, value="palemoon").grid(row=6, column=3, sticky="w")
        btn_frame = ttk.Frame(capture_tab)
        btn_frame.grid(row=7, column=0, columnspan=4, pady=8, sticky="ew")
        self.start_btn = ttk.Button(btn_frame, text="Start", command=self.start)
        self.start_btn.grid(row=0, column=0, padx=4)
        self.stop_btn = ttk.Button(btn_frame, text="Stop", command=self.stop, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=1, padx=4)
        self.cert_btn = ttk.Button(btn_frame, text="Install proxy certificate", command=self.install_proxy_cert)
        self.cert_btn.grid(row=0, column=2, padx=4)
        self.cert_open_btn = ttk.Button(btn_frame, text="Open cert folder", command=self.open_cert_folder)
        self.cert_open_btn.grid(row=0, column=3, padx=4)
        ttk.Button(btn_frame, text="Launch Edge (CDP)", command=self.launch_edge_cdp).grid(row=0, column=4, padx=4)
        ttk.Button(btn_frame, text="Save settings", command=self.save_settings).grid(row=0, column=5, padx=4)
        ttk.Button(btn_frame, text="Load settings", command=self.load_settings).grid(row=0, column=6, padx=4)
        ttk.Button(btn_frame, text="Import HAR", command=self.import_har_dialog).grid(row=0, column=7, padx=4)
        ttk.Button(btn_frame, text="Import SAZ", command=self.import_saz_dialog).grid(row=0, column=8, padx=4)
        ttk.Button(btn_frame, text="Kill Edge", command=self.kill_edge_tasks).grid(row=0, column=9, padx=4)
        ttk.Button(btn_frame, text="Verify CDP", command=self.verify_cdp).grid(row=0, column=10, padx=4)
        ttk.Button(btn_frame, text="Check Edge Policy", command=self.check_edge_policy).grid(row=0, column=11, padx=4)
        ttk.Button(btn_frame, text="Launch Edge (CDP auto)", command=self.launch_edge_cdp_auto).grid(row=0, column=12, padx=4)
        ttk.Button(btn_frame, text="Attach Now (CDP)", command=self.attach_now_cdp).grid(row=0, column=13, padx=4)
        ttk.Button(btn_frame, text="Start Proxy Only", command=self.start_proxy_only).grid(row=0, column=14, padx=4)
        self.proxy_status_var = tk.StringVar(value="")
        ttk.Label(btn_frame, textvariable=self.proxy_status_var).grid(row=1, column=0, columnspan=15, sticky="w")
        ttk.Label(filters_tab, text="Include filters (comma)").grid(row=0, column=0, sticky="w")
        self.includes_var = tk.StringVar(value=".swf")
        ttk.Entry(filters_tab, textvariable=self.includes_var).grid(row=0, column=1, columnspan=2, sticky="ew")
        ttk.Label(filters_tab, text="Exclude filters (comma)").grid(row=1, column=0, sticky="w")
        self.excludes_var = tk.StringVar(value="")
        ttk.Entry(filters_tab, textvariable=self.excludes_var).grid(row=1, column=1, columnspan=2, sticky="ew")
        ttk.Label(filters_tab, text="Content-Types (comma)").grid(row=2, column=0, sticky="w")
        self.ct_includes_var = tk.StringVar(value="")
        ttk.Entry(filters_tab, textvariable=self.ct_includes_var).grid(row=2, column=1, columnspan=2, sticky="ew")
        ttk.Label(filters_tab, text="Host includes (comma)").grid(row=3, column=0, sticky="w")
        self.host_includes_var = tk.StringVar(value="")
        ttk.Entry(filters_tab, textvariable=self.host_includes_var).grid(row=3, column=1, columnspan=2, sticky="ew")
        ttk.Label(filters_tab, text="Host excludes (comma)").grid(row=4, column=0, sticky="w")
        self.host_excludes_var = tk.StringVar(value="")
        ttk.Entry(filters_tab, textvariable=self.host_excludes_var).grid(row=4, column=1, columnspan=2, sticky="ew")
        self.mirror_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(filters_tab, text="Mirror URL path into folders", variable=self.mirror_var).grid(row=5, column=0, sticky="w")
        self.proxy_save_all_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(filters_tab, text="Save all via Proxy", variable=self.proxy_save_all_var).grid(row=6, column=0, sticky="w")
        filters_tab.columnconfigure(1, weight=1)
        ttk.Label(advanced_tab, text="Edge executable").grid(row=0, column=0, sticky="w")
        self.edge_path_var = tk.StringVar(value="")
        ttk.Entry(advanced_tab, textvariable=self.edge_path_var).grid(row=0, column=1, sticky="ew")
        ttk.Button(advanced_tab, text="Browse", command=lambda: self._choose_file(self.edge_path_var)).grid(row=0, column=2, sticky="ew")
        ttk.Label(advanced_tab, text="CDP port").grid(row=1, column=0, sticky="w")
        self.cdp_port_var = tk.StringVar(value="9222")
        ttk.Entry(advanced_tab, textvariable=self.cdp_port_var, width=8).grid(row=1, column=1, sticky="w")
        self.ruffle_enable_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(advanced_tab, text="Enable Ruffle extension (Browser mode)", variable=self.ruffle_enable_var).grid(row=2, column=0, sticky="w")
        ttk.Label(advanced_tab, text="Ruffle extension folder").grid(row=3, column=0, sticky="w")
        self.ruffle_path_var = tk.StringVar(value="")
        ttk.Entry(advanced_tab, textvariable=self.ruffle_path_var).grid(row=3, column=1, sticky="ew")
        ttk.Button(advanced_tab, text="Browse", command=lambda: self._choose_dir(self.ruffle_path_var)).grid(row=3, column=2, sticky="ew")
        self.ruffle_verify_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(advanced_tab, text="Verify Ruffle (demo) before URL", variable=self.ruffle_verify_var).grid(row=4, column=0, sticky="w")
        self.ruffle_require_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(advanced_tab, text="Require Ruffle to start", variable=self.ruffle_require_var).grid(row=5, column=0, sticky="w")
        advanced_tab.columnconfigure(1, weight=1)
        self.log = ScrolledText(logs_tab, height=18)
        self.log.grid(row=0, column=0, columnspan=1, sticky="nsew")
        logs_tab.columnconfigure(0, weight=1)
        logs_tab.rowconfigure(0, weight=1)
        self.status_var = tk.StringVar(value="Idle")
        ttk.Separator(frm).grid(row=16, column=0, columnspan=3, sticky="ew", pady=4)
        ttk.Label(frm, textvariable=self.status_var).grid(row=18, column=0, columnspan=3, sticky="ew")
        self.mitm_proc = None
        self.edge_proc = None
        self.cdp_profile_dir = None
        try:
            self.load_settings()
        except Exception:
            pass
        try:
            self.update_proxy_status()
        except Exception:
            pass
        try:
            self.update_status("Idle")
        except Exception:
            pass

    def choose_dir(self):
        d = filedialog.askdirectory()
        if d:
            self.dir_var.set(d)

    def _choose_dir(self, var):
        d = filedialog.askdirectory()
        if d:
            var.set(d)

    def _choose_file(self, var):
        f = filedialog.askopenfilename()
        if f:
            var.set(f)

    def _normalize_url(self, u: str) -> str:
        s = (u or "").strip()
        if not s:
            return s
        if re.match(r'^[a-zA-Z]+://', s):
            return s
        return "https://" + s

    def import_har_dialog(self):
        fp = filedialog.askopenfilename(filetypes=[("HAR", "*.har"), ("JSON", "*.json"), ("All", "*.*")])
        if not fp:
            return
        includes = [x.strip().lower() for x in (self.includes_var.get() or "").split(',') if x.strip()]
        excludes = [x.strip().lower() for x in (self.excludes_var.get() or "").split(',') if x.strip()]
        ct_includes = [x.strip().lower() for x in (self.ct_includes_var.get() or "").split(',') if x.strip()]
        host_includes = [x.strip().lower() for x in (self.host_includes_var.get() or "").split(',') if x.strip()]
        host_excludes = [x.strip().lower() for x in (self.host_excludes_var.get() or "").split(',') if x.strip()]
        host_includes = [x.strip().lower() for x in (self.host_includes_var.get() or "").split(',') if x.strip()]
        host_excludes = [x.strip().lower() for x in (self.host_excludes_var.get() or "").split(',') if x.strip()]
        mirror = self.mirror_var.get()
        outdir = self.dir_var.get().strip()
        if not outdir:
            self.log_line("Choose a destination folder")
            return
        threading.Thread(target=self._run_import_har, args=(fp, outdir, host_includes, host_excludes, includes, excludes, ct_includes, mirror), daemon=True).start()

    def import_saz_dialog(self):
        fp = filedialog.askopenfilename(filetypes=[("SAZ", "*.saz"), ("ZIP", "*.zip"), ("All", "*.*")])
        if not fp:
            return
        includes = [x.strip().lower() for x in (self.includes_var.get() or "").split(',') if x.strip()]
        excludes = [x.strip().lower() for x in (self.excludes_var.get() or "").split(',') if x.strip()]
        ct_includes = [x.strip().lower() for x in (self.ct_includes_var.get() or "").split(',') if x.strip()]
        host_includes = [x.strip().lower() for x in (self.host_includes_var.get() or "").split(',') if x.strip()]
        host_excludes = [x.strip().lower() for x in (self.host_excludes_var.get() or "").split(',') if x.strip()]
        mirror = self.mirror_var.get()
        outdir = self.dir_var.get().strip()
        if not outdir:
            self.log_line("Choose a destination folder")
            return
        threading.Thread(target=self._run_import_saz, args=(fp, outdir, host_includes, host_excludes, includes, excludes, ct_includes, mirror), daemon=True).start()

    def log_line(self, msg):
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)

    def start(self):
        if self.running:
            return
        url = self.url_var.get().strip()
        outdir = self.dir_var.get().strip()
        if not url:
            self.log_line("Enter a URL")
            return
        if not outdir:
            self.log_line("Choose a destination folder")
            return
        self.running = True
        self.stop_event.clear()
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        mode = self.capture_mode.get()
        includes = [x.strip().lower() for x in (self.includes_var.get() or "").split(',') if x.strip()]
        excludes = [x.strip().lower() for x in (self.excludes_var.get() or "").split(',') if x.strip()]
        ct_includes = [x.strip().lower() for x in (self.ct_includes_var.get() or "").split(',') if x.strip()]
        host_includes = [x.strip().lower() for x in (self.host_includes_var.get() or "").split(',') if x.strip()]
        host_excludes = [x.strip().lower() for x in (self.host_excludes_var.get() or "").split(',') if x.strip()]
        mirror = self.mirror_var.get()
        try:
            self.update_status(f"Running {mode}…")
        except Exception:
            pass
        if mode == "proxy":
            engine = self.browser_engine.get()
            engine_path = ""
            if engine == "edge":
                engine_path = self.edge_path_var.get().strip()
            elif engine == "palemoon":
                # optional UI can be added later; auto-discovery happens in launcher
                engine_path = ""
            self.thread = threading.Thread(
                target=self._run_proxy_capture,
                args=(url, outdir, self.domain_only_var.get(), host_includes, host_excludes, includes, excludes, ct_includes, mirror, engine, engine_path),
                daemon=True,
            )
            self.thread.start()
        elif mode == "cdp":
            port = self.cdp_port_var.get().strip() or "9222"
            self.thread = threading.Thread(
                target=self._run_cdp_capture,
                args=(url, outdir, self.domain_only_var.get(), host_includes, host_excludes, includes, excludes, ct_includes, mirror, port),
                daemon=True,
            )
            self.thread.start()
        else:
            use_edge = (self.browser_engine.get() == "edge")
            ruffle_enable = self.ruffle_enable_var.get()
            ruffle_dir = self.ruffle_path_var.get().strip()
            ruffle_verify = self.ruffle_verify_var.get()
            ruffle_require = self.ruffle_require_var.get()
            ruffle_ok = ruffle_enable and os.path.isdir(ruffle_dir) and os.path.isfile(os.path.join(ruffle_dir, "manifest.json"))
            if ruffle_enable and ruffle_require and not ruffle_ok:
                self.log_line("Ruffle extension folder invalid. Select unpacked folder containing manifest.json.")
                self.start_btn.config(state=tk.NORMAL)
                self.stop_btn.config(state=tk.DISABLED)
                self.running = False
                return
            if use_edge and ruffle_ok:
                self.thread = threading.Thread(
                    target=self._run_capture,
                    args=(url, outdir, True, self.domain_only_var.get(), host_includes, host_excludes, includes, excludes, ct_includes, mirror, ruffle_enable, ruffle_dir, self.edge_path_var.get().strip(), ruffle_verify, ruffle_require),
                    daemon=True,
                )
                self.thread.start()
            elif use_edge and not ruffle_ok:
                self.log_line("Ruffle folder invalid; launching Playwright Edge without extension")
                self.thread = threading.Thread(
                    target=self._run_capture,
                    args=(url, outdir, True, self.domain_only_var.get(), host_includes, host_excludes, includes, excludes, ct_includes, mirror, False, "", self.edge_path_var.get().strip(), False, False),
                    daemon=True,
                )
                self.thread.start()
            elif self.browser_engine.get() == "palemoon":
                engine = "palemoon"
                engine_path = ""
                self.thread = threading.Thread(
                    target=self._run_proxy_capture,
                    args=(url, outdir, self.domain_only_var.get(), host_includes, host_excludes, includes, excludes, ct_includes, mirror, engine, engine_path),
                    daemon=True,
                )
                self.thread.start()
            else:
                self.thread = threading.Thread(
                    target=self._run_capture,
                    args=(url, outdir, False, self.domain_only_var.get(), host_includes, host_excludes, includes, excludes, ct_includes, mirror, ruffle_enable, ruffle_dir, "", ruffle_verify, ruffle_require),
                    daemon=True,
                )
                self.thread.start()

    def stop(self):
        if not self.running:
            return
        self.stop_event.set()
        try:
            if self.mitm_proc and self.mitm_proc.poll() is None:
                try:
                    self.mitm_proc.terminate()
                except Exception:
                    pass
            if self.edge_proc and self.edge_proc.poll() is None:
                try:
                    self.edge_proc.terminate()
                except Exception:
                    pass
        finally:
            self.mitm_proc = None
            self.edge_proc = None
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.running = False
        try:
            self.update_status("Idle")
        except Exception:
            pass

    def launch_edge_cdp(self):
        try:
            edge_path = self.edge_path_var.get().strip() or shutil.which("msedge")
            if not edge_path:
                candidates = [
                    r"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                    r"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
                ]
                for c in candidates:
                    if os.path.exists(c):
                        edge_path = c
                        break
            if not edge_path:
                self.log_line("Edge not found")
                return
            port_in = self.cdp_port_var.get().strip()
            port = port_in or "9222"
            user_dir = os.path.join(os.path.expanduser("~"), ".swf_downloader", "edge_cdp_profile")
            os.makedirs(user_dir, exist_ok=True)
            self.cdp_profile_dir = user_dir
            rd_arg = f"--remote-debugging-port={port}" if port.lower() not in ("auto", "0") else "--remote-debugging-port=0"
            launch_args = [edge_path, rd_arg, f"--user-data-dir={user_dir}", "--no-first-run", "--no-default-browser-check", "--new-window"]
            if self.url_var.get().strip():
                launch_args.append(self.url_var.get().strip())
            subprocess.Popen(launch_args)
            if rd_arg.endswith("=0"):
                self.log_line("Launched Edge with CDP (auto port)")
            else:
                self.log_line(f"Launched Edge with CDP on port {port}")
        except Exception as e:
            self.log_line(str(e))

    def launch_edge_cdp_auto(self):
        try:
            self.cdp_port_var.set("0")
            self.launch_edge_cdp()
        except Exception as e:
            self.log_line(str(e))

    def attach_now_cdp(self):
        try:
            if self.running:
                return
            url = self.url_var.get().strip()
            outdir = self.dir_var.get().strip()
            if not outdir:
                self.log_line("Choose a destination folder")
                return
            self.running = True
            self.stop_event.clear()
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            includes = [x.strip().lower() for x in (self.includes_var.get() or "").split(',') if x.strip()]
            excludes = [x.strip().lower() for x in (self.excludes_var.get() or "").split(',') if x.strip()]
            ct_includes = [x.strip().lower() for x in (self.ct_includes_var.get() or "").split(',') if x.strip()]
            host_includes = [x.strip().lower() for x in (self.host_includes_var.get() or "").split(',') if x.strip()]
            host_excludes = [x.strip().lower() for x in (self.host_excludes_var.get() or "").split(',') if x.strip()]
            mirror = self.mirror_var.get()
            port = self.cdp_port_var.get().strip() or "0"
            self.thread = threading.Thread(
                target=self._run_cdp_capture,
                args=(url, outdir, self.domain_only_var.get(), host_includes, host_excludes, includes, excludes, ct_includes, mirror, port),
                daemon=True,
            )
            self.thread.start()
            try:
                self.update_status("Running cdp…")
            except Exception:
                pass
        except Exception as e:
            self.log_line(str(e))

    def _cert_candidates(self):
        home = os.path.expanduser("~")
        d = os.path.join(home, ".mitmproxy")
        return d, [
            os.path.join(d, "mitmproxy-ca-cert.cer"),
            os.path.join(d, "mitmproxy-ca-cert.pem"),
            os.path.join(d, "mitmproxy-ca.pem"),
        ]

    def open_cert_folder(self):
        d, _ = self._cert_candidates()
        try:
            if os.path.isdir(d):
                subprocess.Popen(["explorer", d])
            else:
                self.log_line("Certificate folder not found")
        except Exception as e:
            self.log_line(str(e))

    def install_proxy_cert(self):
        try:
            mitmdump = shutil.which("mitmdump")
            if not mitmdump:

                self.log_line("Install mitmproxy: pip install mitmproxy")
                return
            d, candidates = self._cert_candidates()
            cert_path = None
            for c in candidates:
                if os.path.exists(c):
                    cert_path = c
                    break
            if not cert_path:
                try:
                    tmp = subprocess.Popen([mitmdump, "--listen-host", "127.0.0.1", "-p", "0"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    time.sleep(2)
                    try:
                        tmp.terminate()
                    except Exception:
                        pass
                except Exception:
                    pass
                for c in candidates:
                    if os.path.exists(c):
                        cert_path = c
                        break
            if not cert_path:
                self.log_line("Certificate not found; start Proxy once then retry")
                return
            certutil = shutil.which("certutil") or "certutil"
            try:
                r = subprocess.run([certutil, "-user", "-addstore", "Root", cert_path], capture_output=True, text=True)
                if r.returncode == 0:
                    self.log_line("Certificate installed to user Trusted Root")
                    try:
                        self.update_proxy_status()
                    except Exception:
                        pass
                else:
                    self.log_line(r.stdout.strip() or r.stderr.strip() or "Certificate install failed")
            except Exception as e:
                self.log_line(str(e))
        except Exception as e:
            self.log_line(str(e))

    def update_proxy_status(self):
        d, candidates = self._cert_candidates()
        present = any(os.path.exists(c) for c in candidates)
        if present:
            self.proxy_status_var.set("Proxy CA files present — HTTPS decryption enabled")
        else:
            self.proxy_status_var.set("Proxy CA missing — open http://mitm.it to install")

    def update_status(self, text):
        try:
            self.status_var.set(text)
        except Exception:
            pass

    def start_proxy_only(self):
        try:
            if self.running:
                return
            url = self.url_var.get().strip()
            outdir = self.dir_var.get().strip()
            if not outdir:
                self.log_line("Choose a destination folder")
                return
            self.running = True
            self.stop_event.clear()
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            includes = [x.strip().lower() for x in (self.includes_var.get() or "").split(',') if x.strip()]
            excludes = [x.strip().lower() for x in (self.excludes_var.get() or "").split(',') if x.strip()]
            ct_includes = [x.strip().lower() for x in (self.ct_includes_var.get() or "").split(',') if x.strip()]
            host_includes = [x.strip().lower() for x in (self.host_includes_var.get() or "").split(',') if x.strip()]
            host_excludes = [x.strip().lower() for x in (self.host_excludes_var.get() or "").split(',') if x.strip()]
            mirror = self.mirror_var.get()
            engine = "none"
            engine_path = ""
            self.thread = threading.Thread(
                target=self._run_proxy_capture,
                args=(url, outdir, self.domain_only_var.get(), host_includes, host_excludes, includes, excludes, ct_includes, mirror, engine, engine_path),
                daemon=True,
            )
            self.thread.start()
            try:
                self.update_proxy_status()
            except Exception:
                pass
        except Exception as e:
            self.log_line(str(e))

    def _run_capture(self, url, outdir, use_edge, domain_only, host_includes, host_excludes, includes, excludes, ct_includes, mirror, ruffle_enable, ruffle_path, edge_exe, ruffle_verify, ruffle_require):
        asyncio.run(self._capture_async(url, outdir, use_edge, domain_only, host_includes, host_excludes, includes, excludes, ct_includes, mirror, ruffle_enable, ruffle_path, edge_exe, ruffle_verify, ruffle_require))

    async def _capture_async(self, url, outdir, use_edge, domain_only, host_includes, host_excludes, includes, excludes, ct_includes, mirror, ruffle_enable, ruffle_path, edge_exe, ruffle_verify, ruffle_require):
        try:
            from playwright.async_api import async_playwright
        except Exception as e:
            self.root.after(0, lambda: self.log_line("Install playwright: pip install playwright, then: python -m playwright install"))
            return
        try:
            async with async_playwright() as p:
                launch_args = {"headless": False}
                if use_edge:
                    edge_path = edge_exe or shutil.which("msedge")
                    if not edge_path:
                        candidates = [
                            r"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                            r"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
                        ]
                        for c in candidates:
                            if os.path.exists(c):
                                edge_path = c
                                break
                    if edge_path and os.path.exists(edge_path):
                        launch_args["executable_path"] = edge_path
                        self.root.after(0, lambda: self.log_line(f"Launching Edge executable: {edge_path}"))
                    else:
                        launch_args["channel"] = "msedge"
                        self.root.after(0, lambda: self.log_line("Launching Edge channel (msedge)"))
                else:
                    self.root.after(0, lambda: self.log_line("Launching Chromium"))
                context = None
                browser = None
                ext_args = []
                use_ext = ruffle_enable and os.path.isdir(ruffle_path) and os.path.isfile(os.path.join(ruffle_path, "manifest.json"))
                if use_ext:
                    ext_args = [f"--disable-extensions-except={ruffle_path}", f"--load-extension={ruffle_path}"]
                try:
                    if use_ext:
                        user_data_dir = os.path.join(os.path.expanduser("~"), ".swf_downloader", "pw_profile")
                        os.makedirs(user_data_dir, exist_ok=True)
                        launch_opts = {"headless": False, "args": ext_args}
                        for k, v in launch_args.items():
                            launch_opts[k] = v
                        context = await p.chromium.launchPersistentContext(user_data_dir, **launch_opts)
                    else:
                        browser = await p.chromium.launch(**launch_args)
                        context = await browser.new_context()
                except Exception as le:
                    self.root.after(0, lambda: self.log_line(f"Launch failed: {le}"))
                    if not context:
                        browser = await p.chromium.launch(headless=False)
                        context = await browser.new_context()
                if ruffle_enable and not use_ext:
                    self.root.after(0, lambda: self.log_line("Ruffle extension not loaded: select an unpacked extension folder containing manifest.json"))
                page = await context.new_page()
                try:
                    ua = await page.evaluate("navigator.userAgent")
                    self.root.after(0, lambda: self.log_line(f"User-Agent: {ua}"))
                except Exception:
                    pass
                self.root.after(0, lambda: self.log_line("Browser ready"))
                if ruffle_enable and use_ext and ruffle_verify:
                    try:
                        await page.goto("https://ruffle.rs/demo/")
                        ok = await page.evaluate("typeof window.RufflePlayer !== 'undefined' || !!document.querySelector('ruffle-player')")
                        self.root.after(0, lambda: self.log_line("Ruffle OK" if ok else "Ruffle not detected"))
                        if ruffle_require and not ok:
                            try:
                                await context.close()
                            except Exception:
                                pass
                            self.root.after(0, lambda: self.log_line("Stopping: Ruffle required but not active"))
                            return
                    except Exception as ve:
                        self.root.after(0, lambda: self.log_line(f"Ruffle verify error: {ve}"))
                seen = set()
                target_host = urllib.parse.urlparse(url).hostname or ""
                async def process_response(response):
                    try:
                        req_url = response.url or ""
                        headers = response.headers or {}
                        ct = (headers.get("content-type") or "").lower()
                        if domain_only and target_host:
                            resp_host = urllib.parse.urlparse(req_url).hostname or ""
                            if resp_host and not (resp_host == target_host or resp_host.endswith("." + target_host)):
                                return
                        resp_host = urllib.parse.urlparse(req_url).hostname or ""
                        url_l = req_url.lower()
                        cd = (headers.get("content-disposition") or "").lower()
                        name_in_cd = "filename=" in cd and ".swf" in cd
                        is_swf = url_l.endswith(".swf") or ".swf" in url_l or ("application/x-shockwave-flash" in ct) or name_in_cd
                        if req_url in seen:
                            return
                        body = await response.body()
                        def match_filters():
                            if host_includes:
                                hit_h = False
                                for tok in host_includes:
                                    if tok == "*":
                                        hit_h = True
                                        break
                                    if tok and (resp_host == tok or resp_host.endswith("." + tok)):
                                        hit_h = True
                                        break
                                if not hit_h:
                                    return False
                            if host_excludes:
                                for tok in host_excludes:
                                    if tok and (resp_host == tok or resp_host.endswith("." + tok)):
                                        return False
                            if includes:
                                inc_hit = False
                                for tok in includes:
                                    if tok == "*":
                                        inc_hit = True
                                        break
                                    if tok and (tok in url_l or tok in (headers.get("content-disposition") or "").lower()):
                                        inc_hit = True
                                        break
                                if not inc_hit:
                                    return False
                            if ct_includes:
                                ok_ct = any(t in ct for t in ct_includes)
                                if not ok_ct:
                                    return False
                            if excludes:
                                for tok in excludes:
                                    if tok and (tok in url_l or tok in ct or tok in (headers.get("content-disposition") or "").lower()):
                                        return False
                            return True

                        should_save = match_filters()
                        if not should_save:
                            if not is_swf:
                                sig = body[:3]
                                if sig not in (b"FWS", b"CWS", b"ZWS"):
                                    return
                                self.root.after(0, lambda: self.log_line(f"Signature-detected SWF from {req_url}"))
                        else:
                            self.root.after(0, lambda: self.log_line(f"Detected by filters {req_url}"))
                        seen.add(req_url)
                        path = urllib.parse.urlparse(req_url).path
                        base = os.path.basename(path) or "file.swf"
                        base = sanitize_name(base)
                        if base == "file.swf":
                            cd_hdr = (headers.get("content-disposition") or "")
                            m = re.search(r'filename="?([^";]+)"?', cd_hdr, re.IGNORECASE)
                            if m:
                                cand = sanitize_name(m.group(1))
                                if cand:
                                    base = cand
                        if mirror:
                            host = urllib.parse.urlparse(req_url).hostname or ""
                            dir_path = os.path.dirname(path)
                            safe_parts = [sanitize_name(p) for p in dir_path.split('/') if p]
                            target_dir = os.path.join(outdir, sanitize_name(host), *safe_parts)
                        else:
                            target_dir = outdir
                        os.makedirs(target_dir, exist_ok=True)
                        fp = os.path.join(target_dir, base)
                        with open(fp, "wb") as f:
                            f.write(body)
                        self.root.after(0, lambda: self.log_line(f"Saved {fp}"))
                    except Exception as e:
                        msg = f"Error: {e}"
                        self.root.after(0, lambda m=msg: self.log_line(m))
                page.on("response", lambda r: asyncio.create_task(process_response(r)))
                go_url = self._normalize_url(url)
                try:
                    await page.goto(go_url)
                    self.root.after(0, lambda: self.log_line("Navigated"))
                except Exception as nav_e:
                    try:
                        if go_url.startswith("https://"):
                            alt = "http://" + go_url[len("https://"):]
                            await page.goto(alt)
                            self.root.after(0, lambda: self.log_line("Navigated via http"))
                        else:
                            raise nav_e
                    except Exception:
                        msg = f"Navigation error: {nav_e}"
                        self.root.after(0, lambda m=msg: self.log_line(m))
                while not self.stop_event.is_set():
                    await asyncio.sleep(0.1)
                try:
                    if browser:
                        await browser.close()
                    else:
                        await context.close()
                except Exception:
                    pass
        except Exception as e:
            msg = str(e)
            self.root.after(0, lambda m=msg: self.log_line(m))

    def kill_edge_tasks(self):
        try:
            r = subprocess.run(["taskkill", "/F", "/IM", "msedge.exe"], capture_output=True, text=True)
            out = r.stdout.strip() or r.stderr.strip() or "Done"
            self.log_line(out)
            try:
                if self.edge_proc and self.edge_proc.poll() is None:
                    self.edge_proc.terminate()
            except Exception:
                pass
            self.edge_proc = None
        except Exception as e:
            self.log_line(str(e))

    def verify_cdp(self):
        try:
            port = self.cdp_port_var.get().strip() or "9222"
            if self.cdp_profile_dir:
                dtp = os.path.join(self.cdp_profile_dir, "DevToolsActivePort")
                try:
                    with open(dtp, "r", encoding="utf-8") as f:
                        lines = f.read().strip().splitlines()
                    if lines:
                        p = lines[0].strip()
                        self.log_line(f"DevToolsActivePort port: {p}")
                    if len(lines) > 1:
                        self.log_line(f"DevToolsActivePort ws path: {lines[1].strip()}")
                except Exception:
                    pass
            for host in ("127.0.0.1", "localhost", "[::1]"):
                try:
                    with urllib.request.urlopen(f"http://{host}:{port}/json/version", timeout=2) as resp:
                        data = resp.read().decode("utf-8", errors="ignore")
                        self.log_line(f"CDP OK on {host}:{port}")
                        self.log_line(data)
                        return
                except Exception:
                    pass
            try:
                threading.Thread(target=self._verify_cdp_run, args=(port,), daemon=True).start()
                return
            except Exception:
                pass
            if self.cdp_profile_dir:
                dtp = os.path.join(self.cdp_profile_dir, "DevToolsActivePort")
                try:
                    with open(dtp, "r", encoding="utf-8") as f:
                        lines = f.read().strip().splitlines()
                    if lines:
                        p = lines[0].strip()
                        self.log_line(f"DevToolsActivePort port: {p}")
                    if len(lines) > 1:
                        self.log_line(f"DevToolsActivePort ws path: {lines[1].strip()}")
                except Exception:
                    pass
            self.log_line("CDP not reachable")
        except Exception as e:
            self.log_line(str(e))

    def _verify_cdp_run(self, port):
        try:
            asyncio.run(self._verify_cdp_async(port))
        except Exception as e:
            self.root.after(0, lambda: self.log_line(str(e)))

    async def _verify_cdp_async(self, port):
        try:
            from playwright.async_api import async_playwright
        except Exception:
            self.root.after(0, lambda: self.log_line("Install playwright: pip install playwright, then: python -m playwright install"))
            return
        try:
            async with async_playwright() as p:
                ws_url = None
                if self.cdp_profile_dir:
                    dtp = os.path.join(self.cdp_profile_dir, "DevToolsActivePort")
                    try:
                        with open(dtp, "r", encoding="utf-8") as f:
                            lines = f.read().strip().splitlines()
                        if len(lines) > 1:
                            pval = lines[0].strip()
                            pathval = lines[1].strip()
                            ws_url = f"ws://127.0.0.1:{pval}{pathval}"
                    except Exception:
                        pass
                browser = None
                if ws_url:
                    try:
                        browser = await p.chromium.connect_over_cdp(ws_url)
                        await browser.close()
                        self.root.after(0, lambda: self.log_line(f"CDP websocket connect OK: {ws_url}"))
                        return
                    except Exception as e:
                        self.root.after(0, lambda: self.log_line(f"Websocket connect failed: {e}"))
                for host in ("127.0.0.1", "localhost"):
                    try:
                        browser = await p.chromium.connect_over_cdp(f"http://{host}:{port}")
                        await browser.close()
                        self.root.after(0, lambda: self.log_line(f"CDP HTTP connect OK: http://{host}:{port}"))
                        return
                    except Exception as e:
                        self.root.after(0, lambda: self.log_line(f"HTTP connect failed on {host}:{port}: {e}"))
                self.root.after(0, lambda: self.log_line("CDP not reachable"))
        except Exception as e:
            self.root.after(0, lambda: self.log_line(str(e)))

    def check_edge_policy(self):
        try:
            keys = [
                (winreg.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Edge"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Microsoft\Edge"),
            ]
            found = False
            for hive, path in keys:
                try:
                    k = winreg.OpenKey(hive, path)
                    try:
                        val, _ = winreg.QueryValueEx(k, "DeveloperToolsAvailability")
                        self.log_line(f"Policy DeveloperToolsAvailability at {path}: {val}")
                        found = True
                    except FileNotFoundError:
                        pass
                    finally:
                        winreg.CloseKey(k)
                except FileNotFoundError:
                    continue
            if not found:
                self.log_line("No Edge DevTools policy found (default allows DevTools)")
            else:
                self.log_line("Value 2 disables DevTools; 1 allows; 0 default")
        except Exception as e:
            self.log_line(str(e))

    def _settings_path(self):
        d = os.path.join(os.path.expanduser("~"), ".swf_downloader")
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, "settings.json")

    def save_settings(self):
        data = {
            "url": self.url_var.get(),
            "dir": self.dir_var.get(),
            "domain_only": bool(self.domain_only_var.get()),
            "capture_mode": self.capture_mode.get(),
            "browser_engine": self.browser_engine.get(),
            "edge_path": self.edge_path_var.get(),
            "ruffle_enable": bool(self.ruffle_enable_var.get()),
            "ruffle_path": self.ruffle_path_var.get(),
            "includes": self.includes_var.get(),
            "excludes": self.excludes_var.get(),
            "ct_includes": self.ct_includes_var.get(),
            "host_includes": self.host_includes_var.get(),
            "host_excludes": self.host_excludes_var.get(),
            "mirror": bool(self.mirror_var.get()),
            "proxy_save_all": bool(self.proxy_save_all_var.get()),
            "cdp_port": self.cdp_port_var.get(),
        }
        try:
            with open(self._settings_path(), "w", encoding="utf-8") as f:
                json.dump(data, f)
            self.log_line("Settings saved")
        except Exception as e:
            self.log_line(str(e))

    def load_settings(self):
        try:
            with open(self._settings_path(), "r", encoding="utf-8") as f:
                data = json.load(f)
            self.url_var.set(data.get("url", ""))
            self.dir_var.set(data.get("dir", ""))
            self.domain_only_var.set(bool(data.get("domain_only", False)))
            self.capture_mode.set(data.get("capture_mode", "playwright"))
            self.browser_engine.set(data.get("browser_engine", "edge"))
            self.edge_path_var.set(data.get("edge_path", ""))
            self.ruffle_enable_var.set(bool(data.get("ruffle_enable", True)))
            self.ruffle_path_var.set(data.get("ruffle_path", ""))
            self.includes_var.set(data.get("includes", ".swf"))
            self.excludes_var.set(data.get("excludes", ""))
            self.ct_includes_var.set(data.get("ct_includes", ""))
            self.host_includes_var.set(data.get("host_includes", ""))
            self.host_excludes_var.set(data.get("host_excludes", ""))
            self.mirror_var.set(bool(data.get("mirror", False)))
            self.proxy_save_all_var.set(bool(data.get("proxy_save_all", False)))
            self.cdp_port_var.set(data.get("cdp_port", "9222"))
            self.log_line("Settings loaded")
        except FileNotFoundError:
            pass
        except Exception as e:
            self.log_line(str(e))

    def _run_proxy_capture(self, url, outdir, domain_only, host_includes, host_excludes, includes, excludes, ct_includes, mirror, engine, engine_path):
        try:
            script_path = os.path.join(os.path.dirname(__file__), "mitm_swf.py")
            mitmdump = shutil.which("mitmdump")
            if not mitmdump:
                self.root.after(0, lambda: self.log_line("Install mitmproxy: pip install mitmproxy"))
                return
            os.makedirs(outdir, exist_ok=True)
            target_host = urllib.parse.urlparse(url).hostname or ""
            port = "8888"
            args = [mitmdump, "--listen-host", "127.0.0.1", "-p", port, "-s", script_path]
            env = os.environ.copy()
            env["SWF_OUTDIR"] = outdir
            env["SWF_HOST"] = (target_host if domain_only else "")
            env["SWF_HOST_INCLUDES"] = ",".join(host_includes)
            env["SWF_HOST_EXCLUDES"] = ",".join(host_excludes)
            env["SWF_INCLUDES"] = ",".join(includes)
            env["SWF_EXCLUDES"] = ",".join(excludes)
            env["SWF_CT_INCLUDES"] = ",".join(ct_includes)
            env["SWF_MIRROR"] = ("1" if mirror else "0")
            env["SWF_SAVE_ALL"] = ("1" if self.proxy_save_all_var.get() else "0")
            self.root.after(0, lambda: self.log_line(f"Starting proxy on 127.0.0.1:{port}"))
            self.mitm_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1, text=True, env=env)
            if engine == "edge":
                edge_path = engine_path or shutil.which("msedge")
                if not edge_path:
                    candidates = [
                        r"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                        r"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
                    ]
                    for c in candidates:
                        if os.path.exists(c):
                            edge_path = c
                            break
                if not edge_path:
                    self.root.after(0, lambda: self.log_line("Edge not found"))
                    return
                user_dir = os.path.join(os.path.expanduser("~"), ".swf_downloader", "edge_proxy_profile")
                os.makedirs(user_dir, exist_ok=True)
                launch_args = [edge_path, f"--proxy-server=127.0.0.1:{port}", f"--user-data-dir={user_dir}", "--new-window", url]
                self.root.after(0, lambda: self.log_line("Launching Edge with proxy"))
                self.edge_proc = subprocess.Popen(launch_args)
            elif engine == "palemoon":
                pm_path = engine_path
                if not pm_path:
                    candidates = [
                        r"C:\\Program Files\\Pale Moon\\palemoon.exe",
                        r"C:\\Program Files (x86)\\Pale Moon\\palemoon.exe",
                    ]
                    for c in candidates:
                        if os.path.exists(c):
                            pm_path = c
                            break
                if not pm_path:
                    self.root.after(0, lambda: self.log_line("Pale Moon not found"))
                    return
                profile_dir = os.path.join(os.path.expanduser("~"), ".swf_downloader", "palemoon_proxy_profile")
                os.makedirs(profile_dir, exist_ok=True)
                user_js = os.path.join(profile_dir, "user.js")
                try:
                    with open(user_js, "w", encoding="utf-8") as f:
                        f.write('\n'.join([
                            'user_pref("network.proxy.type", 1);',
                            'user_pref("network.proxy.http", "127.0.0.1");',
                            f'user_pref("network.proxy.http_port", {port});',
                            'user_pref("network.proxy.ssl", "127.0.0.1");',
                            f'user_pref("network.proxy.ssl_port", {port});',
                            'user_pref("network.proxy.no_proxies_on", "");',
                            'user_pref("network.proxy.share_proxy_settings", true);',
                        ]))
                except Exception as e:
                    self.root.after(0, lambda: self.log_line(f"Failed to write user.js: {e}"))
                launch_args = [pm_path, '-no-remote', '-new-instance', '-profile', profile_dir, url]
                self.root.after(0, lambda: self.log_line("Launching Pale Moon with proxy profile"))
                self.edge_proc = subprocess.Popen(launch_args)
            self.root.after(0, lambda: self.log_line("If HTTPS fails, trust mitmproxy CA: mitmproxy --set block_global=false, then open http://mitm.it"))
            def read_mitm_output():
                try:
                    for line in self.mitm_proc.stdout:
                        ln = line.strip()
                        if ln:
                            self.root.after(0, lambda m=ln: self.log_line(m))
                except Exception:
                    pass
            threading.Thread(target=read_mitm_output, daemon=True).start()
            while not self.stop_event.is_set():
                try:
                    if self.mitm_proc and self.mitm_proc.poll() is not None:
                        break
                except Exception:
                    pass
                time.sleep(0.2)
        except Exception as e:
            msg = str(e)
            self.root.after(0, lambda m=msg: self.log_line(m))

    def _run_cdp_capture(self, url, outdir, domain_only, host_includes, host_excludes, includes, excludes, ct_includes, mirror, port):
        asyncio.run(self._capture_cdp_async(url, outdir, domain_only, host_includes, host_excludes, includes, excludes, ct_includes, mirror, port))

    def _run_import_har(self, fp, outdir, host_includes, host_excludes, includes, excludes, ct_includes, mirror):
        try:
            with open(fp, "r", encoding="utf-8") as f:
                har = json.load(f)
            entries = (har.get("log", {}).get("entries", []) or [])
            saved = 0
            for e in entries:
                try:
                    url = (e.get("request", {}).get("url") or "")
                    resp = e.get("response", {})
                    headers = resp.get("headers", [])
                    def get_hdr(name):
                        for h in headers:
                            if (h.get("name") or "").lower() == name:
                                return h.get("value") or ""
                        return ""
                    ct = (resp.get("content", {}).get("mimeType") or get_hdr("content-type") or "").lower()
                    cd = (get_hdr("content-disposition") or "").lower()
                    url_l = url.lower()
                    def match_filters():
                        up = urllib.parse.urlparse(url)
                        hu = up.hostname or ""
                        if host_includes:
                            hit_h = False
                            for tok in host_includes:
                                if tok == "*":
                                    hit_h = True
                                    break
                                if tok and (hu == tok or hu.endswith("." + tok)):
                                    hit_h = True
                                    break
                            if not hit_h:
                                return False
                        if host_excludes:
                            for tok in host_excludes:
                                if tok and (hu == tok or hu.endswith("." + tok)):
                                    return False
                        if includes:
                            hit = False
                            for tok in includes:
                                if tok == "*":
                                    hit = True
                                    break
                                if tok and (tok in url_l or tok in cd):
                                    hit = True
                                    break
                            if not hit:
                                return False
                        if ct_includes:
                            if not any(t in ct for t in ct_includes):
                                return False
                        if excludes:
                            for tok in excludes:
                                if tok and (tok in url_l or tok in ct or tok in cd):
                                    return False
                        return True
                    should_save = match_filters()
                    content = resp.get("content", {})
                    text = content.get("text")
                    if text is None:
                        continue
                    enc = (content.get("encoding") or "").lower()
                    import base64
                    if enc == "base64":
                        body = base64.b64decode(text)
                    else:
                        body = text.encode("utf-8", errors="replace")
                    if not should_save:
                        sig = body[:3]
                        if sig not in (b"FWS", b"CWS", b"ZWS"):
                            continue
                    path = urllib.parse.urlparse(url).path
                    base = os.path.basename(path) or "file"
                    m = re.search(r'filename="?([^";]+)"?', cd, re.IGNORECASE)
                    if m:
                        cand = sanitize_name(m.group(1))
                        if cand:
                            base = cand
                    base = sanitize_name(base)
                    if mirror:
                        host = urllib.parse.urlparse(url).hostname or ""
                        dir_path = os.path.dirname(path)
                        safe_parts = [sanitize_name(p) for p in dir_path.split('/') if p]
                        target_dir = os.path.join(outdir, sanitize_name(host), *safe_parts)
                    else:
                        target_dir = outdir
                    os.makedirs(target_dir, exist_ok=True)
                    fp_out = os.path.join(target_dir, base)
                    with open(fp_out, "wb") as wf:
                        wf.write(body)
                    saved += 1
                    self.root.after(0, lambda m=f"Saved {fp_out}": self.log_line(m))
                except Exception as ie:
                    self.root.after(0, lambda m=str(ie): self.log_line(m))
            self.root.after(0, lambda m=f"HAR import done: {saved} saved": self.log_line(m))
        except Exception as e:
            self.root.after(0, lambda m=str(e): self.log_line(m))

    def _run_import_saz(self, fp, outdir, host_includes, host_excludes, includes, excludes, ct_includes, mirror):
        try:
            import zipfile
            z = zipfile.ZipFile(fp, 'r')
            names = z.namelist()
            groups = {}
            for n in names:
                if not n.lower().startswith('raw/'):
                    continue
                bn = os.path.basename(n)
                m = re.match(r'^(\d+)_', bn)
                if not m:
                    continue
                key = m.group(1)
                groups.setdefault(key, []).append(n)
            saved = 0
            for key, files in groups.items():
                try:
                    req_hdr = next((n for n in files if n.lower().endswith('_c.txt')), None)
                    rsp_hdr = next((n for n in files if n.lower().endswith('_s.txt')), None)
                    body_n = None
                    for cand in files:
                        cl = cand.lower()
                        if cl.endswith('_b.dat') or cl.endswith('_s.dat') or cl.endswith('_msbody.dat') or cl.endswith('_responsebody.dat'):
                            body_n = cand
                            break
                    if not req_hdr or not rsp_hdr or not body_n:
                        continue
                    req = z.read(req_hdr).decode('utf-8', errors='replace')
                    rsp = z.read(rsp_hdr).decode('utf-8', errors='replace')
                    body = z.read(body_n)
                    lines = req.splitlines()
                    first = lines[0] if lines else ''
                    host = ''
                    path = ''
                    if first:
                        parts = first.split()
                        if len(parts) >= 2:
                            pth = parts[1]
                            if pth.startswith('http://') or pth.startswith('https://'):
                                url = pth
                            else:
                                for ln in lines:
                                    if ln.lower().startswith('host:'):
                                        host = ln.split(':', 1)[1].strip()
                                        break
                                url = ('http://' + host + pth) if host else pth
                        else:
                            url = ''
                    else:
                        url = ''
                    headers = {}
                    for ln in rsp.splitlines():
                        if ':' in ln:
                            k, v = ln.split(':', 1)
                            headers[k.strip().lower()] = v.strip()
                    ct = (headers.get('content-type') or '').lower()
                    cd = (headers.get('content-disposition') or '').lower()
                    url_l = url.lower()
                    def match_filters():
                        up = urllib.parse.urlparse(url)
                        hu = up.hostname or ''
                        if host_includes:
                            hit_h = False
                            for tok in host_includes:
                                if tok == '*':
                                    hit_h = True
                                    break
                                if tok and (hu == tok or hu.endswith('.' + tok)):
                                    hit_h = True
                                    break
                            if not hit_h:
                                return False
                        if host_excludes:
                            for tok in host_excludes:
                                if tok and (hu == tok or hu.endswith('.' + tok)):
                                    return False
                        if includes:
                            hit = False
                            for tok in includes:
                                if tok == '*':
                                    hit = True
                                    break
                                if tok and (tok in url_l or tok in cd):
                                    hit = True
                                    break
                            if not hit:
                                return False
                        if ct_includes:
                            if not any(t in ct for t in ct_includes):
                                return False
                        if excludes:
                            for tok in excludes:
                                if tok and (tok in url_l or tok in ct or tok in cd):
                                    return False
                        return True
                    should_save = match_filters()
                    if not should_save:
                        sig = body[:3]
                        if sig not in (b'FWS', b'CWS', b'ZWS'):
                            continue
                    up = urllib.parse.urlparse(url)
                    path = up.path
                    base = os.path.basename(path) or 'file'
                    mfn = re.search(r'filename="?([^";]+)"?', cd, re.IGNORECASE)
                    if mfn:
                        cand = sanitize_name(mfn.group(1))
                        if cand:
                            base = cand
                    base = sanitize_name(base)
                    if mirror:
                        host = up.hostname or ''
                        dir_path = os.path.dirname(path)
                        safe_parts = [sanitize_name(p) for p in dir_path.split('/') if p]
                        target_dir = os.path.join(outdir, sanitize_name(host), *safe_parts)
                    else:
                        target_dir = outdir
                    os.makedirs(target_dir, exist_ok=True)
                    fp_out = os.path.join(target_dir, base)
                    with open(fp_out, 'wb') as wf:
                        wf.write(body)
                    saved += 1
                    self.root.after(0, lambda m=f"Saved {fp_out}": self.log_line(m))
                except Exception as ie:
                    self.root.after(0, lambda m=str(ie): self.log_line(m))
            self.root.after(0, lambda m=f"SAZ import done: {saved} saved": self.log_line(m))
        except Exception as e:
            self.root.after(0, lambda m=str(e): self.log_line(m))

    async def _capture_cdp_async(self, url, outdir, domain_only, host_includes, host_excludes, includes, excludes, ct_includes, mirror, port):
        try:
            from playwright.async_api import async_playwright
        except Exception:
            self.root.after(0, lambda: self.log_line("Install playwright: pip install playwright, then: python -m playwright install"))
            return
        try:
            async with async_playwright() as p:
                def wait_ready(pn, timeout_ms=10000):
                    import time
                    start = time.time()
                    host_used = None
                    while (time.time() - start) * 1000 < timeout_ms:
                        for host in ("127.0.0.1", "localhost"):
                            try:
                                with urllib.request.urlopen(f"http://{host}:{pn}/json/version", timeout=1) as resp:
                                    host_used = host
                                    return host_used
                            except Exception:
                                pass
                        time.sleep(0.2)
                    return host_used

                # Prefer DevToolsActivePort if present
                browser = None
                connected_info = ""
                dtp = os.path.join(self.cdp_profile_dir or "", "DevToolsActivePort")
                if os.path.isfile(dtp):
                    try:
                        with open(dtp, "r", encoding="utf-8") as f:
                            lines = f.read().strip().splitlines()
                        if lines:
                            port = lines[0].strip()
                        if len(lines) > 1:
                            ws_path = lines[1].strip()
                            ws_url = f"ws://127.0.0.1:{port}{ws_path}"
                            browser = await p.chromium.connect_over_cdp(ws_url)
                            connected_info = f"127.0.0.1:{port} (ws)"
                    except Exception:
                        pass
                host = None if browser else wait_ready(port, 3000)
                if not host:
                    self.root.after(0, lambda: self.log_line("Edge CDP not detected; launching Edge now"))
                    try:
                        self.launch_edge_cdp()
                    except Exception as e:
                        self.root.after(0, lambda: self.log_line(str(e)))
                    # Wait for DevToolsActivePort first if auto-port
                    dtp = os.path.join(self.cdp_profile_dir or "", "DevToolsActivePort")
                    import time
                    for _ in range(50):
                        if os.path.isfile(dtp):
                            break
                        time.sleep(0.2)
                    if os.path.isfile(dtp) and browser is None:
                        try:
                            with open(dtp, "r", encoding="utf-8") as f:
                                lines = f.read().strip().splitlines()
                            if lines:
                                port = lines[0].strip()
                            if len(lines) > 1:
                                ws_path = lines[1].strip()
                                ws_url = f"ws://127.0.0.1:{port}{ws_path}"
                                browser = await p.chromium.connect_over_cdp(ws_url)
                                connected_info = f"127.0.0.1:{port} (ws)"
                        except Exception:
                            pass
                    if browser is None:
                        host = wait_ready(port, 10000)
                if not host and self.cdp_profile_dir:
                    dtp = os.path.join(self.cdp_profile_dir, "DevToolsActivePort")
                    try:
                        with open(dtp, "r", encoding="utf-8") as f:
                            lines = f.read().strip().splitlines()
                        if lines:
                            port = lines[0].strip()
                        if len(lines) > 1:
                            ws_path = lines[1].strip()
                            ws_url = f"ws://127.0.0.1:{port}{ws_path}"
                            browser = await p.chromium.connect_over_cdp(ws_url)
                            connected_info = f"127.0.0.1:{port} (ws)"
                        else:
                            host = "127.0.0.1"
                            browser = await p.chromium.connect_over_cdp(f"http://{host}:{port}")
                            connected_info = f"{host}:{port}"
                    except Exception:
                        pass
                else:
                    if not host:
                        self.root.after(0, lambda: self.log_line("Failed to detect Edge CDP. Ensure Edge launched with --remote-debugging-port."))
                        return
                    browser = await p.chromium.connect_over_cdp(f"http://{host}:{port}")
                    connected_info = f"{host}:{port}"

                if browser is None:
                    self.root.after(0, lambda: self.log_line("Failed to connect to Edge CDP"))
                    return
                self.root.after(0, lambda: self.log_line(f"Connected to Edge CDP on {connected_info}"))
                contexts = browser.contexts
                if not contexts:
                    context = await browser.new_context()
                else:
                    context = contexts[0]
                seen = set()
                target_host = urllib.parse.urlparse(url).hostname or ""
                async def process_response(response):
                    try:
                        req_url = response.url or ""
                        headers = response.headers or {}
                        ct = (headers.get("content-type") or "").lower()
                        if domain_only and target_host:
                            resp_host = urllib.parse.urlparse(req_url).hostname or ""
                            if resp_host and not (resp_host == target_host or resp_host.endswith("." + target_host)):
                                return
                        resp_host = urllib.parse.urlparse(req_url).hostname or ""
                        url_l = req_url.lower()
                        cd = (headers.get("content-disposition") or "").lower()
                        def match_filters():
                            if host_includes:
                                hit_h = False
                                for tok in host_includes:
                                    if tok == "*":
                                        hit_h = True
                                        break
                                    if tok and (resp_host == tok or resp_host.endswith("." + tok)):
                                        hit_h = True
                                        break
                                if not hit_h:
                                    return False
                            if host_excludes:
                                for tok in host_excludes:
                                    if tok and (resp_host == tok or resp_host.endswith("." + tok)):
                                        return False
                            if includes:
                                inc_hit = False
                                for tok in includes:
                                    if tok == "*":
                                        inc_hit = True
                                        break
                                    if tok and (tok in url_l or tok in cd):
                                        inc_hit = True
                                        break
                                if not inc_hit:
                                    return False
                            if ct_includes:
                                ok_ct = any(t in ct for t in ct_includes)
                                if not ok_ct:
                                    return False
                            if excludes:
                                for tok in excludes:
                                    if tok and (tok in url_l or tok in ct or tok in cd):
                                        return False
                            return True
                        should_save = match_filters()
                        if req_url in seen and should_save:
                            return
                        body = await response.body()
                        if not should_save:
                            sig = body[:3]
                            if sig not in (b"FWS", b"CWS", b"ZWS"):
                                return
                            self.root.after(0, lambda: self.log_line(f"Signature-detected SWF from {req_url}"))
                        else:
                            self.root.after(0, lambda: self.log_line(f"Detected by filters {req_url}"))
                        seen.add(req_url)
                        path = urllib.parse.urlparse(req_url).path
                        base = os.path.basename(path) or "file.swf"
                        base = sanitize_name(base)
                        if base == "file.swf":
                            cd_hdr = cd
                            m = re.search(r'filename="?([^";]+)"?', cd_hdr, re.IGNORECASE)
                            if m:
                                cand = sanitize_name(m.group(1))
                                if cand:
                                    base = cand
                        if mirror:
                            host = urllib.parse.urlparse(req_url).hostname or ""
                            dir_path = os.path.dirname(path)
                            safe_parts = [sanitize_name(p) for p in dir_path.split('/') if p]
                            target_dir = os.path.join(outdir, sanitize_name(host), *safe_parts)
                        else:
                            target_dir = outdir
                        os.makedirs(target_dir, exist_ok=True)
                        fp = os.path.join(target_dir, base)
                        with open(fp, "wb") as f:
                            f.write(body)
                        self.root.after(0, lambda: self.log_line(f"Saved {fp}"))
                    except Exception as e:
                        msg = f"Error: {e}"
                        self.root.after(0, lambda m=msg: self.log_line(m))

                # Attach to existing pages and future pages
                for ctx in browser.contexts:
                    for pg in ctx.pages:
                        pg.on("response", lambda r: asyncio.create_task(process_response(r)))
                    ctx.on("page", lambda pg: pg.on("response", lambda r: asyncio.create_task(process_response(r))))

                if url:
                    try:
                        page = await context.new_page()
                        await page.goto(url)
                        self.root.after(0, lambda: self.log_line("Navigated"))
                    except Exception as nav_e:
                        self.root.after(0, lambda: self.log_line(f"Navigation error: {nav_e}"))

                while not self.stop_event.is_set():
                    await asyncio.sleep(0.1)
                try:
                    await browser.close()
                except Exception:
                    pass
        except Exception as e:
            msg = str(e)
            self.root.after(0, lambda m=msg: self.log_line(m))

def main():
    root = tk.Tk()
    app = SwfDownloaderApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
