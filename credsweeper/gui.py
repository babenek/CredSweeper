import os
import queue
import re
import shlex
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from credsweeper import Severity
from credsweeper.logger.logger import Logger

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


class GUI(ttk.Frame):

    def __init__(self, master):
        super().__init__(master, padding=10)
        self.pack(fill="both", expand=True)
        self.q = queue.Queue()
        self.proc = None

        self.src = tk.StringVar()
        self.jobs = tk.IntVar(value=1)
        self.pedantic = tk.BooleanVar()
        self.depth = tk.IntVar(value=0)
        self.severity = tk.StringVar(value="info")
        self.out = tk.StringVar(value="output.json")
        self.log_level = tk.StringVar(value="INFO")

        top = ttk.LabelFrame(self, text="Source (files or directory)", padding=6)
        top.pack(fill="x")
        ttk.Button(top, text="Directory…", command=self.pick_dir).pack(side="right", padx=(6, 0))
        ttk.Button(top, text="Files…", command=self.pick_files).pack(side="right", padx=(6, 0))
        ttk.Entry(top, textvariable=self.src).pack(side="left", fill="x", expand=True)

        opt = ttk.LabelFrame(self, text="Options", padding=6)
        opt.pack(fill="x", pady=6)
        ttk.Label(opt, text="Jobs:").pack(side="left")
        ttk.Spinbox(opt, from_=1, to=99, width=3, textvariable=self.jobs, state="readonly").pack(side="left",
                                                                                                 padx=(4, 0))
        ttk.Checkbutton(opt, text="Pedantic", variable=self.pedantic).pack(side="left", padx=(16, 0))
        ttk.Label(opt, text="Depth:").pack(side="left", padx=(16, 4))
        ttk.Spinbox(opt, from_=0, to=9, width=3, textvariable=self.depth, state="readonly").pack(side="left")
        ttk.Label(opt, text="Severity:").pack(side="left", padx=(16, 4))
        ttk.Combobox(opt, values=[x.value for x in Severity], textvariable=self.severity, width=10,
                     state="readonly").pack(side="left")

        out = ttk.LabelFrame(self, text="Save JSON to", padding=6)
        out.pack(fill="x")
        ttk.Button(out,
                   text="Browse…",
                   command=lambda: self.out.set(
                       filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")]) or self.
                       out.get())).pack(side="right", padx=(6, 0))
        ttk.Entry(out, textvariable=self.out).pack(side="left", fill="x", expand=True)

        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(8, 2))
        self.run_btn = ttk.Button(bar, text="Run", command=self.run)
        self.run_btn.pack(side="left")
        ttk.Label(bar, text="Log level:").pack(side="left", padx=(16, 4))
        ttk.Combobox(bar,
                     values=[y for y, _ in sorted(Logger.LEVELS.items(), key=lambda x: x[1])],
                     textvariable=self.log_level,
                     width=10,
                     state="readonly").pack(side="left")
        ttk.Button(bar, text="Clear", command=self.clear_log).pack(side="right")

        box = ttk.Frame(self)
        box.pack(fill="both", expand=True)
        self.text = tk.Text(box, height=18, wrap="none", state="disabled")
        sb = ttk.Scrollbar(box, command=self.text.yview)
        self.text.configure(yscrollcommand=sb.set)
        self.text.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self.after(100, self.poll)

    def pick_files(self):
        p = filedialog.askopenfilenames(title="Select file(s)")
        if p:
            self.src.set(os.pathsep.join(p))

    def pick_dir(self):
        p = filedialog.askdirectory(title="Select directory", mustexist=True)
        if p:
            self.src.set(p)

    def log(self, s):
        self.text.configure(state="normal")
        self.text.insert("end", s)
        self.text.see("end")
        self.text.configure(state="disabled")

    def clear_log(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")

    def run(self):
        paths = [s.strip() for s in self.src.get().split(os.pathsep) if s.strip()]
        if not paths:
            messagebox.showwarning("CredSweeper", "Select a source first")
            return
        bad = [s for s in paths if not os.path.exists(s)]
        if bad:
            messagebox.showerror("CredSweeper", "Path not found:\n" + "\n".join(bad))
            return

        cmd = [
            sys.executable,
            "-m",
            "credsweeper",
            "--banner",
            "--log",
            self.log_level.get(),
            "--jobs",
            str(self.jobs.get()),
            "--severity",
            self.severity.get(),
            "--path",
            *paths,
        ]
        if depth := self.depth.get():
            cmd += ["--depth", str(depth)]
        if self.pedantic.get():
            cmd.append("--pedantic")
        if self.out.get():
            cmd += ["--save-json", self.out.get()]

        self.log("$ " + shlex.join(cmd) + "\n")
        self.run_btn.configure(state="disabled")
        threading.Thread(target=self.worker, args=(cmd, ), daemon=True).start()

    def worker(self, cmd):
        env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
        try:
            self.proc = subprocess.Popen(cmd,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT,
                                         text=True,
                                         encoding="utf-8",
                                         errors="replace",
                                         env=env,
                                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            for line in self.proc.stdout:
                self.q.put(ANSI_RE.sub("", line))
            self.q.put(f"\n[exit code {self.proc.wait()}]\n")
        except Exception as e:
            self.q.put(f"\n[error] {e!r}\n")
        finally:
            self.q.put(None)

    def poll(self):
        try:
            while True:
                item = self.q.get_nowait()
                if item is None:
                    self.run_btn.configure(state="normal")
                else:
                    self.log(item)
        except queue.Empty:
            pass
        self.after(100, self.poll)

    def on_close(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
        self.master.destroy()


def main():
    root = tk.Tk()
    root.title("CredSweeper GUI")
    root.geometry("760x560")
    gui = GUI(root)
    root.protocol("WM_DELETE_WINDOW", gui.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
