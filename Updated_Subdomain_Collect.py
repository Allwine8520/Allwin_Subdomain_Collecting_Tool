import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import threading
import csv
import os

class SubdomainCollectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Allwin Advanced Subdomain Collecting Tool")
        self.root.geometry("800x520")
        self.root.resizable(False, False)

        # Set TTK theme and style
        self.setup_style()

        mainframe = ttk.Frame(root, style="MyMain.TFrame", padding=16)
        mainframe.pack(fill='both', expand=True)

        title = ttk.Label(mainframe, text="Allwin Advanced Subdomain Collecting Tool",
                          style="Title.TLabel")
        title.grid(row=0, column=0, columnspan=5, pady=(2, 12), sticky='ew')

        # Domain input
        ttk.Label(mainframe, text="Target Domain:", style="MyLabel.TLabel").grid(row=1, column=0, sticky='w')
        self.domain_entry = ttk.Entry(mainframe, width=34)
        self.domain_entry.grid(row=1, column=1, padx=4, pady=3)

        # Wordlist
        ttk.Label(mainframe, text="Wordlist:", style="MyLabel.TLabel").grid(row=1, column=2, sticky='w', padx=(24, 0))
        self.wordlist_var = tk.StringVar(value="subdomains.txt")
        self.wordlist_entry = ttk.Entry(mainframe, textvariable=self.wordlist_var, width=22)
        self.wordlist_entry.grid(row=1, column=3, sticky='w', padx=(0, 0))
        ttk.Button(mainframe, text="Browse", style="Accent.TButton",
                   command=self.browse_wordlist).grid(row=1, column=4, padx=7, pady=2)

        # Timeout and Threads
        ttk.Label(mainframe, text="Timeout (s):", style="MyLabel.TLabel").grid(row=2, column=0, sticky='w')
        self.timeout_spin = ttk.Spinbox(mainframe, from_=1, to=10, width=6)
        self.timeout_spin.grid(row=2, column=1, sticky='w')
        self.timeout_spin.delete(0, "end")
        self.timeout_spin.insert(0, "3")

        ttk.Label(mainframe, text="Threads:", style="MyLabel.TLabel").grid(row=2, column=2, sticky='w', padx=(24, 0))
        self.threads_spin = ttk.Spinbox(mainframe, from_=1, to=50, width=6)
        self.threads_spin.grid(row=2, column=3, sticky='w')
        self.threads_spin.delete(0, "end")
        self.threads_spin.insert(0, "10")

        # Control buttons (Start, Stop, Export)
        self.start_button = ttk.Button(mainframe, text="Start Scan", style="Accent.TButton", command=self.start_scan)
        self.start_button.grid(row=3, column=0, padx=0, pady=9)

        self.stop_button = ttk.Button(mainframe, text="Stop Scan", style="Stop.TButton",
                                      command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=3, column=1, padx=4, pady=9)

        self.export_button = ttk.Button(mainframe, text="Export Results", style="Export.TButton",
                                        command=self.export_results, state=tk.DISABLED)
        self.export_button.grid(row=3, column=2, padx=4, pady=9)

        # Progress bar
        self.progress = ttk.Progressbar(mainframe, length=320, mode="determinate", style="My.Horizontal.TProgressbar")
        self.progress.grid(row=3, column=3, columnspan=2, padx=(4, 0), pady=9, sticky="ew")

        # Results box
        self.result_frame = ttk.Frame(mainframe, style="Box.TFrame")
        self.result_frame.grid(row=4, column=0, columnspan=5, pady=(0, 8), sticky="nsew")
        self.result_box = tk.Text(self.result_frame, width=102, height=14, bg="#202835", fg="#FAFAFA",
                                  insertbackground="#d0bcff", font=("Consolas", 11), borderwidth=0)
        self.result_box.pack(side="left", fill="both", expand=True, padx=(1, 0), pady=3)
        self.result_scroll = ttk.Scrollbar(self.result_frame, orient="vertical", command=self.result_box.yview)
        self.result_scroll.pack(side="right", fill="y")
        self.result_box["yscrollcommand"] = self.result_scroll.set

        # Status label
        self.status_label = ttk.Label(mainframe, text="Idle", style="Status.TLabel")
        self.status_label.grid(row=5, column=0, columnspan=5, sticky='w')

        self.found_subdomains = []
        self.log = []
        self.stop_flag = threading.Event()

    def setup_style(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("MyMain.TFrame", background="#121b25")
        style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"),
                        foreground="#5ad2ff", background="#121b25")
        style.configure("MyLabel.TLabel", font=("Segoe UI", 12, "bold"),
                        foreground="#b7e6ff", background="#121b25")
        style.configure("Accent.TButton", font=("Segoe UI", 11, "bold"),
                        foreground="#1b2f50", background="#5ad2ff", borderwidth=0, relief="flat")
        style.map("Accent.TButton",
            foreground=[("active", "#292929")],
            background=[("active", "#98e0ff")])
        style.configure("Stop.TButton", font=("Segoe UI", 11, "bold"),
                        foreground="#ffffff", background="#ff4040", borderwidth=0, relief="flat")
        style.map("Stop.TButton",
            foreground=[("active", "#292929")],
            background=[("active", "#ff6666")])
        style.configure("Export.TButton", font=("Segoe UI", 11, "bold"),
                        foreground="#ffffff", background="#52c995")
        style.map("Export.TButton",
            foreground=[("active", "#292929")],
            background=[("active", "#85eabf")])
        style.configure("Status.TLabel", font=("Segoe UI", 10, "italic"),
                        background="#121b25", foreground="#90ffe0")
        style.configure("Box.TFrame", background="#202835", borderwidth=1, relief="groove")
        style.configure("My.Horizontal.TProgressbar", troughcolor="#292e49",
                        background="#5ad2ff", bordercolor="#98e0ff", lightcolor="#98e0ff", darkcolor="#4d6eb1")

    def browse_wordlist(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if path:
            self.wordlist_var.set(path)

    def start_scan(self):
        if self.stop_flag.is_set():
            self.stop_flag.clear()
        self.result_box.delete(1.0, tk.END)
        self.log.clear()
        self.found_subdomains.clear()
        domain = self.domain_entry.get().strip()
        wordlist_path = self.wordlist_var.get().strip()
        try:
            timeout = int(self.timeout_spin.get())
            threads = int(self.threads_spin.get())
        except ValueError:
            messagebox.showerror("Input Error", "Timeout and threads must be integers.")
            return
        if not domain:
            messagebox.showerror("Input Error", "Please enter a domain.")
            return
        if not os.path.isfile(wordlist_path):
            messagebox.showerror("File Error", f"Wordlist file '{wordlist_path}' not found.")
            return

        self.export_button.config(state=tk.DISABLED)
        self.status_label.config(text="Scanning...", foreground="#ffe066")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.stop_flag.clear()
        scanning_thread = threading.Thread(target=self.scan_subdomains, args=(domain, wordlist_path, timeout, threads))
        scanning_thread.start()

    def stop_scan(self):
        # Set the stop flag to tell threads to stop scanning asap
        if not self.stop_flag.is_set():
            self.stop_flag.set()
            self.status_label.config(text="Stopping scan...", foreground="#ff6666")
            self.stop_button.config(state=tk.DISABLED)  # Disable stop button during stopping

    def scan_subdomains(self, domain, wordlist_path, timeout, threads):
        try:
            with open(wordlist_path, "r") as f:
                subdomains = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.log_message(f"Wordlist read error: {e}")
            self.safe_update(lambda: self.status_label.config(text="Error"))
            self.safe_update(lambda: self.start_button.config(state=tk.NORMAL))
            self.safe_update(lambda: self.stop_button.config(state=tk.DISABLED))
            return

        total = len(subdomains)
        self.safe_update(lambda: self.progress.config(maximum=total))
        resolver = dns.resolver.Resolver()

        def check_sub(sub):
            if self.stop_flag.is_set():
                return None
            full = f"{sub}.{domain}"
            try:
                ans = resolver.resolve(full, "A", lifetime=timeout)
                ips = [str(rr) for rr in ans]  # IPs gathered but not saved/exported
                self.log_message(f"[+] {full} --> {', '.join(ips)}")
                return (full, ips)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                return None
            except Exception as exc:
                self.log_message(f"[ERROR] {full}: {exc}")
                return None

        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_map = {executor.submit(check_sub, sub): sub for sub in subdomains}
            for fut in as_completed(future_map):
                if self.stop_flag.is_set():
                    break
                res = fut.result()
                self.safe_update(lambda: self.progress.step(1))
                if res:
                    subdomain, ips = res
                    self.found_subdomains.append((subdomain, ips))
                    self.safe_update(
                        lambda: self.result_box.insert(tk.END, f"{subdomain} -> {', '.join(ips)}\n")
                    )
                self.safe_update(lambda: self.result_box.see(tk.END))

        self.safe_update(self.scan_complete)

    def scan_complete(self):
        cnt = len(self.found_subdomains)
        if self.stop_flag.is_set():
            self.status_label.config(text=f"Scan stopped. {cnt} subdomains found.", foreground="#ff6666")
        else:
            self.status_label.config(text=f"Scan complete: {cnt} subdomains found.", foreground="#90ffe0")
        self.export_button.config(state=tk.NORMAL if cnt else tk.DISABLED)
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress["value"] = 0
        self.stop_flag.clear()

    def export_results(self):
        if not self.found_subdomains:
            messagebox.showinfo("No Results", "No subdomains found to export.")
            return
        filetypes = [("Text files", "*.txt"), ("CSV files", "*.csv")]
        filepath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=filetypes)
        if filepath:
            try:
                if filepath.endswith(".csv"):
                    with open(filepath, "w", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerow(["Subdomain"])  # Only subdomain column
                        for sub, _ in self.found_subdomains:
                            writer.writerow([sub])
                else:
                    with open(filepath, "w") as f:
                        for sub, _ in self.found_subdomains:
                            f.write(f"{sub}\n")
                messagebox.showinfo("Export Success", f"Results saved to {filepath}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    def safe_update(self, func):
        self.root.after(0, func)

    def log_message(self, msg):
        self.log.append(msg)
        self.safe_update(lambda: self.status_label.config(text=msg))

if __name__ == "__main__":
    root = tk.Tk()
    app = SubdomainCollectorApp(root)
    root.mainloop()
