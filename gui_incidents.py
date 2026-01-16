#!/usr/bin/env python3
"""
GUI för incidentloggar och säkerhetsrapport.

Funktioner:
- Läser data från data/anomalies.log och data/final_security_report.txt (söker även i parent/data).
- Visar rader i en Treeview med kolumner: Time, Severity, Source, Message.
- Sökfält + severity-filter (Allt/CRITICAL/WARNING/INFO).
- Knapp för Refresh, Open full report, Export selected, Quit.
- Dubbelklick för att visa full text i popup.

Kör: python3 gui_incidents.py
Kräver: Python 3 + Tk som ingår i standard-Python (på Debian/Ubuntu installera paketet python3-tk om saknas).
"""
import os
import re
import sys
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Leta efter data-katalog i några vanliga platser
candidate_dirs = [
    os.path.join(SCRIPT_DIR, "data"),
    os.path.join(SCRIPT_DIR, "..", "data"),
    os.path.join(SCRIPT_DIR, "scripts", "data"),
]
DATA_DIR = None
for d in candidate_dirs:
    if os.path.isdir(os.path.abspath(d)):
        DATA_DIR = os.path.abspath(d)
        break
if DATA_DIR is None:
    # fallback: create ./data next to script
    DATA_DIR = os.path.join(SCRIPT_DIR, "data")
    os.makedirs(DATA_DIR, exist_ok=True)

ANOMALIES_FILE = os.path.join(DATA_DIR, "anomalies.log")
FINAL_REPORT_FILE = os.path.join(DATA_DIR, "final_security_report.txt")

# Parsing heuristics
ts_re = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})')
severity_re = re.compile(r'\b(CRITICAL|WARNING|ERROR|FEL|VARNING|INFO)\b', re.I)

def detect_severity(text):
    m = severity_re.search(text)
    if not m:
        # look for Swedish words
        if "fel" in text.lower():
            return "ERROR"
        if "varning" in text.lower() or "varning" in text:
            return "WARNING"
        return "INFO"
    s = m.group(1).upper()
    if s in ("FEL", "ERROR"):
        return "ERROR"
    if s in ("VARNING", "WARNING"):
        return "WARNING"
    return s

def extract_timestamp(text):
    m = ts_re.search(text)
    if m:
        return m.group(1)
    # try RFC-like "Mon Jan  2 15:04:05" - keep simple: fallback None
    return ""

def clean_message(text):
    # remove timestamp and severity tokens from start if present
    t = ts_re.sub('', text)
    t = severity_re.sub('', t)
    # remove common prefixes like " - " or ":"
    t = re.sub(r'^[\s\-\:\[\]]+', '', t)
    return t.strip()

def load_entries():
    """Läs in rader från anomalies.log och final_security_report.txt och returnera lista av dicts."""
    entries = []
    # Läs anomalies.log först (eller skapa om ej finns)
    if os.path.isfile(ANOMALIES_FILE):
        try:
            with open(ANOMALIES_FILE, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.rstrip("\n")
                    if not line.strip():
                        continue
                    ts = extract_timestamp(line)
                    sev = detect_severity(line)
                    msg = clean_message(line)
                    entries.append({
                        "time": ts,
                        "severity": sev,
                        "source": "anomalies.log",
                        "message": msg,
                        "raw": line,
                    })
        except Exception as e:
            print("Kunde inte läsa anomalies.log:", e, file=sys.stderr)

    # Läs final_security_report.txt (kan innehålla CRITICAL/WARNING + avsnitt ANOMALI-LOGG)
    if os.path.isfile(FINAL_REPORT_FILE):
        try:
            with open(FINAL_REPORT_FILE, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.rstrip("\n")
                    if not line.strip():
                        continue
                    # Hoppa över rubriker
                    if line.strip().startswith("==="):
                        continue
                    ts = extract_timestamp(line)
                    sev = detect_severity(line)
                    msg = clean_message(line)
                    entries.append({
                        "time": ts,
                        "severity": sev,
                        "source": "final_security_report.txt",
                        "message": msg,
                        "raw": line,
                    })
        except Exception as e:
            print("Kunde inte läsa final_security_report.txt:", e, file=sys.stderr)

    # Som sista försök: läs windows_services.csv och linux_processes.json och skapa sammanfattande poster
    windows_csv = os.path.join(DATA_DIR, "windows_services.csv")
    if os.path.isfile(windows_csv):
        entries.append({
            "time": "",
            "severity": "INFO",
            "source": "windows_services.csv",
            "message": f"Windows services CSV finns: {os.path.basename(windows_csv)}",
            "raw": ""
        })
    linux_json = os.path.join(DATA_DIR, "linux_processes.json")
    if os.path.isfile(linux_json):
        entries.append({
            "time": "",
            "severity": "INFO",
            "source": "linux_processes.json",
            "message": f"Linux processes JSON finns: {os.path.basename(linux_json)}",
            "raw": ""
        })
    # Sortera så att kritiska kommer först (CRITICAL/ERROR, WARNING, INFO) och därefter tidsstämpel om finns
    def sort_key(e):
        sev_order = {"CRITICAL": 0, "ERROR": 0, "WARNING": 1, "INFO": 2}
        return (sev_order.get(e["severity"], 3), e["time"] or "")
    entries.sort(key=sort_key)
    return entries

class IncidentGUI:
    def __init__(self, root):
        self.root = root
        root.title("Incidentloggar - GUI")
        root.geometry("1000x600")

        # Top frame: filter + search
        top = ttk.Frame(root, padding=(8,8))
        top.pack(side="top", fill="x")

        ttk.Label(top, text="Sök:").pack(side="left")
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(top, textvariable=self.search_var, width=40)
        search_entry.pack(side="left", padx=(4,8))
        search_entry.bind("<KeyRelease>", lambda e: self.apply_filters())

        ttk.Label(top, text="Severity:").pack(side="left")
        self.sev_var = tk.StringVar(value="ALL")
        sev_combo = ttk.Combobox(top, textvariable=self.sev_var, values=["ALL","CRITICAL","ERROR","WARNING","INFO"], state="readonly", width=10)
        sev_combo.pack(side="left", padx=(4,8))
        sev_combo.bind("<<ComboboxSelected>>", lambda e: self.apply_filters())

        refresh_btn = ttk.Button(top, text="Refresh", command=self.refresh)
        refresh_btn.pack(side="left", padx=(4,2))

        open_report_btn = ttk.Button(top, text="Open Report", command=self.open_report)
        open_report_btn.pack(side="left", padx=(2,2))

        export_btn = ttk.Button(top, text="Export Selected", command=self.export_selected)
        export_btn.pack(side="left", padx=(6,2))

        quit_btn = ttk.Button(top, text="Quit", command=root.quit)
        quit_btn.pack(side="right")

        # Treeview
        columns = ("time","severity","source","message")
        self.tree = ttk.Treeview(root, columns=columns, show="headings")
        self.tree.heading("time", text="Time")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("source", text="Source")
        self.tree.heading("message", text="Message / short")
        self.tree.column("time", width=160, anchor="w")
        self.tree.column("severity", width=90, anchor="center")
        self.tree.column("source", width=180, anchor="w")
        self.tree.column("message", width=560, anchor="w")
        self.tree.pack(side="top", fill="both", expand=True, padx=8, pady=6)

        # scrollbar
        vsb = ttk.Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")

        # Bind double-click
        self.tree.bind("<Double-1>", self.on_double_click)

        # status bar
        self.status = ttk.Label(root, text="Laddar...", anchor="w")
        self.status.pack(side="bottom", fill="x")

        # load entries
        self.all_entries = []
        self.refresh()

    def refresh(self):
        self.status.config(text="Läser in loggar...")
        self.root.update_idletasks()
        self.all_entries = load_entries()
        self.populate_tree(self.all_entries)
        self.status.config(text=f"Laddat {len(self.all_entries)} poster från {DATA_DIR}")

    def populate_tree(self, entries):
        self.tree.delete(*self.tree.get_children())
        for idx, e in enumerate(entries):
            short_msg = e["message"][:200] if e["message"] else ""
            self.tree.insert("", "end", iid=str(idx), values=(e["time"], e["severity"], e["source"], short_msg))

    def apply_filters(self):
        q = self.search_var.get().lower().strip()
        sev = self.sev_var.get()
        filtered = []
        for e in self.all_entries:
            if sev != "ALL" and e["severity"] != sev:
                continue
            hay = " ".join([e.get("time",""), e.get("severity",""), e.get("source",""), e.get("message","")]).lower()
            if q and q not in hay:
                continue
            filtered.append(e)
        self.populate_tree(filtered)
        self.status.config(text=f"Visar {len(filtered)} av {len(self.all_entries)} poster")

    def on_double_click(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            return
        idx = int(item)
        entry = None
        if 0 <= idx < len(self.all_entries):
            entry = self.all_entries[idx]
        else:
            # if filtered view changed iids, try to get values and show them
            vals = self.tree.item(item, "values")
            entry = {"time": vals[0], "severity": vals[1], "source": vals[2], "message": vals[3], "raw": None}
        if entry:
            self.show_entry_detail(entry)

    def show_entry_detail(self, entry):
        top = tk.Toplevel(self.root)
        top.title("Detaljvy")
        top.geometry("800x400")
        txt = tk.Text(top, wrap="word")
        txt.pack(fill="both", expand=True)
        content = f"Source: {entry.get('source')}\nSeverity: {entry.get('severity')}\nTime: {entry.get('time')}\n\nMessage / raw:\n{entry.get('message')}\n\nRaw line:\n{entry.get('raw')}"
        txt.insert("1.0", content)
        txt.config(state="disabled")
        btn = ttk.Button(top, text="Stäng", command=top.destroy)
        btn.pack(pady=6)

    def export_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Export", "Ingen rad vald.")
            return
        lines = []
        for item in sel:
            vals = self.tree.item(item, "values")
            lines.append(f"Time: {vals[0]}\nSeverity: {vals[1]}\nSource: {vals[2]}\nMessage: {vals[3]}\n---\n")
        default = os.path.join(DATA_DIR, f"export_selected_{int(time.time())}.txt")
        path = filedialog.asksaveasfilename(initialfile=default, defaultextension=".txt", filetypes=[("Text","*.txt"),("All","*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            messagebox.showinfo("Export", f"Exporterat {len(lines)} poster till:\n{path}")
        except Exception as e:
            messagebox.showerror("Fel", f"Kunde inte skriva fil: {e}")

    def open_report(self):
        if not os.path.isfile(FINAL_REPORT_FILE):
            messagebox.showinfo("Open Report", f"Ingen fil: {FINAL_REPORT_FILE}")
            return
        try:
            with open(FINAL_REPORT_FILE, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            messagebox.showerror("Fel", f"Kunde inte läsa rapporten: {e}")
            return
        top = tk.Toplevel(self.root)
        top.title("Slutrapport")
        top.geometry("900x600")
        txt = tk.Text(top, wrap="none")
        txt.insert("1.0", content)
        txt.config(state="disabled")
        txt.pack(fill="both", expand=True)
        # add scrollbars
        xscroll = ttk.Scrollbar(top, orient="horizontal", command=txt.xview)
        yscroll = ttk.Scrollbar(top, orient="vertical", command=txt.yview)
        txt.configure(xscrollcommand=xscroll.set, yscrollcommand=yscroll.set)
        xscroll.pack(side="bottom", fill="x")
        yscroll.pack(side="right", fill="y")
        btn = ttk.Button(top, text="Stäng", command=top.destroy)
        btn.pack(pady=6)

def main():
    root = tk.Tk()
    app = IncidentGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()