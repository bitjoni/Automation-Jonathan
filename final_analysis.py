import json
import csv
import os

# Använd absolut sökväg baserat på script-placeringen
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "data")

# --- Läs Linux-processer ---
try:
    linux_file = os.path.join(DATA_DIR, "linux_processes.json")
    with open(linux_file, "r", encoding="utf-8") as f:
        linux = json.load(f).get("processes", [])
except FileNotFoundError:
    print(f"Fel: linux_processes.json hittades inte ({linux_file})")
    linux = []
except json.JSONDecodeError:
    print("Fel: Ogiltig JSON i linux_processes.json")
    linux = []

# --- Läs Windows-tjänster ---
services = []
try:
    csv_file = os.path.join(DATA_DIR, "windows_services.csv")
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            services.append(row)
except FileNotFoundError:
    print(f"Fel: windows_services.csv hittades inte ({csv_file})")

# --- Läs anomaly-loggen ---
try:
    log_file = os.path.join(DATA_DIR, "anomalies.log")
    with open(log_file, "r", encoding="utf-8") as f:
        anomalies = f.readlines()
except FileNotFoundError:
    print(f"Fel: anomalies.log hittades inte ({log_file})")
    anomalies = []

# --- Risklogik ---
report = []

# Kontrollera misstänkta Linux-processer
linux_risk = [p.get("name") for p in linux if p.get("name") in ["nc", "netcat", "hydra"]]

for p in linux_risk:
    if p:  # Kontrollera att p inte är None
        report.append(f"CRITICAL: Linux riskprocess upptäckt – {p}")

# Kontrollera riskabla Windows-tjänster
risk_services = ["Telnet", "RemoteRegistry", "Spooler"]

for svc in services:
    # Hitta Name-kolumnen (kan heta olika i CSV)
    svc_name = svc.get("Name") or list(svc.values())[0] if svc else None
    if svc_name and svc_name in risk_services:
        report.append(f"WARNING: Riskabel Windows-tjänst – {svc_name}")

# Lägg in anomaly-loggar
report.append("=== ANOMALI-LOGG ===")
report.extend([line.strip() for line in anomalies])

# --- Skriv slutrapport ---
report_file = os.path.join(DATA_DIR, "final_security_report.txt")
with open(report_file, "w", encoding="utf-8") as f:
    f.write(f"=== SÄKERHETSKONTROLL RAPPORT ===\n")
    f.write(f"Linux-processer analyserade: {len(linux)}\n")
    f.write(f"Windows-tjänster analyserade: {len(services)}\n")
    f.write(f"\n")
    for line in report:
        f.write(line + "\n")

print(f"Slutrapport skapad: {report_file}")
print(f"Totalt fynd: {len([r for r in report if r.startswith('CRITICAL') or r.startswith('WARNING')])}")

