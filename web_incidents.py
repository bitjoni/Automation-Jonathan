#!/usr/bin/env python3
"""
Web-baserat GUI för incidentloggar (Flask).

Start: FLASK_APP=web_incidents.py flask run --host=0.0.0.0
Eller: python3 web_incidents.py
"""
from flask import Flask, render_template, send_file, request, jsonify, abort
import os
import re
import sys
from io import BytesIO

app = Flask(__name__, template_folder='templates', static_folder='static')

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# sökvägar som Tk-appen använder också
candidate_dirs = [
    os.path.join(SCRIPT_DIR, 'data'),
    os.path.join(SCRIPT_DIR, '..', 'data'),
    os.path.join(SCRIPT_DIR, 'scripts', 'data'),
]
DATA_DIR = None
for d in candidate_dirs:
    if os.path.isdir(os.path.abspath(d)):
        DATA_DIR = os.path.abspath(d)
        break
if DATA_DIR is None:
    DATA_DIR = os.path.join(SCRIPT_DIR, 'data')
    os.makedirs(DATA_DIR, exist_ok=True)

ANOMALIES_FILE = os.path.join(DATA_DIR, 'anomalies.log')
FINAL_REPORT_FILE = os.path.join(DATA_DIR, 'final_security_report.txt')

# Parsing heuristics (samma som i gui_incidents.py)
ts_re = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})')
severity_re = re.compile(r'\b(CRITICAL|WARNING|ERROR|FEL|VARNING|INFO)\b', re.I)

def detect_severity(text):
    m = severity_re.search(text)
    if not m:
        if 'fel' in text.lower():
            return 'ERROR'
        if 'varning' in text.lower():
            return 'WARNING'
        return 'INFO'
    s = m.group(1).upper()
    if s in ('FEL','ERROR'):
        return 'ERROR'
    if s in ('VARNING','WARNING'):
        return 'WARNING'
    return s

def extract_timestamp(text):
    m = ts_re.search(text)
    if m:
        return m.group(1)
    return ''

def clean_message(text):
    t = ts_re.sub('', text)
    t = severity_re.sub('', t)
    t = re.sub(r'^[\s\-\:\[\]]+', '', t)
    return t.strip()


def load_entries():
    entries = []
    if os.path.isfile(ANOMALIES_FILE):
        try:
            with open(ANOMALIES_FILE, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.rstrip('\n')
                    if not line.strip():
                        continue
                    ts = extract_timestamp(line)
                    sev = detect_severity(line)
                    msg = clean_message(line)
                    entries.append({
                        'time': ts,
                        'severity': sev,
                        'source': 'anomalies.log',
                        'message': msg,
                        'raw': line,
                    })
        except Exception as e:
            print('Kunde inte läsa anomalies.log:', e, file=sys.stderr)
    if os.path.isfile(FINAL_REPORT_FILE):
        try:
            with open(FINAL_REPORT_FILE, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.rstrip('\n')
                    if not line.strip():
                        continue
                    if line.strip().startswith('==='):
                        continue
                    ts = extract_timestamp(line)
                    sev = detect_severity(line)
                    msg = clean_message(line)
                    entries.append({
                        'time': ts,
                        'severity': sev,
                        'source': 'final_security_report.txt',
                        'message': msg,
                        'raw': line,
                    })
        except Exception as e:
            print('Kunde inte läsa final_security_report.txt:', e, file=sys.stderr)
    windows_csv = os.path.join(DATA_DIR, 'windows_services.csv')
    if os.path.isfile(windows_csv):
        entries.append({
            'time': '',
            'severity': 'INFO',
            'source': 'windows_services.csv',
            'message': f'Windows services CSV finns: {os.path.basename(windows_csv)}',
            'raw': ''
        })
    linux_json = os.path.join(DATA_DIR, 'linux_processes.json')
    if os.path.isfile(linux_json):
        entries.append({
            'time': '',
            'severity': 'INFO',
            'source': 'linux_processes.json',
            'message': f'Linux processes JSON finns: {os.path.basename(linux_json)}',
            'raw': ''
        })
    def sort_key(e):
        sev_order = {'CRITICAL':0,'ERROR':0,'WARNING':1,'INFO':2}
        return (sev_order.get(e['severity'],3), e['time'] or '')
    entries.sort(key=sort_key)
    return entries


@app.route('/')
def index():
    entries = load_entries()
    # Allow optional query params for server-side filtering
    q = request.args.get('q','').strip().lower()
    sev = request.args.get('severity','ALL').upper()
    if q or sev != 'ALL':
        filtered = []
        for e in entries:
            if sev != 'ALL' and e['severity'] != sev:
                continue
            hay = ' '.join([e.get('time',''), e.get('severity',''), e.get('source',''), e.get('message','')]).lower()
            if q and q not in hay:
                continue
            filtered.append(e)
        entries = filtered
    return render_template('index.html', entries=entries)


@app.route('/download_report')
def download_report():
    if not os.path.isfile(FINAL_REPORT_FILE):
        abort(404)
    return send_file(FINAL_REPORT_FILE, as_attachment=True, download_name=os.path.basename(FINAL_REPORT_FILE))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)