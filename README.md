# Firewall Configuration Compare

A Streamlit utility for comparing FortiGate configurations and troubleshooting
active sessions. Choose HA Comparison, Configuration Comparison, or Session
Analyzer from the page selector.

## Requirements

- Python 3.10 or newer
- The packages listed in `requirements.txt`

## Run on Windows

Open PowerShell in this folder and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

Streamlit prints a local URL, usually `http://localhost:8501`. Choose **Pre/Post
Comparison** or **HA Firewall A vs Firewall B Comparison** before uploading.

The included `.streamlit/config.toml` permits uploads up to 500 MB per file.
For HA comparisons, choose Policy ID Match or Functional Match. Functional
matching pairs policies by their interfaces, addresses, services, action,
schedule, NAT, and security profiles, even when policy IDs differ. The summary
reports exact, equivalent, modified, and missing policies.

The fullscreen comparison uses Monaco's virtualized diff editor with
SequenceMatcher-based difference blocks, synchronized block navigation, source
line mapping, and horizontal scrolling for long lines. The editor loads from
jsDelivr, so browser access to `cdn.jsdelivr.net` is required. HTML/TXT export is
also available. Hostname, interface IP, UUID, comments, configuration revisions,
and HA settings can optionally be ignored.

Session Analyzer accepts pasted output from `diagnose sys session list`. It
extracts session details, calculates traffic and throughput, identifies common
services and health findings, and exports a workbook with summary, session,
talker, endpoint, and finding sheets. Parsing is cached for the submitted paste
so interactive filtering does not reparse the input.

Run comparison regression checks with:

```powershell
python -m unittest discover -v
```