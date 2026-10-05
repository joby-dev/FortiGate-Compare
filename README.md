# Firewall Configuration Compare

A Streamlit utility for comparing two complete FortiGate configuration
exports. Choose Pre/Post or HA comparison, upload both files, select optional
ignore filters, then open the dedicated fullscreen comparison window.

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
For HA comparisons, choose Policy ID Match, Functional Match, or Sequence
Validation. Functional matching pairs policies by their interfaces, addresses,
services, action, schedule, NAT, and security profiles, even when policy IDs
differ. The summary reports exact, equivalent, modified, missing, and reordered
policies.

The fullscreen comparison uses Monaco's virtualized diff editor with
SequenceMatcher-based difference blocks, synchronized block navigation, source
line mapping, and horizontal scrolling for long lines. The editor loads from
jsDelivr, so browser access to `cdn.jsdelivr.net` is required. HTML/TXT export is
also available. Hostname, interface IP, UUID, comments, configuration revisions,
and HA settings can optionally be ignored.

Run comparison regression checks with:

```powershell
python -m unittest discover -v
```