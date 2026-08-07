"""
HTML Reporter — Azure Audit Pro
Exact same format/structure as AWS CloudAudit Pro html_reporter.py.
- index.html at output root
- service pages in /pages/ subfolder with relative links
- Compliance popup on click
- Severity: Critical=Dark Red, High=Light Red, Medium=Yellow, Low=Green
- Framework compliance % click → shows affected requirements
"""

import json
from pathlib import Path
from datetime import datetime
from engine.compliance_calc import calculate_compliance, severity_counts, load_compliance_requirements

# ── Framework reference links ─────────────────────────────────────────────────
FW_REFS = {
    "CIS":          ("CIS Azure Benchmark 2.0",  "https://www.cisecurity.org/benchmark/azure"),
    "NIST_CSF":     ("NIST CSF 2.0",             "https://www.nist.gov/cyberframework"),
    "NIST_800_53":  ("NIST 800-53 Rev5",         "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"),
    "CSA_CCM":      ("CSA CCM v4.0",             "https://cloudsecurityalliance.org/research/cloud-controls-matrix"),
    "MITRE_ATTACK": ("MITRE ATT&CK Cloud",       "https://attack.mitre.org/matrices/enterprise/cloud/"),
    "HIPAA":        ("HIPAA Security Rule",      "https://www.hhs.gov/hipaa/for-professionals/security/index.html"),
    "PCI_DSS":      ("PCI DSS 4.0",              "https://www.pcisecuritystandards.org/document_library"),
    "GDPR":         ("GDPR",                     "https://gdpr.eu/article-32-security-of-processing/"),
}

SVC_ICONS = {
    "IAM":              "🔑", "Storage":          "💾", "VirtualMachines":  "🖥️",
    "SQL":              "🗄️", "Networking":       "🌐", "KeyVault":         "🔐",
    "Monitor":          "📋", "Defender":         "🛡️", "AKS":              "⚙️",
    "AppService":       "🌍", "Functions":        "⚡", "ServiceBus":       "📨",
    "CosmosDB":         "🌌", "Redis":            "🔴", "ContainerRegistry":"📦",
    "LogicApps":        "🔄", "Backup":           "💿", "Policy":           "📜",
    "DNS":              "🌐", "Security":         "🛡️",
}

SEV_ORDER = ["Critical", "High", "Medium", "Low"]


class HTMLReporter:

    def __init__(self, display):
        self.display = display

    def generate(self, findings, out_dir, account_name, company, partial=False):
        out_dir   = Path(out_dir)
        pages_dir = out_dir / "pages"
        out_dir.mkdir(parents=True, exist_ok=True)
        pages_dir.mkdir(exist_ok=True)

        fails      = [f for f in findings if f.get("status") == "FAIL"]
        by_service = self._group(fails)
        compliance = calculate_compliance(findings, "azure")
        sev        = severity_counts(findings)
        scan_time  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        partial_note = " [PARTIAL SCAN]" if partial else ""

        fw_details = self._build_fw_details(findings)

        (out_dir / "index.html").write_text(
            self._render_index(fails, by_service, compliance, sev,
                               fw_details, account_name, company,
                               scan_time, partial_note),
            encoding="utf-8"
        )

        for svc, svc_findings in by_service.items():
            safe = svc.lower().replace(" ", "_").replace("/", "_")
            (pages_dir / f"{safe}.html").write_text(
                self._render_service(svc, svc_findings, account_name,
                                     company, scan_time, by_service),
                encoding="utf-8"
            )

        self.display.success(
            f"  HTML  → {out_dir}/index.html  "
            f"(+{len(by_service)} service pages in pages/)"
        )
        return out_dir / "index.html"

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _group(self, findings):
        groups  = {}
        sev_map = {s: i for i, s in enumerate(SEV_ORDER)}
        for f in findings:
            groups.setdefault(f.get("service", "Other"), []).append(f)
        for s in groups:
            groups[s].sort(key=lambda f: sev_map.get(f.get("severity", "Low"), 99))
        return groups

    def _build_fw_details(self, findings):
        fw_reqs       = load_compliance_requirements("azure")
        failed_checks = {f.get("check_id") for f in findings if f.get("status") == "FAIL"}
        check_counts  = {}
        for f in findings:
            if f.get("status") == "FAIL":
                cid = f.get("check_id", "")
                check_counts[cid] = check_counts.get(cid, 0) + 1

        result = {}
        for fw_key, reqs in fw_reqs.items():
            fw_name, fw_url = FW_REFS.get(fw_key, (fw_key, "#"))
            affected = []
            for req in reqs:
                req_id   = req.get("Id", "")
                req_desc = req.get("Description", "")
                checks   = req.get("Checks", [])
                hits     = [c for c in checks if c in failed_checks]
                if hits:
                    total_hits = sum(check_counts.get(c, 0) for c in hits)
                    affected.append({
                        "req_id":      req_id,
                        "description": req_desc,
                        "checks":      hits,
                        "count":       total_hits,
                    })
            result[fw_name] = {
                "url":      fw_url,
                "affected": affected,
                "fw_key":   fw_key,
            }
        return result

    # ── CSS — identical to AWS version ────────────────────────────────────────

    def _css(self):
        return """<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:ital,wght@0,400;0,600;0,700;1,400&display=swap');
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2128;--border:#30363d;
  --text:#e6edf3;--muted:#8b949e;--accent:#0078D4;
  /* Severity — same as AWS tool */
  --critical:#C00000;   /* Dark Red  */
  --high:    #FF4444;   /* Light Red */
  --medium:  #FFC107;   /* Yellow    */
  --low:     #4CAF50;   /* Green     */
  --pass:    #00B050;
  --hipaa:#bc8cff;--cis:#58a6ff;--nist:#79c0ff;--csa:#56d364;
  --mitre:#ff7b72;--pci:#ffa657;--gdpr:#e8b4fb;--ct:#f0c000;
  --mono:'IBM Plex Mono',monospace;--sans:'IBM Plex Sans',sans-serif;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
html{scroll-behavior:smooth;}
body{font-family:var(--sans);background:var(--bg);color:var(--text);font-size:13px;line-height:1.5;}

.nav{background:#0d1117;border-bottom:1px solid var(--border);padding:10px 20px;display:flex;
  align-items:center;gap:10px;position:sticky;top:0;z-index:200;flex-wrap:wrap;}
.nav-logo{background:var(--accent);color:#fff;font-weight:700;font-size:11px;padding:3px 9px;
  border-radius:5px;text-decoration:none;font-family:var(--mono);}
.nav-title{font-weight:700;font-size:14px;}
.nav-links{display:flex;gap:4px;flex-wrap:wrap;margin-left:auto;}
.nav-link{padding:4px 10px;border-radius:5px;border:1px solid var(--border);background:var(--surface);
  color:var(--muted);font-size:11px;text-decoration:none;font-weight:600;transition:all .15s;}
.nav-link:hover,.nav-link.active{border-color:var(--accent);color:var(--accent);}

.container{max-width:1500px;margin:0 auto;padding:16px 20px;}
.section-title{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1.5px;
  color:var(--muted);margin:20px 0 10px;padding-bottom:5px;border-bottom:1px solid var(--border);}

.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:8px;margin-bottom:14px;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:9px;
  padding:10px 13px;position:relative;overflow:hidden;}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;}
.stat-card.critical::before{background:var(--critical);}
.stat-card.high::before{background:var(--high);}
.stat-card.medium::before{background:var(--medium);}
.stat-card.low::before{background:var(--low);}
.stat-card.total::before{background:var(--accent);}
.stat-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;}
.stat-value{font-size:26px;font-weight:700;font-family:var(--mono);margin-top:2px;}
.stat-card.critical .stat-value{color:var(--critical);}
.stat-card.high     .stat-value{color:var(--high);}
.stat-card.medium   .stat-value{color:var(--medium);}
.stat-card.low      .stat-value{color:var(--low);}
.stat-card.total    .stat-value{color:var(--accent);}

.fw-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:8px;margin-bottom:16px;}
.fw-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:10px 12px;cursor:pointer;transition:all .2s;}
.fw-card:hover{border-color:var(--accent);transform:translateY(-2px);}
.fw-name{font-size:10px;font-weight:600;margin-bottom:4px;}
.fw-pct{font-size:20px;font-weight:700;font-family:var(--mono);}
.fw-bar{height:3px;background:var(--surface2);border-radius:99px;margin-top:5px;overflow:hidden;}
.fw-bar-fill{height:100%;border-radius:99px;}
.fw-click-hint{font-size:9px;color:var(--muted);margin-top:3px;}

.service-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;margin-bottom:16px;}
.service-card{background:var(--surface);border:1px solid var(--border);border-radius:9px;
  padding:12px;text-decoration:none;color:var(--text);transition:all .15s;display:block;}
.service-card:hover{border-color:var(--accent);transform:translateY(-1px);}
.service-card-icon{font-size:20px;margin-bottom:4px;}
.service-card-name{font-weight:700;font-size:12px;}
.service-card-count{font-size:10px;color:var(--muted);margin-top:2px;}
.service-card-sev{display:flex;gap:6px;margin-top:6px;font-size:10px;font-family:var(--mono);}

.table-wrap{background:var(--surface);border:1px solid var(--border);border-radius:9px;overflow:hidden;margin-bottom:16px;}
.table-toolbar{padding:9px 12px;display:flex;gap:7px;align-items:center;border-bottom:1px solid var(--border);flex-wrap:wrap;}
.search-box{background:var(--surface2);border:1px solid var(--border);border-radius:5px;color:var(--text);
  padding:5px 9px;font-size:12px;width:240px;outline:none;}
.search-box:focus{border-color:var(--accent);}
.filter-sel{background:var(--surface2);border:1px solid var(--border);border-radius:5px;
  color:var(--text);padding:5px 8px;font-size:11px;outline:none;}
.count-lbl{margin-left:auto;font-size:11px;color:var(--muted);font-family:var(--mono);}

table{width:100%;border-collapse:collapse;font-size:11px;}
thead th{background:var(--surface2);padding:7px 9px;text-align:left;font-size:10px;
  font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);
  border-bottom:1px solid var(--border);white-space:nowrap;}
tbody tr{border-bottom:1px solid var(--border);cursor:pointer;transition:background .1s;}
tbody tr:hover{background:rgba(255,255,255,.03);}
td{padding:7px 9px;vertical-align:top;}

.badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;font-family:var(--mono);}
.badge-critical{background:rgba(192,0,0,.2);   color:#ff8080;border:1px solid rgba(192,0,0,.4);}
.badge-high    {background:rgba(255,68,68,.15); color:#ff8080;border:1px solid rgba(255,68,68,.3);}
.badge-medium  {background:rgba(255,193,7,.15); color:#ffc107;border:1px solid rgba(255,193,7,.3);}
.badge-low     {background:rgba(76,175,80,.15); color:#4caf50;border:1px solid rgba(76,175,80,.3);}

.fw-tag{display:inline-block;padding:1px 5px;border-radius:3px;font-size:9px;font-family:var(--mono);
  margin:1px 1px 1px 0;cursor:pointer;text-decoration:underline dotted;}
.fw-cis   {background:rgba(88,166,255,.12);color:var(--cis);}
.fw-nist  {background:rgba(121,192,255,.12);color:var(--nist);}
.fw-csa   {background:rgba(86,211,100,.12);color:var(--csa);}
.fw-mitre {background:rgba(255,123,114,.12);color:var(--mitre);}
.fw-hipaa {background:rgba(188,140,255,.12);color:var(--hipaa);}
.fw-pci   {background:rgba(255,166,87,.12);color:var(--pci);}
.fw-gdpr  {background:rgba(232,180,251,.12);color:var(--gdpr);}
.fw-other {background:rgba(139,148,158,.12);color:var(--muted);}

.exp-row{display:none;background:var(--surface2);}
.exp-row.open{display:table-row;}
.exp-grid{padding:14px 16px;display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;}
.exp-block h4{font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:var(--muted);margin-bottom:5px;}
.path-box{background:rgba(30,40,60,.8);border:1px solid var(--border);border-radius:5px;
  padding:8px 10px;font-family:var(--mono);font-size:10px;color:#79c0ff;word-break:break-all;line-height:1.6;}
.issue-box{background:rgba(192,0,0,.06);border:1px solid rgba(192,0,0,.2);border-radius:5px;
  padding:9px 11px;font-size:12px;color:#ffb3b0;line-height:1.6;}
.rem-box{background:rgba(76,175,80,.06);border:1px solid rgba(76,175,80,.2);border-radius:5px;
  padding:9px 11px;font-size:12px;color:#a8f0b0;line-height:1.7;}
.ct-box{background:rgba(0,120,212,.06);border:1px solid rgba(0,120,212,.2);border-radius:5px;
  padding:9px 11px;font-size:12px;color:#79c0ff;line-height:1.6;}
.tag-box{background:rgba(188,140,255,.06);border:1px solid rgba(188,140,255,.2);border-radius:5px;
  padding:6px 10px;font-size:11px;color:var(--hipaa);font-family:var(--mono);}
.ct-note{background:rgba(0,120,212,.06);border:1px solid rgba(0,120,212,.2);border-radius:7px;
  padding:9px 13px;font-size:11px;color:#79c0ff;margin-bottom:10px;}
.no-results{padding:34px;text-align:center;color:var(--muted);}

.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:1000;
  align-items:center;justify-content:center;}
.modal-overlay.open{display:flex;}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:12px;
  max-width:700px;width:90%;max-height:85vh;overflow:hidden;display:flex;flex-direction:column;}
.modal-header{padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;}
.modal-title{font-size:16px;font-weight:700;flex:1;}
.modal-close{background:none;border:1px solid var(--border);color:var(--muted);
  border-radius:6px;padding:4px 10px;cursor:pointer;font-size:13px;}
.modal-close:hover{color:var(--text);border-color:var(--text);}
.modal-body{padding:16px 20px;overflow-y:auto;flex:1;}
.modal-fw-link{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;
  background:rgba(0,120,212,.1);border:1px solid rgba(0,120,212,.3);border-radius:6px;
  color:var(--accent);text-decoration:none;font-size:12px;margin-bottom:14px;}
.modal-fw-link:hover{background:rgba(0,120,212,.2);}
.req-item{padding:10px 12px;border:1px solid var(--border);border-radius:7px;margin-bottom:8px;
  background:var(--surface2);}
.req-id{font-family:var(--mono);font-size:11px;font-weight:700;color:var(--accent);}
.req-desc{font-size:12px;color:var(--text);margin-top:3px;line-height:1.5;}
.req-checks{margin-top:5px;font-size:10px;color:var(--muted);font-family:var(--mono);}
.req-count{float:right;font-size:10px;color:var(--critical);font-family:var(--mono);font-weight:700;}
.modal-empty{color:var(--muted);text-align:center;padding:30px;font-size:13px;}

.issue-cell{position:relative;cursor:pointer;}
.issue-cell .itip{display:none;position:absolute;z-index:600;left:0;top:100%;
  min-width:360px;max-width:520px;background:#1c2128;border:1px solid #30363d;
  border-left:3px solid #C00000;border-radius:8px;padding:12px 14px;
  box-shadow:0 8px 32px rgba(0,0,0,.75);font-family:'IBM Plex Mono',monospace;
  font-size:10px;line-height:1.8;color:#e6edf3;white-space:normal;}
.issue-cell:hover .itip,.issue-cell:focus .itip{display:block;}
.itip .ih{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;
  color:#8b949e;margin-bottom:8px;font-family:'IBM Plex Sans',sans-serif;
  border-bottom:1px solid #30363d;padding-bottom:4px;}

footer{border-top:1px solid var(--border);padding:12px 20px;text-align:center;
  font-size:10px;color:var(--muted);font-family:var(--mono);}
</style>"""

    # ── Nav ───────────────────────────────────────────────────────────────────

    def _nav(self, by_service, account_name, active="index", depth=""):
        prefix = depth
        links  = [
            f'<a class="nav-link {"active" if active=="index" else ""}" '
            f'href="{prefix}index.html">📊 Dashboard</a>'
        ]
        for svc in by_service:
            icon = SVC_ICONS.get(svc, "☁")
            safe = svc.lower().replace(" ", "_").replace("/", "_")
            cnt  = len(by_service[svc])
            actv = "active" if active == svc else ""
            href = f"{prefix}pages/{safe}.html" if active == "index" else f"{safe}.html"
            links.append(
                f'<a class="nav-link {actv}" href="{href}">{icon} {svc} ({cnt})</a>'
            )
        return f"""<nav class="nav">
  <a class="nav-logo" href="{prefix}index.html">🛡 Azure Audit Pro</a>
  <span class="nav-title">{account_name}</span>
  <div class="nav-links">{"".join(links)}</div>
</nav>"""

    def _head(self, title):
        return f"""<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{title}</title>{self._css()}</head><body>"""

    def _fw_popup_js(self, fw_details):
        return f"const FW_DETAILS = {json.dumps(fw_details, default=str)};"

    # ── Index page ────────────────────────────────────────────────────────────

    def _render_index(self, findings, by_service, compliance, sev,
                      fw_details, account_name, company, scan_time, partial_note):

        stats = f"""<div class="stat-grid">
  <div class="stat-card total"><div class="stat-label">Total</div><div class="stat-value">{sev['Total']}</div></div>
  <div class="stat-card critical"><div class="stat-label">Critical</div><div class="stat-value">{sev['Critical']}</div></div>
  <div class="stat-card high"><div class="stat-label">High</div><div class="stat-value">{sev['High']}</div></div>
  <div class="stat-card medium"><div class="stat-label">Medium</div><div class="stat-value">{sev['Medium']}</div></div>
  <div class="stat-card low"><div class="stat-label">Low</div><div class="stat-value">{sev['Low']}</div></div>
</div>"""

        fw_cards = ""
        for fw_name, pct in sorted(compliance.items()):
            color = ("var(--low)" if pct >= 80 else
                     "var(--medium)" if pct >= 60 else
                     "var(--high)" if pct >= 40 else "var(--critical)")
            fw_cards += f"""
<div class="fw-card" onclick="openFwModal('{fw_name}')">
  <div class="fw-name" style="color:{color}">{fw_name}</div>
  <div class="fw-pct" style="color:{color}">{pct}%</div>
  <div class="fw-bar"><div class="fw-bar-fill" style="width:{pct}%;background:{color}"></div></div>
  <div class="fw-click-hint">Click to see affected requirements →</div>
</div>"""

        svc_cards = ""
        for svc, svc_f in by_service.items():
            icon = SVC_ICONS.get(svc, "☁")
            safe = svc.lower().replace(" ", "_").replace("/", "_")
            cnt  = len(svc_f)
            crit = sum(1 for f in svc_f if f.get("severity") == "Critical")
            high = sum(1 for f in svc_f if f.get("severity") == "High")
            med  = sum(1 for f in svc_f if f.get("severity") == "Medium")
            low  = sum(1 for f in svc_f if f.get("severity") == "Low")
            svc_cards += f"""
<a class="service-card" href="pages/{safe}.html">
  <div class="service-card-icon">{icon}</div>
  <div class="service-card-name">{svc}</div>
  <div class="service-card-count">{cnt} findings</div>
  <div class="service-card-sev">
    {"<span style='color:var(--critical)'>🔴"+str(crit)+"</span>" if crit else ""}
    {"<span style='color:var(--high)'>🟠"+str(high)+"</span>" if high else ""}
    {"<span style='color:var(--medium)'>🟡"+str(med)+"</span>" if med else ""}
    {"<span style='color:var(--low)'>🟢"+str(low)+"</span>" if low else ""}
  </div>
</a>"""

        fw_js = self._fw_popup_js(fw_details)

        return self._head(f"Azure Audit — {account_name}") + f"""
{self._nav(by_service, account_name, "index", "")}
<div class="container">
  <div style="margin:14px 0 6px;display:flex;align-items:baseline;gap:14px;">
    <h1 style="font-size:18px">{company} — Azure Security Assessment{partial_note}</h1>
    <span style="font-size:11px;background:rgba(0,120,212,.15);border:1px solid rgba(0,120,212,.3);
      border-radius:4px;padding:2px 8px;color:#0078D4;font-weight:600">
      🦅 Developed by Singaram
    </span>
    <span style="font-size:11px;color:var(--muted);font-family:var(--mono)">{scan_time}</span>
  </div>
  <p style="color:var(--muted);font-size:12px;margin-bottom:16px">
    Subscription: <code style="color:var(--accent)">{account_name}</code> &nbsp;·&nbsp;
    CIS · NIST CSF · NIST 800-53 · CSA CCM · MITRE ATT&CK · HIPAA · PCI DSS · GDPR
  </p>

  <div class="section-title">Vulnerability Summary</div>
  {stats}

  <div class="section-title">Framework Compliance — Click any card to see affected requirements</div>
  <div class="fw-grid">{fw_cards}</div>

  <div class="section-title">Azure Services ({len(by_service)} with findings)</div>
  <div class="service-grid">{svc_cards}</div>

  <div class="ct-note">
    ℹ <strong>Azure Audit Pro v1</strong> · Developed by 🦅 Singaram ·
    20 Azure Services · 120+ Security Checks · 8 Compliance Frameworks ·
    CIS Azure Benchmark 2.0 · NIST CSF · NIST 800-53 · CSA CCM · MITRE ATT&CK · HIPAA · PCI DSS · GDPR
  </div>
</div>

<!-- Framework compliance popup modal -->
<div class="modal-overlay" id="fwModal" onclick="if(event.target===this)closeFwModal()">
  <div class="modal">
    <div class="modal-header">
      <span class="modal-title" id="modalTitle">Framework Details</span>
      <button class="modal-close" onclick="closeFwModal()">✕ Close</button>
    </div>
    <div class="modal-body" id="modalBody"></div>
  </div>
</div>

<footer>Azure Audit Pro v1 · Developed by 🦅 Singaram · {account_name} · {scan_time} · {company} · Confidential</footer>

<script>
{fw_js}

function openFwModal(fwName) {{
  const detail = FW_DETAILS[fwName];
  if (!detail) return;
  document.getElementById('modalTitle').textContent = fwName + ' — Affected Requirements';
  const body = document.getElementById('modalBody');
  if (!detail.affected || !detail.affected.length) {{
    body.innerHTML = '<div class="modal-empty">✅ No affected requirements found for this framework.</div>';
  }} else {{
    let html = '<a href="' + detail.url + '" target="_blank" class="modal-fw-link">' +
      '📖 Read full ' + fwName + ' specification →</a>';
    html += `<p style="font-size:11px;color:var(--muted);margin-bottom:12px">
      ${{detail.affected.length}} requirements affected by current findings:</p>`;
    for (const req of detail.affected) {{
      html += `<div class="req-item">
        <span class="req-id">${{req.req_id}}</span>
        <span class="req-count">${{req.count}} finding(s)</span>
        <div class="req-desc">${{req.description}}</div>
        <div class="req-checks">Checks: ${{req.checks.join(', ')}}</div>
      </div>`;
    }}
    body.innerHTML = html;
  }}
  document.getElementById('fwModal').classList.add('open');
}}

function closeFwModal() {{
  document.getElementById('fwModal').classList.remove('open');
}}

document.addEventListener('keydown', e => {{ if(e.key==='Escape') closeFwModal(); }});
</script>
</body></html>"""

    # ── Service page ──────────────────────────────────────────────────────────

    def _render_service(self, svc, findings, account_name,
                        company, scan_time, by_service):
        icon    = SVC_ICONS.get(svc, "☁")
        sev     = severity_counts(findings)
        rows_js = self._findings_js(findings)

        return self._head(f"{svc} — {account_name}") + f"""
{self._nav(by_service, account_name, svc, "../")}
<div class="container">
  <div style="margin:14px 0 6px;display:flex;align-items:center;gap:10px;">
    <span style="font-size:26px">{icon}</span>
    <div>
      <h1 style="font-size:17px">{svc} Security Findings</h1>
      <p style="color:var(--muted);font-size:11px">{account_name} · {company} · {scan_time}
        &nbsp;·&nbsp;<a href="../index.html" style="color:var(--accent)">← Dashboard</a></p>
    </div>
  </div>

  <div class="stat-grid" style="margin:12px 0">
    <div class="stat-card total"><div class="stat-label">Total</div><div class="stat-value">{sev['Total']}</div></div>
    <div class="stat-card critical"><div class="stat-label">Critical</div><div class="stat-value">{sev['Critical']}</div></div>
    <div class="stat-card high"><div class="stat-label">High</div><div class="stat-value">{sev['High']}</div></div>
    <div class="stat-card medium"><div class="stat-label">Medium</div><div class="stat-value">{sev['Medium']}</div></div>
    <div class="stat-card low"><div class="stat-label">Low</div><div class="stat-value">{sev['Low']}</div></div>
  </div>

  <div class="ct-note">
    ℹ Azure Audit Pro v1 · 🦅 Singaram · Click any row to expand full details ·
    Click any framework tag to see requirement details.
  </div>

  <div class="table-wrap">
    <div class="table-toolbar">
      <input class="search-box" type="text" placeholder="🔍  Search findings, resources, paths…"
             oninput="doSearch(this.value)"/>
      <select class="filter-sel" onchange="doSevF(this.value)">
        <option value="">All Severities</option>
        <option>Critical</option><option>High</option>
        <option>Medium</option><option>Low</option>
      </select>
      <span class="count-lbl" id="cLbl">{sev['Total']} findings</span>
    </div>
    <div style="overflow-x:auto">
      <table>
        <thead><tr>
          <th>Finding</th><th>Resource</th><th>Type / Location</th>
          <th>Check</th><th>Severity</th>
          <th>Frameworks (click for details)</th>
          <th>Exact Path</th><th>Issue Detail</th>
          <th>Tags / Owner</th>
          <th>Subscription</th><th>Resource Group</th>
          <th>Remediation</th>
        </tr></thead>
        <tbody id="tbody"></tbody>
      </table>
      <div class="no-results" id="noRes" style="display:none">No findings match your filters.</div>
    </div>
  </div>
</div>

<!-- Compliance popup -->
<div class="modal-overlay" id="fwModal" onclick="if(event.target===this)closeFwModal()">
  <div class="modal">
    <div class="modal-header">
      <span class="modal-title" id="modalTitle">Compliance Requirement</span>
      <button class="modal-close" onclick="closeFwModal()">✕ Back</button>
    </div>
    <div class="modal-body" id="modalBody"></div>
  </div>
</div>

<footer>Azure Audit Pro v1 · Developed by 🦅 Singaram · {svc} · {account_name} · {scan_time} · Confidential</footer>

<script>
const F = {rows_js};
let search='', sevF='';

function parseIssue(detail) {{
  if (!detail) return '';
  var lines = detail.split(/[,;]/).map(function(s){{ return s.trim(); }}).filter(Boolean);
  var out = '';
  lines.forEach(function(line, i) {{
    var eq = line.indexOf('=');
    var ln = '<span style="color:#555;font-size:9px;margin-right:5px">L'+(i+1)+'</span>';
    if (eq > 0 && eq < 60) {{
      var k = xh(line.slice(0,eq).trim());
      var v = xh(line.slice(eq+1).trim());
      var raw = line.slice(eq+1).trim();
      var bad = /0[.]0[.]0[.]0|none|false|disabled|public|[*]/i.test(raw);
      out += '<div style="margin:2px 0">'+ln+
        '<span style="color:#ffa657">'+k+'</span>'+
        '<span style="color:#8b949e"> = </span>'+
        '<span style="'+(bad?'color:#ff8080;font-weight:700':'color:#79c0ff')+'">'+v+'</span></div>';
    }} else {{
      var bad2=/open to|exposed|public|no mfa|unencrypted|disabled|not set/i.test(line);
      out+='<div style="margin:2px 0">'+ln+
        '<span style="'+(bad2?'color:#ff8080;font-weight:700':'')+'">'+ xh(line)+'</span></div>';
    }}
  }});
  return out;
}}
function xh(s){{
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}}

const FW_CSS = {{
  CIS:'fw-cis', NIST_CSF:'fw-nist', NIST_800_53:'fw-nist',
  CSA_CCM:'fw-csa', MITRE_ATTACK:'fw-mitre', HIPAA:'fw-hipaa',
  PCI_DSS:'fw-pci', GDPR:'fw-gdpr'
}};

const FW_REFS_JS = {json.dumps({k: list(v) for k, v in FW_REFS.items()}, default=str)};

function sevClass(s){{
  return {{Critical:'badge-critical',High:'badge-high',Medium:'badge-medium',Low:'badge-low'}}[s]||'badge-low';
}}

function buildTags(comp){{
  if(!comp||!comp.length) return '<span class="fw-tag fw-other">—</span>';
  return comp.map(c=>{{
    const cls = FW_CSS[c.framework]||'fw-other';
    return `<span class="fw-tag ${{cls}}" onclick="showReqPopup('${{c.framework}}','${{c.requirement}}','${{c.description.replace(/'/g,"\\'")}}')">
      ${{c.requirement}}</span>`;
  }}).join('');
}}

function showReqPopup(fw, reqId, desc){{
  const ref    = FW_REFS_JS[fw];
  const fname  = ref ? ref[0] : fw;
  const furl   = ref ? ref[1] : '#';
  document.getElementById('modalTitle').textContent = `${{fname}} — ${{reqId}}`;
  document.getElementById('modalBody').innerHTML = `
    <a href="${{furl}}" target="_blank" class="modal-fw-link">📖 Read full ${{fname}} specification →</a>
    <div class="req-item">
      <span class="req-id">${{reqId}}</span>
      <div class="req-desc" style="margin-top:8px">${{desc||'No description available.'}}</div>
    </div>`;
  document.getElementById('fwModal').classList.add('open');
}}

function closeFwModal(){{document.getElementById('fwModal').classList.remove('open');}}
document.addEventListener('keydown', e=>{{ if(e.key==='Escape') closeFwModal(); }});

function render(){{
  const fil = F.filter(f=>{{
    const ms = !search||Object.values(f).some(v=>String(v).toLowerCase().includes(search));
    const mv = !sevF||f.severity===sevF;
    return ms&&mv;
  }});
  document.getElementById('cLbl').textContent = fil.length+' findings';
  const tb = document.getElementById('tbody');
  const nr = document.getElementById('noRes');
  if(!fil.length){{tb.innerHTML='';nr.style.display='block';return;}}
  nr.style.display='none';

  tb.innerHTML = fil.map((f,i)=>{{
    const sc   = f.severity.toLowerCase();
    const tags = buildTags(f.compliance);
    return `
    <tr onclick="tog('e${{i}}')">
      <td><span style="font-family:var(--mono);font-size:9px;color:var(--muted)">${{f.check_id}}</span></td>
      <td><strong>${{f.resource_name}}</strong><br>
          <span style="font-family:var(--mono);font-size:9px;color:var(--muted)">${{(f.resource_id||'').substring(0,40)}}...</span></td>
      <td><span style="font-size:10px">${{f.resource_type}}</span><br>
          <span style="font-family:var(--mono);font-size:10px;color:var(--muted)">${{f.location}}</span></td>
      <td style="font-size:11px;font-weight:500">${{f.check_name}}</td>
      <td><span class="badge badge-${{sc}}">${{f.severity}}</span></td>
      <td style="min-width:180px">${{tags}}</td>
      <td><span style="font-family:var(--mono);font-size:9px;color:#79c0ff;line-height:1.5">
          ${{(f.exact_path||'').substring(0,65)}}${{f.exact_path&&f.exact_path.length>65?'…':''}}</span></td>
      <td class="issue-cell" tabindex="0">
        <span style="font-size:10px;color:#ffb3b0;line-height:1.4">
          ${{(f.issue_detail||'').substring(0,60)}}${{f.issue_detail&&f.issue_detail.length>60?'…':''}}
        </span>
        <div class="itip">
          <div class="ih">⚠ Issue Detail</div>
          ${{parseIssue(f.issue_detail||'')}}
        </div>
      </td>
      <td style="font-size:10px;color:var(--hipaa);font-family:var(--mono)">
          ${{f.owner_tag||''}}${{f.tags?'<br><span style="font-size:9px;color:var(--muted)">'+f.tags.substring(0,40)+'</span>':''}}</td>
      <td style="font-size:10px;color:#79c0ff">${{f.subscription_alias||''}}</td>
      <td style="font-size:10px;color:var(--muted)">${{f.resource_group||''}}</td>
      <td style="font-size:10px;color:#a8f0b0;line-height:1.5">
          ${{(f.remediation||'').substring(0,90)}}${{f.remediation&&f.remediation.length>90?'…':''}}</td>
    </tr>
    <tr class="exp-row" id="e${{i}}">
      <td colspan="12">
        <div class="exp-grid">
          <div class="exp-block">
            <h4>Full Resource ID</h4>
            <div class="path-box" style="color:var(--muted);margin-bottom:10px">${{f.resource_id}}</div>
            <h4>Exact Path in Azure Portal</h4>
            <div class="path-box">${{f.exact_path}}</div>
          </div>
          <div class="exp-block">
            <h4>Issue Detail</h4>
            <div class="issue-box">${{f.issue_detail}}</div>
            <br><h4>Framework Mapping (click for details)</h4>
            <p>${{tags}}</p>
            ${{f.tags?`<br><h4>Resource Tags</h4><div class="tag-box">${{f.tags}}</div>`:''}}
          </div>
          <div class="exp-block">
            <h4>Remediation</h4>
            <div class="rem-box">${{f.remediation}}</div>
            <br><h4>Azure Resource Details</h4>
            <div class="ct-box">
              <strong>Subscription:</strong> ${{f.subscription_alias||'—'}}<br>
              <strong>Resource Group:</strong> ${{f.resource_group||'—'}}<br>
              <strong>Location:</strong> ${{f.location||'—'}}<br>
              <strong>Owner Tag:</strong> ${{f.owner_tag||'—'}}
            </div>
          </div>
        </div>
      </td>
    </tr>`;
  }}).join('');
}}

function tog(id){{document.getElementById(id).classList.toggle('open');}}
function doSearch(v){{search=v.toLowerCase();render();}}
function doSevF(v){{sevF=v;render();}}
render();
</script></body></html>"""

    def _findings_js(self, findings):
        safe = []
        for f in findings:
            safe.append({
                "check_id":          f.get("check_id",         ""),
                "resource_id":       f.get("resource_id",      ""),
                "resource_name":     f.get("resource_name",    ""),
                "resource_type":     f.get("resource_type",    ""),
                "resource_group":    f.get("resource_group",   ""),
                "location":          f.get("location",         ""),
                "check_name":        f.get("check_name",       ""),
                "severity":          f.get("severity",         "Low"),
                "exact_path":        f.get("exact_path",       ""),
                "issue_detail":      f.get("issue_detail",     ""),
                "remediation":       f.get("remediation",      ""),
                "compliance":        f.get("compliance",       []),
                "tags":              f.get("tags",             ""),
                "owner_tag":         f.get("owner_tag",        ""),
                "subscription_alias":f.get("subscription_alias",""),
            })
        return json.dumps(safe, default=str)


# ── Standalone function wrapper (called from main.py) ─────────────────────────

def generate_html_report(all_findings, subscriptions_info, compliance_results,
                          sev_counts, output_dir, display):
    import os
    os.makedirs(output_dir, exist_ok=True)
    reporter  = HTMLReporter(display)
    sub_alias = (subscriptions_info[0].get("subscription_alias", "azure-audit")
                 if subscriptions_info else "azure-audit")
    company   = "Azure Security Assessment"
    path      = reporter.generate(all_findings, output_dir, sub_alias, company)
    return str(path)
