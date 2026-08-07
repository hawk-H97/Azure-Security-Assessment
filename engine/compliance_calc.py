"""Compliance % calculator — mirrors AWS compliance_calc.py exactly, reads azure/ provider."""
import json
from pathlib import Path

ROOT = Path(__file__).parent.parent

DISPLAY_NAMES = {
    "CIS":          "CIS Azure Benchmark 2.0",
    "NIST_CSF":     "NIST CSF 2.0",
    "NIST_800_53":  "NIST 800-53 Rev5",
    "CSA_CCM":      "CSA CCM v4.0",
    "MITRE_ATTACK": "MITRE ATT&CK Cloud",
    "HIPAA":        "HIPAA Security Rule",
    "PCI_DSS":      "PCI DSS 4.0",
    "GDPR":         "GDPR",
}

def load_compliance_requirements(provider="azure"):
    frameworks = {}
    compliance_dir = ROOT / "compliance" / provider
    if not compliance_dir.exists():
        return frameworks
    for jfile in compliance_dir.glob("*.json"):
        try:
            data = json.loads(jfile.read_text())
            fw   = data.get("Framework", "")
            if not fw:
                continue
            frameworks.setdefault(fw, []).extend(data.get("Requirements", []))
        except Exception:
            continue
    return frameworks

def calculate_compliance(findings, provider="azure"):
    frameworks    = load_compliance_requirements(provider)
    failed_checks = {f.get("check_id", "") for f in findings if f.get("status") == "FAIL"}
    results       = {}
    for fw_key, requirements in frameworks.items():
        total = len(requirements)
        if total == 0:
            continue
        failed = sum(1 for req in requirements
                     if any(c in failed_checks for c in req.get("Checks", [])))
        passed = total - failed
        pct    = round((passed / total) * 100, 1)
        results[DISPLAY_NAMES.get(fw_key, fw_key)] = pct
    return results

def severity_counts(findings):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Total": 0}
    for f in findings:
        if f.get("status") != "FAIL":
            continue
        sev = f.get("severity", "Low")
        if sev in counts:
            counts[sev] += 1
        counts["Total"] += 1
    return counts
