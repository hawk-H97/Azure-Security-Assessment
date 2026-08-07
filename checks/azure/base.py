"""Base check — all Azure service checks inherit from this.
No region/location filtering; resources are discovered globally within the subscription."""
import json
from datetime import datetime, timezone
from pathlib import Path

# base.py lives at: <project_root>/checks/azure/base.py
# So .parent.parent.parent = <project_root>
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class BaseCheck:
    SERVICE = "Azure"

    def __init__(self, credential, subscription_id, location="", display=None):
        self.credential        = credential
        self.subscription_id   = subscription_id
        # location kept for signature compatibility but not used for filtering
        self.location          = location
        self.display           = display
        self._compliance_cache = None

    def run_all(self):
        raise NotImplementedError

    # ─── Finding builder ──────────────────────────────────────────────────────

    def finding(self, check_id, resource_id, resource_name, resource_type,
                status, severity, check_name, exact_path, issue_detail,
                remediation="", tags=None, resource_group="", location=""):
        """Build a standardised finding dict.
        'location' is taken from the resource itself, not from scan config."""
        from engine.remediation import get_remediation

        proper = get_remediation(check_id)
        if proper:
            remediation = proper
        elif not remediation or len(remediation) < 50:
            remediation = (
                f"Review and remediate the security configuration for {resource_type} "
                f"'{resource_name}'. Apply Azure security best practices for {check_name}."
            )

        # Extract owner from tags
        owner_tag = ""
        tag_str   = ""
        if tags:
            tag_dict  = tags if isinstance(tags, dict) else {}
            owner_tag = (tag_dict.get("Owner") or tag_dict.get("owner") or
                         tag_dict.get("CreatedBy") or tag_dict.get("Team") or "")
            tag_str   = ", ".join(f"{k}={v}" for k, v in tag_dict.items()) if tag_dict else ""

        return {
            "check_id":           check_id,
            "service":            self.SERVICE,
            "resource_id":        str(resource_id),
            "resource_name":      str(resource_name),
            "resource_type":      str(resource_type),
            "resource_group":     str(resource_group),
            "location":           str(location),   # from resource metadata
            "check_name":         check_name,
            "severity":           severity,
            "status":             status,
            "exact_path":         exact_path,
            "issue_detail":       issue_detail,
            "remediation":        remediation,
            "created_by":         "",
            "last_modified_by":   "",
            "last_modified_date": "",
            "owner_tag":          owner_tag,
            "tags":               tag_str,
            "compliance":         self._get_compliance(check_id),
            "scan_time":          datetime.now(timezone.utc).isoformat(),
        }

    def error_finding(self, check_id, error_msg):
        return {
            "check_id":           check_id,
            "service":            self.SERVICE,
            "resource_id":        "ERROR",
            "resource_name":      "ERROR",
            "resource_type":      "ERROR",
            "resource_group":     "",
            "location":           "",
            "check_name":         f"Check failed: {check_id}",
            "severity":           "Low",
            "status":             "ERROR",
            "exact_path":         "N/A",
            "issue_detail":       str(error_msg)[:300],
            "remediation":        "",
            "created_by":         "",
            "last_modified_by":   "",
            "last_modified_date": "",
            "owner_tag":          "",
            "tags":               "",
            "compliance":         [],
            "scan_time":          datetime.now(timezone.utc).isoformat(),
        }

    def _get_compliance(self, check_id):
        """Return list of dicts [{framework, version, requirement, description, source}].
        Loads from <project_root>/compliance/azure/*.json (built by deps.py at startup)."""
        if self._compliance_cache is None:
            self._compliance_cache = {}
            try:
                comp_dir = PROJECT_ROOT / "compliance" / "azure"
                if not comp_dir.exists():
                    return []
                for jf in comp_dir.glob("*.json"):
                    try:
                        data = json.loads(jf.read_text(encoding="utf-8"))
                    except Exception:
                        continue
                    fw  = data.get("Framework", "")
                    ver = data.get("Version", "")
                    src = data.get("Source", "")
                    for req in data.get("Requirements", []):
                        for cid in req.get("Checks", []):
                            self._compliance_cache.setdefault(cid, []).append({
                                "framework":   fw,
                                "version":     ver,
                                "requirement": req.get("Id", ""),
                                "description": req.get("Description", ""),
                                "source":      src,
                            })
            except Exception:
                pass
        return self._compliance_cache.get(check_id, [])
