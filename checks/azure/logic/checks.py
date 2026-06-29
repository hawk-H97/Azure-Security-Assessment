"""Azure Logic Apps — 3 checks."""
from ..base import BaseCheck


class LogicChecks(BaseCheck):
    SERVICE = "LogicApps"

    def run_all(self):
        f = []
        f += self._diagnostic_logging()
        f += self._managed_identity()
        f += self._ip_restriction()
        return f

    def _client(self):
        from azure.mgmt.logic import LogicManagementClient
        return LogicManagementClient(self.credential, self.subscription_id)

    def _rg(self, rid):
        try:
            parts = (rid or "").split("/")
            idx = parts.index("resourceGroups") if "resourceGroups" in parts else -1
            return parts[idx + 1] if idx >= 0 and idx + 1 < len(parts) else ""
        except Exception:
            return ""

    def _diagnostic_logging(self):
        findings = []
        try:
            from azure.mgmt.monitor import MonitorManagementClient
            mc = MonitorManagementClient(self.credential, self.subscription_id)
            for wf in self._client().workflows.list_by_subscription():
                rg = self._rg(wf.id)
                diag = list(mc.diagnostic_settings.list(wf.id))
                if not diag:
                    findings.append(self.finding(
                        "logic_app_no_diagnostic_logging",
                        wf.id, wf.name, "Logic App", "FAIL", "Medium",
                        "Logic App has no diagnostic logging configured",
                        f"Azure Portal → Logic apps → {wf.name} → Monitoring → Diagnostic settings → Add",
                        f"Logic App '{wf.name}' has no diagnostic settings. "
                        "Workflow run history and trigger events should be streamed to Log Analytics for audit and SIEM.",
                        tags=wf.tags, resource_group=rg, location=getattr(wf, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("logic_app_no_diagnostic_logging", e))
        return findings

    def _managed_identity(self):
        findings = []
        try:
            for wf in self._client().workflows.list_by_subscription():
                rg = self._rg(wf.id)
                if not wf.identity:
                    findings.append(self.finding(
                        "logic_app_no_managed_identity",
                        wf.id, wf.name, "Logic App", "FAIL", "Medium",
                        "Logic App does not use Managed Identity for downstream authentication",
                        f"Azure Portal → Logic apps → {wf.name} → Settings → Identity → System assigned → On",
                        f"Logic App '{wf.name}' has no Managed Identity. Connectors using stored credentials "
                        "are harder to audit and rotate. Use Managed Identity for authenticating to Azure services.",
                        tags=wf.tags, resource_group=rg, location=getattr(wf, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("logic_app_no_managed_identity", e))
        return findings

    def _ip_restriction(self):
        findings = []
        try:
            for wf in self._client().workflows.list_by_subscription():
                rg   = self._rg(wf.id)
                acl  = getattr(wf, "access_control", None)
                trig = getattr(acl, "triggers", None) if acl else None
                allowed = getattr(trig, "allowed_caller_ip_addresses", None) if trig else None
                if not allowed:
                    findings.append(self.finding(
                        "logic_app_trigger_no_ip_restriction",
                        wf.id, wf.name, "Logic App", "FAIL", "Medium",
                        "Logic App HTTP trigger has no IP restriction",
                        f"Azure Portal → Logic apps → {wf.name} → Settings → Workflow settings → Access control → Add allowed IPs",
                        f"Logic App '{wf.name}' triggers accept requests from any IP. "
                        "If the trigger uses a callable URL, restrict to known source IPs to prevent unauthorized invocations.",
                        tags=wf.tags, resource_group=rg, location=getattr(wf, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("logic_app_trigger_no_ip_restriction", e))
        return findings
