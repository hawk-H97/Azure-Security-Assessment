"""Azure Monitor / Activity Log / Alerts — 7 checks."""
from ..base import BaseCheck


class MonitorChecks(BaseCheck):
    SERVICE = "Monitor"

    def run_all(self):
        f = []
        f += self._activity_log_retention()
        f += self._diagnostic_settings_subscription()
        f += self._alert_policy_write()
        f += self._alert_nsg_change()
        f += self._alert_security_solution()
        f += self._alert_sql_firewall()
        f += self._alert_vm_delete()
        return f

    def _client(self):
        from azure.mgmt.monitor import MonitorManagementClient
        return MonitorManagementClient(self.credential, self.subscription_id)

    def _activity_log_retention(self):
        findings = []
        try:
            mc = self._client()
            profiles = list(mc.log_profiles.list())
            if not profiles:
                findings.append(self.finding(
                    "monitor_no_log_profile",
                    f"/subscriptions/{self.subscription_id}",
                    "Subscription", "Log Profile", "FAIL", "High",
                    "No Activity Log Profile configured",
                    "Azure Portal → Monitor → Activity log → Export Activity Logs → Add diagnostic setting",
                    "No Activity Log export profile found. Azure Activity Logs must be exported to a Log Analytics "
                    "Workspace or Storage Account for retention and analysis.",
                ))
            else:
                for profile in profiles:
                    ret = profile.retention_policy
                    days = getattr(ret, "days", 0) or 0
                    enabled = getattr(ret, "enabled", False)
                    if enabled and days < 365:
                        findings.append(self.finding(
                            "monitor_log_retention_under_365_days",
                            profile.id or "", profile.name or "Log Profile",
                            "Log Profile", "FAIL", "Medium",
                            "Activity Log retention is less than 365 days",
                            "Azure Portal → Monitor → Activity log → Export Activity Logs → Retention (days) → 365",
                            f"Log profile '{profile.name}' retention is {days} days. "
                            "Set retention to at least 365 days for compliance with CIS, PCI DSS, and HIPAA requirements.",
                        ))
        except Exception as e:
            findings.append(self.error_finding("monitor_no_log_profile", e))
        return findings

    def _diagnostic_settings_subscription(self):
        findings = []
        try:
            mc = self._client()
            sub_resource = f"/subscriptions/{self.subscription_id}"
            diag = list(mc.diagnostic_settings.list(sub_resource))
            if not diag:
                findings.append(self.finding(
                    "monitor_subscription_diagnostic_settings_missing",
                    sub_resource, "Subscription",
                    "Diagnostic Settings", "FAIL", "High",
                    "Subscription-level diagnostic settings not configured",
                    "Azure Portal → Monitor → Diagnostic settings → + Add diagnostic setting → Subscription",
                    "No subscription-level diagnostic settings found. Configure diagnostic settings to stream "
                    "Activity Logs to Log Analytics Workspace for centralized SIEM integration.",
                ))
        except Exception as e:
            findings.append(self.error_finding("monitor_subscription_diagnostic_settings_missing", e))
        return findings

    def _has_alert(self, mc, keyword):
        """Check if any alert rule exists containing the keyword."""
        try:
            alerts = list(mc.alert_rules.list_by_subscription())
            return any(keyword.lower() in (a.name or "").lower() or
                       keyword.lower() in (getattr(a, "description", None) or "").lower()
                       for a in alerts)
        except Exception:
            return False

    def _check_activity_alert(self, check_id, operation, description, portal_path):
        findings = []
        try:
            mc = self._client()
            # Check activity log alerts for the operation
            try:
                from azure.mgmt.monitor.models import ActivityLogAlertLeafCondition
            except ImportError:
                pass

            alerts = []
            try:
                alerts = list(mc.activity_log_alerts.list_by_subscription_id())
            except Exception:
                pass

            found = False
            for alert in alerts:
                if not alert.enabled:
                    continue
                for cond in (getattr(alert.condition, "all_of", None) or []):
                    val = getattr(cond, "equals", "") or ""
                    if operation.lower() in val.lower():
                        found = True
                        break

            if not found:
                findings.append(self.finding(
                    check_id,
                    f"/subscriptions/{self.subscription_id}",
                    "Subscription", "Activity Log Alert", "FAIL", "Medium",
                    f"No Activity Log Alert for: {description}",
                    portal_path,
                    f"No Activity Log Alert exists for '{operation}'. "
                    f"Create an alert to detect {description} and notify the security team in real time.",
                ))
        except Exception as e:
            findings.append(self.error_finding(check_id, e))
        return findings

    def _alert_policy_write(self):
        return self._check_activity_alert(
            "monitor_alert_policy_assignment",
            "Microsoft.Authorization/policyAssignments/write",
            "policy assignment changes",
            "Azure Portal → Monitor → Alerts → + Create alert rule → Scope: Subscription → Condition: Policy assignment - Write",
        )

    def _alert_nsg_change(self):
        return self._check_activity_alert(
            "monitor_alert_nsg_change",
            "Microsoft.Network/networkSecurityGroups/write",
            "NSG create/update events",
            "Azure Portal → Monitor → Alerts → + Create alert rule → Scope: Subscription → Condition: Network security groups - Write",
        )

    def _alert_security_solution(self):
        return self._check_activity_alert(
            "monitor_alert_security_solution_delete",
            "Microsoft.Security/securitySolutions/delete",
            "security solution deletion",
            "Azure Portal → Monitor → Alerts → + Create alert rule → Condition: Security solutions - Delete",
        )

    def _alert_sql_firewall(self):
        return self._check_activity_alert(
            "monitor_alert_sql_firewall_change",
            "Microsoft.Sql/servers/firewallRules/write",
            "SQL firewall rule changes",
            "Azure Portal → Monitor → Alerts → + Create alert rule → Condition: SQL server firewall rules - Write",
        )

    def _alert_vm_delete(self):
        return self._check_activity_alert(
            "monitor_alert_vm_delete",
            "Microsoft.Compute/virtualMachines/delete",
            "VM deletion events",
            "Azure Portal → Monitor → Alerts → + Create alert rule → Condition: Virtual machines - Delete",
        )
