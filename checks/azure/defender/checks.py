"""Microsoft Defender for Cloud (Security Center) — 8 checks."""
from ..base import BaseCheck


class DefenderChecks(BaseCheck):
    SERVICE = "Defender"

    def run_all(self):
        f = []
        f += self._defender_plans()
        f += self._security_contacts()
        f += self._auto_provisioning()
        f += self._secure_score()
        f += self._high_severity_alerts()
        f += self._email_notifications()
        f += self._integration_sentinel()
        f += self._regulatory_compliance()
        return f

    def _client(self):
        from azure.mgmt.security import SecurityCenter
        return SecurityCenter(self.credential, self.subscription_id)

    def _defender_plans(self):
        findings = []
        try:
            sc = self._client()
            critical_plans = [
                "VirtualMachines", "SqlServers", "AppServices",
                "StorageAccounts", "Containers", "KeyVaults",
            ]
            enabled_plans = set()
            for pricing in sc.pricings.list(
                scope=f"/subscriptions/{self.subscription_id}"
            ):
                if pricing.pricing_tier and pricing.pricing_tier.lower() == "standard":
                    name = pricing.name or ""
                    enabled_plans.add(name)

            for plan in critical_plans:
                if plan not in enabled_plans:
                    findings.append(self.finding(
                        f"defender_plan_{plan.lower()}_not_enabled",
                        f"/subscriptions/{self.subscription_id}",
                        "Subscription", "Defender Plan", "FAIL", "High",
                        f"Microsoft Defender for {plan} is not enabled",
                        f"Azure Portal → Microsoft Defender for Cloud → Environment settings → {self.subscription_id} → Defender plans → {plan} → On",
                        f"Defender for {plan} is not on the Standard (paid) tier. "
                        f"Without it, threat detection, vulnerability scanning, and security alerts for {plan} are unavailable.",
                    ))
        except Exception as e:
            findings.append(self.error_finding("defender_plan_not_enabled", e))
        return findings

    def _security_contacts(self):
        findings = []
        try:
            sc = self._client()
            contacts = list(sc.security_contacts.list())
            if not contacts:
                findings.append(self.finding(
                    "defender_no_security_contact",
                    f"/subscriptions/{self.subscription_id}",
                    "Subscription", "Security Contact", "FAIL", "High",
                    "No security contact configured in Defender for Cloud",
                    "Azure Portal → Microsoft Defender for Cloud → Environment settings → Security contacts → Add",
                    "No security contact email or phone configured. Security alerts from Defender for Cloud "
                    "will not be delivered to your security team — incidents may go undetected.",
                ))
            else:
                for c in contacts:
                    if not getattr(c, "email", None):
                        findings.append(self.finding(
                            "defender_security_contact_no_email",
                            c.id or "", c.name or "Security Contact",
                            "Security Contact", "FAIL", "Medium",
                            "Security contact has no email address configured",
                            "Azure Portal → Microsoft Defender for Cloud → Environment settings → Security contacts",
                            f"Security contact '{c.name}' has no email address. "
                            "Add a valid email to ensure security alerts are received.",
                        ))
        except Exception as e:
            findings.append(self.error_finding("defender_no_security_contact", e))
        return findings

    def _auto_provisioning(self):
        findings = []
        try:
            sc = self._client()
            for setting in sc.auto_provisioning_settings.list():
                if setting.auto_provision and setting.auto_provision.lower() == "off":
                    findings.append(self.finding(
                        "defender_auto_provisioning_disabled",
                        setting.id or "", setting.name or "",
                        "Auto Provisioning", "FAIL", "Medium",
                        "Defender for Cloud auto-provisioning of agents is disabled",
                        "Azure Portal → Microsoft Defender for Cloud → Environment settings → Auto provisioning → On",
                        f"Auto provisioning for '{setting.name}' is Off. Without auto provisioning, "
                        "monitoring agents are not automatically deployed to new VMs, leaving them unmonitored.",
                    ))
        except Exception as e:
            findings.append(self.error_finding("defender_auto_provisioning_disabled", e))
        return findings

    def _secure_score(self):
        findings = []
        try:
            sc = self._client()
            for score in sc.secure_scores.list():
                current = getattr(score.score, "current", None)
                max_val = getattr(score.score, "max", None)
                if current is not None and max_val and max_val > 0:
                    pct = (current / max_val) * 100
                    if pct < 70:
                        findings.append(self.finding(
                            "defender_secure_score_low",
                            f"/subscriptions/{self.subscription_id}",
                            "Subscription", "Secure Score", "FAIL", "High",
                            f"Defender for Cloud Secure Score is critically low ({pct:.0f}%)",
                            "Azure Portal → Microsoft Defender for Cloud → Secure score → Recommendations",
                            f"Secure Score is {pct:.1f}% ({current}/{max_val}). "
                            "A score below 70% indicates significant security misconfigurations. "
                            "Review and remediate the top recommendations in Defender for Cloud.",
                        ))
        except Exception as e:
            findings.append(self.error_finding("defender_secure_score_low", e))
        return findings

    def _high_severity_alerts(self):
        findings = []
        try:
            sc = self._client()
            alerts = [a for a in sc.alerts.list()
                      if (a.severity or "").lower() in ("high", "critical") and
                      (a.status or "").lower() == "active"]
            if alerts:
                for a in alerts[:5]:  # Report first 5
                    findings.append(self.finding(
                        "defender_active_high_severity_alert",
                        a.id or "", a.alert_display_name or "Alert",
                        "Security Alert", "FAIL", "Critical",
                        "Active HIGH/CRITICAL security alert in Defender for Cloud",
                        "Azure Portal → Microsoft Defender for Cloud → Security alerts → Filter by severity: High/Critical",
                        f"Alert: '{a.alert_display_name}' — {a.description or 'No description'}. "
                        "Immediately investigate and respond to this active security alert.",
                    ))
        except Exception as e:
            findings.append(self.error_finding("defender_active_high_severity_alert", e))
        return findings

    def _email_notifications(self):
        findings = []
        try:
            sc = self._client()
            for c in sc.security_contacts.list():
                notify = getattr(c, "alert_notifications", None)
                if notify and (notify.state or "").lower() != "on":
                    findings.append(self.finding(
                        "defender_email_notifications_disabled",
                        c.id or "", c.name or "",
                        "Security Contact", "FAIL", "Medium",
                        "Defender for Cloud email notifications for alerts are disabled",
                        "Azure Portal → Microsoft Defender for Cloud → Environment settings → Email notifications",
                        "Email alert notifications are disabled. Enable notifications to ensure "
                        "security alerts are sent to your team immediately when threats are detected.",
                    ))
        except Exception as e:
            findings.append(self.error_finding("defender_email_notifications_disabled", e))
        return findings

    def _integration_sentinel(self):
        """Advisory: check if Microsoft Sentinel is connected."""
        findings = []
        try:
            findings.append(self.finding(
                "defender_sentinel_not_connected",
                f"/subscriptions/{self.subscription_id}",
                "Subscription", "Sentinel Integration", "FAIL", "Medium",
                "Verify Microsoft Sentinel is connected for SIEM capabilities",
                "Azure Portal → Microsoft Sentinel → Create → Connect to Log Analytics Workspace",
                "Verify that Microsoft Sentinel is connected to Defender for Cloud. "
                "Without Sentinel, security alerts are not correlated, investigated, or escalated automatically "
                "in a centralized SIEM/SOAR platform.",
            ))
        except Exception as e:
            findings.append(self.error_finding("defender_sentinel_not_connected", e))
        return findings

    def _regulatory_compliance(self):
        findings = []
        try:
            sc = self._client()
            for std in sc.regulatory_compliance_standards.list():
                state = getattr(std, "state", "") or ""
                if state.lower() == "failed":
                    findings.append(self.finding(
                        "defender_regulatory_compliance_failed",
                        std.id or "", std.name or "",
                        "Regulatory Standard", "FAIL", "High",
                        f"Regulatory compliance standard FAILED: {std.name}",
                        f"Azure Portal → Microsoft Defender for Cloud → Regulatory compliance → {std.name}",
                        f"Regulatory compliance standard '{std.name}' is failing. "
                        "Review the failed controls and remediate to achieve compliance.",
                    ))
        except Exception as e:
            findings.append(self.error_finding("defender_regulatory_compliance_failed", e))
        return findings
