"""Azure Policy — 3 checks."""
from ..base import BaseCheck


class PolicyChecks(BaseCheck):
    SERVICE = "Policy"

    def run_all(self):
        f = []
        f += self._policy_assignments_exist()
        f += self._non_compliant_resources()
        f += self._security_benchmark()
        return f

    def _client(self):
        from azure.mgmt.resource import PolicyClient
        return PolicyClient(self.credential, self.subscription_id)

    def _policy_assignments_exist(self):
        findings = []
        try:
            assignments = list(self._client().policy_assignments.list())
            if not assignments:
                findings.append(self.finding(
                    "policy_no_assignments",
                    f"/subscriptions/{self.subscription_id}",
                    "Subscription", "Policy", "FAIL", "High",
                    "No Azure Policy assignments found in subscription",
                    "Azure Portal → Policy → Assignments → + Assign policy or initiative",
                    "No policy assignments found. Assign at minimum the Azure Security Benchmark initiative "
                    "and deny policies for common misconfigurations (public blob access, no TLS, etc.).",
                ))
        except Exception as e:
            findings.append(self.error_finding("policy_no_assignments", e))
        return findings

    def _non_compliant_resources(self):
        findings = []
        try:
            from azure.mgmt.policyinsights import PolicyInsightsClient
            pic = PolicyInsightsClient(self.credential, self.subscription_id)
            # v1.0.x requires subscription_id as second positional argument
            states = list(pic.policy_states.list_query_results_for_subscription(
                "latest",
                self.subscription_id,
                query_options=None,
            ))
            non_compliant = [s for s in states if getattr(s, "compliance_state", "") == "NonCompliant"]
            if non_compliant:
                count = len(non_compliant)
                findings.append(self.finding(
                    "policy_non_compliant_resources",
                    f"/subscriptions/{self.subscription_id}",
                    "Subscription", "Policy", "FAIL", "High",
                    f"{count} resource(s) are non-compliant with Azure Policy",
                    "Azure Portal → Policy → Compliance → Filter: Non-compliant",
                    f"Found {count} non-compliant resource(s) against assigned policies. "
                    "Review the Policy Compliance dashboard and remediate or create exemptions with documented justification.",
                ))
        except Exception as e:
            findings.append(self.error_finding("policy_non_compliant_resources", e))
        return findings

    def _security_benchmark(self):
        findings = []
        try:
            assignments = list(self._client().policy_assignments.list())
            names = [(a.display_name or "").lower() + (a.name or "").lower() for a in assignments]
            has_benchmark = any(
                "security benchmark" in n or "azure security" in n or "mcsb" in n
                for n in names
            )
            if not has_benchmark:
                findings.append(self.finding(
                    "policy_no_security_benchmark",
                    f"/subscriptions/{self.subscription_id}",
                    "Subscription", "Policy", "FAIL", "High",
                    "Azure Security Benchmark (MCSB) initiative not assigned",
                    "Azure Portal → Policy → Assignments → + Assign initiative → Microsoft Cloud Security Benchmark",
                    "The Microsoft Cloud Security Benchmark initiative is not assigned. "
                    "MCSB covers 150+ security controls across all Azure services and is the foundation "
                    "for Defender for Cloud's Secure Score.",
                ))
        except Exception as e:
            findings.append(self.error_finding("policy_no_security_benchmark", e))
        return findings
