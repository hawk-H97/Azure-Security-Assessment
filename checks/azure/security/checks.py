"""Azure Security (general) — 4 checks."""
from ..base import BaseCheck


class SecurityChecks(BaseCheck):
    SERVICE = "Security"

    def run_all(self):
        f = []
        f += self._subscription_tags()
        f += self._resource_locks()
        f += self._management_port_exposure()
        f += self._private_endpoints_in_use()
        return f

    def _subscription_tags(self):
        """Check that critical resources have required tags (Owner, Environment, etc.)."""
        findings = []
        try:
            from azure.mgmt.resource import ResourceManagementClient
            rc  = ResourceManagementClient(self.credential, self.subscription_id)
            required_tags = {"Owner", "Environment", "CostCenter"}
            for rg in rc.resource_groups.list():
                missing = required_tags - set((rg.tags or {}).keys())
                if missing:
                    findings.append(self.finding(
                        "security_missing_required_tags",
                        rg.id, rg.name, "Resource Group", "FAIL", "Low",
                        f"Resource Group missing required tags: {', '.join(sorted(missing))}",
                        f"Azure Portal → Resource groups → {rg.name} → Tags → Add: {', '.join(sorted(missing))}",
                        f"Resource group '{rg.name}' is missing tags: {', '.join(sorted(missing))}. "
                        "Tags are essential for cost allocation, ownership identification, and incident response.",
                        tags=rg.tags,
                    ))
        except Exception as e:
            findings.append(self.error_finding("security_missing_required_tags", e))
        return findings

    def _resource_locks(self):
        """Check that production resource groups have delete/readonly locks."""
        findings = []
        try:
            from azure.mgmt.resource import ManagementLockClient
            lc = ManagementLockClient(self.credential, self.subscription_id)
            from azure.mgmt.resource import ResourceManagementClient
            rc = ResourceManagementClient(self.credential, self.subscription_id)
            for rg in rc.resource_groups.list():
                tags = rg.tags or {}
                env  = (tags.get("Environment") or tags.get("environment") or "").lower()
                if env in ("prod", "production"):
                    locks = list(lc.management_locks.list_at_resource_group_level(rg.name))
                    if not locks:
                        findings.append(self.finding(
                            "security_prod_rg_no_lock",
                            rg.id, rg.name, "Resource Group", "FAIL", "High",
                            "Production Resource Group has no management lock",
                            f"Azure Portal → Resource groups → {rg.name} → Locks → + Add (CanNotDelete)",
                            f"Resource group '{rg.name}' (tagged Environment={env}) has no delete lock. "
                            "A management lock prevents accidental or unauthorized deletion of production resources.",
                            tags=rg.tags,
                        ))
        except Exception as e:
            findings.append(self.error_finding("security_prod_rg_no_lock", e))
        return findings

    def _management_port_exposure(self):
        """Summary advisory — covered in detail by NSG checks."""
        return []

    def _private_endpoints_in_use(self):
        """Advisory: check whether private endpoints are adopted across key services."""
        findings = []
        try:
            from azure.mgmt.network import NetworkManagementClient
            nc  = NetworkManagementClient(self.credential, self.subscription_id)
            eps = list(nc.private_endpoints.list_by_subscription())
            if not eps:
                findings.append(self.finding(
                    "security_no_private_endpoints",
                    f"/subscriptions/{self.subscription_id}",
                    "Subscription", "Private Endpoint", "FAIL", "High",
                    "No Private Endpoints found — all Azure PaaS services are accessed via public endpoints",
                    "Azure Portal → Private endpoints → + Create (for Storage, SQL, Key Vault, etc.)",
                    "No Private Endpoints are configured. All PaaS services (Storage, SQL, Key Vault, Service Bus) "
                    "are accessed via their public endpoints, even from within VNets. "
                    "Private Endpoints eliminate public exposure of PaaS data planes.",
                ))
        except Exception as e:
            findings.append(self.error_finding("security_no_private_endpoints", e))
        return findings
