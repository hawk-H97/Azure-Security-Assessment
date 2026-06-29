"""Azure Container Registry — 4 checks."""
from ..base import BaseCheck


class ACRChecks(BaseCheck):
    SERVICE = "ContainerRegistry"

    def run_all(self):
        f = []
        f += self._admin_user_disabled()
        f += self._image_scan()
        f += self._public_network_access()
        f += self._geo_replication()
        return f

    def _client(self):
        from azure.mgmt.containerregistry import ContainerRegistryManagementClient
        return ContainerRegistryManagementClient(self.credential, self.subscription_id)

    def _rg(self, resource_id):
        try:
            parts = (resource_id or "").split("/")
            idx   = parts.index("resourceGroups") if "resourceGroups" in parts else -1
            return parts[idx + 1] if idx >= 0 and idx + 1 < len(parts) else ""
        except Exception:
            return ""

    def _admin_user_disabled(self):
        findings = []
        try:
            for reg in self._client().registries.list():
                rg = self._rg(reg.id)
                if reg.admin_user_enabled:
                    findings.append(self.finding(
                        "acr_admin_user_enabled",
                        reg.id, reg.name, "Container Registry", "FAIL", "High",
                        "Container Registry admin user is enabled",
                        f"Azure Portal → Container registries → {reg.name} → Settings → Access keys → Admin user → Disabled",
                        f"ACR '{reg.name}' admin user is enabled. The admin account uses a shared password "
                        "with no MFA. Use Entra ID service principals or managed identities for pulling images.",
                        tags=reg.tags, resource_group=rg, location=getattr(reg, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("acr_admin_user_enabled", e))
        return findings

    def _image_scan(self):
        findings = []
        try:
            for reg in self._client().registries.list():
                rg  = self._rg(reg.id)
                sku = (reg.sku.name if reg.sku else "") or ""
                if sku.lower() not in ("premium",):
                    findings.append(self.finding(
                        "acr_not_premium_sku",
                        reg.id, reg.name, "Container Registry", "FAIL", "Medium",
                        "Container Registry is not Premium SKU — vulnerability scanning unavailable",
                        f"Azure Portal → Container registries → {reg.name} → Settings → Upgrade → Premium",
                        f"ACR '{reg.name}' is on {sku} SKU. Vulnerability scanning with Microsoft Defender "
                        "for Containers requires Premium SKU and private link support.",
                        tags=reg.tags, resource_group=rg, location=getattr(reg, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("acr_not_premium_sku", e))
        return findings

    def _public_network_access(self):
        findings = []
        try:
            for reg in self._client().registries.list():
                rg = self._rg(reg.id)
                if reg.public_network_access and reg.public_network_access.lower() == "enabled":
                    findings.append(self.finding(
                        "acr_public_network_access_enabled",
                        reg.id, reg.name, "Container Registry", "FAIL", "Medium",
                        "Container Registry allows public network access",
                        f"Azure Portal → Container registries → {reg.name} → Settings → Networking → Public access → Disabled",
                        f"ACR '{reg.name}' has public network access enabled. "
                        "Restrict to Private Endpoint and deny public access for production registries.",
                        tags=reg.tags, resource_group=rg, location=getattr(reg, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("acr_public_network_access_enabled", e))
        return findings

    def _geo_replication(self):
        """Informational — geo-replication is a resiliency feature."""
        return []
