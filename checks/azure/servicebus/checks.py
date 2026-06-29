"""Azure Service Bus — 4 checks."""
from ..base import BaseCheck


class ServiceBusChecks(BaseCheck):
    SERVICE = "ServiceBus"

    def run_all(self):
        f = []
        f += self._premium_sku()
        f += self._tls_version()
        f += self._public_network_access()
        f += self._local_auth_disabled()
        return f

    def _client(self):
        from azure.mgmt.servicebus import ServiceBusManagementClient
        return ServiceBusManagementClient(self.credential, self.subscription_id)

    def _rg(self, rid):
        try:
            parts = (rid or "").split("/")
            idx = parts.index("resourceGroups") if "resourceGroups" in parts else -1
            return parts[idx + 1] if idx >= 0 and idx + 1 < len(parts) else ""
        except Exception:
            return ""

    def _premium_sku(self):
        findings = []
        try:
            for ns in self._client().namespaces.list():
                rg  = self._rg(ns.id)
                sku = (ns.sku.name if ns.sku else "") or ""
                if sku.lower() != "premium":
                    findings.append(self.finding(
                        "servicebus_not_premium_sku",
                        ns.id, ns.name, "Service Bus Namespace", "FAIL", "Medium",
                        "Service Bus is not Premium SKU — Private Endpoint unavailable",
                        f"Azure Portal → Service Bus → {ns.name} → Settings → Upgrade to Premium",
                        f"Service Bus '{ns.name}' is {sku} SKU. "
                        "Private Endpoint support and network isolation require Premium SKU.",
                        tags=ns.tags, resource_group=rg, location=getattr(ns, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("servicebus_not_premium_sku", e))
        return findings

    def _tls_version(self):
        findings = []
        try:
            for ns in self._client().namespaces.list():
                rg  = self._rg(ns.id)
                tls = getattr(ns, "minimum_tls_version", "1.0") or "1.0"
                if tls in ("1.0", "1.1"):
                    findings.append(self.finding(
                        "servicebus_min_tls_below_1_2",
                        ns.id, ns.name, "Service Bus Namespace", "FAIL", "High",
                        "Service Bus minimum TLS version is below 1.2",
                        f"Azure Portal → Service Bus → {ns.name} → Settings → Configuration → Minimum TLS version → 1.2",
                        f"Service Bus '{ns.name}' minimum TLS is {tls}. Deprecated TLS versions expose message traffic.",
                        tags=ns.tags, resource_group=rg, location=getattr(ns, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("servicebus_min_tls_below_1_2", e))
        return findings

    def _public_network_access(self):
        findings = []
        try:
            for ns in self._client().namespaces.list():
                rg = self._rg(ns.id)
                pna = getattr(ns, "public_network_access", "Enabled") or "Enabled"
                if pna.lower() == "enabled":
                    findings.append(self.finding(
                        "servicebus_public_network_access",
                        ns.id, ns.name, "Service Bus Namespace", "FAIL", "High",
                        "Service Bus namespace allows public network access",
                        f"Azure Portal → Service Bus → {ns.name} → Settings → Networking → Public access → Disabled",
                        f"Service Bus '{ns.name}' has public network access enabled. "
                        "Restrict to Private Endpoint to prevent internet-based access to messaging infrastructure.",
                        tags=ns.tags, resource_group=rg, location=getattr(ns, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("servicebus_public_network_access", e))
        return findings

    def _local_auth_disabled(self):
        findings = []
        try:
            for ns in self._client().namespaces.list():
                rg = self._rg(ns.id)
                if not getattr(ns, "disable_local_auth", False):
                    findings.append(self.finding(
                        "servicebus_local_auth_enabled",
                        ns.id, ns.name, "Service Bus Namespace", "FAIL", "Medium",
                        "Service Bus local (SAS key) authentication is not disabled",
                        f"Azure Portal → Service Bus → {ns.name} → Settings → Local authentication → Disable",
                        f"Service Bus '{ns.name}' allows SAS key authentication. "
                        "Disable local auth and enforce Entra ID RBAC for granular, auditable access control.",
                        tags=ns.tags, resource_group=rg, location=getattr(ns, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("servicebus_local_auth_enabled", e))
        return findings
