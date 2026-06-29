"""Azure Cosmos DB — 5 checks."""
from ..base import BaseCheck


class CosmosChecks(BaseCheck):
    SERVICE = "CosmosDB"

    def run_all(self):
        f = []
        f += self._public_network_access()
        f += self._cmk_encryption()
        f += self._local_auth_disabled()
        f += self._automatic_failover()
        f += self._advanced_threat_protection()
        return f

    def _client(self):
        from azure.mgmt.cosmosdb import CosmosDBManagementClient
        return CosmosDBManagementClient(self.credential, self.subscription_id)

    def _rg(self, resource_id):
        try:
            parts = (resource_id or "").split("/")
            idx   = parts.index("resourceGroups") if "resourceGroups" in parts else -1
            return parts[idx + 1] if idx >= 0 and idx + 1 < len(parts) else ""
        except Exception:
            return ""

    def _public_network_access(self):
        findings = []
        try:
            for acct in self._client().database_accounts.list():
                rg = self._rg(acct.id)
                if acct.public_network_access and acct.public_network_access.lower() == "enabled":
                    findings.append(self.finding(
                        "cosmos_public_network_access_enabled",
                        acct.id, acct.name, "Cosmos DB Account", "FAIL", "High",
                        "Cosmos DB account allows public network access",
                        f"Azure Portal → Azure Cosmos DB → {acct.name} → Settings → Networking → Public access → Disable",
                        f"Cosmos DB '{acct.name}' has public network access enabled. "
                        "Restrict to selected networks or Private Endpoint to prevent internet-based data access.",
                        tags=acct.tags, resource_group=rg, location=getattr(acct, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("cosmos_public_network_access_enabled", e))
        return findings

    def _cmk_encryption(self):
        findings = []
        try:
            for acct in self._client().database_accounts.list():
                rg = self._rg(acct.id)
                if not acct.key_vault_key_uri:
                    findings.append(self.finding(
                        "cosmos_no_customer_managed_key",
                        acct.id, acct.name, "Cosmos DB Account", "FAIL", "Medium",
                        "Cosmos DB not using Customer-Managed Key encryption",
                        f"Azure Portal → Azure Cosmos DB → {acct.name} → Settings → Encryption → Customer-managed key",
                        f"Cosmos DB '{acct.name}' uses Microsoft-managed encryption keys. "
                        "For sensitive datasets, enable CMK via Key Vault for full control over encryption key lifecycle.",
                        tags=acct.tags, resource_group=rg, location=getattr(acct, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("cosmos_no_customer_managed_key", e))
        return findings

    def _local_auth_disabled(self):
        findings = []
        try:
            for acct in self._client().database_accounts.list():
                rg = self._rg(acct.id)
                if not getattr(acct, "disable_local_auth", False):
                    findings.append(self.finding(
                        "cosmos_local_auth_enabled",
                        acct.id, acct.name, "Cosmos DB Account", "FAIL", "Medium",
                        "Cosmos DB local (key-based) authentication is not disabled",
                        f"Azure Portal → Azure Cosmos DB → {acct.name} → Settings → Keys → Disable local authentication",
                        f"Cosmos DB '{acct.name}' allows primary/secondary key authentication. "
                        "Keys cannot be scoped and rotate manually. Disable local auth and use Entra ID RBAC instead.",
                        tags=acct.tags, resource_group=rg, location=getattr(acct, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("cosmos_local_auth_enabled", e))
        return findings

    def _automatic_failover(self):
        findings = []
        try:
            for acct in self._client().database_accounts.list():
                rg = self._rg(acct.id)
                if not acct.enable_automatic_failover:
                    findings.append(self.finding(
                        "cosmos_automatic_failover_disabled",
                        acct.id, acct.name, "Cosmos DB Account", "FAIL", "Low",
                        "Cosmos DB automatic failover not enabled",
                        f"Azure Portal → Azure Cosmos DB → {acct.name} → Settings → Replicate data globally → Automatic failover → On",
                        f"Cosmos DB '{acct.name}' automatic failover is disabled. "
                        "Without it, a regional outage requires manual intervention, causing extended downtime.",
                        tags=acct.tags, resource_group=rg, location=getattr(acct, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("cosmos_automatic_failover_disabled", e))
        return findings

    def _advanced_threat_protection(self):
        findings = []
        try:
            from azure.mgmt.security import SecurityCenter
            sc = SecurityCenter(self.credential, self.subscription_id)
            for acct in self._client().database_accounts.list():
                rg = self._rg(acct.id)
                try:
                    atp = sc.advanced_threat_protection.get(acct.id)
                    if not atp or not atp.is_enabled:
                        findings.append(self.finding(
                            "cosmos_atp_not_enabled",
                            acct.id, acct.name, "Cosmos DB Account", "FAIL", "High",
                            "Cosmos DB Advanced Threat Protection not enabled",
                            f"Azure Portal → Azure Cosmos DB → {acct.name} → Microsoft Defender for Cloud → Enable",
                            f"Cosmos DB '{acct.name}' has Advanced Threat Protection disabled. "
                            "ATP detects SQL injection, unusual access, and data exfiltration in real time.",
                            tags=acct.tags, resource_group=rg, location=getattr(acct, "location", None),
                        ))
                except Exception:
                    pass
        except Exception as e:
            findings.append(self.error_finding("cosmos_atp_not_enabled", e))
        return findings
