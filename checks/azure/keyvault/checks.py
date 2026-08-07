"""Azure Key Vault — 7 checks."""
from ..base import BaseCheck


class KeyVaultChecks(BaseCheck):
    SERVICE = "KeyVault"

    def run_all(self):
        f = []
        f += self._soft_delete()
        f += self._purge_protection()
        f += self._rbac_vs_access_policy()
        f += self._network_access()
        f += self._diagnostic_logging()
        f += self._key_expiry()
        f += self._secret_expiry()
        return f

    def _client(self):
        from azure.mgmt.keyvault import KeyVaultManagementClient
        return KeyVaultManagementClient(self.credential, self.subscription_id)

    def _rg(self, resource_id):
        try:
            parts = (resource_id or "").split("/")
            idx   = parts.index("resourceGroups") if "resourceGroups" in parts else -1
            return parts[idx + 1] if idx >= 0 and idx + 1 < len(parts) else ""
        except Exception:
            return ""

    def _soft_delete(self):
        findings = []
        try:
            for vault in self._client().vaults.list_by_subscription():
                rg = self._rg(vault.id)
                props = vault.properties
                if not getattr(props, "enable_soft_delete", True):
                    findings.append(self.finding(
                        "keyvault_soft_delete_disabled",
                        vault.id, vault.name, "Key Vault", "FAIL", "High",
                        "Key Vault soft delete is not enabled",
                        f"Azure Portal → Key vaults → {vault.name} → Properties → Soft delete → Enable",
                        f"Key Vault '{vault.name}' has soft delete disabled. Without soft delete, accidentally or "
                        "maliciously deleted keys/secrets/certificates are permanently unrecoverable.",
                        tags=vault.tags, resource_group=rg, location=getattr(vault, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("keyvault_soft_delete_disabled", e))
        return findings

    def _purge_protection(self):
        findings = []
        try:
            for vault in self._client().vaults.list_by_subscription():
                rg = self._rg(vault.id)
                props = vault.properties
                if not getattr(props, "enable_purge_protection", False):
                    findings.append(self.finding(
                        "keyvault_purge_protection_disabled",
                        vault.id, vault.name, "Key Vault", "FAIL", "High",
                        "Key Vault purge protection is not enabled",
                        f"Azure Portal → Key vaults → {vault.name} → Properties → Purge protection → Enable",
                        f"Key Vault '{vault.name}' purge protection is disabled. Without it, a malicious insider "
                        "can permanently destroy all secrets within the soft-delete retention window.",
                        tags=vault.tags, resource_group=rg, location=getattr(vault, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("keyvault_purge_protection_disabled", e))
        return findings

    def _rbac_vs_access_policy(self):
        findings = []
        try:
            for vault in self._client().vaults.list_by_subscription():
                rg    = self._rg(vault.id)
                props = vault.properties
                # Prefer RBAC authorization over legacy access policies
                if not getattr(props, "enable_rbac_authorization", False):
                    findings.append(self.finding(
                        "keyvault_uses_legacy_access_policies",
                        vault.id, vault.name, "Key Vault", "FAIL", "Medium",
                        "Key Vault uses legacy access policies instead of Azure RBAC",
                        f"Azure Portal → Key vaults → {vault.name} → Access configuration → Permission model → Azure role-based access control",
                        f"Key Vault '{vault.name}' uses vault access policies, not Azure RBAC. "
                        "RBAC provides finer-grained control, full audit via Azure Activity Logs, "
                        "and supports Privileged Identity Management for just-in-time access.",
                        tags=vault.tags, resource_group=rg, location=getattr(vault, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("keyvault_uses_legacy_access_policies", e))
        return findings

    def _network_access(self):
        findings = []
        try:
            for vault in self._client().vaults.list_by_subscription():
                rg    = self._rg(vault.id)
                props = vault.properties
                np    = getattr(props, "network_acls", None)
                default_action = "Allow"
                if np:
                    default_action = getattr(np, "default_action", "Allow") or "Allow"
                if default_action.lower() == "allow":
                    findings.append(self.finding(
                        "keyvault_public_network_access",
                        vault.id, vault.name, "Key Vault", "FAIL", "High",
                        "Key Vault allows public network access from all networks",
                        f"Azure Portal → Key vaults → {vault.name} → Networking → Firewalls and virtual networks → Selected networks or Private endpoint",
                        f"Key Vault '{vault.name}' network default action is Allow. "
                        "Restrict Key Vault access to specific VNets and Private Endpoints to prevent internet-based attacks.",
                        tags=vault.tags, resource_group=rg, location=getattr(vault, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("keyvault_public_network_access", e))
        return findings

    def _diagnostic_logging(self):
        findings = []
        try:
            from azure.mgmt.monitor import MonitorManagementClient
            mc = MonitorManagementClient(self.credential, self.subscription_id)
            for vault in self._client().vaults.list_by_subscription():
                rg   = self._rg(vault.id)
                diag = list(mc.diagnostic_settings.list(vault.id))
                if not diag:
                    findings.append(self.finding(
                        "keyvault_diagnostic_logging_disabled",
                        vault.id, vault.name, "Key Vault", "FAIL", "High",
                        "Key Vault diagnostic logging not configured",
                        f"Azure Portal → Key vaults → {vault.name} → Monitoring → Diagnostic settings → Add diagnostic setting",
                        f"Key Vault '{vault.name}' has no diagnostic settings. Without logging, secret access, "
                        "key operations, and administrative changes are not audited for security investigations.",
                        tags=vault.tags, resource_group=rg, location=getattr(vault, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("keyvault_diagnostic_logging_disabled", e))
        return findings

    def _key_expiry(self):
        findings = []
        try:
            from azure.keyvault.keys import KeyClient
            for vault in self._client().vaults.list_by_subscription():
                vault_url = f"https://{vault.name}.vault.azure.net"
                rg = self._rg(vault.id)
                try:
                    kc = KeyClient(vault_url=vault_url, credential=self.credential)
                    for key in kc.list_properties_of_keys():
                        exp = key.expires_on
                        if exp is None:
                            findings.append(self.finding(
                                "keyvault_key_no_expiry",
                                f"{vault.id}/keys/{key.name}", key.name,
                                "Key Vault Key", "FAIL", "Medium",
                                "Key Vault key has no expiry date set",
                                f"Azure Portal → Key vaults → {vault.name} → Keys → {key.name} → Set expiry date",
                                f"Key '{key.name}' in vault '{vault.name}' has no expiration date. "
                                "Keys without expiry accumulate over time and increase the risk of using compromised key material.",
                                resource_group=rg, location=getattr(vault, "location", None),
                            ))
                except Exception:
                    pass  # May lack data plane permissions
        except Exception as e:
            findings.append(self.error_finding("keyvault_key_no_expiry", e))
        return findings

    def _secret_expiry(self):
        findings = []
        try:
            from azure.keyvault.secrets import SecretClient
            for vault in self._client().vaults.list_by_subscription():
                vault_url = f"https://{vault.name}.vault.azure.net"
                rg = self._rg(vault.id)
                try:
                    sc = SecretClient(vault_url=vault_url, credential=self.credential)
                    for secret in sc.list_properties_of_secrets():
                        exp = secret.expires_on
                        if exp is None:
                            findings.append(self.finding(
                                "keyvault_secret_no_expiry",
                                f"{vault.id}/secrets/{secret.name}", secret.name,
                                "Key Vault Secret", "FAIL", "Medium",
                                "Key Vault secret has no expiry date set",
                                f"Azure Portal → Key vaults → {vault.name} → Secrets → {secret.name} → Set expiration date",
                                f"Secret '{secret.name}' in vault '{vault.name}' has no expiration date. "
                                "Stale secrets can persist after rotation is overdue, increasing breach risk.",
                                resource_group=rg, location=getattr(vault, "location", None),
                            ))
                except Exception:
                    pass
        except Exception as e:
            findings.append(self.error_finding("keyvault_secret_no_expiry", e))
        return findings
