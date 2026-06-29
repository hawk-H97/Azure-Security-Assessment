"""Azure Storage — 10 checks."""
from ..base import BaseCheck


class StorageChecks(BaseCheck):
    SERVICE = "Storage"

    def run_all(self):
        f = []
        f += self._public_blob_access()
        f += self._https_only()
        f += self._tls_version()
        f += self._encryption_at_rest()
        f += self._encryption_in_transit()
        f += self._soft_delete_blobs()
        f += self._soft_delete_containers()
        f += self._logging_enabled()
        f += self._network_default_deny()
        f += self._shared_access_signature()
        return f

    def _client(self):
        from azure.mgmt.storage import StorageManagementClient
        return StorageManagementClient(self.credential, self.subscription_id)

    def _public_blob_access(self):
        findings = []
        try:
            for acct in self._client().storage_accounts.list():
                if acct.allow_blob_public_access in (True, None):
                    rg = self._rg(acct.id)
                    findings.append(self.finding(
                        "storage_blob_public_access_enabled",
                        acct.id, acct.name, "Storage Account", "FAIL", "Critical",
                        "Storage account allows public blob access",
                        f"Azure Portal → Storage accounts → {acct.name} → Settings → Configuration → Allow Blob public access → Disabled",
                        f"Storage account '{acct.name}' has AllowBlobPublicAccess={acct.allow_blob_public_access}. "
                        "Public blob access exposes data to the entire internet without authentication.",
                        tags=acct.tags, resource_group=rg, location=getattr(acct, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("storage_blob_public_access_enabled", e))
        return findings

    def _https_only(self):
        findings = []
        try:
            for acct in self._client().storage_accounts.list():
                if not acct.enable_https_traffic_only:
                    rg = self._rg(acct.id)
                    findings.append(self.finding(
                        "storage_https_only_disabled",
                        acct.id, acct.name, "Storage Account", "FAIL", "High",
                        "Storage account does not enforce HTTPS-only traffic",
                        f"Azure Portal → Storage accounts → {acct.name} → Settings → Configuration → Secure transfer required → Enabled",
                        f"Storage account '{acct.name}' allows HTTP connections. Data in transit can be intercepted.",
                        tags=acct.tags, resource_group=rg, location=getattr(acct, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("storage_https_only_disabled", e))
        return findings

    def _tls_version(self):
        findings = []
        try:
            for acct in self._client().storage_accounts.list():
                tls = acct.minimum_tls_version or "TLS1_0"
                if tls in ("TLS1_0", "TLS1_1"):
                    rg = self._rg(acct.id)
                    findings.append(self.finding(
                        "storage_min_tls_version_below_1_2",
                        acct.id, acct.name, "Storage Account", "FAIL", "High",
                        "Storage account minimum TLS version below 1.2",
                        f"Azure Portal → Storage accounts → {acct.name} → Settings → Configuration → Minimum TLS version → TLS 1.2",
                        f"Storage account '{acct.name}' allows {tls}. TLS 1.0/1.1 are deprecated with known vulnerabilities.",
                        tags=acct.tags, resource_group=rg, location=getattr(acct, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("storage_min_tls_version_below_1_2", e))
        return findings

    def _encryption_at_rest(self):
        """Azure Storage encrypts at rest by default — check for CMK."""
        findings = []
        try:
            for acct in self._client().storage_accounts.list():
                enc = acct.encryption
                if enc and enc.key_source and enc.key_source.lower() == "microsoft.storage":
                    rg = self._rg(acct.id)
                    findings.append(self.finding(
                        "storage_no_customer_managed_key",
                        acct.id, acct.name, "Storage Account", "FAIL", "Medium",
                        "Storage account uses Microsoft-managed keys instead of Customer-Managed Keys",
                        f"Azure Portal → Storage accounts → {acct.name} → Security + networking → Encryption → Customer-managed keys",
                        f"Storage account '{acct.name}' uses Microsoft-managed encryption keys. "
                        "For sensitive data, use Customer-Managed Keys (CMK) via Azure Key Vault for full key lifecycle control.",
                        tags=acct.tags, resource_group=rg, location=getattr(acct, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("storage_no_customer_managed_key", e))
        return findings

    def _encryption_in_transit(self):
        # Covered by https_only — no separate check needed
        return []

    def _soft_delete_blobs(self):
        findings = []
        try:
            sc = self._client()
            for acct in sc.storage_accounts.list():
                rg = self._rg(acct.id)
                try:
                    props = sc.blob_services.get_service_properties(rg, acct.name)
                    sd = props.delete_retention_policy
                    if not sd or not sd.enabled or (sd.days or 0) < 7:
                        findings.append(self.finding(
                            "storage_blob_soft_delete_disabled",
                            acct.id, acct.name, "Storage Account", "FAIL", "Medium",
                            "Blob soft delete not enabled or retention < 7 days",
                            f"Azure Portal → Storage accounts → {acct.name} → Data management → Data protection → Enable soft delete for blobs",
                            f"Storage account '{acct.name}': Blob soft delete is {'disabled' if not (sd and sd.enabled) else f'only {sd.days} days'}. "
                            "Soft delete protects against accidental or malicious blob deletion.",
                            tags=acct.tags, resource_group=rg, location=getattr(acct, "location", None),
                        ))
                except Exception:
                    pass
        except Exception as e:
            findings.append(self.error_finding("storage_blob_soft_delete_disabled", e))
        return findings

    def _soft_delete_containers(self):
        findings = []
        try:
            sc = self._client()
            for acct in sc.storage_accounts.list():
                rg = self._rg(acct.id)
                try:
                    props = sc.blob_services.get_service_properties(rg, acct.name)
                    sd = props.container_delete_retention_policy
                    if not sd or not sd.enabled or (sd.days or 0) < 7:
                        findings.append(self.finding(
                            "storage_container_soft_delete_disabled",
                            acct.id, acct.name, "Storage Account", "FAIL", "Medium",
                            "Container soft delete not enabled or retention < 7 days",
                            f"Azure Portal → Storage accounts → {acct.name} → Data management → Data protection → Enable soft delete for containers",
                            f"Storage account '{acct.name}': Container soft delete is disabled or < 7 days. "
                            "Enables recovery from accidental container deletion.",
                            tags=acct.tags, resource_group=rg, location=getattr(acct, "location", None),
                        ))
                except Exception:
                    pass
        except Exception as e:
            findings.append(self.error_finding("storage_container_soft_delete_disabled", e))
        return findings

    def _logging_enabled(self):
        findings = []
        try:
            sc = self._client()
            for acct in sc.storage_accounts.list():
                rg = self._rg(acct.id)
                try:
                    props = sc.blob_services.get_service_properties(rg, acct.name)
                    log = getattr(props, "logging", None)
                    if not log or not (getattr(log, "read", False) and
                                       getattr(log, "write", False) and
                                       getattr(log, "delete", False)):
                        findings.append(self.finding(
                            "storage_logging_not_enabled",
                            acct.id, acct.name, "Storage Account", "FAIL", "Medium",
                            "Storage account blob logging not fully enabled",
                            f"Azure Portal → Storage accounts → {acct.name} → Monitoring → Diagnostic settings → Add diagnostic setting",
                            f"Storage account '{acct.name}' does not have full read/write/delete logging enabled. "
                            "Enable diagnostic logging to detect unauthorized access and data exfiltration.",
                            tags=acct.tags, resource_group=rg, location=getattr(acct, "location", None),
                        ))
                except Exception:
                    pass
        except Exception as e:
            findings.append(self.error_finding("storage_logging_not_enabled", e))
        return findings

    def _network_default_deny(self):
        findings = []
        try:
            for acct in self._client().storage_accounts.list():
                nr = acct.network_rule_set
                if not nr or nr.default_action and nr.default_action.lower() == "allow":
                    rg = self._rg(acct.id)
                    findings.append(self.finding(
                        "storage_network_default_allow",
                        acct.id, acct.name, "Storage Account", "FAIL", "High",
                        "Storage account network rule default action is Allow (no firewall)",
                        f"Azure Portal → Storage accounts → {acct.name} → Security + networking → Networking → Firewalls and virtual networks → Selected networks",
                        f"Storage account '{acct.name}' network default action is Allow. "
                        "Set to Deny and whitelist only required VNets/IPs to enforce network isolation.",
                        tags=acct.tags, resource_group=rg, location=getattr(acct, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("storage_network_default_allow", e))
        return findings

    def _shared_access_signature(self):
        """Advisory: remind to expire SAS tokens and avoid account-level SAS."""
        findings = []
        try:
            for acct in self._client().storage_accounts.list():
                rg = self._rg(acct.id)
                findings.append(self.finding(
                    "storage_sas_expiry_policy",
                    acct.id, acct.name, "Storage Account", "FAIL", "Low",
                    "Ensure SAS expiry policy is configured and SAS tokens are short-lived",
                    f"Azure Portal → Storage accounts → {acct.name} → Settings → Configuration → Allowed storage account key access → SAS expiry policy",
                    f"Storage account '{acct.name}': Verify SAS expiry policy is set (max 1 hour for sensitive data). "
                    "Long-lived SAS tokens are equivalent to permanent credentials if leaked.",
                    tags=acct.tags, resource_group=rg, location=getattr(acct, "location", None),
                ))
        except Exception as e:
            findings.append(self.error_finding("storage_sas_expiry_policy", e))
        return findings

    def _rg(self, resource_id):
        try:
            parts = (resource_id or "").split("/")
            idx   = parts.index("resourceGroups") if "resourceGroups" in parts else -1
            return parts[idx + 1] if idx >= 0 and idx + 1 < len(parts) else ""
        except Exception:
            return ""
