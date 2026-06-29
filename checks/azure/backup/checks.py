"""Azure Backup / Recovery Services Vault — 4 checks."""
from ..base import BaseCheck


class BackupChecks(BaseCheck):
    SERVICE = "Backup"

    def run_all(self):
        f = []
        f += self._vault_exists()
        f += self._soft_delete()
        f += self._immutability()
        f += self._encryption_cmk()
        return f

    def _client(self):
        from azure.mgmt.recoveryservices import RecoveryServicesClient
        return RecoveryServicesClient(self.credential, self.subscription_id)

    def _rg(self, rid):
        try:
            parts = (rid or "").split("/")
            idx = parts.index("resourceGroups") if "resourceGroups" in parts else -1
            return parts[idx + 1] if idx >= 0 and idx + 1 < len(parts) else ""
        except Exception:
            return ""

    def _vault_exists(self):
        findings = []
        try:
            vaults = list(self._client().vaults.list_by_subscription_id())
            if not vaults:
                findings.append(self.finding(
                    "backup_no_recovery_vault",
                    f"/subscriptions/{self.subscription_id}",
                    "Subscription", "Recovery Services Vault", "FAIL", "High",
                    "No Recovery Services Vault found in subscription",
                    "Azure Portal → Backup center → + Create → Recovery Services vault",
                    "No Recovery Services Vault found. Without one, Azure Backup policies for VMs, SQL, "
                    "file shares, and other resources cannot be configured.",
                ))
        except Exception as e:
            findings.append(self.error_finding("backup_no_recovery_vault", e))
        return findings

    def _soft_delete(self):
        findings = []
        try:
            for vault in self._client().vaults.list_by_subscription_id():
                rg    = self._rg(vault.id)
                props = vault.properties
                # v4 SDK: soft delete lives under properties.soft_delete_settings.soft_delete_state
                sd_settings = getattr(props, "soft_delete_settings", None) if props else None
                if sd_settings:
                    sd_state = getattr(sd_settings, "soft_delete_state", "Enabled") or "Enabled"
                else:
                    sd_state = "Enabled"  # default is enabled — only flag if explicitly disabled
                if sd_state.lower() == "disabled":
                    findings.append(self.finding(
                        "backup_vault_soft_delete_disabled",
                        vault.id, vault.name, "Recovery Services Vault", "FAIL", "Critical",
                        "Recovery Services Vault soft delete is disabled",
                        f"Azure Portal → Recovery Services vaults → {vault.name} → Properties → Security settings → Soft delete → Enable",
                        f"Vault '{vault.name}' has soft delete disabled. Without it, backup data deleted by a "
                        "ransomware attack or malicious insider is permanently and immediately destroyed.",
                        tags=vault.tags, resource_group=rg, location=getattr(vault, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("backup_vault_soft_delete_disabled", e))
        return findings

    def _immutability(self):
        findings = []
        try:
            for vault in self._client().vaults.list_by_subscription_id():
                rg    = self._rg(vault.id)
                props = vault.properties
                # v4 SDK: immutability lives under properties.immutability_settings.state
                imm_settings = getattr(props, "immutability_settings", None) if props else None
                state = getattr(imm_settings, "state", "Disabled") if imm_settings else "Disabled"
                state = state or "Disabled"
                if state.lower() in ("disabled", "unlocked"):
                    findings.append(self.finding(
                        "backup_vault_immutability_not_locked",
                        vault.id, vault.name, "Recovery Services Vault", "FAIL", "High",
                        "Recovery Services Vault immutability is not locked",
                        f"Azure Portal → Recovery Services vaults → {vault.name} → Properties → Security settings → Immutability → Enable and Lock",
                        f"Vault '{vault.name}' immutability state is '{state}'. Immutability prevents backup data "
                        "modification or deletion for the retention period, protecting against ransomware that targets backups.",
                        tags=vault.tags, resource_group=rg, location=getattr(vault, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("backup_vault_immutability_not_locked", e))
        return findings

    def _encryption_cmk(self):
        findings = []
        try:
            for vault in self._client().vaults.list_by_subscription_id():
                rg    = self._rg(vault.id)
                props = vault.properties
                enc   = getattr(props, "encryption", None) if props else None
                if not enc or not getattr(enc, "key_vault_properties", None):
                    findings.append(self.finding(
                        "backup_vault_no_cmk",
                        vault.id, vault.name, "Recovery Services Vault", "FAIL", "Medium",
                        "Recovery Services Vault not using Customer-Managed Key encryption",
                        f"Azure Portal → Recovery Services vaults → {vault.name} → Properties → Encryption → Customer-managed key",
                        f"Vault '{vault.name}' uses Microsoft-managed encryption. "
                        "For regulatory compliance (PCI, HIPAA), configure CMK via Key Vault for full key control.",
                        tags=vault.tags, resource_group=rg, location=getattr(vault, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("backup_vault_no_cmk", e))
        return findings
