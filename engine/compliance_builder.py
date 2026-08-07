"""Builds all Azure compliance JSON files locally."""
import json
from pathlib import Path

ROOT = Path(__file__).parent.parent


class AzureComplianceBuilder:
    def __init__(self, display):
        self.display = display

    def build_all(self, azure_dir):
        azure_dir.mkdir(parents=True, exist_ok=True)
        builders = {
            "cis_azure_2.0.json":       self._cis,
            "nist_csf_2.0_azure.json":  self._nist_csf,
            "nist_800_53_azure.json":   self._nist_800_53,
            "hipaa_azure.json":         self._hipaa,
            "pci_dss_4.0_azure.json":   self._pci_dss,
            "gdpr_azure.json":          self._gdpr,
            "csa_ccm_azure.json":       self._csa_ccm,
            "mitre_attack_azure.json":  self._mitre,
        }
        for fname, fn in builders.items():
            fpath = azure_dir / fname
            if not fpath.exists():
                self.display.warn(f"  {fname} — creating...")
                data = fn()
                fpath.write_text(json.dumps(data, indent=2))
            self.display.success(f"  {fname}")

    # ── CIS Azure Benchmark 2.0 ───────────────────────────────────────────
    def _cis(self):
        return {
            "Framework": "CIS",
            "Version": "2.0",
            "Provider": "Azure",
            "Description": "CIS Microsoft Azure Foundations Benchmark v2.0",
            "Source": "https://www.cisecurity.org/benchmark/azure",
            "Requirements": [
                {"Id": "1.1",  "Description": "Ensure MFA is enabled for all privileged users",
                 "Checks": ["iam_mfa_not_enforced", "iam_conditional_access_required"], "Severity": "Critical"},
                {"Id": "1.2",  "Description": "Ensure MFA is enabled for all non-privileged users",
                 "Checks": ["iam_security_defaults_enabled"], "Severity": "High"},
                {"Id": "1.3",  "Description": "Ensure guest users are reviewed monthly",
                 "Checks": ["iam_guest_owner_role", "iam_guest_invite_policy"], "Severity": "Medium"},
                {"Id": "1.4",  "Description": "Ensure Azure Active Directory administrator is configured for SQL",
                 "Checks": ["sql_no_aad_admin"], "Severity": "High"},
                {"Id": "1.5",  "Description": "Ensure no more than 3 subscription owners are assigned",
                 "Checks": ["iam_too_many_subscription_owners"], "Severity": "High"},
                {"Id": "1.6",  "Description": "Ensure PIM is used to manage privileged roles",
                 "Checks": ["iam_no_pim_privileged_roles"], "Severity": "High"},
                {"Id": "1.7",  "Description": "Ensure custom roles do not allow wildcard actions",
                 "Checks": ["iam_custom_role_wildcard_action"], "Severity": "High"},
                {"Id": "1.8",  "Description": "Ensure Classic administrators are removed",
                 "Checks": ["iam_classic_administrator_exists"], "Severity": "High"},
                {"Id": "2.1",  "Description": "Ensure Microsoft Defender for Cloud is enabled for all resource types",
                 "Checks": ["defender_plan_virtualmachines_not_enabled",
                            "defender_plan_sqlservers_not_enabled",
                            "defender_plan_appservices_not_enabled",
                            "defender_plan_storageaccounts_not_enabled",
                            "defender_plan_containers_not_enabled",
                            "defender_plan_keyvaults_not_enabled"], "Severity": "High"},
                {"Id": "2.2",  "Description": "Ensure auto provisioning of monitoring agent is on",
                 "Checks": ["defender_auto_provisioning_disabled"], "Severity": "High"},
                {"Id": "2.3",  "Description": "Ensure Defender for Cloud security contact is configured",
                 "Checks": ["defender_no_security_contact", "defender_security_contact_no_email"], "Severity": "Medium"},
                {"Id": "3.1",  "Description": "Ensure storage account Public access is disallowed",
                 "Checks": ["storage_blob_public_access_enabled"], "Severity": "Critical"},
                {"Id": "3.2",  "Description": "Ensure secure transfer is required for storage accounts",
                 "Checks": ["storage_https_only_disabled"], "Severity": "High"},
                {"Id": "3.3",  "Description": "Ensure storage account minimum TLS version is 1.2",
                 "Checks": ["storage_min_tls_version_below_1_2"], "Severity": "High"},
                {"Id": "3.4",  "Description": "Ensure default action for storage accounts is Deny",
                 "Checks": ["storage_network_default_allow"], "Severity": "High"},
                {"Id": "3.5",  "Description": "Ensure blob soft delete is enabled",
                 "Checks": ["storage_blob_soft_delete_disabled"], "Severity": "Medium"},
                {"Id": "3.6",  "Description": "Ensure container soft delete is enabled",
                 "Checks": ["storage_container_soft_delete_disabled"], "Severity": "Medium"},
                {"Id": "4.1",  "Description": "Ensure SQL server auditing is enabled",
                 "Checks": ["sql_server_auditing_disabled"], "Severity": "High"},
                {"Id": "4.2",  "Description": "Ensure TDE is enabled for SQL databases",
                 "Checks": ["sql_tde_disabled"], "Severity": "Critical"},
                {"Id": "4.3",  "Description": "Ensure SQL servers have Azure Defender enabled",
                 "Checks": ["sql_threat_detection_disabled"], "Severity": "High"},
                {"Id": "4.4",  "Description": "Ensure SQL server public network access is disabled",
                 "Checks": ["sql_server_public_network_access"], "Severity": "High"},
                {"Id": "4.5",  "Description": "Ensure SQL firewall does not allow all IPs",
                 "Checks": ["sql_firewall_allows_all_ips"], "Severity": "Critical"},
                {"Id": "4.6",  "Description": "Ensure SQL vulnerability assessment is configured",
                 "Checks": ["sql_vulnerability_assessment_disabled"], "Severity": "High"},
                {"Id": "5.1",  "Description": "Ensure Azure Activity log retention is set to at least one year",
                 "Checks": ["monitor_no_log_profile", "monitor_log_retention_under_365_days"], "Severity": "Medium"},
                {"Id": "5.2",  "Description": "Ensure alert for policy assignment exists",
                 "Checks": ["monitor_alert_policy_assignment"], "Severity": "Medium"},
                {"Id": "5.3",  "Description": "Ensure alert for NSG changes exists",
                 "Checks": ["monitor_alert_nsg_change"], "Severity": "Medium"},
                {"Id": "5.4",  "Description": "Ensure alert for security solution delete exists",
                 "Checks": ["monitor_alert_security_solution_delete"], "Severity": "Medium"},
                {"Id": "5.5",  "Description": "Ensure alert for SQL firewall changes exists",
                 "Checks": ["monitor_alert_sql_firewall_change"], "Severity": "Medium"},
                {"Id": "6.1",  "Description": "Ensure NSG does not allow unrestricted SSH access",
                 "Checks": ["nsg_ssh_open_to_internet"], "Severity": "Critical"},
                {"Id": "6.2",  "Description": "Ensure NSG does not allow unrestricted RDP access",
                 "Checks": ["nsg_rdp_open_to_internet"], "Severity": "Critical"},
                {"Id": "6.3",  "Description": "Ensure Azure Network Watcher is enabled",
                 "Checks": ["network_watcher_not_enabled"], "Severity": "Medium"},
                {"Id": "6.4",  "Description": "Ensure NSG flow log retention is at least 90 days",
                 "Checks": ["nsg_flow_logs_not_enabled"], "Severity": "Medium"},
                {"Id": "7.1",  "Description": "Ensure VM OS disks are encrypted",
                 "Checks": ["vm_os_disk_not_encrypted"], "Severity": "High"},
                {"Id": "7.2",  "Description": "Ensure Just-In-Time VM access is enabled",
                 "Checks": ["vm_jit_access_not_configured"], "Severity": "High"},
                {"Id": "8.1",  "Description": "Ensure Key Vault soft delete is enabled",
                 "Checks": ["keyvault_soft_delete_disabled"], "Severity": "High"},
                {"Id": "8.2",  "Description": "Ensure Key Vault purge protection is enabled",
                 "Checks": ["keyvault_purge_protection_disabled"], "Severity": "High"},
                {"Id": "8.3",  "Description": "Ensure Key Vault keys have an expiration date",
                 "Checks": ["keyvault_key_no_expiry"], "Severity": "Medium"},
                {"Id": "8.4",  "Description": "Ensure Key Vault secrets have an expiration date",
                 "Checks": ["keyvault_secret_no_expiry"], "Severity": "Medium"},
                {"Id": "9.1",  "Description": "Ensure App Service enforces HTTPS only",
                 "Checks": ["appservice_https_only_disabled", "functions_https_only_disabled"], "Severity": "High"},
                {"Id": "9.2",  "Description": "Ensure App Service minimum TLS is 1.2",
                 "Checks": ["appservice_min_tls_below_1_2"], "Severity": "High"},
                {"Id": "9.3",  "Description": "Ensure App Service does not allow FTP",
                 "Checks": ["appservice_ftp_enabled"], "Severity": "High"},
                {"Id": "9.4",  "Description": "Ensure remote debugging is disabled on App Service",
                 "Checks": ["appservice_remote_debugging_enabled"], "Severity": "High"},
                {"Id": "10.1", "Description": "Ensure AKS RBAC is enabled",
                 "Checks": ["aks_rbac_disabled"], "Severity": "Critical"},
                {"Id": "10.2", "Description": "Ensure AKS has Azure AD integration",
                 "Checks": ["aks_aad_integration_disabled"], "Severity": "High"},
                {"Id": "10.3", "Description": "Ensure AKS API server has authorized IP ranges",
                 "Checks": ["aks_api_server_unrestricted_access"], "Severity": "Critical"},
            ]
        }

    def _nist_csf(self):
        return {
            "Framework": "NIST_CSF",
            "Version": "2.0",
            "Provider": "Azure",
            "Description": "NIST Cybersecurity Framework 2.0 — Azure",
            "Requirements": [
                {"Id": "GV.SC-07", "Description": "Cybersecurity supply chain risk managed",
                 "Checks": ["acr_admin_user_enabled", "acr_public_network_access_enabled"], "Severity": "Medium"},
                {"Id": "ID.AM-01", "Description": "Asset inventories are maintained",
                 "Checks": ["security_missing_required_tags"], "Severity": "Low"},
                {"Id": "PR.AA-01", "Description": "Identities and credentials are managed",
                 "Checks": ["iam_mfa_not_enforced", "iam_conditional_access_required",
                            "keyvault_key_no_expiry", "keyvault_secret_no_expiry"], "Severity": "Critical"},
                {"Id": "PR.AA-03", "Description": "Users have minimum necessary access",
                 "Checks": ["iam_too_many_subscription_owners", "iam_no_pim_privileged_roles",
                            "iam_custom_role_wildcard_action"], "Severity": "High"},
                {"Id": "PR.DS-01", "Description": "Data-at-rest is protected",
                 "Checks": ["storage_no_customer_managed_key", "sql_tde_disabled",
                            "vm_os_disk_not_encrypted", "cosmos_no_customer_managed_key",
                            "keyvault_purge_protection_disabled"], "Severity": "High"},
                {"Id": "PR.DS-02", "Description": "Data-in-transit is protected",
                 "Checks": ["storage_https_only_disabled", "storage_min_tls_version_below_1_2",
                            "appservice_https_only_disabled", "redis_non_ssl_port_enabled",
                            "redis_min_tls_below_1_2", "servicebus_min_tls_below_1_2"], "Severity": "High"},
                {"Id": "PR.IR-01", "Description": "Networks and environments are protected",
                 "Checks": ["nsg_ssh_open_to_internet", "nsg_rdp_open_to_internet",
                            "subnet_no_nsg_attached", "security_no_private_endpoints"], "Severity": "Critical"},
                {"Id": "PR.PS-01", "Description": "Configuration management is established",
                 "Checks": ["policy_no_assignments", "policy_no_security_benchmark"], "Severity": "High"},
                {"Id": "DE.AE-02", "Description": "Potentially adverse events are analysed",
                 "Checks": ["monitor_no_log_profile", "monitor_alert_nsg_change",
                            "nsg_flow_logs_not_enabled"], "Severity": "High"},
                {"Id": "DE.CM-01", "Description": "Networks are monitored",
                 "Checks": ["network_watcher_not_enabled", "nsg_flow_logs_not_enabled",
                            "azure_bastion_not_deployed"], "Severity": "High"},
                {"Id": "RS.MA-01", "Description": "Incident response plan is executed",
                 "Checks": ["defender_no_security_contact", "defender_sentinel_not_connected"], "Severity": "High"},
                {"Id": "RC.RP-01", "Description": "Recovery plan is executed",
                 "Checks": ["backup_no_recovery_vault", "backup_vault_soft_delete_disabled"], "Severity": "High"},
            ]
        }

    def _nist_800_53(self):
        return {
            "Framework": "NIST_800_53",
            "Version": "Rev5",
            "Provider": "Azure",
            "Description": "NIST SP 800-53 Revision 5 — Azure",
            "Requirements": [
                {"Id": "AC-2",  "Description": "Account Management",
                 "Checks": ["iam_guest_owner_role", "iam_too_many_subscription_owners",
                            "iam_classic_administrator_exists"], "Severity": "High"},
                {"Id": "AC-3",  "Description": "Access Enforcement",
                 "Checks": ["iam_custom_role_wildcard_action", "cosmos_local_auth_enabled",
                            "servicebus_local_auth_enabled"], "Severity": "High"},
                {"Id": "AC-6",  "Description": "Least Privilege",
                 "Checks": ["iam_no_pim_privileged_roles", "acr_admin_user_enabled",
                            "vm_no_managed_identity"], "Severity": "High"},
                {"Id": "AU-2",  "Description": "Event Logging",
                 "Checks": ["monitor_no_log_profile", "sql_server_auditing_disabled",
                            "keyvault_diagnostic_logging_disabled", "logic_app_no_diagnostic_logging"], "Severity": "High"},
                {"Id": "AU-9",  "Description": "Protection of Audit Information",
                 "Checks": ["monitor_log_retention_under_365_days", "backup_vault_immutability_not_locked"], "Severity": "Medium"},
                {"Id": "CP-9",  "Description": "Information System Backup",
                 "Checks": ["backup_no_recovery_vault", "backup_vault_soft_delete_disabled",
                            "cosmos_automatic_failover_disabled"], "Severity": "High"},
                {"Id": "IA-2",  "Description": "Identification and Authentication",
                 "Checks": ["iam_mfa_not_enforced", "iam_conditional_access_required",
                            "iam_security_defaults_enabled", "sql_no_aad_admin"], "Severity": "Critical"},
                {"Id": "IA-5",  "Description": "Authenticator Management",
                 "Checks": ["keyvault_key_no_expiry", "keyvault_secret_no_expiry",
                            "iam_service_principal_use_certificates", "storage_sas_expiry_policy"], "Severity": "Medium"},
                {"Id": "SC-7",  "Description": "Boundary Protection",
                 "Checks": ["nsg_ssh_open_to_internet", "nsg_rdp_open_to_internet",
                            "nsg_all_ports_open_to_internet", "subnet_no_nsg_attached",
                            "sql_server_public_network_access", "storage_network_default_allow"], "Severity": "Critical"},
                {"Id": "SC-8",  "Description": "Transmission Confidentiality and Integrity",
                 "Checks": ["storage_https_only_disabled", "appservice_https_only_disabled",
                            "redis_non_ssl_port_enabled"], "Severity": "High"},
                {"Id": "SC-28", "Description": "Protection of Information at Rest",
                 "Checks": ["sql_tde_disabled", "vm_os_disk_not_encrypted",
                            "storage_no_customer_managed_key"], "Severity": "High"},
                {"Id": "SI-2",  "Description": "Flaw Remediation",
                 "Checks": ["vm_auto_update_disabled", "aks_node_os_auto_upgrade_disabled",
                            "functions_outdated_runtime"], "Severity": "High"},
                {"Id": "SI-3",  "Description": "Malicious Code Protection",
                 "Checks": ["vm_no_endpoint_protection", "defender_plan_virtualmachines_not_enabled"], "Severity": "High"},
                {"Id": "SI-4",  "Description": "Information System Monitoring",
                 "Checks": ["defender_auto_provisioning_disabled", "aks_monitoring_disabled",
                            "network_watcher_not_enabled"], "Severity": "High"},
            ]
        }

    def _hipaa(self):
        return {
            "Framework": "HIPAA",
            "Version": "Security Rule",
            "Provider": "Azure",
            "Description": "HIPAA Security Rule — Azure Controls",
            "Requirements": [
                {"Id": "§164.308(a)(1)", "Description": "Risk Management",
                 "Checks": ["defender_secure_score_low", "policy_non_compliant_resources"], "Severity": "High"},
                {"Id": "§164.308(a)(3)", "Description": "Workforce Access Management",
                 "Checks": ["iam_mfa_not_enforced", "iam_too_many_subscription_owners",
                            "iam_no_pim_privileged_roles"], "Severity": "Critical"},
                {"Id": "§164.308(a)(5)", "Description": "Security Awareness",
                 "Checks": ["defender_no_security_contact"], "Severity": "Medium"},
                {"Id": "§164.308(a)(6)", "Description": "Security Incident Procedures",
                 "Checks": ["defender_active_high_severity_alert", "defender_sentinel_not_connected"], "Severity": "High"},
                {"Id": "§164.310(d)(2)(iv)", "Description": "Data Backup and Storage",
                 "Checks": ["backup_no_recovery_vault", "storage_blob_soft_delete_disabled"], "Severity": "High"},
                {"Id": "§164.312(a)(2)(iv)", "Description": "Encryption and Decryption",
                 "Checks": ["sql_tde_disabled", "vm_os_disk_not_encrypted",
                            "storage_no_customer_managed_key", "backup_vault_no_cmk"], "Severity": "Critical"},
                {"Id": "§164.312(b)", "Description": "Audit Controls",
                 "Checks": ["sql_server_auditing_disabled", "monitor_no_log_profile",
                            "keyvault_diagnostic_logging_disabled"], "Severity": "High"},
                {"Id": "§164.312(c)(2)", "Description": "Integrity",
                 "Checks": ["backup_vault_immutability_not_locked"], "Severity": "High"},
                {"Id": "§164.312(d)", "Description": "Person or Entity Authentication",
                 "Checks": ["iam_mfa_not_enforced", "iam_conditional_access_required"], "Severity": "Critical"},
                {"Id": "§164.312(e)(1)", "Description": "Transmission Security",
                 "Checks": ["storage_https_only_disabled", "storage_min_tls_version_below_1_2",
                            "redis_non_ssl_port_enabled"], "Severity": "High"},
            ]
        }

    def _pci_dss(self):
        return {
            "Framework": "PCI_DSS",
            "Version": "4.0",
            "Provider": "Azure",
            "Description": "PCI DSS v4.0 — Azure Controls",
            "Requirements": [
                {"Id": "1.3.2", "Description": "Restrict inbound and outbound traffic",
                 "Checks": ["nsg_ssh_open_to_internet", "nsg_rdp_open_to_internet",
                            "nsg_all_ports_open_to_internet", "subnet_no_nsg_attached"], "Severity": "Critical"},
                {"Id": "2.2.1", "Description": "Configuration standards are implemented",
                 "Checks": ["vm_boot_diagnostics_disabled", "policy_no_security_benchmark"], "Severity": "Medium"},
                {"Id": "3.4.1", "Description": "Primary account numbers are protected",
                 "Checks": ["sql_tde_disabled", "storage_no_customer_managed_key"], "Severity": "Critical"},
                {"Id": "6.3.3", "Description": "Security patches are installed",
                 "Checks": ["vm_auto_update_disabled", "sql_vulnerability_assessment_disabled"], "Severity": "High"},
                {"Id": "7.2.1", "Description": "Least privilege access",
                 "Checks": ["iam_too_many_subscription_owners", "iam_custom_role_wildcard_action"], "Severity": "High"},
                {"Id": "8.4.2", "Description": "MFA is implemented",
                 "Checks": ["iam_mfa_not_enforced", "iam_conditional_access_required"], "Severity": "Critical"},
                {"Id": "10.2.1", "Description": "Audit logs capture required events",
                 "Checks": ["sql_server_auditing_disabled", "monitor_no_log_profile",
                            "keyvault_diagnostic_logging_disabled"], "Severity": "High"},
                {"Id": "10.3.3", "Description": "Audit log retention at least 12 months",
                 "Checks": ["monitor_log_retention_under_365_days"], "Severity": "Medium"},
                {"Id": "12.3.1", "Description": "Targeted risk analysis is performed",
                 "Checks": ["defender_secure_score_low", "defender_regulatory_compliance_failed"], "Severity": "High"},
            ]
        }

    def _gdpr(self):
        return {
            "Framework": "GDPR",
            "Version": "2018",
            "Provider": "Azure",
            "Description": "GDPR Technical Controls — Azure",
            "Requirements": [
                {"Id": "Art5-1-f", "Description": "Data integrity and confidentiality",
                 "Checks": ["sql_tde_disabled", "storage_blob_public_access_enabled",
                            "vm_os_disk_not_encrypted"], "Severity": "Critical"},
                {"Id": "Art25",    "Description": "Data protection by design",
                 "Checks": ["storage_no_customer_managed_key", "cosmos_no_customer_managed_key",
                            "backup_vault_no_cmk"], "Severity": "High"},
                {"Id": "Art32",    "Description": "Security of processing",
                 "Checks": ["storage_https_only_disabled", "storage_min_tls_version_below_1_2",
                            "appservice_min_tls_below_1_2", "keyvault_public_network_access"], "Severity": "High"},
                {"Id": "Art33",    "Description": "Notification of a personal data breach",
                 "Checks": ["defender_no_security_contact", "defender_active_high_severity_alert"], "Severity": "High"},
                {"Id": "Art35",    "Description": "Data protection impact assessment",
                 "Checks": ["policy_non_compliant_resources", "defender_secure_score_low"], "Severity": "Medium"},
            ]
        }

    def _csa_ccm(self):
        return {
            "Framework": "CSA_CCM",
            "Version": "4.0",
            "Provider": "Azure",
            "Description": "CSA Cloud Controls Matrix v4.0 — Azure",
            "Requirements": [
                {"Id": "IAM-01", "Description": "Identity and Access Management",
                 "Checks": ["iam_mfa_not_enforced", "iam_conditional_access_required",
                            "iam_no_pim_privileged_roles"], "Severity": "Critical"},
                {"Id": "IAM-04", "Description": "Least Privilege",
                 "Checks": ["iam_custom_role_wildcard_action", "iam_too_many_subscription_owners"], "Severity": "High"},
                {"Id": "IAM-09", "Description": "Multi-Factor Authentication",
                 "Checks": ["iam_mfa_not_enforced", "iam_security_defaults_enabled"], "Severity": "Critical"},
                {"Id": "DSI-01", "Description": "Data Security and Integrity",
                 "Checks": ["sql_tde_disabled", "storage_no_customer_managed_key",
                            "keyvault_purge_protection_disabled"], "Severity": "High"},
                {"Id": "IVS-06", "Description": "Network and Infrastructure Security",
                 "Checks": ["nsg_ssh_open_to_internet", "nsg_rdp_open_to_internet",
                            "subnet_no_nsg_attached", "vnet_ddos_standard_not_enabled"], "Severity": "Critical"},
                {"Id": "IVS-09", "Description": "Container Security",
                 "Checks": ["aks_rbac_disabled", "aks_no_network_policy",
                            "acr_admin_user_enabled"], "Severity": "High"},
                {"Id": "SEF-02", "Description": "Security Event Logging",
                 "Checks": ["monitor_no_log_profile", "sql_server_auditing_disabled",
                            "keyvault_diagnostic_logging_disabled"], "Severity": "High"},
                {"Id": "BCR-02", "Description": "Business Continuity Management",
                 "Checks": ["backup_no_recovery_vault", "cosmos_automatic_failover_disabled"], "Severity": "High"},
            ]
        }

    def _mitre(self):
        return {
            "Framework": "MITRE_ATTACK",
            "Version": "14.0",
            "Provider": "Azure",
            "Description": "MITRE ATT&CK for Cloud — Azure",
            "Requirements": [
                {"Id": "T1078",     "Description": "Valid Accounts",
                 "Checks": ["iam_mfa_not_enforced", "iam_security_defaults_enabled"], "Severity": "Critical"},
                {"Id": "T1190",     "Description": "Exploit Public-Facing Application",
                 "Checks": ["nsg_ssh_open_to_internet", "nsg_rdp_open_to_internet",
                            "sql_server_public_network_access"], "Severity": "Critical"},
                {"Id": "T1530",     "Description": "Data from Cloud Storage",
                 "Checks": ["storage_blob_public_access_enabled", "storage_network_default_allow"], "Severity": "Critical"},
                {"Id": "T1552.001", "Description": "Credentials in Files",
                 "Checks": ["vm_no_managed_identity", "appservice_no_managed_identity",
                            "functions_no_managed_identity"], "Severity": "High"},
                {"Id": "T1562.008", "Description": "Disable Cloud Logs",
                 "Checks": ["monitor_no_log_profile", "keyvault_diagnostic_logging_disabled",
                            "nsg_flow_logs_not_enabled"], "Severity": "High"},
                {"Id": "T1580",     "Description": "Cloud Infrastructure Discovery",
                 "Checks": ["aks_api_server_unrestricted_access", "keyvault_public_network_access"], "Severity": "High"},
                {"Id": "T1610",     "Description": "Deploy Container",
                 "Checks": ["aks_rbac_disabled", "acr_admin_user_enabled"], "Severity": "High"},
                {"Id": "T1485",     "Description": "Data Destruction",
                 "Checks": ["backup_vault_soft_delete_disabled", "keyvault_soft_delete_disabled",
                            "backup_vault_immutability_not_locked"], "Severity": "Critical"},
            ]
        }


# ── Compliance % calculator ───────────────────────────────────────────────

DISPLAY_NAMES = {
    "CIS":          "CIS Azure Benchmark 2.0",
    "NIST_CSF":     "NIST CSF 2.0",
    "NIST_800_53":  "NIST 800-53 Rev5",
    "HIPAA":        "HIPAA Security Rule",
    "PCI_DSS":      "PCI DSS 4.0",
    "GDPR":         "GDPR",
    "CSA_CCM":      "CSA CCM v4.0",
    "MITRE_ATTACK": "MITRE ATT&CK Cloud",
}


def load_compliance_requirements(provider="azure"):
    frameworks = {}
    comp_dir   = ROOT / "compliance" / provider
    if not comp_dir.exists():
        return frameworks
    for jf in comp_dir.glob("*.json"):
        try:
            data = json.loads(jf.read_text())
            fw   = data.get("Framework", "")
            if fw:
                frameworks.setdefault(fw, []).extend(data.get("Requirements", []))
        except Exception:
            continue
    return frameworks


def calculate_compliance(findings, provider="azure"):
    frameworks    = load_compliance_requirements(provider)
    failed_checks = {f.get("check_id", "") for f in findings if f.get("status") == "FAIL"}
    results       = {}
    for fw_key, requirements in frameworks.items():
        total = len(requirements)
        if total == 0:
            continue
        failed = sum(1 for req in requirements
                     if any(c in failed_checks for c in req.get("Checks", [])))
        passed = total - failed
        pct    = round((passed / total) * 100, 1)
        results[DISPLAY_NAMES.get(fw_key, fw_key)] = pct
    return results


def severity_counts(findings):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Total": 0}
    for f in findings:
        if f.get("status") != "FAIL":
            continue
        sev = f.get("severity", "Low")
        if sev in counts:
            counts[sev] += 1
        counts["Total"] += 1
    return counts


def compliance_color(pct):
    if pct >= 90:   return "excellent"
    elif pct >= 75: return "good"
    elif pct >= 60: return "warning"
    elif pct >= 40: return "poor"
    else:           return "critical"
