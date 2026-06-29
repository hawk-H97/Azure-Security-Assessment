"""Remediation paragraphs for all Azure audit check IDs."""

_REMEDIATIONS = {
    # IAM
    "iam_guest_owner_role": (
        "Review all Owner role assignments at subscription scope. Remove guest/external accounts from the Owner role. "
        "Grant only the minimum required role (Reader, Contributor for specific resource groups) and enforce MFA via "
        "Conditional Access. Navigate to: Azure Portal → Subscriptions → Access control (IAM) → Role assignments → "
        "Filter by Role: Owner → Remove any guest or unrecognised accounts."
    ),
    "iam_mfa_not_enforced": (
        "Enable Multi-Factor Authentication for all Azure AD users, especially those with privileged roles. "
        "If you have Azure AD P1/P2 licensing, create a Conditional Access policy requiring MFA for all users. "
        "If not licensed, enable Security Defaults (Azure Portal → Entra ID → Properties → Manage security defaults → Enable). "
        "Test MFA policy in report-only mode before enforcing to avoid lockouts."
    ),
    "iam_too_many_subscription_owners": (
        "Reduce subscription Owner role assignments to a maximum of 3. Convert unnecessary Owners to Contributor or "
        "use resource-group-level roles. Enable Privileged Identity Management (PIM) for remaining Owners so the role "
        "is only active when needed. Navigate to: Azure Portal → Subscriptions → Access control (IAM) → Role assignments → "
        "Owner → Remove excess assignments."
    ),
    "iam_no_pim_privileged_roles": (
        "Enable Azure AD Privileged Identity Management (PIM) for all Owner and Contributor role assignments. "
        "PIM converts permanent roles to eligible roles activated on-demand with approval, MFA, and time limits. "
        "Navigate to: Azure Portal → Entra ID → Privileged Identity Management → Azure resources → Select subscription → "
        "Add assignment → Set maximum activation duration (e.g., 8 hours)."
    ),
    "iam_custom_role_wildcard_action": (
        "Replace wildcard (*) actions in custom role definitions with explicit, enumerated action lists. "
        "Identify all actions the role actually needs, list them specifically, and remove the * entry. "
        "Navigate to: Azure Portal → Entra ID → Roles and administrators → Custom roles → Edit → Permissions → "
        "Replace Actions: [\"*\"] with specific actions like [\"Microsoft.Compute/virtualMachines/read\"]."
    ),
    "iam_service_principal_use_certificates": (
        "Rotate service principal client secrets to use certificate-based authentication instead. "
        "Generate an X.509 certificate, upload the public key to the App Registration, and update your "
        "application to authenticate with the private key. Set a maximum secret/certificate lifetime of 90 days "
        "and enable expiry notifications. Navigate to: Azure Portal → Entra ID → App registrations → "
        "Certificates & secrets → Certificates → Upload certificate."
    ),
    "iam_classic_administrator_exists": (
        "Remove all Classic Administrator (Service Administrator, Co-Administrator) role assignments. "
        "Classic roles are deprecated and bypass modern Azure RBAC and audit controls. Assign equivalent "
        "Azure RBAC roles to affected users and then remove Classic Admin access. "
        "Navigate to: Azure Portal → Subscriptions → Access control (IAM) → Classic administrators → Remove."
    ),
    "iam_guest_invite_policy": (
        "Restrict guest user invitation to Admins only. Navigate to: Azure Portal → Entra ID → "
        "External Identities → External collaboration settings → Guest invite settings → "
        "Select 'Only users assigned to specific admin roles can invite guest users'. "
        "Also enable access reviews for guest users (Entra ID → Identity Governance → Access reviews)."
    ),
    "iam_conditional_access_required": (
        "Create Conditional Access policies to enforce MFA, restrict access by location and device compliance, "
        "and block legacy authentication protocols. Start with: (1) Require MFA for all users; "
        "(2) Block legacy authentication (Exchange ActiveSync, IMAP, POP3, SMTP); "
        "(3) Require compliant device for privileged roles. "
        "Navigate to: Azure Portal → Entra ID → Security → Conditional Access → + New policy."
    ),
    "iam_security_defaults_enabled": (
        "Enable Entra ID Security Defaults if Conditional Access is not configured. Security Defaults block "
        "legacy authentication, require MFA registration for all users, and enforce MFA for admin sign-ins. "
        "Navigate to: Azure Portal → Entra ID → Properties → Manage security defaults → Security defaults → Enabled. "
        "Note: Security Defaults and Conditional Access cannot be used simultaneously."
    ),
    # Storage
    "storage_blob_public_access_enabled": (
        "Disable public blob access at the storage account level. Navigate to: Azure Portal → Storage accounts → "
        "[account name] → Settings → Configuration → Allow Blob public access → Disabled → Save. "
        "Also audit all containers for public access level (Private, Blob, Container) and set all to Private. "
        "For serving public content, use Azure CDN with a private blob backend and SAS token."
    ),
    "storage_https_only_disabled": (
        "Enable secure transfer (HTTPS only) on the storage account. Navigate to: Azure Portal → "
        "Storage accounts → [account] → Settings → Configuration → Secure transfer required → Enabled → Save. "
        "Update any applications using plain HTTP endpoints to use the HTTPS storage endpoint. "
        "HTTP storage requests will be rejected with HTTP 400 after this change."
    ),
    "storage_min_tls_version_below_1_2": (
        "Set the minimum TLS version to TLS 1.2. Navigate to: Azure Portal → Storage accounts → [account] → "
        "Settings → Configuration → Minimum TLS version → Version 1.2 → Save. "
        "Ensure all client applications and SDKs support TLS 1.2+ before enforcing this change. "
        "Applications using TLS 1.0 or 1.1 will receive connection errors."
    ),
    "storage_no_customer_managed_key": (
        "Enable Customer-Managed Key (CMK) encryption using Azure Key Vault. Create a Key Vault with purge "
        "protection enabled, generate an RSA key, and assign the storage account a managed identity with "
        "'Key Vault Crypto Service Encryption User' role. Navigate to: Azure Portal → Storage accounts → "
        "[account] → Security + networking → Encryption → Customer-managed keys → Select Key Vault and key."
    ),
    "storage_blob_soft_delete_disabled": (
        "Enable blob soft delete with a minimum 7-day retention period. Navigate to: Azure Portal → "
        "Storage accounts → [account] → Data management → Data protection → Enable soft delete for blobs → "
        "Set retention days to 7 or more → Save. Soft delete allows recovery of overwritten or deleted blobs "
        "within the retention window, protecting against accidental deletion and ransomware."
    ),
    "storage_container_soft_delete_disabled": (
        "Enable container soft delete with a minimum 7-day retention period. Navigate to: Azure Portal → "
        "Storage accounts → [account] → Data management → Data protection → Enable soft delete for containers → "
        "Set retention days to 7 or more → Save."
    ),
    "storage_logging_not_enabled": (
        "Enable diagnostic logging for the storage account. Navigate to: Azure Portal → Storage accounts → "
        "[account] → Monitoring → Diagnostic settings → + Add diagnostic setting → Select: StorageRead, "
        "StorageWrite, StorageDelete → Destination: Log Analytics workspace → Save. "
        "Logs capture all read, write, and delete operations for audit and anomaly detection."
    ),
    "storage_network_default_allow": (
        "Configure the storage account firewall to deny traffic by default. Navigate to: Azure Portal → "
        "Storage accounts → [account] → Security + networking → Networking → Firewalls and virtual networks → "
        "Selected networks → Add your VNet(s) and/or IP ranges → Default action: Deny → Save. "
        "Test access from allowed networks before enforcing to avoid disruption."
    ),
    "storage_sas_expiry_policy": (
        "Configure a SAS expiry policy limiting SAS token validity. Navigate to: Azure Portal → "
        "Storage accounts → [account] → Settings → Configuration → SAS expiry policy → Enable → "
        "Set allowed SAS interval to 1 hour for sensitive data. Also disable storage account key access "
        "('Allow storage account key access → Disabled') and enforce Entra ID authentication exclusively."
    ),
    # SQL
    "sql_server_auditing_disabled": (
        "Enable SQL Server auditing. Navigate to: Azure Portal → SQL servers → [server] → Security → "
        "Auditing → Enable Azure SQL Auditing → Select storage account or Log Analytics workspace → Save. "
        "Ensure audit log retention is set to at least 90 days. Auditing captures logins, schema changes, "
        "data access, and failed queries essential for incident investigation."
    ),
    "sql_tde_disabled": (
        "Enable Transparent Data Encryption on the SQL database. Navigate to: Azure Portal → SQL databases → "
        "[database] → Security → Transparent data encryption → Status: On → Save. "
        "For enhanced security, configure TDE with a Customer-Managed Key via Key Vault: "
        "SQL servers → [server] → Security → Transparent data encryption → Customer-managed key."
    ),
    "sql_threat_detection_disabled": (
        "Enable Microsoft Defender for SQL. Navigate to: Azure Portal → SQL servers → [server] → "
        "Security → Microsoft Defender for SQL → Enable at server level. "
        "Configure email notifications for alerts. Defender for SQL detects SQL injection attempts, "
        "unusual access patterns, potential data exfiltration, and brute-force login attacks."
    ),
    "sql_server_public_network_access": (
        "Disable public network access and use Private Endpoint. Navigate to: Azure Portal → SQL servers → "
        "[server] → Security → Networking → Public access → Disable → Save. "
        "Then create a Private Endpoint: Networking → Private access → + Create a private endpoint. "
        "Update connection strings in applications to use the private endpoint FQDN."
    ),
    "sql_no_aad_admin": (
        "Configure an Azure Active Directory administrator for the SQL server. Navigate to: Azure Portal → "
        "SQL servers → [server] → Settings → Azure Active Directory → Set admin → Select user or group → Save. "
        "Using AAD authentication enables MFA enforcement and eliminates shared SQL passwords. "
        "Consider setting 'Azure Active Directory Only Authentication' to disable SQL auth entirely."
    ),
    "sql_short_retention_period": (
        "Increase the backup retention period to at least 7 days. Navigate to: Azure Portal → SQL databases → "
        "[database] → Manage backups → Retention policies → Short-term retention → 7 days → Apply. "
        "For long-term retention (months/years for compliance), configure: "
        "SQL databases → [database] → Manage backups → Retention policies → Long-term retention."
    ),
    "sql_firewall_allows_all_ips": (
        "Remove firewall rules that allow 0.0.0.0-255.255.255.255 (all IPs). Navigate to: Azure Portal → "
        "SQL servers → [server] → Security → Networking → Firewall rules → Delete the 0.0.0.0/255.255.255.255 rule → Save. "
        "Add only specific IP ranges for known management hosts. Prefer Private Endpoint over firewall rules for production."
    ),
    "sql_vulnerability_assessment_disabled": (
        "Enable SQL Vulnerability Assessment. Navigate to: Azure Portal → SQL servers → [server] → "
        "Security → Microsoft Defender for SQL → Configure → Vulnerability assessment → "
        "Select storage account → Enable periodic recurring scans → Add email recipients → Save. "
        "VA scans run weekly and detect misconfigurations, excessive permissions, and unpatched databases."
    ),
    # Networking
    "nsg_ssh_open_to_internet": (
        "Remove or restrict the NSG inbound rule allowing SSH (port 22) from 0.0.0.0/0. Navigate to: "
        "Azure Portal → Network security groups → [NSG] → Inbound security rules → Edit rule → "
        "Change source from 'Any' to specific management IP ranges or 'VirtualNetwork'. "
        "Alternatively, use Azure Bastion for SSH/RDP access and remove all internet-facing management port rules."
    ),
    "nsg_rdp_open_to_internet": (
        "Remove or restrict the NSG inbound rule allowing RDP (port 3389) from 0.0.0.0/0. Navigate to: "
        "Azure Portal → Network security groups → [NSG] → Inbound security rules → Edit or delete the rule. "
        "Deploy Azure Bastion (Azure Portal → Bastions → + Create) to provide browser-based RDP "
        "without exposing port 3389 to the internet."
    ),
    "nsg_all_ports_open_to_internet": (
        "Immediately remove or restrict the NSG rule allowing all traffic from the Internet. "
        "Navigate to: Azure Portal → Network security groups → [NSG] → Inbound security rules → Delete the rule. "
        "Replace with specific rules permitting only required ports from trusted source IPs. "
        "Add a 'Deny All' rule at the lowest priority (e.g., 4096) to block all other traffic explicitly."
    ),
    "subnet_no_nsg_attached": (
        "Attach a Network Security Group to the subnet. Navigate to: Azure Portal → Virtual networks → "
        "[VNet] → Subnets → [Subnet] → Network security group → Associate → Select or create an NSG → Save. "
        "The NSG should have a default-deny inbound rule and allow only explicitly required traffic. "
        "Apply NSG at subnet level for broad coverage and optionally at NIC level for per-VM control."
    ),
    "vnet_ddos_standard_not_enabled": (
        "Enable DDoS Network Protection (Standard) for the VNet. Navigate to: Azure Portal → "
        "DDoS protection plans → + Create a plan → Associate with the VNet. "
        "Or: Azure Portal → Virtual networks → [VNet] → DDoS protection → Enable Standard. "
        "DDoS Standard provides automatic attack mitigation, real-time metrics, and a financial SLA."
    ),
    "network_watcher_not_enabled": (
        "Enable Network Watcher in each region where you have resources. Navigate to: Azure Portal → "
        "Network Watcher → Overview → Enable for your regions. "
        "Network Watcher is automatically enabled in some cases — verify it is active. "
        "Enable NSG Flow Logs and Traffic Analytics after Network Watcher is active."
    ),
    "nsg_flow_logs_not_enabled": (
        "Enable NSG Flow Logs for each NSG. Navigate to: Azure Portal → Network Watcher → NSG flow logs → "
        "+ Create → Select subscription and NSG → Select storage account → Version 2 (includes VNet info) → "
        "Retention: 90+ days → Enable Traffic Analytics → Select Log Analytics workspace → Save. "
        "Flow logs record all traffic decisions (allow/deny) at the NSG and are critical for incident investigation."
    ),
    "azure_bastion_not_deployed": (
        "Deploy Azure Bastion for secure VM access. Navigate to: Azure Portal → Bastions → + Create → "
        "Select resource group and VNet → Create AzureBastionSubnet (/27 or larger) → Standard SKU for "
        "file transfer and native client support → Create. "
        "After deployment, remove all NSG rules allowing SSH/RDP from the internet."
    ),
    # Key Vault
    "keyvault_soft_delete_disabled": (
        "Enable soft delete on the Key Vault. As of 2020, soft delete is mandatory and cannot be disabled on new vaults. "
        "For existing vaults: az keyvault update --name [vault] --enable-soft-delete true. "
        "Also configure the retention period: az keyvault update --name [vault] --retention-days 90."
    ),
    "keyvault_purge_protection_disabled": (
        "Enable purge protection on the Key Vault. Navigate to: Azure Portal → Key vaults → [vault] → "
        "Properties → Purge protection → Enable. "
        "Warning: once enabled, purge protection cannot be disabled. It prevents vault and object purging "
        "for the entire soft-delete retention period, even by administrators."
    ),
    "keyvault_uses_legacy_access_policies": (
        "Migrate from vault access policies to Azure RBAC permission model. Navigate to: Azure Portal → "
        "Key vaults → [vault] → Access configuration → Permission model → Azure role-based access control → Apply. "
        "Then assign Key Vault roles (Key Vault Secrets User, Key Vault Reader) to identities via IAM. "
        "Remove legacy access policies after migration is validated."
    ),
    "keyvault_public_network_access": (
        "Disable public network access and use Private Endpoint. Navigate to: Azure Portal → Key vaults → "
        "[vault] → Networking → Firewalls and virtual networks → Selected networks → Add VNet/IP rules or "
        "disable public access entirely → Private endpoint connections → + Private endpoint. "
        "Update all applications using the vault to resolve via the private DNS zone."
    ),
    "keyvault_diagnostic_logging_disabled": (
        "Enable diagnostic logging for the Key Vault. Navigate to: Azure Portal → Key vaults → [vault] → "
        "Monitoring → Diagnostic settings → + Add diagnostic setting → Select: AuditEvent, AllMetrics → "
        "Destination: Log Analytics workspace → Save. "
        "AuditEvent logs capture every key, secret, and certificate operation with caller identity and timestamp."
    ),
    "keyvault_key_no_expiry": (
        "Set an expiration date on all Key Vault keys. Navigate to: Azure Portal → Key vaults → [vault] → "
        "Keys → [key] → + New version → Set expiration date (e.g., 1 year). "
        "Automate key rotation using Azure Key Vault key rotation policy: Keys → [key] → Rotation policy → "
        "Set rotation interval (e.g., 6 months) and expiry notification (30 days before)."
    ),
    "keyvault_secret_no_expiry": (
        "Set an expiration date on all Key Vault secrets. Navigate to: Azure Portal → Key vaults → [vault] → "
        "Secrets → [secret] → [version] → Set expiration date. "
        "For automated rotation, configure Azure Key Vault secret rotation with Event Grid notifications "
        "to trigger a rotation function when secrets are near expiry."
    ),
    # Monitor
    "monitor_no_log_profile": (
        "Configure Activity Log export. Navigate to: Azure Portal → Monitor → Activity log → "
        "Export Activity Logs → + Add diagnostic setting → Select all categories → "
        "Destination: Log Analytics workspace and/or Storage account → Save. "
        "Activity Logs capture all control-plane operations (create, delete, modify) across all Azure services."
    ),
    "monitor_log_retention_under_365_days": (
        "Increase Activity Log retention to 365 days. Navigate to: Azure Portal → Monitor → "
        "Diagnostic settings for the subscription → Edit → Retention (days): 365 → Save. "
        "For long-term archival beyond 90 days in Log Analytics, set workspace retention: "
        "Log Analytics workspaces → [workspace] → General → Usage and estimated costs → Data retention → 365 days."
    ),
    "monitor_subscription_diagnostic_settings_missing": (
        "Create subscription-level diagnostic settings. Navigate to: Azure Portal → Monitor → "
        "Diagnostic settings → Subscription → + Add diagnostic setting → Select all log categories → "
        "Destination: Log Analytics workspace → Save. "
        "This sends all subscription Activity Log events to your central SIEM/Log Analytics workspace."
    ),
    # Alerts
    "monitor_alert_policy_assignment": (
        "Create an Activity Log Alert for policy assignment changes. Navigate to: Azure Portal → Monitor → "
        "Alerts → + Create → Alert rule → Scope: Subscription → Condition: Policy assignment - Write → "
        "Action group: notify security team via email/SMS/webhook → Alert rule name: PolicyAssignmentChange → Create."
    ),
    "monitor_alert_nsg_change": (
        "Create an Activity Log Alert for NSG changes. Navigate to: Azure Portal → Monitor → Alerts → "
        "+ Create → Alert rule → Scope: Subscription → Condition: Network security groups - Write → "
        "Action group: security notification → Create."
    ),
    "monitor_alert_security_solution_delete": (
        "Create an Activity Log Alert for security solution deletion. Navigate to: Azure Portal → Monitor → "
        "Alerts → + Create → Alert rule → Scope: Subscription → Condition: Security solutions - Delete → "
        "Action group: security notification → Create."
    ),
    "monitor_alert_sql_firewall_change": (
        "Create an Activity Log Alert for SQL firewall rule changes. Navigate to: Azure Portal → Monitor → "
        "Alerts → + Create → Alert rule → Scope: Subscription → Condition: SQL server firewall rules - Write → "
        "Action group: security notification → Create."
    ),
    "monitor_alert_vm_delete": (
        "Create an Activity Log Alert for VM deletion. Navigate to: Azure Portal → Monitor → Alerts → "
        "+ Create → Alert rule → Scope: Subscription → Condition: Virtual machines - Delete → "
        "Action group: security notification → Create."
    ),
    # Defender
    "defender_plan_not_enabled": (
        "Enable Microsoft Defender for the relevant resource type. Navigate to: Azure Portal → "
        "Microsoft Defender for Cloud → Environment settings → [subscription] → Defender plans → "
        "Enable the required plan (VirtualMachines, SqlServers, AppServices, StorageAccounts, Containers, KeyVaults) → Save. "
        "Each plan is billed separately. Start with VirtualMachines and StorageAccounts for highest impact."
    ),
    "defender_no_security_contact": (
        "Add a security contact in Defender for Cloud. Navigate to: Azure Portal → "
        "Microsoft Defender for Cloud → Environment settings → [subscription] → Email notifications → "
        "Add security contact email and phone number → Enable: Send email notifications for high severity alerts → Save."
    ),
    "defender_auto_provisioning_disabled": (
        "Enable auto provisioning of monitoring agents. Navigate to: Azure Portal → "
        "Microsoft Defender for Cloud → Environment settings → [subscription] → Auto provisioning → "
        "Set Log Analytics agent / Azure Monitor Agent to On → Save. "
        "This automatically deploys the monitoring agent to new and existing VMs for Defender coverage."
    ),
    "defender_secure_score_low": (
        "Review and remediate recommendations in Defender for Cloud to improve Secure Score. Navigate to: "
        "Azure Portal → Microsoft Defender for Cloud → Recommendations → Sort by Score impact (descending). "
        "Address Quick Fix recommendations first. Focus on Critical and High severity items. "
        "Track score improvement over time using the Secure Score over time workbook."
    ),
    "defender_active_high_severity_alert": (
        "Investigate and respond to the active security alert immediately. Navigate to: Azure Portal → "
        "Microsoft Defender for Cloud → Security alerts → Select alert → Investigate. "
        "Follow the MITRE ATT&CK mapping shown in the alert to understand the attack chain. "
        "Use 'Take action' to initiate remediation steps. Connect to Microsoft Sentinel for automated response playbooks."
    ),
    "defender_email_notifications_disabled": (
        "Enable email notifications for security alerts. Navigate to: Azure Portal → "
        "Microsoft Defender for Cloud → Environment settings → [subscription] → Email notifications → "
        "Notify about alerts with the following severity: High and Critical → Save."
    ),
    "defender_sentinel_not_connected": (
        "Connect Microsoft Sentinel to Defender for Cloud. Navigate to: Azure Portal → Microsoft Sentinel → "
        "Select workspace → Content hub → Search 'Defender for Cloud' → Install → "
        "Data connectors → Microsoft Defender for Cloud → Connect. "
        "This enables automated incident creation, threat hunting, and SOAR playbooks for Defender alerts."
    ),
    "defender_regulatory_compliance_failed": (
        "Review failed controls in the Regulatory Compliance dashboard and remediate. Navigate to: "
        "Azure Portal → Microsoft Defender for Cloud → Regulatory compliance → Select standard → "
        "Expand failed domain → Select failed control → View recommendations → Remediate. "
        "For controls requiring manual verification, add an attestation with evidence documentation."
    ),
    # AKS
    "aks_rbac_disabled": (
        "Enable Kubernetes RBAC on the AKS cluster. For existing clusters: "
        "az aks update --resource-group [rg] --name [cluster] --enable-rbac. "
        "Note: enabling RBAC on an existing cluster without RBAC may disrupt workloads — test in staging first. "
        "For new clusters, always use: az aks create ... --enable-rbac."
    ),
    "aks_aad_integration_disabled": (
        "Enable Managed Azure AD integration on AKS. Navigate to: Azure Portal → Kubernetes services → "
        "[cluster] → Settings → Cluster configuration → Authentication and Authorization → "
        "Azure AD authentication with Azure RBAC → Save. "
        "Or via CLI: az aks update --resource-group [rg] --name [cluster] --enable-aad --enable-azure-rbac."
    ),
    "aks_no_network_policy": (
        "Enable Kubernetes Network Policy on the AKS cluster. This requires recreating the cluster with "
        "network policy enabled: az aks create ... --network-policy azure (or calico). "
        "After enabling, create NetworkPolicy resources to deny all traffic by default and allow only required pod-to-pod communication. "
        "Start with a default-deny-all policy in each namespace."
    ),
    "aks_api_server_unrestricted_access": (
        "Restrict AKS API server access to authorized IP ranges. Navigate to: Azure Portal → "
        "Kubernetes services → [cluster] → Networking → Set authorized IP ranges → Add management IP CIDRs → Save. "
        "Or via CLI: az aks update --resource-group [rg] --name [cluster] --api-server-authorized-ip-ranges [CIDR]. "
        "For complete isolation, use private cluster: --enable-private-cluster."
    ),
    "aks_node_os_auto_upgrade_disabled": (
        "Configure node OS auto-upgrade for the AKS cluster. Navigate to: Azure Portal → "
        "Kubernetes services → [cluster] → Settings → Cluster configuration → Node OS upgrade channel → "
        "NodeImage (for security patches only) or SecurityPatch → Save. "
        "Or via CLI: az aks update --resource-group [rg] --name [cluster] --node-os-upgrade-channel NodeImage."
    ),
    "aks_monitoring_disabled": (
        "Enable Container Insights monitoring for AKS. Navigate to: Azure Portal → "
        "Kubernetes services → [cluster] → Monitoring → Insights → Enable → Select Log Analytics workspace → Enable. "
        "Container Insights provides CPU/memory usage, pod counts, node health, and container logs "
        "for proactive monitoring and incident investigation."
    ),
    # App Service
    "appservice_https_only_disabled": (
        "Enable HTTPS-only traffic for the App Service. Navigate to: Azure Portal → App Services → "
        "[app] → Settings → TLS/SSL settings → HTTPS Only → On → Save. "
        "HTTP requests will be automatically redirected to HTTPS (301 redirect). "
        "Also set minimum TLS version to 1.2: TLS/SSL settings → Minimum TLS Version → 1.2."
    ),
    "appservice_min_tls_below_1_2": (
        "Set minimum TLS version to 1.2 for the App Service. Navigate to: Azure Portal → App Services → "
        "[app] → Settings → TLS/SSL settings → Minimum TLS Version → 1.2 → Save. "
        "Validate that all clients connecting to this app support TLS 1.2 before enforcing."
    ),
    "appservice_auth_not_configured": (
        "Enable Azure App Service Authentication. Navigate to: Azure Portal → App Services → "
        "[app] → Settings → Authentication → Add identity provider → Microsoft (Azure AD) → "
        "Select tenant → Require authentication → Redirect unauthenticated requests to Microsoft sign-in → Save. "
        "This adds Entra ID authentication without code changes."
    ),
    "appservice_no_managed_identity": (
        "Enable Managed Identity for the App Service. Navigate to: Azure Portal → App Services → "
        "[app] → Settings → Identity → System assigned → Status: On → Save. "
        "Then replace connection strings in App Settings with Key Vault references: "
        "@Microsoft.KeyVault(VaultName=[vault];SecretName=[secret])"
    ),
    "appservice_remote_debugging_enabled": (
        "Disable remote debugging on the App Service. Navigate to: Azure Portal → App Services → "
        "[app] → Settings → Configuration → General settings → Remote debugging → Off → Save. "
        "Remote debugging opens an unauthenticated port that can allow code execution if exposed."
    ),
    "appservice_ftp_enabled": (
        "Disable plain FTP access. Navigate to: Azure Portal → App Services → "
        "[app] → Settings → Configuration → General settings → FTP state → Disabled → Save. "
        "If FTPS is required for legacy tooling, set to FtpsOnly. "
        "Prefer deployment via GitHub Actions, Azure DevOps, or ZIP deploy over FTP."
    ),
    # Functions
    "functions_https_only_disabled": (
        "Enable HTTPS-only on the Function App. Navigate to: Azure Portal → Function apps → "
        "[app] → Settings → Configuration → General settings → HTTPS Only → On → Save."
    ),
    "functions_no_managed_identity": (
        "Enable Managed Identity for the Function App. Navigate to: Azure Portal → Function apps → "
        "[app] → Settings → Identity → System assigned → On → Save. "
        "Then use Key Vault references for all secrets in Application Settings: "
        "@Microsoft.KeyVault(VaultName=[vault];SecretName=[secret])"
    ),
    "functions_outdated_runtime": (
        "Upgrade the Function App runtime to a supported version. Navigate to: Azure Portal → "
        "Function apps → [app] → Settings → Configuration → General settings → [Language] version → "
        "Select latest supported version. Test functions in a staging slot before swapping to production."
    ),
    "functions_no_auth": (
        "Enable authentication for HTTP-triggered functions. Navigate to: Azure Portal → Function apps → "
        "[app] → Settings → Authentication → Add identity provider → Microsoft. "
        "Alternatively, ensure all HTTP functions use Function or Admin authorization level (not Anonymous) "
        "and rotate function keys regularly."
    ),
    # Cosmos DB
    "cosmos_public_network_access_enabled": (
        "Disable public network access for Cosmos DB. Navigate to: Azure Portal → Azure Cosmos DB → "
        "[account] → Settings → Networking → Firewalls and virtual networks → Disable public access or "
        "restrict to selected networks and VNets → Save. "
        "Create a Private Endpoint for VNet-based access."
    ),
    "cosmos_no_customer_managed_key": (
        "Enable Customer-Managed Key encryption for Cosmos DB. CMK must be configured at account creation. "
        "For existing accounts, create a new CMK-enabled account and migrate data. "
        "Navigate to: Azure Portal → Azure Cosmos DB → Create → Encryption → Customer-managed key → "
        "Select Key Vault URI."
    ),
    "cosmos_local_auth_enabled": (
        "Disable local (primary/secondary key) authentication on Cosmos DB. Navigate to: Azure Portal → "
        "Azure Cosmos DB → [account] → Settings → Keys → Disable local authentication → Confirm. "
        "First ensure all applications use Entra ID RBAC: assign 'Cosmos DB Built-in Data Contributor' role to managed identities."
    ),
    "cosmos_automatic_failover_disabled": (
        "Enable automatic failover for Cosmos DB. Navigate to: Azure Portal → Azure Cosmos DB → "
        "[account] → Settings → Replicate data globally → Automatic failover → On → Save. "
        "Configure at least one additional read region to enable failover capability."
    ),
    "cosmos_atp_not_enabled": (
        "Enable Advanced Threat Protection for Cosmos DB. Navigate to: Azure Portal → Azure Cosmos DB → "
        "[account] → Microsoft Defender for Cloud → Enable Microsoft Defender for Azure Cosmos DB. "
        "This detects SQL injection in NoSQL queries, unusual access patterns, and potential data exfiltration."
    ),
    # Redis
    "redis_non_ssl_port_enabled": (
        "Disable the non-SSL Redis port (6379). Navigate to: Azure Portal → Azure Cache for Redis → "
        "[cache] → Settings → Access ports → Non-SSL port (6379) → Disabled → Save. "
        "Update all client connection strings to use the SSL port (6380) with TLS enabled."
    ),
    "redis_min_tls_below_1_2": (
        "Set minimum TLS version to 1.2 for Redis Cache. Navigate to: Azure Portal → Azure Cache for Redis → "
        "[cache] → Settings → Advanced settings → Minimum TLS version → 1.2 → Save."
    ),
    # Service Bus
    "servicebus_not_premium_sku": (
        "Upgrade Service Bus to Premium SKU to enable Private Endpoint and network isolation. "
        "Navigate to: Azure Portal → Service Bus → [namespace] → Upgrade to Premium → Confirm. "
        "Premium SKU also provides dedicated capacity, larger message sizes, and higher throughput."
    ),
    "servicebus_min_tls_below_1_2": (
        "Set minimum TLS version to 1.2. Navigate to: Azure Portal → Service Bus → [namespace] → "
        "Settings → Configuration → Minimum TLS version → 1.2 → Save."
    ),
    "servicebus_public_network_access": (
        "Disable public network access and use Private Endpoint (requires Premium SKU). Navigate to: "
        "Azure Portal → Service Bus → [namespace] → Settings → Networking → Public access → Disabled → Save. "
        "Create Private Endpoint: Networking → Private endpoint connections → + Private endpoint."
    ),
    "servicebus_local_auth_enabled": (
        "Disable local (SAS key) authentication. Navigate to: Azure Portal → Service Bus → [namespace] → "
        "Settings → Local authentication → Disabled → Save. "
        "Migrate all producers/consumers to use Entra ID RBAC: assign 'Azure Service Bus Data Sender' "
        "and 'Azure Service Bus Data Receiver' roles to managed identities."
    ),
    # Logic Apps
    "logic_app_no_diagnostic_logging": (
        "Enable diagnostic logging for Logic App. Navigate to: Azure Portal → Logic apps → [app] → "
        "Monitoring → Diagnostic settings → + Add diagnostic setting → Select: WorkflowRuntime → "
        "Destination: Log Analytics workspace → Save."
    ),
    "logic_app_no_managed_identity": (
        "Enable Managed Identity for Logic App. Navigate to: Azure Portal → Logic apps → [app] → "
        "Settings → Identity → System assigned → On → Save. "
        "Update connectors to authenticate via managed identity instead of stored credentials."
    ),
    "logic_app_trigger_no_ip_restriction": (
        "Restrict Logic App trigger access to known source IPs. Navigate to: Azure Portal → Logic apps → "
        "[app] → Settings → Workflow settings → Access control → Trigger → Add allowed IP ranges. "
        "Enter the CIDRs of legitimate callers (e.g., your API management IP, integration service IP)."
    ),
    # Backup
    "backup_no_recovery_vault": (
        "Create a Recovery Services Vault and configure backup policies. Navigate to: Azure Portal → "
        "Backup center → + Create → Recovery Services vault → Select region (same as resources) → Create. "
        "Then configure backup policies for VMs, SQL databases, and file shares."
    ),
    "backup_vault_soft_delete_disabled": (
        "Enable soft delete for the Recovery Services Vault. Navigate to: Azure Portal → "
        "Recovery Services vaults → [vault] → Properties → Security settings → Soft delete → Enable → Save. "
        "Once enabled, deleted backup data is retained for 14 days before permanent deletion."
    ),
    "backup_vault_immutability_not_locked": (
        "Enable and lock vault immutability. Navigate to: Azure Portal → Recovery Services vaults → "
        "[vault] → Properties → Security settings → Immutability settings → Enable → Lock. "
        "Warning: locking is irreversible for the vault lifetime. Test in a non-production vault first."
    ),
    "backup_vault_no_cmk": (
        "Enable Customer-Managed Key encryption for the Recovery Services Vault. Navigate to: "
        "Azure Portal → Recovery Services vaults → [vault] → Properties → Encryption → Customer managed key → "
        "Select Key Vault and key → Save. Requires the vault's managed identity to have Key Vault Crypto User role."
    ),
    # Policy
    "policy_no_assignments": (
        "Assign Azure Policy initiatives. Start with: Azure Portal → Policy → Assignments → + Assign initiative → "
        "Microsoft Cloud Security Benchmark. Then add deny policies for common misconfigurations: "
        "'Deny public blob access', 'Require TLS 1.2', 'Deny public IP on SQL'. "
        "Use Azure Policy in audit mode first, then switch to deny after validating no legitimate violations."
    ),
    "policy_non_compliant_resources": (
        "Review and remediate non-compliant resources. Navigate to: Azure Portal → Policy → Compliance → "
        "Select non-compliant policy → Remediation → Create remediation task (for deployIfNotExists/modify policies). "
        "For auditIfNotExists policies, manually remediate or create an exemption with documented justification."
    ),
    "policy_no_security_benchmark": (
        "Assign the Microsoft Cloud Security Benchmark initiative. Navigate to: Azure Portal → Policy → "
        "Assignments → + Assign initiative → Category: Security Center → Microsoft Cloud Security Benchmark → "
        "Assign to subscription → Review + create. This initiative underpins Defender for Cloud's Secure Score."
    ),
    # DNS
    "dns_dnssec_not_supported": (
        "For zones requiring DNSSEC, use an external DNS provider with DNSSEC support (e.g., Cloudflare, AWS Route 53). "
        "Delegate the zone from Azure DNS to the DNSSEC-capable provider, or use Azure DNS only for internal resolution "
        "via Private DNS zones which are not exposed to the internet."
    ),
    "dns_private_zone_no_vnet_link": (
        "Link the Private DNS Zone to your VNet(s). Navigate to: Azure Portal → Private DNS zones → "
        "[zone] → Virtual network links → + Add → Select VNet → Enable auto-registration if desired → OK. "
        "Without a VNet link, DNS queries from VMs in the VNet cannot resolve names in this private zone."
    ),
    "dns_potential_dangling_cname": (
        "Verify the CNAME target is a live, owned Azure resource. Navigate to: Azure Portal → DNS zones → "
        "[zone] → [CNAME record] → Verify the target domain exists and is owned by your organisation. "
        "If the target resource has been deprovisioned, delete the CNAME record immediately. "
        "Dangling CNAMEs can be exploited via subdomain takeover to serve phishing content under your domain."
    ),
    # Security
    "security_missing_required_tags": (
        "Add required tags to the resource group. Navigate to: Azure Portal → Resource groups → "
        "[group] → Tags → Add: Owner, Environment, CostCenter → Apply. "
        "Enforce tagging policy going forward: Azure Policy → Assign 'Require a tag on resource groups' → "
        "Set tag names to enforce → Effect: Deny."
    ),
    "security_prod_rg_no_lock": (
        "Add a CanNotDelete lock to the production resource group. Navigate to: Azure Portal → "
        "Resource groups → [group] → Locks → + Add → Lock type: Delete → Name: ProductionProtection → OK. "
        "This prevents accidental deletion of the resource group and all its resources."
    ),
    "security_no_private_endpoints": (
        "Deploy Private Endpoints for all PaaS services (Storage, SQL, Key Vault, Service Bus, Cosmos DB). "
        "Navigate to: Azure Portal → Private endpoints → + Create → Select target resource and subnet → "
        "Configure private DNS zone integration → Create. "
        "After deploying Private Endpoints, disable public access on each service. "
        "Prioritise: Key Vault → SQL → Storage → Service Bus → Cosmos DB."
    ),
    # ACR
    "acr_admin_user_enabled": (
        "Disable the Container Registry admin user. Navigate to: Azure Portal → Container registries → "
        "[registry] → Settings → Access keys → Admin user → Disabled → Save. "
        "Use service principals or managed identities with 'AcrPull' role for image pulls instead: "
        "Assign managed identity → Grant AcrPull role on registry → Update deployment manifests."
    ),
    "acr_not_premium_sku": (
        "Upgrade Container Registry to Premium SKU. Navigate to: Azure Portal → Container registries → "
        "[registry] → Settings → Upgrade → Premium → Upgrade. "
        "Premium SKU enables Private Endpoint, geo-replication, content trust, and vulnerability scanning via Defender."
    ),
    "acr_public_network_access_enabled": (
        "Disable public network access on Container Registry (requires Premium SKU). Navigate to: "
        "Azure Portal → Container registries → [registry] → Settings → Networking → "
        "Public access → Disabled → Save. "
        "Create Private Endpoint: Networking → Private endpoint connections → + Create."
    ),
}


def get_remediation(check_id):
    """Return the remediation paragraph for a check_id, or empty string if not found."""
    return _REMEDIATIONS.get(check_id, "")
