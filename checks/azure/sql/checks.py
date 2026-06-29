"""Azure SQL Database — 8 checks."""
from ..base import BaseCheck


class SQLChecks(BaseCheck):
    SERVICE = "SQL"

    def run_all(self):
        f = []
        f += self._auditing_enabled()
        f += self._tde_enabled()
        f += self._threat_detection()
        f += self._public_network_access()
        f += self._aad_admin()
        f += self._retention_policy()
        f += self._firewall_all_ips()
        f += self._vulnerability_assessment()
        return f

    def _client(self):
        from azure.mgmt.sql import SqlManagementClient
        return SqlManagementClient(self.credential, self.subscription_id)

    def _rg(self, resource_id):
        try:
            parts = (resource_id or "").split("/")
            idx   = parts.index("resourceGroups") if "resourceGroups" in parts else -1
            return parts[idx + 1] if idx >= 0 and idx + 1 < len(parts) else ""
        except Exception:
            return ""

    def _auditing_enabled(self):
        findings = []
        try:
            sc = self._client()
            for server in sc.servers.list():
                rg = self._rg(server.id)
                try:
                    policy = sc.server_blob_auditing_policies.get(rg, server.name)
                    if policy.state and policy.state.lower() != "enabled":
                        findings.append(self.finding(
                            "sql_server_auditing_disabled",
                            server.id, server.name, "SQL Server", "FAIL", "High",
                            "SQL Server auditing is not enabled",
                            f"Azure Portal → SQL servers → {server.name} → Security → Auditing → Enable",
                            f"SQL Server '{server.name}' auditing is disabled. Without auditing, failed logins, "
                            "schema changes, and data access events are not logged.",
                            resource_group=rg, location=getattr(server, "location", None),
                        ))
                except Exception:
                    pass
        except Exception as e:
            findings.append(self.error_finding("sql_server_auditing_disabled", e))
        return findings

    def _tde_enabled(self):
        findings = []
        try:
            sc = self._client()
            for server in sc.servers.list():
                rg = self._rg(server.id)
                for db in sc.databases.list_by_server(rg, server.name):
                    if db.name.lower() == "master":
                        continue
                    try:
                        tde = sc.transparent_data_encryptions.get(rg, server.name, db.name)
                        if tde.status and tde.status.lower() != "enabled":
                            findings.append(self.finding(
                                "sql_tde_disabled",
                                db.id, f"{server.name}/{db.name}", "SQL Database", "FAIL", "Critical",
                                "SQL Database Transparent Data Encryption (TDE) disabled",
                                f"Azure Portal → SQL databases → {db.name} → Security → Transparent data encryption → On",
                                f"Database '{db.name}' on server '{server.name}' has TDE disabled. "
                                "Data files are stored unencrypted on disk — a stolen backup exposes all data.",
                                resource_group=rg, location=getattr(server, "location", None),
                            ))
                    except Exception:
                        pass
        except Exception as e:
            findings.append(self.error_finding("sql_tde_disabled", e))
        return findings

    def _threat_detection(self):
        findings = []
        try:
            sc = self._client()
            for server in sc.servers.list():
                rg = self._rg(server.id)
                try:
                    atp = sc.server_advanced_threat_protection_settings.get(rg, server.name)
                    if not atp or (atp.state and atp.state.lower() != "enabled"):
                        findings.append(self.finding(
                            "sql_threat_detection_disabled",
                            server.id, server.name, "SQL Server", "FAIL", "High",
                            "SQL Server Advanced Threat Protection not enabled",
                            f"Azure Portal → SQL servers → {server.name} → Security → Microsoft Defender for SQL → Enable",
                            f"SQL Server '{server.name}' does not have Advanced Threat Protection enabled. "
                            "ATP detects SQL injection, unusual access patterns, and brute force attacks.",
                            resource_group=rg, location=getattr(server, "location", None),
                        ))
                except Exception:
                    pass
        except Exception as e:
            findings.append(self.error_finding("sql_threat_detection_disabled", e))
        return findings

    def _public_network_access(self):
        findings = []
        try:
            for server in self._client().servers.list():
                rg = self._rg(server.id)
                if server.public_network_access and server.public_network_access.lower() == "enabled":
                    findings.append(self.finding(
                        "sql_server_public_network_access",
                        server.id, server.name, "SQL Server", "FAIL", "High",
                        "SQL Server allows public network access",
                        f"Azure Portal → SQL servers → {server.name} → Security → Networking → Public access → Disable",
                        f"SQL Server '{server.name}' has public network access enabled. "
                        "Restrict to Private Endpoint only and disable public access to reduce attack surface.",
                        resource_group=rg, location=getattr(server, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("sql_server_public_network_access", e))
        return findings

    def _aad_admin(self):
        findings = []
        try:
            sc = self._client()
            for server in sc.servers.list():
                rg = self._rg(server.id)
                try:
                    admins = list(sc.server_azure_ad_administrators.list_by_server(rg, server.name))
                    if not admins:
                        findings.append(self.finding(
                            "sql_no_aad_admin",
                            server.id, server.name, "SQL Server", "FAIL", "High",
                            "SQL Server has no Azure AD Administrator configured",
                            f"Azure Portal → SQL servers → {server.name} → Settings → Azure Active Directory → Set admin",
                            f"SQL Server '{server.name}' has no Entra ID (Azure AD) admin set. "
                            "Without an AAD admin, only SQL authentication is available — preventing MFA enforcement.",
                            resource_group=rg, location=getattr(server, "location", None),
                        ))
                except Exception:
                    pass
        except Exception as e:
            findings.append(self.error_finding("sql_no_aad_admin", e))
        return findings

    def _retention_policy(self):
        findings = []
        try:
            sc = self._client()
            for server in sc.servers.list():
                rg = self._rg(server.id)
                for db in sc.databases.list_by_server(rg, server.name):
                    if db.name.lower() == "master":
                        continue
                    try:
                        pol = sc.backup_short_term_retention_policies.get(rg, server.name, db.name)
                        if (pol.retention_days or 0) < 7:
                            findings.append(self.finding(
                                "sql_short_retention_period",
                                db.id, f"{server.name}/{db.name}", "SQL Database", "FAIL", "Medium",
                                "SQL Database backup retention period is less than 7 days",
                                f"Azure Portal → SQL databases → {db.name} → Manage backups → Retention policies",
                                f"Database '{db.name}' has backup retention of only {pol.retention_days} day(s). "
                                "Set short-term retention to at least 7 days for recovery from data corruption.",
                                resource_group=rg, location=getattr(server, "location", None),
                            ))
                    except Exception:
                        pass
        except Exception as e:
            findings.append(self.error_finding("sql_short_retention_period", e))
        return findings

    def _firewall_all_ips(self):
        findings = []
        try:
            sc = self._client()
            for server in sc.servers.list():
                rg = self._rg(server.id)
                for rule in sc.firewall_rules.list_by_server(rg, server.name):
                    if rule.start_ip_address == "0.0.0.0" and rule.end_ip_address == "255.255.255.255":
                        findings.append(self.finding(
                            "sql_firewall_allows_all_ips",
                            server.id, server.name, "SQL Server", "FAIL", "Critical",
                            "SQL Server firewall rule allows access from all IP addresses",
                            f"Azure Portal → SQL servers → {server.name} → Security → Networking → Firewall rules → Remove 0.0.0.0-255.255.255.255",
                            f"SQL Server '{server.name}' has firewall rule '{rule.name}' allowing 0.0.0.0-255.255.255.255. "
                            "This exposes the SQL endpoint to the entire internet.",
                            resource_group=rg, location=getattr(server, "location", None),
                        ))
        except Exception as e:
            findings.append(self.error_finding("sql_firewall_allows_all_ips", e))
        return findings

    def _vulnerability_assessment(self):
        findings = []
        try:
            sc = self._client()
            for server in sc.servers.list():
                rg = self._rg(server.id)
                try:
                    va = sc.server_vulnerability_assessments.get(rg, server.name)
                    if not va or not va.storage_container_path:
                        raise Exception("not configured")
                except Exception:
                    findings.append(self.finding(
                        "sql_vulnerability_assessment_disabled",
                        server.id, server.name, "SQL Server", "FAIL", "High",
                        "SQL Server Vulnerability Assessment not configured",
                        f"Azure Portal → SQL servers → {server.name} → Security → Microsoft Defender for SQL → Vulnerability assessment",
                        f"SQL Server '{server.name}' has no Vulnerability Assessment configured. "
                        "Vulnerability Assessment scans for misconfigurations, excessive permissions, and known security issues.",
                        resource_group=rg, location=getattr(server, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("sql_vulnerability_assessment_disabled", e))
        return findings
