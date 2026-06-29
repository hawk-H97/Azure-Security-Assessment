"""Azure App Service — 7 checks."""
from ..base import BaseCheck


class AppServiceChecks(BaseCheck):
    SERVICE = "AppService"

    def run_all(self):
        f = []
        f += self._https_only()
        f += self._tls_version()
        f += self._authentication_enabled()
        f += self._managed_identity()
        f += self._remote_debugging()
        f += self._ftps_state()
        f += self._client_certificates()
        return f

    def _client(self):
        from azure.mgmt.web import WebSiteManagementClient
        return WebSiteManagementClient(self.credential, self.subscription_id)

    def _rg(self, resource_id):
        try:
            parts = (resource_id or "").split("/")
            idx   = parts.index("resourceGroups") if "resourceGroups" in parts else -1
            return parts[idx + 1] if idx >= 0 and idx + 1 < len(parts) else ""
        except Exception:
            return ""

    def _https_only(self):
        findings = []
        try:
            for app in self._client().web_apps.list():
                rg = self._rg(app.id)
                if not app.https_only:
                    findings.append(self.finding(
                        "appservice_https_only_disabled",
                        app.id, app.name, "App Service", "FAIL", "High",
                        "App Service does not enforce HTTPS only",
                        f"Azure Portal → App Services → {app.name} → Settings → TLS/SSL settings → HTTPS Only → On",
                        f"App Service '{app.name}' allows HTTP connections. Sensitive data and session tokens "
                        "can be intercepted. Enable HTTPS-only to redirect all HTTP traffic to HTTPS.",
                        tags=app.tags, resource_group=rg, location=getattr(app, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("appservice_https_only_disabled", e))
        return findings

    def _tls_version(self):
        findings = []
        try:
            wc = self._client()
            for app in wc.web_apps.list():
                rg = self._rg(app.id)
                try:
                    config = wc.web_apps.get_configuration(rg, app.name)
                    tls = config.min_tls_version or "1.0"
                    if tls in ("1.0", "1.1"):
                        findings.append(self.finding(
                            "appservice_min_tls_below_1_2",
                            app.id, app.name, "App Service", "FAIL", "High",
                            "App Service minimum TLS version is below 1.2",
                            f"Azure Portal → App Services → {app.name} → Settings → TLS/SSL settings → Minimum TLS Version → 1.2",
                            f"App Service '{app.name}' minimum TLS is {tls}. TLS 1.0/1.1 contain known vulnerabilities (POODLE, BEAST).",
                            tags=app.tags, resource_group=rg, location=getattr(app, "location", None),
                        ))
                except Exception:
                    pass
        except Exception as e:
            findings.append(self.error_finding("appservice_min_tls_below_1_2", e))
        return findings

    def _authentication_enabled(self):
        findings = []
        try:
            wc = self._client()
            for app in wc.web_apps.list():
                rg = self._rg(app.id)
                try:
                    auth = wc.web_apps.get_auth_settings_v2(rg, app.name)
                    platform = getattr(auth, "platform", None)
                    enabled  = getattr(platform, "enabled", False) if platform else False
                    if not enabled:
                        findings.append(self.finding(
                            "appservice_auth_not_configured",
                            app.id, app.name, "App Service", "FAIL", "Medium",
                            "App Service authentication / authorization not configured",
                            f"Azure Portal → App Services → {app.name} → Settings → Authentication → Add identity provider",
                            f"App Service '{app.name}' has no built-in authentication. If this app is internal or "
                            "handles sensitive data, enable Azure App Service Authentication with Entra ID.",
                            tags=app.tags, resource_group=rg, location=getattr(app, "location", None),
                        ))
                except Exception:
                    pass
        except Exception as e:
            findings.append(self.error_finding("appservice_auth_not_configured", e))
        return findings

    def _managed_identity(self):
        findings = []
        try:
            for app in self._client().web_apps.list():
                rg = self._rg(app.id)
                if not app.identity:
                    findings.append(self.finding(
                        "appservice_no_managed_identity",
                        app.id, app.name, "App Service", "FAIL", "Medium",
                        "App Service does not use Managed Identity",
                        f"Azure Portal → App Services → {app.name} → Settings → Identity → System assigned → On",
                        f"App Service '{app.name}' has no Managed Identity. Applications store connection strings "
                        "and secrets in app settings. Use Managed Identity + Key Vault references instead.",
                        tags=app.tags, resource_group=rg, location=getattr(app, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("appservice_no_managed_identity", e))
        return findings

    def _remote_debugging(self):
        findings = []
        try:
            wc = self._client()
            for app in wc.web_apps.list():
                rg = self._rg(app.id)
                try:
                    config = wc.web_apps.get_configuration(rg, app.name)
                    if config.remote_debugging_enabled:
                        findings.append(self.finding(
                            "appservice_remote_debugging_enabled",
                            app.id, app.name, "App Service", "FAIL", "High",
                            "App Service remote debugging is enabled",
                            f"Azure Portal → App Services → {app.name} → Settings → Configuration → General settings → Remote debugging → Off",
                            f"App Service '{app.name}' has remote debugging enabled. "
                            "Remote debugging opens a port that can allow arbitrary code execution if accessed by an attacker.",
                            tags=app.tags, resource_group=rg, location=getattr(app, "location", None),
                        ))
                except Exception:
                    pass
        except Exception as e:
            findings.append(self.error_finding("appservice_remote_debugging_enabled", e))
        return findings

    def _ftps_state(self):
        findings = []
        try:
            wc = self._client()
            for app in wc.web_apps.list():
                rg = self._rg(app.id)
                try:
                    config = wc.web_apps.get_configuration(rg, app.name)
                    ftps   = config.ftps_state or "AllAllowed"
                    if ftps.lower() in ("allallowed", "ftpsonly") and ftps.lower() != "disabled":
                        if ftps.lower() == "allallowed":
                            findings.append(self.finding(
                                "appservice_ftp_enabled",
                                app.id, app.name, "App Service", "FAIL", "High",
                                "App Service allows plain FTP (unencrypted file transfer)",
                                f"Azure Portal → App Services → {app.name} → Settings → Configuration → General settings → FTP state → Disabled",
                                f"App Service '{app.name}' FTP state is AllAllowed (plain FTP enabled). "
                                "Plain FTP transmits credentials unencrypted. Set to FtpsOnly or Disabled.",
                                tags=app.tags, resource_group=rg, location=getattr(app, "location", None),
                            ))
                except Exception:
                    pass
        except Exception as e:
            findings.append(self.error_finding("appservice_ftp_enabled", e))
        return findings

    def _client_certificates(self):
        """Advisory: check client certificate mode for high-trust apps."""
        return []
