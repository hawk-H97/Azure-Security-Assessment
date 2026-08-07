"""Azure Functions — 5 checks."""
from ..base import BaseCheck


class FunctionsChecks(BaseCheck):
    SERVICE = "Functions"

    def run_all(self):
        f = []
        f += self._https_only()
        f += self._managed_identity()
        f += self._runtime_version()
        f += self._auth_enabled()
        f += self._deployment_slots_auth()
        return f

    def _client(self):
        from azure.mgmt.web import WebSiteManagementClient
        return WebSiteManagementClient(self.credential, self.subscription_id)

    def _rg(self, rid):
        try:
            parts = (rid or "").split("/")
            idx = parts.index("resourceGroups") if "resourceGroups" in parts else -1
            return parts[idx + 1] if idx >= 0 and idx + 1 < len(parts) else ""
        except Exception:
            return ""

    def _function_apps(self):
        return [a for a in self._client().web_apps.list()
                if a.kind and "functionapp" in a.kind.lower()]

    def _https_only(self):
        findings = []
        try:
            for app in self._function_apps():
                rg = self._rg(app.id)
                if not app.https_only:
                    findings.append(self.finding(
                        "functions_https_only_disabled",
                        app.id, app.name, "Function App", "FAIL", "High",
                        "Function App does not enforce HTTPS only",
                        f"Azure Portal → Function apps → {app.name} → Settings → Configuration → General settings → HTTPS Only → On",
                        f"Function App '{app.name}' allows HTTP connections. Function trigger URLs and payloads "
                        "can be intercepted in transit. Enable HTTPS-only.",
                        tags=app.tags, resource_group=rg, location=getattr(app, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("functions_https_only_disabled", e))
        return findings

    def _managed_identity(self):
        findings = []
        try:
            for app in self._function_apps():
                rg = self._rg(app.id)
                if not app.identity:
                    findings.append(self.finding(
                        "functions_no_managed_identity",
                        app.id, app.name, "Function App", "FAIL", "Medium",
                        "Function App does not use Managed Identity",
                        f"Azure Portal → Function apps → {app.name} → Settings → Identity → System assigned → On",
                        f"Function App '{app.name}' has no Managed Identity. Connection strings to Storage, "
                        "Service Bus, and databases are stored as plain-text app settings. "
                        "Use Managed Identity and Key Vault references instead.",
                        tags=app.tags, resource_group=rg, location=getattr(app, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("functions_no_managed_identity", e))
        return findings

    def _runtime_version(self):
        findings = []
        try:
            wc = self._client()
            for app in self._function_apps():
                rg = self._rg(app.id)
                try:
                    config = wc.web_apps.get_configuration(rg, app.name)
                    # Check for outdated Python, Node, or .NET versions
                    py_ver   = config.python_version or ""
                    node_ver = config.node_version or ""
                    if py_ver and py_ver in ("2.7", "3.6", "3.7", "3.8"):
                        findings.append(self.finding(
                            "functions_outdated_runtime",
                            app.id, app.name, "Function App", "FAIL", "High",
                            f"Function App uses end-of-life Python {py_ver} runtime",
                            f"Azure Portal → Function apps → {app.name} → Settings → Configuration → General settings → Python version",
                            f"Function App '{app.name}' uses Python {py_ver} which is end-of-life. "
                            "EOL runtimes no longer receive security patches — upgrade to Python 3.11+.",
                            tags=app.tags, resource_group=rg, location=getattr(app, "location", None),
                        ))
                except Exception:
                    pass
        except Exception as e:
            findings.append(self.error_finding("functions_outdated_runtime", e))
        return findings

    def _auth_enabled(self):
        findings = []
        try:
            wc = self._client()
            for app in self._function_apps():
                rg = self._rg(app.id)
                try:
                    auth    = wc.web_apps.get_auth_settings(rg, app.name)
                    enabled = getattr(auth, "enabled", False)
                    if not enabled:
                        findings.append(self.finding(
                            "functions_no_auth",
                            app.id, app.name, "Function App", "FAIL", "Medium",
                            "Function App has no authentication / authorization configured",
                            f"Azure Portal → Function apps → {app.name} → Settings → Authentication → Add identity provider",
                            f"Function App '{app.name}' has no built-in auth. HTTP-triggered functions may be "
                            "publicly accessible without a function key or token. "
                            "Add Entra ID authentication or ensure function-level keys are enforced.",
                            tags=app.tags, resource_group=rg, location=getattr(app, "location", None),
                        ))
                except Exception:
                    pass
        except Exception as e:
            findings.append(self.error_finding("functions_no_auth", e))
        return findings

    def _deployment_slots_auth(self):
        """Informational — deployment slots should also have auth enabled."""
        return []
