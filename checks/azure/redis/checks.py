"""Azure Cache for Redis — 4 checks."""
from ..base import BaseCheck


class RedisChecks(BaseCheck):
    SERVICE = "Redis"

    def run_all(self):
        f = []
        f += self._tls_only()
        f += self._ssl_port()
        f += self._non_ssl_port_disabled()
        f += self._minimum_tls()
        return f

    def _client(self):
        from azure.mgmt.redis import RedisManagementClient
        return RedisManagementClient(self.credential, self.subscription_id)

    def _rg(self, rid):
        try:
            parts = (rid or "").split("/")
            idx = parts.index("resourceGroups") if "resourceGroups" in parts else -1
            return parts[idx + 1] if idx >= 0 and idx + 1 < len(parts) else ""
        except Exception:
            return ""

    def _tls_only(self):
        findings = []
        try:
            for r in self._client().redis.list_all():
                rg = self._rg(r.id)
                if not r.enable_non_ssl_port is False:
                    if getattr(r, "enable_non_ssl_port", True):
                        findings.append(self.finding(
                            "redis_non_ssl_port_enabled",
                            r.id, r.name, "Redis Cache", "FAIL", "High",
                            "Redis Cache non-SSL port (6379) is enabled",
                            f"Azure Portal → Azure Cache for Redis → {r.name} → Settings → Access ports → Non-SSL port → Disabled",
                            f"Redis Cache '{r.name}' has non-SSL port 6379 enabled. "
                            "Unencrypted Redis traffic exposes all cached data and commands to interception.",
                            tags=r.tags, resource_group=rg, location=getattr(r, "location", None),
                        ))
        except Exception as e:
            findings.append(self.error_finding("redis_non_ssl_port_enabled", e))
        return findings

    def _ssl_port(self):
        return []  # SSL port 6380 is always available

    def _non_ssl_port_disabled(self):
        return []  # Covered by _tls_only

    def _minimum_tls(self):
        findings = []
        try:
            for r in self._client().redis.list_all():
                rg  = self._rg(r.id)
                tls = getattr(r, "minimum_tls_version", "1.0") or "1.0"
                if tls in ("1.0", "1.1"):
                    findings.append(self.finding(
                        "redis_min_tls_below_1_2",
                        r.id, r.name, "Redis Cache", "FAIL", "High",
                        "Redis Cache minimum TLS version is below 1.2",
                        f"Azure Portal → Azure Cache for Redis → {r.name} → Settings → Advanced settings → Minimum TLS version → 1.2",
                        f"Redis Cache '{r.name}' minimum TLS is {tls}. TLS 1.0/1.1 are deprecated and vulnerable.",
                        tags=r.tags, resource_group=rg, location=getattr(r, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("redis_min_tls_below_1_2", e))
        return findings
