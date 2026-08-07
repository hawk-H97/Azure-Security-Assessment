"""Azure Kubernetes Service (AKS) — 6 checks."""
from ..base import BaseCheck


class AKSChecks(BaseCheck):
    SERVICE = "AKS"

    def run_all(self):
        f = []
        f += self._rbac_enabled()
        f += self._aad_integration()
        f += self._network_policy()
        f += self._api_server_access()
        f += self._node_os_patching()
        f += self._monitoring_enabled()
        return f

    def _client(self):
        from azure.mgmt.containerservice import ContainerServiceClient
        return ContainerServiceClient(self.credential, self.subscription_id)

    def _rg(self, resource_id):
        try:
            parts = (resource_id or "").split("/")
            idx   = parts.index("resourceGroups") if "resourceGroups" in parts else -1
            return parts[idx + 1] if idx >= 0 and idx + 1 < len(parts) else ""
        except Exception:
            return ""

    def _rbac_enabled(self):
        findings = []
        try:
            for cluster in self._client().managed_clusters.list():
                rg = self._rg(cluster.id)
                if not cluster.enable_rbac:
                    findings.append(self.finding(
                        "aks_rbac_disabled",
                        cluster.id, cluster.name, "AKS Cluster", "FAIL", "Critical",
                        "AKS cluster does not have RBAC enabled",
                        f"Azure Portal → Kubernetes services → {cluster.name} → Settings → Cluster configuration → Kubernetes RBAC → Enabled",
                        f"AKS cluster '{cluster.name}' has RBAC disabled. Without RBAC, all authenticated users "
                        "have full admin access to the cluster — this violates least-privilege.",
                        tags=cluster.tags, resource_group=rg, location=getattr(cluster, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("aks_rbac_disabled", e))
        return findings

    def _aad_integration(self):
        findings = []
        try:
            for cluster in self._client().managed_clusters.list():
                rg = self._rg(cluster.id)
                aad = cluster.aad_profile
                if not aad or not getattr(aad, "managed", False):
                    findings.append(self.finding(
                        "aks_aad_integration_disabled",
                        cluster.id, cluster.name, "AKS Cluster", "FAIL", "High",
                        "AKS cluster lacks Azure AD (Entra ID) managed integration",
                        f"Azure Portal → Kubernetes services → {cluster.name} → Settings → Cluster configuration → Azure AD authentication",
                        f"AKS cluster '{cluster.name}' is not integrated with Entra ID. "
                        "Without AAD integration, MFA cannot be enforced for kubectl access, "
                        "and cluster access cannot be managed via Azure RBAC.",
                        tags=cluster.tags, resource_group=rg, location=getattr(cluster, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("aks_aad_integration_disabled", e))
        return findings

    def _network_policy(self):
        findings = []
        try:
            for cluster in self._client().managed_clusters.list():
                rg = self._rg(cluster.id)
                np = getattr(cluster.network_profile, "network_policy", None) if cluster.network_profile else None
                if not np or np.lower() == "none":
                    findings.append(self.finding(
                        "aks_no_network_policy",
                        cluster.id, cluster.name, "AKS Cluster", "FAIL", "High",
                        "AKS cluster has no Kubernetes Network Policy configured",
                        f"Azure Portal → Kubernetes services → {cluster.name} → Settings → Networking → Network policy → Azure or Calico",
                        f"AKS cluster '{cluster.name}' has no network policy. Without network policies, "
                        "all pods can communicate with all other pods, enabling lateral movement after a breach.",
                        tags=cluster.tags, resource_group=rg, location=getattr(cluster, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("aks_no_network_policy", e))
        return findings

    def _api_server_access(self):
        findings = []
        try:
            for cluster in self._client().managed_clusters.list():
                rg   = self._rg(cluster.id)
                apip = cluster.api_server_access_profile
                if not apip or not getattr(apip, "authorized_ip_ranges", None):
                    findings.append(self.finding(
                        "aks_api_server_unrestricted_access",
                        cluster.id, cluster.name, "AKS Cluster", "FAIL", "Critical",
                        "AKS API server has no authorized IP range restrictions",
                        f"Azure Portal → Kubernetes services → {cluster.name} → Networking → Set authorized IP ranges",
                        f"AKS cluster '{cluster.name}' API server is accessible from any IP address. "
                        "Restrict API server access to known management CIDRs to prevent unauthorized kubectl access.",
                        tags=cluster.tags, resource_group=rg, location=getattr(cluster, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("aks_api_server_unrestricted_access", e))
        return findings

    def _node_os_patching(self):
        findings = []
        try:
            for cluster in self._client().managed_clusters.list():
                rg = self._rg(cluster.id)
                # Check node OS upgrade channel
                upgrade = getattr(cluster, "auto_upgrade_profile", None)
                channel = getattr(upgrade, "node_os_upgrade_channel", None) if upgrade else None
                if not channel or channel.lower() == "none":
                    findings.append(self.finding(
                        "aks_node_os_auto_upgrade_disabled",
                        cluster.id, cluster.name, "AKS Cluster", "FAIL", "High",
                        "AKS cluster node OS auto-upgrade not configured",
                        f"Azure Portal → Kubernetes services → {cluster.name} → Settings → Cluster configuration → Node OS upgrade channel",
                        f"AKS cluster '{cluster.name}' has no node OS auto-upgrade configured. "
                        "Node OS patches address kernel vulnerabilities and must be applied regularly.",
                        tags=cluster.tags, resource_group=rg, location=getattr(cluster, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("aks_node_os_auto_upgrade_disabled", e))
        return findings

    def _monitoring_enabled(self):
        findings = []
        try:
            for cluster in self._client().managed_clusters.list():
                rg = self._rg(cluster.id)
                addon = (cluster.addon_profiles or {}).get("omsagent")
                if not addon or not addon.enabled:
                    findings.append(self.finding(
                        "aks_monitoring_disabled",
                        cluster.id, cluster.name, "AKS Cluster", "FAIL", "Medium",
                        "AKS cluster monitoring (Container Insights) not enabled",
                        f"Azure Portal → Kubernetes services → {cluster.name} → Monitoring → Insights → Enable",
                        f"AKS cluster '{cluster.name}' does not have Container Insights (omsagent) enabled. "
                        "Without monitoring, container crashes, high resource usage, and suspicious activity are not visible.",
                        tags=cluster.tags, resource_group=rg, location=getattr(cluster, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("aks_monitoring_disabled", e))
        return findings
