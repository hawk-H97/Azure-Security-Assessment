"""Azure Networking (NSG, VNet, etc.) — 8 checks."""
from ..base import BaseCheck


class NetworkingChecks(BaseCheck):
    SERVICE = "Networking"

    def run_all(self):
        f = []
        f += self._nsg_ssh_open()
        f += self._nsg_rdp_open()
        f += self._nsg_all_inbound()
        f += self._vnet_no_nsg()
        f += self._ddos_protection()
        f += self._network_watcher()
        f += self._flow_logs()
        f += self._bastion_not_used()
        return f

    def _client(self):
        from azure.mgmt.network import NetworkManagementClient
        return NetworkManagementClient(self.credential, self.subscription_id)

    def _rg(self, resource_id):
        try:
            parts = (resource_id or "").split("/")
            idx   = parts.index("resourceGroups") if "resourceGroups" in parts else -1
            return parts[idx + 1] if idx >= 0 and idx + 1 < len(parts) else ""
        except Exception:
            return ""

    def _nsg_ssh_open(self):
        findings = []
        try:
            for nsg in self._client().network_security_groups.list_all():
                rg = self._rg(nsg.id)
                for rule in (nsg.security_rules or []):
                    if (rule.direction and rule.direction.lower() == "inbound" and
                            rule.access and rule.access.lower() == "allow"):
                        dest_port = rule.destination_port_range or ""
                        src = rule.source_address_prefix or ""
                        if (dest_port in ("22", "*", "0-65535") or
                                ("22" in dest_port)):
                            if src in ("*", "0.0.0.0/0", "Internet", "Any"):
                                findings.append(self.finding(
                                    "nsg_ssh_open_to_internet",
                                    nsg.id, nsg.name, "Network Security Group", "FAIL", "Critical",
                                    "NSG allows SSH (port 22) inbound from Internet",
                                    f"Azure Portal → Network security groups → {nsg.name} → Inbound security rules → Rule: {rule.name} → Delete or restrict source",
                                    f"NSG '{nsg.name}' rule '{rule.name}' allows SSH (port 22) from {src}. "
                                    "SSH exposed to the internet is a primary vector for brute-force attacks.",
                                    tags=nsg.tags, resource_group=rg, location=getattr(nsg, "location", None),
                                ))
        except Exception as e:
            findings.append(self.error_finding("nsg_ssh_open_to_internet", e))
        return findings

    def _nsg_rdp_open(self):
        findings = []
        try:
            for nsg in self._client().network_security_groups.list_all():
                rg = self._rg(nsg.id)
                for rule in (nsg.security_rules or []):
                    if (rule.direction and rule.direction.lower() == "inbound" and
                            rule.access and rule.access.lower() == "allow"):
                        dest_port = rule.destination_port_range or ""
                        src = rule.source_address_prefix or ""
                        if (dest_port in ("3389", "*", "0-65535") or
                                "3389" in dest_port):
                            if src in ("*", "0.0.0.0/0", "Internet", "Any"):
                                findings.append(self.finding(
                                    "nsg_rdp_open_to_internet",
                                    nsg.id, nsg.name, "Network Security Group", "FAIL", "Critical",
                                    "NSG allows RDP (port 3389) inbound from Internet",
                                    f"Azure Portal → Network security groups → {nsg.name} → Inbound security rules → Rule: {rule.name} → Delete or restrict source",
                                    f"NSG '{nsg.name}' rule '{rule.name}' allows RDP (port 3389) from {src}. "
                                    "Internet-exposed RDP is a leading ransomware entry point.",
                                    tags=nsg.tags, resource_group=rg, location=getattr(nsg, "location", None),
                                ))
        except Exception as e:
            findings.append(self.error_finding("nsg_rdp_open_to_internet", e))
        return findings

    def _nsg_all_inbound(self):
        findings = []
        try:
            for nsg in self._client().network_security_groups.list_all():
                rg = self._rg(nsg.id)
                for rule in (nsg.security_rules or []):
                    if (rule.direction and rule.direction.lower() == "inbound" and
                            rule.access and rule.access.lower() == "allow"):
                        src = rule.source_address_prefix or ""
                        port = rule.destination_port_range or ""
                        if src in ("*", "0.0.0.0/0", "Internet", "Any") and port in ("*", "0-65535", "Any"):
                            findings.append(self.finding(
                                "nsg_all_ports_open_to_internet",
                                nsg.id, nsg.name, "Network Security Group", "FAIL", "Critical",
                                "NSG allows all inbound traffic from the Internet on all ports",
                                f"Azure Portal → Network security groups → {nsg.name} → Inbound security rules → {rule.name}",
                                f"NSG '{nsg.name}' rule '{rule.name}' allows ALL traffic from Internet on ALL ports. "
                                "This completely negates network perimeter security.",
                                tags=nsg.tags, resource_group=rg, location=getattr(nsg, "location", None),
                            ))
        except Exception as e:
            findings.append(self.error_finding("nsg_all_ports_open_to_internet", e))
        return findings

    def _vnet_no_nsg(self):
        findings = []
        try:
            nc = self._client()
            for vnet in nc.virtual_networks.list_all():
                rg = self._rg(vnet.id)
                for subnet in (vnet.subnets or []):
                    if not subnet.network_security_group:
                        # Skip GatewaySubnet and AzureBastionSubnet — they don't need NSGs
                        if subnet.name.lower() in ("gatewaysubnet", "azurebastionsubnet"):
                            continue
                        findings.append(self.finding(
                            "subnet_no_nsg_attached",
                            subnet.id or vnet.id,
                            f"{vnet.name}/{subnet.name}", "Subnet", "FAIL", "High",
                            "Subnet has no Network Security Group attached",
                            f"Azure Portal → Virtual networks → {vnet.name} → Subnets → {subnet.name} → Network security group → Associate",
                            f"Subnet '{subnet.name}' in VNet '{vnet.name}' has no NSG. "
                            "Without an NSG, there are no traffic filtering rules protecting resources in this subnet.",
                            tags=vnet.tags, resource_group=rg, location=getattr(vnet, "location", None),
                        ))
        except Exception as e:
            findings.append(self.error_finding("subnet_no_nsg_attached", e))
        return findings

    def _ddos_protection(self):
        findings = []
        try:
            for vnet in self._client().virtual_networks.list_all():
                rg = self._rg(vnet.id)
                ddos = vnet.enable_ddos_protection
                if not ddos:
                    findings.append(self.finding(
                        "vnet_ddos_standard_not_enabled",
                        vnet.id, vnet.name, "Virtual Network", "FAIL", "Medium",
                        "VNet does not have DDoS Standard protection enabled",
                        f"Azure Portal → Virtual networks → {vnet.name} → Settings → DDoS protection → Enable Standard",
                        f"VNet '{vnet.name}' uses Basic DDoS protection only. "
                        "DDoS Standard provides adaptive tuning, attack metrics, and SLA guarantees for production workloads.",
                        tags=vnet.tags, resource_group=rg, location=getattr(vnet, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("vnet_ddos_standard_not_enabled", e))
        return findings

    def _network_watcher(self):
        findings = []
        try:
            watchers = list(self._client().network_watchers.list_all())
            if not watchers:
                findings.append(self.finding(
                    "network_watcher_not_enabled",
                    f"/subscriptions/{self.subscription_id}",
                    "Subscription", "Network Watcher", "FAIL", "Medium",
                    "Azure Network Watcher is not enabled",
                    "Azure Portal → Network Watcher → Enable",
                    "No Network Watcher found. Network Watcher provides packet capture, NSG flow logs, and topology views "
                    "critical for incident investigation and network troubleshooting.",
                ))
        except Exception as e:
            findings.append(self.error_finding("network_watcher_not_enabled", e))
        return findings

    def _flow_logs(self):
        findings = []
        try:
            nc = self._client()
            for nsg in nc.network_security_groups.list_all():
                rg = self._rg(nsg.id)
                # Check for flow log existence per NSG
                has_flow_log = False
                try:
                    for watcher in nc.network_watchers.list_all():
                        w_rg = self._rg(watcher.id)
                        for fl in nc.flow_logs.list(w_rg, watcher.name):
                            if nsg.id and nsg.id.lower() in (fl.target_resource_id or "").lower():
                                if fl.enabled:
                                    has_flow_log = True
                                    break
                except Exception:
                    pass
                if not has_flow_log:
                    findings.append(self.finding(
                        "nsg_flow_logs_not_enabled",
                        nsg.id, nsg.name, "Network Security Group", "FAIL", "Medium",
                        "NSG Flow Logs not enabled",
                        f"Azure Portal → Network Watcher → NSG flow logs → + Create → Select {nsg.name}",
                        f"NSG '{nsg.name}' has no flow logs enabled. NSG flow logs record all inbound/outbound traffic "
                        "decisions and are essential for security investigations and compliance audits.",
                        tags=nsg.tags, resource_group=rg, location=getattr(nsg, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("nsg_flow_logs_not_enabled", e))
        return findings

    def _bastion_not_used(self):
        findings = []
        try:
            bastions = list(self._client().bastion_hosts.list_all())
            if not bastions:
                findings.append(self.finding(
                    "azure_bastion_not_deployed",
                    f"/subscriptions/{self.subscription_id}",
                    "Subscription", "Azure Bastion", "FAIL", "Medium",
                    "Azure Bastion is not deployed for secure VM access",
                    "Azure Portal → Bastions → + Create",
                    "No Azure Bastion found. Without Bastion, VMs require public IPs with SSH/RDP exposed to internet. "
                    "Azure Bastion provides browser-based RDP/SSH via Azure Portal without exposing management ports.",
                ))
        except Exception as e:
            findings.append(self.error_finding("azure_bastion_not_deployed", e))
        return findings
