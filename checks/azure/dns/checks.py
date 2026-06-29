"""Azure DNS — 3 checks."""
from ..base import BaseCheck


class DNSChecks(BaseCheck):
    SERVICE = "DNS"

    def run_all(self):
        f = []
        f += self._dnssec_status()
        f += self._private_dns_zones()
        f += self._dangling_dns()
        return f

    def _client(self):
        from azure.mgmt.dns import DnsManagementClient
        return DnsManagementClient(self.credential, self.subscription_id)

    def _rg(self, rid):
        try:
            parts = (rid or "").split("/")
            idx = parts.index("resourceGroups") if "resourceGroups" in parts else -1
            return parts[idx + 1] if idx >= 0 and idx + 1 < len(parts) else ""
        except Exception:
            return ""

    def _dnssec_status(self):
        """Azure DNS does not yet support DNSSEC — advisory check."""
        findings = []
        try:
            for zone in self._client().zones.list():
                rg = self._rg(zone.id)
                if zone.zone_type and zone.zone_type.lower() == "public":
                    findings.append(self.finding(
                        "dns_dnssec_not_supported",
                        zone.id, zone.name, "DNS Zone", "FAIL", "Low",
                        "Azure DNS does not support DNSSEC — consider alternative DNS provider for signed zones",
                        f"Azure Portal → DNS zones → {zone.name}",
                        f"Public DNS zone '{zone.name}' is hosted in Azure DNS which does not support DNSSEC. "
                        "For zones requiring DNSSEC signing, consider Azure Traffic Manager with a DNSSEC-capable external DNS, "
                        "or use Azure DNS Private Resolver for internal zones.",
                        tags=zone.tags, resource_group=rg, location=getattr(zone, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("dns_dnssec_not_supported", e))
        return findings

    def _private_dns_zones(self):
        """Advisory: verify private DNS zones are linked to VNets."""
        findings = []
        try:
            from azure.mgmt.privatedns import PrivateDnsManagementClient
            pc = PrivateDnsManagementClient(self.credential, self.subscription_id)
            for zone in pc.private_zones.list():
                rg = self._rg(zone.id)
                links = list(pc.virtual_network_links.list(rg, zone.name))
                if not links:
                    findings.append(self.finding(
                        "dns_private_zone_no_vnet_link",
                        zone.id, zone.name, "Private DNS Zone", "FAIL", "Medium",
                        "Private DNS Zone has no VNet link — name resolution will not work",
                        f"Azure Portal → Private DNS zones → {zone.name} → Virtual network links → + Add",
                        f"Private DNS zone '{zone.name}' has no VNet links. Without a link, VMs in VNets "
                        "cannot resolve private DNS names, potentially forcing traffic over public DNS.",
                        tags=zone.tags, resource_group=rg, location=getattr(zone, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("dns_private_zone_no_vnet_link", e))
        return findings

    def _dangling_dns(self):
        """Advisory: detect CNAME records pointing to deprovisioned resources."""
        findings = []
        try:
            for zone in self._client().zones.list():
                rg = self._rg(zone.id)
                for rs in self._client().record_sets.list_by_dns_zone(rg, zone.name):
                    if rs.type and "CNAME" in rs.type and rs.cname_record:
                        target = rs.cname_record.cname or ""
                        # Flag common deprovisioned endpoint patterns
                        risky_suffixes = [
                            ".azurewebsites.net", ".blob.core.windows.net",
                            ".cloudapp.azure.com", ".trafficmanager.net",
                        ]
                        if any(target.endswith(s) for s in risky_suffixes):
                            findings.append(self.finding(
                                "dns_potential_dangling_cname",
                                rs.id or zone.id,
                                f"{zone.name} → {rs.name}",
                                "DNS Record Set", "FAIL", "High",
                                "Potential dangling CNAME record pointing to Azure service endpoint",
                                f"Azure Portal → DNS zones → {zone.name} → Record sets → {rs.name} → Verify target",
                                f"CNAME '{rs.name}.{zone.name}' → '{target}'. Verify this Azure endpoint is still active. "
                                "Dangling CNAMEs pointing to deprovisioned resources can be hijacked by attackers to serve "
                                "malicious content under your domain.",
                                tags=zone.tags, resource_group=rg, location=getattr(zone, "location", None),
                            ))
        except Exception as e:
            findings.append(self.error_finding("dns_potential_dangling_cname", e))
        return findings
