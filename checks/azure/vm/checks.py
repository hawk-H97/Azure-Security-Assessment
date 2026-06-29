"""Azure Virtual Machines — 8 checks."""
from ..base import BaseCheck


class VMChecks(BaseCheck):
    SERVICE = "VirtualMachines"

    def run_all(self):
        f = []
        f += self._disk_encryption()
        f += self._managed_identity()
        f += self._os_patch_status()
        f += self._just_in_time_access()
        f += self._endpoint_protection()
        f += self._boot_diagnostics()
        f += self._vm_extensions_approved()
        f += self._accelerated_networking()
        return f

    def _client(self):
        from azure.mgmt.compute import ComputeManagementClient
        return ComputeManagementClient(self.credential, self.subscription_id)

    def _rg(self, resource_id):
        try:
            parts = (resource_id or "").split("/")
            idx   = parts.index("resourceGroups") if "resourceGroups" in parts else -1
            return parts[idx + 1] if idx >= 0 and idx + 1 < len(parts) else ""
        except Exception:
            return ""

    def _disk_encryption(self):
        findings = []
        try:
            for vm in self._client().virtual_machines.list_all():
                rg = self._rg(vm.id)
                # Check OS disk encryption
                od  = vm.storage_profile.os_disk if vm.storage_profile else None
                enc = od.managed_disk.security_profile if (od and od.managed_disk) else None
                if not enc:
                    # Check if disk encryption extension is present
                    has_enc_ext = any(
                        "diskencryption" in (ext.type or "").lower()
                        for ext in (vm.resources or [])
                    )
                    if not has_enc_ext:
                        findings.append(self.finding(
                            "vm_os_disk_not_encrypted",
                            vm.id, vm.name, "Virtual Machine", "FAIL", "High",
                            "VM OS disk encryption not configured",
                            f"Azure Portal → Virtual machines → {vm.name} → Disks → OS disk → Encryption",
                            f"VM '{vm.name}': OS disk does not use Azure Disk Encryption or CMK. "
                            "Unencrypted OS disks expose data if the disk is detached or copied.",
                            tags=vm.tags, resource_group=rg, location=getattr(vm, "location", None),
                        ))
        except Exception as e:
            findings.append(self.error_finding("vm_os_disk_not_encrypted", e))
        return findings

    def _managed_identity(self):
        findings = []
        try:
            for vm in self._client().virtual_machines.list_all():
                rg = self._rg(vm.id)
                if not vm.identity:
                    findings.append(self.finding(
                        "vm_no_managed_identity",
                        vm.id, vm.name, "Virtual Machine", "FAIL", "Medium",
                        "VM does not use Managed Identity",
                        f"Azure Portal → Virtual machines → {vm.name} → Identity → System assigned → On",
                        f"VM '{vm.name}' has no Managed Identity. Applications on this VM must use stored credentials "
                        "to access Azure services. Enable Managed Identity to eliminate stored secrets.",
                        tags=vm.tags, resource_group=rg, location=getattr(vm, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("vm_no_managed_identity", e))
        return findings

    def _os_patch_status(self):
        findings = []
        try:
            for vm in self._client().virtual_machines.list_all():
                rg = self._rg(vm.id)
                sp = vm.os_profile.windows_configuration if vm.os_profile else None
                if sp:
                    if not sp.enable_automatic_updates:
                        findings.append(self.finding(
                            "vm_auto_update_disabled",
                            vm.id, vm.name, "Virtual Machine", "FAIL", "High",
                            "VM automatic OS updates disabled",
                            f"Azure Portal → Virtual machines → {vm.name} → Operations → Updates → Automatic updates",
                            f"Windows VM '{vm.name}' has automatic updates disabled. "
                            "Unpatched systems are vulnerable to known exploits. Enable automatic OS patching.",
                            tags=vm.tags, resource_group=rg, location=getattr(vm, "location", None),
                        ))
        except Exception as e:
            findings.append(self.error_finding("vm_auto_update_disabled", e))
        return findings

    def _just_in_time_access(self):
        findings = []
        try:
            from azure.mgmt.security import SecurityCenter
            sc = SecurityCenter(self.credential, self.subscription_id)
            jit_policies = list(sc.jit_network_access_policies.list_all())
            if not jit_policies:
                findings.append(self.finding(
                    "vm_jit_access_not_configured",
                    f"/subscriptions/{self.subscription_id}",
                    "Subscription", "JIT Policy", "FAIL", "High",
                    "Just-In-Time VM access is not configured",
                    "Azure Portal → Microsoft Defender for Cloud → Workload protections → Just-in-time VM access",
                    "No JIT access policies found. JIT access reduces attack surface by opening management ports "
                    "(SSH/RDP) only on request for a limited time window. Configure JIT for all internet-facing VMs.",
                ))
        except Exception as e:
            findings.append(self.error_finding("vm_jit_access_not_configured", e))
        return findings

    def _endpoint_protection(self):
        findings = []
        try:
            for vm in self._client().virtual_machines.list_all():
                rg = self._rg(vm.id)
                has_ep = any(
                    "mde" in (ext.type or "").lower() or
                    "endpoint" in (ext.type or "").lower() or
                    "antimalware" in (ext.type or "").lower()
                    for ext in (vm.resources or [])
                )
                if not has_ep:
                    findings.append(self.finding(
                        "vm_no_endpoint_protection",
                        vm.id, vm.name, "Virtual Machine", "FAIL", "High",
                        "VM has no endpoint protection extension",
                        f"Azure Portal → Microsoft Defender for Cloud → Recommendations → Install endpoint protection on VMs",
                        f"VM '{vm.name}' has no antimalware/endpoint detection extension. "
                        "Deploy Microsoft Defender for Endpoint or equivalent to detect and respond to threats.",
                        tags=vm.tags, resource_group=rg, location=getattr(vm, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("vm_no_endpoint_protection", e))
        return findings

    def _boot_diagnostics(self):
        findings = []
        try:
            for vm in self._client().virtual_machines.list_all():
                rg   = self._rg(vm.id)
                diag = vm.diagnostics_profile
                if not diag or not diag.boot_diagnostics or not diag.boot_diagnostics.enabled:
                    findings.append(self.finding(
                        "vm_boot_diagnostics_disabled",
                        vm.id, vm.name, "Virtual Machine", "FAIL", "Low",
                        "VM boot diagnostics not enabled",
                        f"Azure Portal → Virtual machines → {vm.name} → Help → Boot diagnostics → Enable",
                        f"VM '{vm.name}' has boot diagnostics disabled. Without this, troubleshooting boot failures "
                        "and detecting rootkits via serial console output is not possible.",
                        tags=vm.tags, resource_group=rg, location=getattr(vm, "location", None),
                    ))
        except Exception as e:
            findings.append(self.error_finding("vm_boot_diagnostics_disabled", e))
        return findings

    def _vm_extensions_approved(self):
        """Advisory: ensure only approved extensions are installed."""
        findings = []
        try:
            suspicious_exts = [
                "customscriptextension", "runcommand",
            ]
            for vm in self._client().virtual_machines.list_all():
                rg = self._rg(vm.id)
                for ext in (vm.resources or []):
                    ext_type = (ext.type or "").lower()
                    if any(s in ext_type for s in suspicious_exts):
                        findings.append(self.finding(
                            "vm_risky_extension_installed",
                            vm.id, vm.name, "Virtual Machine", "FAIL", "Medium",
                            "VM has a potentially risky extension (Custom Script / Run Command)",
                            f"Azure Portal → Virtual machines → {vm.name} → Extensions + applications → {ext.name}",
                            f"VM '{vm.name}' has extension '{ext.type}' installed. "
                            "Custom Script Extension and Run Command can execute arbitrary code. "
                            "Verify this extension is expected and audited.",
                            tags=vm.tags, resource_group=rg, location=getattr(vm, "location", None),
                        ))
        except Exception as e:
            findings.append(self.error_finding("vm_risky_extension_installed", e))
        return findings

    def _accelerated_networking(self):
        """Informational: accelerated networking improves throughput but is not security-critical."""
        return []
