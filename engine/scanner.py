"""
Azure Scanner — orchestrates all 20 Azure service checks.

No region/location selection — Azure Resource Manager API calls are
subscription-scoped, not region-scoped, so every check naturally covers
resources across all regions within the subscription automatically.
"""

from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent

# A neutral placeholder used only for the "location" field on findings
# that don't have a real per-resource region (e.g. subscription-level checks).
# Individual checks set the real resource location from the Azure API response
# (e.g. storage account .location, VM .location) when available.
DEFAULT_LOCATION_LABEL = "subscription-wide"


def _load_services():
    """Dynamically load all Azure service check classes."""
    from checks.azure.iam.checks        import IAMChecks
    from checks.azure.storage.checks    import StorageChecks
    from checks.azure.vm.checks         import VMChecks
    from checks.azure.sql.checks        import SQLChecks
    from checks.azure.networking.checks import NetworkingChecks
    from checks.azure.keyvault.checks   import KeyVaultChecks
    from checks.azure.monitor.checks    import MonitorChecks
    from checks.azure.defender.checks   import DefenderChecks
    from checks.azure.aks.checks        import AKSChecks
    from checks.azure.appservice.checks import AppServiceChecks
    from checks.azure.functions.checks  import FunctionsChecks
    from checks.azure.servicebus.checks import ServiceBusChecks
    from checks.azure.cosmos.checks     import CosmosChecks
    from checks.azure.redis.checks      import RedisChecks
    from checks.azure.acr.checks        import ACRChecks
    from checks.azure.logic.checks      import LogicChecks
    from checks.azure.backup.checks     import BackupChecks
    from checks.azure.policy.checks     import PolicyChecks
    from checks.azure.dns.checks        import DNSChecks
    from checks.azure.security.checks   import SecurityChecks

    return {
        "IAM":              IAMChecks,
        "Storage":          StorageChecks,
        "VirtualMachines":  VMChecks,
        "SQL":              SQLChecks,
        "Networking":       NetworkingChecks,
        "KeyVault":         KeyVaultChecks,
        "Monitor":          MonitorChecks,
        "Defender":         DefenderChecks,
        "AKS":              AKSChecks,
        "AppService":       AppServiceChecks,
        "Functions":        FunctionsChecks,
        "ServiceBus":       ServiceBusChecks,
        "CosmosDB":         CosmosChecks,
        "Redis":            RedisChecks,
        "ContainerRegistry":ACRChecks,
        "LogicApps":        LogicChecks,
        "Backup":           BackupChecks,
        "Policy":           PolicyChecks,
        "DNS":              DNSChecks,
        "Security":         SecurityChecks,
    }


class Scanner:

    def __init__(self, display):
        self.display   = display
        self._services = _load_services()

    def scan_subscription(self, sub_creds):
        """
        Scan one Azure subscription across all selected services.
        No region/location parameter needed — Azure Resource Manager
        calls are subscription-scoped and naturally return resources
        from every region within the subscription.

        Returns list of FAIL findings only.
        """
        all_findings        = []
        subscription_id     = sub_creds["subscription_id"]
        subscription_alias  = sub_creds.get("subscription_alias", subscription_id)
        credential          = sub_creds["credential"]

        total = len(self._services)
        done  = 0

        self.display.info(f"\n  Scanning {total} Azure service(s)")
        self.display.info(f"  Subscription: {subscription_alias}  ({subscription_id})")
        print()

        for svc_name, CheckClass in self._services.items():
            done += 1
            self.display.progress_bar(done, total, svc_name)

            try:
                checker = CheckClass(
                    credential, subscription_id,
                    DEFAULT_LOCATION_LABEL, self.display
                )
                results = checker.run_all()

                for f in results:
                    f["subscription_id"]    = subscription_id
                    f["subscription_alias"] = subscription_alias
                    f["scan_time"]          = datetime.now(timezone.utc).isoformat()

                failed = [f for f in results if f.get("status") == "FAIL"]
                all_findings.extend(failed)

                if failed:
                    for f in failed:
                        self.display.print_check_result(
                            f.get("check_id", "")[:40],
                            f.get("resource_name", "")[:40],
                            f.get("severity", ""),
                            "FAIL",
                            f.get("resource_group", "") or f.get("location", ""),
                        )

            except Exception as e:
                err = str(e)[:100]
                if any(k in err.lower() for k in (
                    "not found", "resource not found", "subscription not found",
                    "featurenotavailable", "not supported",
                )):
                    pass  # service not available / not enabled in subscription
                else:
                    self.display.error(f"    [{svc_name}]: {err}")

        print()
        return all_findings
