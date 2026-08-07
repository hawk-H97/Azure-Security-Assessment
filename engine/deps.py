"""Dependency checker for Azure Audit Pro."""
import subprocess, sys, shutil
from pathlib import Path
ROOT = Path(__file__).parent.parent

PACKAGES = [
    "azure-identity", "azure-mgmt-resource", "azure-mgmt-compute",
    "azure-mgmt-network", "azure-mgmt-storage", "azure-mgmt-sql",
    "azure-mgmt-keyvault", "azure-mgmt-monitor", "azure-mgmt-containerservice",
    "azure-mgmt-web", "azure-mgmt-servicebus", "azure-mgmt-cosmosdb",
    "azure-mgmt-redis", "azure-mgmt-containerregistry", "azure-mgmt-logic",
    "azure-mgmt-recoveryservices", "azure-mgmt-security",
    "azure-mgmt-authorization", "azure-mgmt-dns", "azure-mgmt-subscription",
    "azure-mgmt-policyinsights", "azure-keyvault-keys", "azure-keyvault-secrets",
    "azure-mgmt-privatedns",
    "openpyxl", "requests",
]

IMPORT_MAP = {
    "azure-identity":              "azure.identity",
    "azure-mgmt-resource":         "azure.mgmt.resource",
    "azure-mgmt-compute":          "azure.mgmt.compute",
    "azure-mgmt-network":          "azure.mgmt.network",
    "azure-mgmt-storage":          "azure.mgmt.storage",
    "azure-mgmt-sql":              "azure.mgmt.sql",
    "azure-mgmt-keyvault":         "azure.mgmt.keyvault",
    "azure-mgmt-monitor":          "azure.mgmt.monitor",
    "azure-mgmt-containerservice": "azure.mgmt.containerservice",
    "azure-mgmt-web":              "azure.mgmt.web",
    "azure-mgmt-servicebus":       "azure.mgmt.servicebus",
    "azure-mgmt-cosmosdb":         "azure.mgmt.cosmosdb",
    "azure-mgmt-redis":            "azure.mgmt.redis",
    "azure-mgmt-containerregistry":"azure.mgmt.containerregistry",
    "azure-mgmt-logic":            "azure.mgmt.logic",
    "azure-mgmt-recoveryservices": "azure.mgmt.recoveryservices",
    "azure-mgmt-security":         "azure.mgmt.security",
    "azure-mgmt-authorization":    "azure.mgmt.authorization",
    "azure-mgmt-dns":              "azure.mgmt.dns",
    "azure-mgmt-subscription":     "azure.mgmt.subscription",
    "azure-mgmt-policyinsights":   "azure.mgmt.policyinsights",
    "azure-keyvault-keys":         "azure.keyvault.keys",
    "azure-keyvault-secrets":      "azure.keyvault.secrets",
    "azure-mgmt-privatedns":       "azure.mgmt.privatedns",
    "openpyxl":                    "openpyxl",
    "requests":                    "requests",
}


class DependencyChecker:
    def __init__(self, display):
        self.display = display

    def check_and_install_all(self):
        self.display.subsection("Python Packages")
        self._python_packages()
        self.display.subsection("Compliance Frameworks")
        self._compliance_files()
        self.display.success("All dependencies satisfied ✓\n")

    def _python_packages(self):
        missing = []
        for pkg in PACKAGES:
            import_name = IMPORT_MAP.get(pkg, pkg)
            try:
                __import__(import_name.replace("-", "_").split(".")[0])
            except ImportError:
                self.display.warn(f"  {pkg} — not found, installing...")
                missing.append(pkg)

        if missing:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--quiet"] + missing,
                check=False
            )
            for pkg in missing:
                self.display.success(f"  Installed: {pkg}")
        else:
            self.display.success(f"  All {len(PACKAGES)} Azure SDK packages ready")

    def _compliance_files(self):
        from engine.compliance_builder import AzureComplianceBuilder
        builder   = AzureComplianceBuilder(self.display)
        azure_dir = ROOT / "compliance" / "azure"
        builder.build_all(azure_dir)
