"""
Azure Credential Collector
--------------------------
Auth method: az login (DefaultAzureCredential) ONLY.

Flow:
  1. Initialise DefaultAzureCredential (uses whatever az login session exists)
  2. Auto-discover ALL subscriptions the logged-in account can access
  3. Let the user pick which subscriptions to audit (all or a subset)
  4. No region / location questions — Azure SDK calls are subscription-scoped,
     not region-scoped, so location is irrelevant here.
"""
from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient


class CredentialCollector:

    def __init__(self, display):
        self.display = display

    # ── Public entry point ────────────────────────────────────────────────────

    def collect(self):
        """
        Authenticate via az login, discover all accessible subscriptions,
        let the user pick which ones to scan.
        Returns list of subscription dicts ready for the scanner.
        """
        d = self.display

        d.section("STEP 2 — AZURE AUTHENTICATION  (az login)")
        d.info("  Using your active  az login  session (DefaultAzureCredential).")
        d.info("  Make sure you have run:  az login  before starting this tool.\n")

        # ── Init credential ───────────────────────────────────────────────────
        d.start_spinner("Connecting to Azure")
        try:
            credential = DefaultAzureCredential()
        except Exception as e:
            d.stop_spinner()
            d.error(f"  Failed to initialise Azure credential: {e}")
            d.error("  Please run  az login  and try again.")
            return []
        d.stop_spinner()
        d.success("  Azure credential initialised ✓")

        # ── Discover subscriptions ────────────────────────────────────────────
        d.info("\n  Discovering subscriptions accessible to your account...")
        d.start_spinner("Fetching subscriptions")
        try:
            sub_client    = SubscriptionClient(credential)
            all_subs      = list(sub_client.subscriptions.list())
        except Exception as e:
            d.stop_spinner()
            d.error(f"  Could not list subscriptions: {e}")
            d.error("  Ensure your account has Reader access and az login is current.")
            return []
        d.stop_spinner()

        if not all_subs:
            d.error("  No subscriptions found for this account.")
            return []

        # ── Display discovered subscriptions ──────────────────────────────────
        print()
        d.success(f"  Found {len(all_subs)} subscription(s):\n")
        for i, sub in enumerate(all_subs, 1):
            state = sub.state or "Unknown"
            name  = sub.display_name or sub.subscription_id
            sid   = sub.subscription_id
            print(f"    [{i:2}]  {name:<40}  {sid}  [{state}]")
        print()

        # ── Let user pick ─────────────────────────────────────────────────────
        d.info("  Which subscriptions do you want to audit?")
        d.info("  Enter 'all' to scan all, or comma-separated numbers (e.g. 1,3,5)\n")
        choice = d.prompt("  Your selection", default="all").strip().lower()

        if choice == "all" or choice == "":
            selected = all_subs
        else:
            try:
                indices  = [int(x.strip()) - 1 for x in choice.split(",") if x.strip()]
                selected = [all_subs[i] for i in indices if 0 <= i < len(all_subs)]
            except (ValueError, IndexError):
                d.warn("  Invalid selection — scanning all subscriptions.")
                selected = all_subs

        if not selected:
            d.error("  No valid subscriptions selected.")
            return []

        d.success(f"\n  Will scan {len(selected)} subscription(s):\n")
        for sub in selected:
            print(f"    •  {sub.display_name}  ({sub.subscription_id})")
        print()

        # ── Build subscription dicts ──────────────────────────────────────────
        result = []
        for sub in selected:
            result.append({
                "subscription_alias": sub.display_name or sub.subscription_id,
                "subscription_id":    sub.subscription_id,
                "credential":         credential,
                "auth_method":        "az_login",
                "tenant_id":          sub.tenant_id,
            })

        return result
