#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         🛡  AZURE AUDIT PRO  v1  —  by 🦅 Singaram          ║
║         Azure Cloud Security Assessment Tool                 ║
║         20 Services · 120+ Checks · 8 Frameworks            ║
║         Auth: az login  ·  Auto-discovers all subscriptions  ║
╚══════════════════════════════════════════════════════════════╝
"""
import sys
import os
import time
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from engine.display import Display


def main():
    display = Display()
    display.banner()

    # ── Step 1: Dependencies ──────────────────────────────────────────────
    display.section("STEP 1 — DEPENDENCY CHECK")
    from engine.deps import DependencyChecker
    DependencyChecker(display).check_and_install_all()

    # ── Step 2: Auth + subscription discovery (az login) ─────────────────
    # collector handles its own section header
    from engine.collector import CredentialCollector
    subscriptions = CredentialCollector(display).collect()

    if not subscriptions:
        display.error("No subscriptions to scan. Exiting.")
        sys.exit(1)

    display.success(f"  {len(subscriptions)} subscription(s) ready to scan ✓\n")

    # ── Step 3: Services selection ────────────────────────────────────────
    display.section("STEP 3 — SERVICE SELECTION")
    all_services = [
        ("IAM",              "Identity & Access Management (Entra ID, Roles, MFA, PIM)"),
        ("Storage",          "Azure Storage (Blob, Files, Tables, Queues)"),
        ("VirtualMachines",  "Virtual Machines (Disk encryption, JIT, patching)"),
        ("SQL",              "Azure SQL Database (Auditing, TDE, firewall, ATP)"),
        ("Networking",       "Networking (NSG, VNet, Bastion, DDoS, Flow logs)"),
        ("KeyVault",         "Key Vault (Soft delete, purge protection, logging)"),
        ("Monitor",          "Monitor (Activity logs, alerts, diagnostic settings)"),
        ("Defender",         "Microsoft Defender for Cloud (Plans, Secure Score)"),
        ("AKS",              "Azure Kubernetes Service (RBAC, network policy, AAD)"),
        ("AppService",       "App Service (HTTPS, TLS, auth, managed identity)"),
        ("Functions",        "Azure Functions (HTTPS, managed identity, runtime)"),
        ("ServiceBus",       "Service Bus (TLS, public access, local auth)"),
        ("CosmosDB",         "Cosmos DB (Public access, CMK, local auth, failover)"),
        ("Redis",            "Azure Cache for Redis (Non-SSL port, TLS version)"),
        ("ContainerRegistry","Container Registry (Admin user, public access, SKU)"),
        ("LogicApps",        "Logic Apps (Diagnostic logging, managed identity)"),
        ("Backup",           "Backup / Recovery Vault (Soft delete, immutability)"),
        ("Policy",           "Azure Policy (Assignments, compliance, benchmark)"),
        ("DNS",              "Azure DNS (Private zone links, dangling CNAMEs)"),
        ("Security",         "General Security (Tags, resource locks, Private Endpoints)"),
    ]

    display.info("  Available Azure services:\n")
    for i, (key, desc) in enumerate(all_services, 1):
        print(f"    \033[96m[{i:2}]\033[0m  \033[1m{key:<20}\033[0m  \033[2m{desc}\033[0m")
    print()
    display.info("  Enter 'all' to scan everything, or comma-separated numbers (e.g. 1,2,5)")
    svc_input = display.prompt("  Services to scan", default="all").strip().lower()

    if svc_input in ("all", ""):
        selected_keys = [k for k, _ in all_services]
    else:
        try:
            indices       = [int(x.strip()) - 1 for x in svc_input.split(",") if x.strip()]
            selected_keys = [all_services[i][0] for i in indices if 0 <= i < len(all_services)]
        except (ValueError, IndexError):
            selected_keys = [k for k, _ in all_services]

    display.success(f"\n  Selected {len(selected_keys)} service(s): {', '.join(selected_keys)}\n")

    # ── Step 4: Output directory ──────────────────────────────────────────
    display.section("STEP 4 — OUTPUT CONFIGURATION")
    default_out = str(ROOT / "output")
    output_dir  = display.prompt("Output directory", default=default_out).strip() or default_out
    os.makedirs(output_dir, exist_ok=True)
    display.success(f"  Reports will be saved to: {output_dir}\n")

    # ── Step 5: Scan — one subscription at a time ─────────────────────────
    display.section("STEP 5 — RUNNING AZURE SECURITY SCAN")
    display.info(f"  {len(subscriptions)} subscription(s)  ×  {len(selected_keys)} service(s)\n")

    from engine.scanner import Scanner, _load_services as _load_all
    from engine.compliance_calc import calculate_compliance, severity_counts as _sev_counts
    from reports.excel         import ExcelReporter
    from reports.html_reporter import HTMLReporter

    all_classes    = _load_all()
    service_filter = {k: v for k, v in all_classes.items() if k in selected_keys}

    company        = "Azure Security Assessment"
    grand_findings = []   # all findings across all subscriptions (for final summary)
    report_paths   = []   # (sub_alias, excel_path, html_path)
    start_time     = time.time()

    for sub in subscriptions:
        sub_id    = sub["subscription_id"]
        sub_alias = sub["subscription_alias"]

        display.subsection(f"Scanning: {sub_alias}  ({sub_id})")

        # ── Run checks ───────────────────────────────────────────────────
        scanner           = Scanner(display)
        scanner._services = service_filter
        sub_findings      = scanner.scan_subscription(sub)
        grand_findings.extend(sub_findings)

        fail_cnt = len([f for f in sub_findings if f.get("status") == "FAIL"])
        display.success(f"  {sub_alias} — {fail_cnt} finding(s)")

        # ── Per-subscription summary ──────────────────────────────────────
        sub_sev  = _sev_counts(sub_findings)
        sub_comp = calculate_compliance(sub_findings, "azure")

        print(f"\n  {'─'*55}")
        print(f"  \033[1m{sub_alias[:50]}\033[0m")
        print(f"  {'─'*55}")
        print(f"  {'Critical':12} \033[91m{sub_sev['Critical']:>4}\033[0m   "
              f"{'High':8} \033[38;5;208m{sub_sev['High']:>4}\033[0m   "
              f"{'Medium':8} \033[93m{sub_sev['Medium']:>4}\033[0m   "
              f"{'Low':4} \033[92m{sub_sev['Low']:>4}\033[0m")
        print(f"  {'─'*55}\n")

        # ── Per-subscription output folder ────────────────────────────────
        # Safe folder name from subscription alias
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_"
                            for c in sub_alias).strip("_")[:60]
        sub_out   = os.path.join(output_dir, safe_name)
        os.makedirs(sub_out, exist_ok=True)

        # ── Generate reports for this subscription ────────────────────────
        display.info(f"  Generating reports for {sub_alias}...")

        excel_path = ExcelReporter(display).generate(
            [f for f in sub_findings if f.get("status") == "FAIL"],
            sub_out, safe_name, company
        )
        html_path = HTMLReporter(display).generate(
            sub_findings, sub_out, sub_alias, company
        )

        report_paths.append((sub_alias, sub_id, str(excel_path), str(html_path)))
        print()

    elapsed = time.time() - start_time

    # ── Step 6: Grand summary ─────────────────────────────────────────────
    display.section("STEP 6 — OVERALL SUMMARY")

    grand_sev  = _sev_counts(grand_findings)
    grand_comp = calculate_compliance(grand_findings, "azure")

    print(f"\n  {'─'*62}")
    print(f"  {'🔍 AZURE AUDIT PRO — OVERALL RESULTS':^62}")
    print(f"  {'─'*62}")
    print(f"  {'Subscriptions Scanned':32}  {len(subscriptions):>6}")
    print(f"  {'Services Checked':32}  {len(selected_keys):>6}")
    print(f"  {'Scan Duration':32}  {elapsed:.1f}s")
    print(f"  {'─'*62}")
    print(f"  \033[91m{'Critical':32}  {grand_sev['Critical']:>6}\033[0m")
    print(f"  \033[38;5;208m{'High':32}  {grand_sev['High']:>6}\033[0m")
    print(f"  \033[93m{'Medium':32}  {grand_sev['Medium']:>6}\033[0m")
    print(f"  \033[92m{'Low':32}  {grand_sev['Low']:>6}\033[0m")
    print(f"  {'Total Findings':32}  {grand_sev['Total']:>6}")
    print(f"  {'─'*62}\n")

    print(f"  {'Compliance Framework Coverage':^62}")
    print(f"  {'─'*62}")
    for fw, pct in grand_comp.items():
        bar_len = int(pct / 5)
        bar_col = ("\033[92m" if pct >= 90 else "\033[93m" if pct >= 70 else "\033[91m")
        bar     = bar_col + "█" * bar_len + "\033[0m" + "░" * (20 - bar_len)
        print(f"  {fw:<30}  {bar}  {pct:.1f}%")
    print(f"  {'─'*62}\n")

    # ── Report locations ──────────────────────────────────────────────────
    display.section("REPORTS GENERATED")
    for sub_alias, sub_id, excel_p, html_p in report_paths:
        print(f"\n  \033[1m{sub_alias}\033[0m  \033[2m({sub_id})\033[0m")
        print(f"    \033[96m📊  Excel  →  {excel_p}\033[0m")
        print(f"    \033[96m🌐  HTML   →  {html_p}\033[0m")

    print(f"\n  \033[92m\033[1m🦅  Azure Audit Pro v1 by Singaram — Complete!\033[0m")
    print(f"  \033[93m⚡  {grand_sev['Critical']} Critical · {grand_sev['High']} High · "
          f"{grand_sev['Medium']} Medium · {grand_sev['Low']} Low  "
          f"(across {len(subscriptions)} subscription(s))\033[0m")
    print(f"\n  \033[2mReports saved to: {output_dir}\033[0m\n")


if __name__ == "__main__":
    main()
