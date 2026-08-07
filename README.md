# 🛡 Azure Audit Pro v1

**Azure Cloud Security Assessment Tool**
Developed by 🦅 **Singaram**

---

## 📋 Overview

Azure Audit Pro scans your Azure subscriptions across **20 services** with **120+ security checks** mapped to **8 compliance frameworks**.

| Feature | Detail |
|---------|--------|
| **Services** | 20 Azure services |
| **Checks** | 120+ security checks |
| **Frameworks** | CIS, NIST CSF, NIST 800-53, HIPAA, PCI DSS, GDPR, CSA CCM, MITRE ATT&CK |
| **Auth** | Service Principal or Azure CLI |
| **Output** | Excel + HTML reports |
| **Multi-Subscription** | Yes |

---

## 🔍 Services Covered

| # | Service | Checks |
|---|---------|--------|
| 1 | IAM / Entra ID | MFA, PIM, custom roles, guest users, classic admins |
| 2 | Storage | Public access, HTTPS, TLS, soft-delete, network ACLs, SAS |
| 3 | Virtual Machines | Disk encryption, managed identity, JIT access, patching |
| 4 | SQL Database | Auditing, TDE, ATP, public access, AAD admin, firewall |
| 5 | Networking | NSG SSH/RDP, VNet NSG, DDoS, Network Watcher, flow logs, Bastion |
| 6 | Key Vault | Soft delete, purge protection, RBAC, network access, key/secret expiry |
| 7 | Monitor | Log retention, diagnostic settings, activity log alerts |
| 8 | Defender for Cloud | Plans, contacts, auto-provisioning, Secure Score, Sentinel |
| 9 | AKS | RBAC, AAD integration, network policy, API server access, monitoring |
| 10 | App Service | HTTPS, TLS, auth, managed identity, remote debugging, FTP |
| 11 | Functions | HTTPS, managed identity, runtime version, auth |
| 12 | Service Bus | SKU, TLS, public access, local auth |
| 13 | Cosmos DB | Public access, CMK, local auth, failover, ATP |
| 14 | Redis Cache | Non-SSL port, TLS version |
| 15 | Container Registry | Admin user, SKU, public access |
| 16 | Logic Apps | Diagnostic logging, managed identity, IP restriction |
| 17 | Backup | Vault exists, soft delete, immutability, CMK |
| 18 | Azure Policy | Assignments, compliance, Security Benchmark |
| 19 | DNS | DNSSEC, private zone VNet links, dangling CNAMEs |
| 20 | Security (General) | Resource tags, resource locks, private endpoints |

---

## 🚀 Quick Start

### Prerequisites

```bash
# Install Azure CLI if you don't have it
# https://learn.microsoft.com/cli/azure/install-azure-cli

# Log in to Azure — this tool uses your active az login session
az login
```

### Option 1: Direct Python

```bash
# 1. Clone / extract the tool
cd cloudaudit_azure

# 2. Setup (installs virtualenv + Azure SDK)
bash setup.sh

# 3. Run
bash run.sh
```

The tool will:
1. Connect using your `az login` session (no Tenant/Client ID/Secret needed)
2. **Auto-discover every subscription** your account can access
3. Let you choose `all` or specific subscriptions to audit
4. Scan each subscription across all Azure regions automatically (no region prompt — Azure Resource Manager calls are subscription-scoped, not region-scoped)
5. Generate a **separate Excel + HTML report per subscription**, in its own subfolder under `output/`

### Option 2: Docker

```bash
docker build -t azure-audit -f docker/Dockerfile .
docker run -it -v $(pwd)/output:/app/output -v ~/.azure:/root/.azure azure-audit
```

> The `-v ~/.azure:/root/.azure` mount shares your existing `az login` session with the container.

---

## 🔑 Required Azure Permissions

No Service Principal needed — just be logged in via `az login` with an account that has, on each subscription you want to audit:

- **Reader** role (minimum, to discover and read resource configurations)
- **Security Reader** role (recommended, for Defender for Cloud / Security Center data)

```bash
az login
az account list --output table     # confirms which subscriptions you can see
```

---

## 📁 Output Structure

Each subscription gets its **own subfolder** with its own complete Excel and HTML report:

```
output/
├── Production-Subscription/
│   ├── Production-Subscription.xlsx
│   ├── index.html
│   └── pages/
│       ├── iam.html
│       ├── storage.html
│       └── ... (one page per service with findings)
├── Dev-Subscription/
│   ├── Dev-Subscription.xlsx
│   ├── index.html
│   └── pages/
│       └── ...
└── ...
```

---

## 📊 Reports Generated

| Report | Contents |
|--------|----------|
| **Excel (.xlsx)** | Executive Dashboard, All Findings, 20 per-service tabs, Compliance Matrix, Remediation Roadmap |
| **HTML** | Interactive report with charts, filterable findings table, compliance bars |

---

## 🏗 Project Structure

```
cloudaudit_azure/
├── main.py                    # Entry point
├── requirements.txt           # Azure SDK dependencies
├── run.sh                     # Quick launcher
├── engine/
│   ├── display.py             # Banner, colors, prompts
│   ├── collector.py           # Azure credential collector
│   ├── scanner.py             # Scan orchestrator (20 services)
│   ├── remediation.py         # 120+ remediation paragraphs
│   ├── compliance_builder.py  # 8 compliance frameworks + calculator
│   └── deps.py                # Dependency checker/installer
├── checks/azure/
│   ├── base.py                # BaseCheck class
│   ├── iam/checks.py          # 12 IAM checks
│   ├── storage/checks.py      # 10 storage checks
│   ├── vm/checks.py           # 8 VM checks
│   ├── sql/checks.py          # 8 SQL checks
│   ├── networking/checks.py   # 8 networking checks
│   ├── keyvault/checks.py     # 7 Key Vault checks
│   ├── monitor/checks.py      # 7 monitor checks
│   ├── defender/checks.py     # 8 Defender checks
│   ├── aks/checks.py          # 6 AKS checks
│   ├── appservice/checks.py   # 7 App Service checks
│   ├── functions/checks.py    # 5 Functions checks
│   ├── servicebus/checks.py   # 4 Service Bus checks
│   ├── cosmos/checks.py       # 5 Cosmos DB checks
│   ├── redis/checks.py        # 4 Redis checks
│   ├── acr/checks.py          # 3 ACR checks
│   ├── logic/checks.py        # 3 Logic Apps checks
│   ├── backup/checks.py       # 4 Backup checks
│   ├── policy/checks.py       # 3 Policy checks
│   ├── dns/checks.py          # 3 DNS checks
│   └── security/checks.py     # 4 General security checks
├── compliance/azure/          # 8 compliance JSON files (auto-generated)
├── reports/
│   ├── excel.py               # Excel report generator
│   └── html_reporter.py       # HTML report generator
├── docker/
│   ├── Dockerfile             # Docker container
│   └── setup.sh               # Setup script
└── output/                    # Reports saved here
```

---

## 🔒 Compliance Frameworks

| Framework | Description |
|-----------|-------------|
| CIS Azure Benchmark 2.0 | 40+ controls across all services |
| NIST CSF 2.0 | Govern, Identify, Protect, Detect, Respond, Recover |
| NIST 800-53 Rev5 | AC, AU, CP, IA, SC, SI control families |
| HIPAA Security Rule | Administrative, Technical, Physical safeguards |
| PCI DSS 4.0 | Cardholder data protection requirements |
| GDPR | Data protection by design, security of processing |
| CSA CCM v4.0 | Cloud-specific controls (IAM, IVS, DSI, BCR) |
| MITRE ATT&CK Cloud | Threat technique mapping for Azure |

---

## 🦅 Developer

Built by **Singaram** — Azure Security Assessment Tool
Companion to **CloudAudit Pro** (AWS) — same architecture, full Azure parity.
