# MITRE ATT&CK Framework Mapping
**Author:** Shashwat Prakhar | SOC Threat Detection & Response  
**Repository:** [shashwat-prakhar/phishing-email-analysis](https://github.com/shashwat-prakhar/phishing-email-analysis)

---

## 1. Overview Matrix
This document maps the adversary behaviors, delivery mechanisms, and exploitation techniques observed during the forensic analysis of all 5 sample phishing emails against the **MITRE ATT&CK Enterprise Matrix**.

| Tactic | Technique ID | Technique Name | Sub-Technique / Specific Implementation | Observed in Sample |
|---|---|---|---|---|
| **Reconnaissance** | `T1589.002` | Gather Victim Identity Info | Email Addresses & Employee Org Chart Targeting | Sample 01, 04 |
| **Resource Development** | `T1583.001` | Acquire Infrastructure: Domains | Typosquatted & lookalike domains (`dh1-express...`, `.top`, `.cc`) | Sample 01, 03, 05 |
| **Resource Development** | `T1586.002` | Compromise Accounts: Email Accounts | Use of free webmail (`@gmail.com`) for executive impersonation | Sample 04 |
| **Initial Access** | `T1566.001` | Phishing: Spearphishing Attachment | Weaponized Excel macro document (`.xlsm`) | Sample 02 |
| **Initial Access** | `T1566.002` | Phishing: Spearphishing Link | Credential harvesting login portals & fake payment sites | Sample 01, 03, 05 |
| **Initial Access** | `T1566.003` | Phishing: Spearphishing Voice / Service | Fraudulent toll-free callback telephone number (Vishing) | Sample 05 |
| **Execution** | `T1204.002` | User Execution: Malicious File | Victim lured into clicking "Enable Content" to execute VBA | Sample 02 |
| **Execution** | `T1059.005` | Command & Scripting Interpreter: Visual Basic | Macro execution in Microsoft Office (`Workbook_Open`) | Sample 02 |
| **Execution** | `T1059.001` | Command & Scripting Interpreter: PowerShell | Hidden PowerShell execution cradle spawned by Excel | Sample 02 |
| **Defense Evasion** | `T1036.005` | Masquerading: Match Legitimate Name | Display name spoofing (DHL, Microsoft 365, PayPal, CEO) | Sample 01, 03, 04, 05 |
| **Defense Evasion** | `T1564.004` | Hide Artifacts: Obfuscated Files | Subdomain prepending (`login.microsoftonline.com-auth...`) | Sample 01, 05 |
| **Credential Access** | `T1056.001` | Input Capture: Keylogging / Phishing Forms | Fake SSO portal stealing username, password, and session token | Sample 01, 05 |
| **Command and Control** | `T1105` | Ingress Tool Transfer | Second-stage malicious binary download via WebClient | Sample 02 |

---

## 2. In-Depth Technique Breakdown & SOC Defenses

### T1566.001 - Spearphishing Attachment (Sample 02)
* **Adversary Behavior:** The attacker delivers an Excel macro-enabled workbook (`INVOICE_INV98234_PAST_DUE.xlsm`). The lure claims that past due charges must be verified by opening the worksheet.
* **Detection Mechanism:**
  * Mail gateway scanning for MIME types matching `application/vnd.ms-excel.sheet.macroEnabled.12`.
  * EDR telemetry detecting `EXCEL.EXE` spawning child processes such as `powershell.exe`, `cmd.exe`, or `wscript.exe`.
* **Mitigation Control (CIS / NIST):**
  * Implement Microsoft Attack Surface Reduction (ASR) rule: `"Block Office applications from creating child processes"`.
  * Enforce group policy: `"Block macros from running in Office files from the Internet"`.

---

### T1566.002 - Spearphishing Link (Sample 01, 03, 05)
* **Adversary Behavior:** Emails include links directing users to counterfeit authentication pages designed to harvest credentials or banking data. Techniques include:
  * Display-text vs href mismatch (Sample 01).
  * Typosquatted brand domains (Sample 03).
  * Subdomain prepending (Sample 05).
* **Detection Mechanism:**
  * Automated URL detonation in a secure virtual sandbox (Safe Links / URL Defense).
  * Detection of anchor mismatches in email HTML parsers.
  * DNS queries to newly registered domains (< 14 days old).
* **Mitigation Control:**
  * Web proxy SSL inspection and real-time categorization blocking unrated or newly observed domains.
  * Mandating Phishing-Resistant Multi-Factor Authentication (FIDO2 / WebAuthn / Passkeys), which prevents token theft via reverse-proxy MITM frameworks like Evilginx.

---

### T1586.002 / T1566 - Business Email Compromise & Impersonation (Sample 04)
* **Adversary Behavior:** Attacker establishes a free external webmail address (`ceo.office.direct@gmail.com`) with the friendly display name set to the company CEO. Because no links or attachments are present, traditional signature-based AV is ineffective.
* **Detection Mechanism:**
  * Natural Language Processing (NLP) classifiers evaluating urgency, secrecy, and financial keywords ("wire transfer", "strictly confidential", "Project Apex").
  * Impersonation Protection Algorithms matching display names against the corporate Active Directory directory.
* **Mitigation Control:**
  * Mandatory dual-authorization accounting controls for financial transfers.
  * Inbound gateway rule prepending prominent `[EXTERNAL EMAIL]` warnings.

---

### T1566.003 - Callback Phishing / Telephone Fraud (Sample 05)
* **Adversary Behavior:** Instead of forcing the user onto a web portal alone, the message provides a toll-free number (+1-888-492-0193) urging the user to call fraud assistance to stop an unauthorized Bitcoin charge.
* **Detection Mechanism:**
  * Regular expression scanning in mail gateway for toll-free telephone patterns paired with financial urgency words.
* **Mitigation Control:**
  * PBX/VoIP outbound call filtering.
  * Application control blocking unauthorized remote desktop clients (`AnyDesk`, `TeamViewer`, `Splashtop`).
