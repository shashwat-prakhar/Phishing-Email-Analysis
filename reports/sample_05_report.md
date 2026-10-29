# SOC Investigation Report: Sample 05
## Incident: PayPal Security Alert & Callback Phishing (Dual-Vector Attack)

---

### 1. Incident Metadata
| Parameter | Value |
|---|---|
| **Incident ID** | INC-20261025-005 |
| **Analyzed By** | Shashwat Prakhar (SOC Analyst) |
| **Analysis Date** | 2026-10-25 20:10 UTC |
| **Target Recipient** | `victim.user@corporate-enterprise.com` |
| **Classification** | Malicious (True Positive) |
| **Threat Category** | Spearphishing Link & Telephone Callback Phishing (Dual-Vector Phishing / Vishing) |
| **Severity Level** | **CRITICAL** (Risk Score: 100/100) |
| **MITRE ATT&CK** | T1566.002 (Spearphishing Link), T1566.003 (Phishing via Service / Voice Callback), T1056.001 (Input Capture) |

---

### 2. Executive Summary
The security monitoring center detected an incoming email masquerading as a high-priority security alert from **PayPal Account Security**. The message claimed that an unauthorized cryptocurrency purchase of **$649.00 USD** for "BTC Crypto Voucher" had been pre-authorized from an unrecognized device in Bucharest, Romania.

The email offered two avenues for the recipient to dispute the charge:
1. Click a fraudulent link (`paypal.com.verify-billing-protection[.]cc`) to cancel the transaction.
2. Call a fraudulent toll-free fraud helpline: `+1 (888) 492-0193`.

This attack combines web credential harvesting with **call-back phishing (vishing)**. If victims call the phone number, fake call center operators instruct them to install remote monitoring tools (e.g., AnyDesk, TeamViewer) to "cancel the payment", resulting in complete endpoint compromise.

---

### 3. Email Header Forensics & Discrepancies

| Header Field | Raw Value in Message | Forensic Findings & Red Flags |
|---|---|---|
| **From** | `PayPal Account Security <service-intl-notice@pay-pal-secure-alert.cc>` | Brand impersonation with fraudulent `.cc` domain. |
| **Reply-To** | `PayPal Fraud Assistance <disputes@resolve-center-cases.online>` | Points to secondary attacker domain with `.online` TLD. |
| **Return-Path** | `<bounces@marketing-blast-vps3.biz>` | Mismatched sender address from bulk marketing spam relay. |
| **Subject** | `Security Alert: Unauthorized Transaction Detected ($649.00 USD - Coinbase Inc.) - Account Limited` | Alarmist financial fraud notification. |
| **X-Mailer** | `Roundcube Webmail/1.4.11` | Open-source webmail software run on a compromised server. |
| **Originating IP** | `91.240.118.77` | IP located in Romania, matching the purported "attacker" location in the email body! |

#### Received Hop Trace (Bottom-to-Top Origin Tracking)
```
[Hop 1 - Compromised Webmail Ingress]
  From: [192.168.1.105] (unknown [91.240.118.77])
  By:   node04.marketing-blast-vps3.biz (Postfix) with ESMTPA id 4S9bH81kLm
  Time: Mon, 26 Oct 2026 01:31:58 +0000

[Hop 2 - External Relay Ingress]
  From: node04.marketing-blast-vps3.biz [103.145.13.204]
  By:   mx.corporate-enterprise.com with ESMTP id z8si5829104edw.14
  Time: Sun, 25 Oct 2026 18:32:03 -0700

[Hop 3 - Inbound Gateway Delivery]
  Delivered-To: victim.user@corporate-enterprise.com
```

---

### 4. Email Authentication Validation

| Protocol | Status | Diagnostic Evaluation |
|---|---|---|
| **SPF** | `FAIL` | IP `103.145.13.204` is not permitted to transmit on behalf of `marketing-blast-vps3.biz`. |
| **DKIM** | `NONE` | Message lacks any cryptographic signature. Official PayPal communications enforce 100% DKIM signing. |
| **DMARC** | `FAIL` | Policy specifies `p=reject`. Message should have been dropped at inbound gateway. |

---

### 5. URL, Telephony & Threat Intelligence Analysis

#### Web Vector: Subdomain Spoofing
* **Target URL:** `hxxps://paypal[.]com[.]verify-billing-protection[.]cc/signin?ref=PAY-99214`
* **Technique:** Subdomain prepending. The attacker configured `paypal.com` as a third-level subdomain under their root domain `verify-billing-protection.cc` to trick users scanning only the beginning of the URL.
* **VirusTotal Score:** **31/90 security vendors** flagged the landing domain as Phishing.

#### Voice Vector: Call-Back Vishing
* **Telephone Number:** `+1 (888) 492-0193`
* **Carrier:** VoIP provider (Bandwidth.com / Twilio)
* **Threat Profile:** Operators answer with "PayPal Security Department" IVR prompts. Victims are walked through downloading remote desktop software (`AnyDesk.exe`) from `fastsupport[.]me` to "remove the unauthorized charge".

---

### 6. Indicators of Compromise (IOCs)

| IOC Type | Indicator Value (Defanged) | Context / Description |
|---|---|---|
| **IPv4** | `91.240.118[.]77` | Attacker webmail injector IP |
| **IPv4** | `103.145.13[.]204` | External outbound relay host |
| **Domain** | `pay-pal-secure-alert[.]cc` | Spoofed sender domain |
| **Domain** | `resolve-center-cases[.]online` | Reply-To domain |
| **Domain** | `marketing-blast-vps3[.]biz` | Return-path relay domain |
| **Domain** | `verify-billing-protection[.]cc` | Root phishing host |
| **URL** | `hxxps://paypal[.]com[.]verify-billing-protection[.]cc/signin` | Credential phishing landing page |
| **Phone Number**| `+1 (888) 492-0193` | Fraudulent callback call center |

---

### 7. SOC Containment & Remediation Playbook

1. **Gateway Policy Tuning:**
   - Enforce strict rejection (`reject`) for inbound emails where DMARC fails and the sender claims a financial institution domain (`paypal.com`, `chase.com`, `bankofamerica.com`).
2. **Network Perimeter & DNS Sinkholing:**
   - Block domains `*.verify-billing-protection.cc` and `*.pay-pal-secure-alert.cc`.
3. **Telephony & PBX Filtering:**
   - Add `+1 (888) 492-0193` to corporate VoIP/PBX outbound blocklists to prevent employees from dialing the fraudulent call center from corporate desk phones.
4. **Endpoint RMM / Remote Access Auditing:**
   - Scan enterprise endpoints for unauthorized installations of remote access software (`AnyDesk`, `TeamViewer`, `ScreenConnect`) executed around the timestamp of the email receipt.
