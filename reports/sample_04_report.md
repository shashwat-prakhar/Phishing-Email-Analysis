# SOC Investigation Report: Sample 04
## Incident: Executive Impersonation & Wire Fraud (Business Email Compromise - BEC)

---

### 1. Incident Metadata
| Parameter | Value |
|---|---|
| **Incident ID** | INC-20261028-004 |
| **Analyzed By** | Shashwat Prakhar (SOC Analyst) |
| **Analysis Date** | 2026-10-28 18:45 UTC |
| **Target Recipient** | `victim.user@corporate-enterprise.com` |
| **Classification** | Malicious (True Positive) |
| **Threat Category** | Business Email Compromise (BEC) / CEO Fraud / Wire Pretexting |
| **Severity Level** | **HIGH** (Risk Score: 75/100) |
| **MITRE ATT&CK** | T1566 (Phishing), T1586.002 (External Webmail Persona), T1534 (Internal Spearphishing Pretexting) |

---

### 2. Executive Summary
A targeted Business Email Compromise (BEC) email was delivered to an accounting specialist within the finance department. The email impersonated the company's Chief Executive Officer, **Marcus Sterling**, claiming that the CEO was stuck in a confidential executive board session regarding a time-sensitive M&A acquisition code-named "Project Apex".

The sender instructed the recipient to bypass standard operational procedures and execute an immediate wire transfer of **$48,500.00 USD** within 45 minutes to an external escrow account. 

Notably, this email contained **zero malicious links and zero file attachments**. It passed all standard SPF, DKIM, and DMARC technical checks because it was sent from a legitimate Gmail account (`ceo.office.direct@gmail.com`). The attack relies purely on human social engineering, authority manipulation, artificial urgency, and secrecy to orchestrate direct financial theft.

---

### 3. Email Header Forensics & Discrepancies

| Header Field | Raw Value in Message | Forensic Findings & Red Flags |
|---|---|---|
| **From** | `"Marcus Sterling (CEO)" <ceo.office.direct@gmail.com>` | **Display Name Spoofing:** Free consumer webmail address mimicking corporate executive. |
| **Reply-To** | `"Marcus Sterling - Private" <ceo.confidential-m.sterling@exec-offices.live>` | **Adversary Redirection:** Directs responses to a dedicated BEC infrastructure domain. |
| **Return-Path** | `<ceo.office.direct@gmail.com>` | Matches sending Google webmail account. |
| **Subject** | `STRICTLY CONFIDENTIAL // Project Apex - Urgent Wire Transfer Request` | Leverages confidentiality to discourage verbal verification with peers. |
| **Originating IP** | `209.85.220.41` | Authorized Google mail server (`mail-sor-f41.google.com`). |

#### Received Hop Trace (Bottom-to-Top Origin Tracking)
```
[Hop 1 - Webmail Submission]
  From: Google Web Interface
  By:   mail-wm1-f49.google.com with HTTP
  Time: Wed, 28 Oct 2026 11:05:38 -0700

[Hop 2 - Google Outbound Relay]
  From: mail-sor-f41.google.com [209.85.220.41]
  By:   mx.corporate-enterprise.com with SMTPS id s11sor2840192eje.1
  Time: Wed, 28 Oct 2026 11:05:39 -0700

[Hop 3 - Inbound Gateway Delivery]
  Delivered-To: victim.user@corporate-enterprise.com
```

---

### 4. Email Authentication Validation: Why Did It Pass?

| Protocol | Status | Diagnostic Evaluation |
|---|---|---|
| **SPF** | **PASS** | Originating IP `209.85.220.41` is part of `_spf.google.com`. |
| **DKIM** | **PASS** | Valid RSA cryptographic signature provided by `d=gmail.com` using selector `20230601`. |
| **DMARC** | **PASS** | Message complies with Google's public DMARC policy (`p=reject`). |

#### SOC Key Takeaway
Traditional email filters that only check SPF/DKIM/DMARC cannot stop BEC attacks because the sender is using a legitimate mail provider. Security solutions require **Natural Language Processing (NLP)**, **Display Name Impersonation Protection**, and strict internal dual-authorization accounting controls.

---

### 5. Social Engineering & Linguistic Red Flags

1. **Authority Bias & Power Dynamic:** Impersonates the highest authority in the company (CEO) to induce deference and fear of insubordination.
2. **Artificial Time Constraint:** Imposes a 45-minute countdown ("before market close at 3:00 PM EST") to rush the employee into bypassing verification protocols.
3. **Enforced Isolation & Secrecy:** Demands "keep this matter strictly between us" and claims inability to answer phone calls ("dialed into a closed-door session"), preventing the employee from doing an out-of-band phone check.
4. **Targeted Role Selection:** Specifically targeted an employee in accounts payable/treasury who possesses wire transfer execution rights.

---

### 6. Indicators of Compromise (IOCs)

| IOC Type | Indicator Value (Defanged) | Context / Description |
|---|---|---|
| **Email Address** | `ceo.office.direct@gmail[.]com` | Fraudulent sender webmail address |
| **Email Address** | `ceo.confidential-m.sterling@exec-offices[.]live` | Fraudulent Reply-To address |
| **Domain** | `exec-offices[.]live` | BEC threat actor communication domain |
| **Keywords** | `Project Apex`, `Urgent Wire Transfer` | Social engineering trigger phrases |

---

### 7. SOC Containment & Remediation Playbook

```mermaid
sequenceDiagram
    participant Attacker as Attacker (Fake CEO)
    participant Gateway as Secure Email Gateway
    participant Victim as Finance Employee
    participant SOC as SOC Team / Treasury
    
    Attacker->>Gateway: Sends wire fraud email via Gmail
    Gateway->>Victim: Delivers message (SPF/DKIM pass)
    Victim->>SOC: Reports suspicious email via PhishAlarm button
    SOC->>SOC: Identifies Display Name mismatch (CEO name on Gmail)
    SOC->>Gateway: Creates tenant-wide block for "exec-offices.live"
    SOC->>Victim: Confirms phish; advises zero response
    SOC->>SOC: Notifies CFO and confirms NO funds wired
```

1. **Display Name Impersonation Protection Rule:**
   - Configure Mail Gateway rule: If an inbound external email has a display name matching any corporate executive (`Marcus Sterling`, etc.) but the sender domain is NOT `corporate-enterprise.com`, append an external warning banner and route to quarantine.
2. **External Banner Enforcement:**
   - Prepend all external inbound emails with: `[CAUTION: EXTERNAL EMAIL - DO NOT EXECUTE FINANCIAL WIRES WITHOUT OUT-OF-BAND VERIFICATION]`.
3. **Out-of-Band Financial Verification Policy:**
   - Mandate that any wire transfer exceeding $5,000 requires verbal telephone verification over an internal directory extension or in-person confirmation with two authorized signatories before release.
4. **Block Adversary Domain:**
   - Block `exec-offices.live` across enterprise email gateways and firewalls.
