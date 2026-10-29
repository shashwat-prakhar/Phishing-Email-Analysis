# SOC Investigation Report: Sample 03
## Incident: DHL Express Delivery Alert via Typosquatted Domain (SPF/DKIM/DMARC Pass Bypass)

---

### 1. Incident Metadata
| Parameter | Value |
|---|---|
| **Incident ID** | INC-20261027-003 |
| **Analyzed By** | Shashwat Prakhar (SOC Analyst) |
| **Analysis Date** | 2026-10-27 12:00 UTC |
| **Target Recipient** | `victim.user@corporate-enterprise.com` |
| **Classification** | Malicious (True Positive) |
| **Threat Category** | Lookalike / Typosquatting Phishing (Financial Theft & Credential Harvesting) |
| **Severity Level** | **CRITICAL** (Risk Score: 95/100) |
| **MITRE ATT&CK** | T1566.002 (Spearphishing Link), T1583.001 (Domains), T1036.005 (Masquerading) |

---

### 2. Executive Summary
An email mimicking **DHL Express Worldwide** was sent to enterprise staff claiming an international parcel from Frankfurt, Germany was placed on hold at the distribution center due to an unpaid customs handling fee of `$2.49 USD` and missing address details.

**Critical Forensic Finding:** The email successfully passed **SPF, DKIM, and DMARC** validation! 
The attacker registered their own typosquatted domain: `dh1-express-notification.com` (using the numeral **`1`** instead of the lowercase letter **`l`**). Because the attacker owns and controls the DNS zone for `dh1-express-notification.com`, they configured their own valid SPF TXT record and signed outgoing messages with their own valid DKIM RSA private key. 

This case represents a classic **authentication-bypass evasion technique**: passing email authentication does *not* prove an email is benign; it only proves that the sending server matches the domain specified in the RFC 5322 headers.

---

### 3. Email Header Forensics & Discrepancies

| Header Field | Raw Value in Message | Forensic Findings & Red Flags |
|---|---|---|
| **From** | `DHL Express Delivery Tracking <tracking@dh1-express-notification.com>` | **Typosquatting Masquerade:** Uses numeral `1` (`dh1`) rather than `dhl`. |
| **Reply-To** | `DHL Logistics Support <support@parcel-redirect-center.click>` | **Mismatch:** Redirects inquiries to a disposable `.click` domain. |
| **Return-Path** | `<delivery-alerts@dh1-express-notification.com>` | Matches the typosquatted sender domain. |
| **Subject** | `Delivery Exception: Package #DHL-98402-US On Hold - Address Correction & Customs Clearance` | Pretext of package delivery failure to elicit hasty compliance. |
| **Originating IP** | `45.142.166.89` | Hosted in an off-shore data center in Latvia known for bulletproof hosting. |

#### Received Hop Trace (Bottom-to-Top Origin Tracking)
```
[Hop 1 - Local Mail Agent]
  From: localhost (unknown [127.0.0.1])
  By:   mail.dh1-express-notification.com (Postfix) with ESMTP id 8B901C021F
  Time: Tue, 27 Oct 2026 10:41:04 +0000

[Hop 2 - External Relay Ingress]
  From: mail.dh1-express-notification.com [45.142.166.89]
  By:   mx.corporate-enterprise.com with ESMTP id m20si1029482lfe.8
  Time: Tue, 27 Oct 2026 03:41:09 -0700

[Hop 3 - Inbound Gateway Delivery]
  Delivered-To: victim.user@corporate-enterprise.com
```

---

### 4. Email Authentication Validation: The Attacker's Illusion

| Protocol | Status | Diagnostic Evaluation |
|---|---|---|
| **SPF** | **PASS** | `mx.corporate-enterprise.com: domain of tracking@dh1-express-notification.com designates 45.142.166.89 as permitted sender`. |
| **DKIM** | **PASS** | Cryptographic signature `header.i=@dh1-express-notification.com` verified against DNS public key selector `default`. |
| **DMARC** | **PASS** | Alignment between `header.from` and SPF/DKIM domains satisfied. Policy `p=reject` set by attacker to appear legitimate to external spam filters. |

#### SOC Takeaway: Why Authentication Passed
Standard authentication protocols check **identity alignment**, not **brand legitimacy**. SPF validates that IP `45.142.166.89` is authorized to send for `dh1-express-notification.com`. Because the threat actor owned that exact domain, the technical check succeeded. Automated filters that rely solely on SPF/DKIM passes will fail to catch this attack.

---

### 5. URL and Threat Intelligence Analysis

#### Link Spoofing Details
* **Visual Anchor Text in Email:** `https://www.dhl.com/en/express/tracking.html?AWB=98402US`
* **Actual Embedded Destination (href):** `hxxps://track-dhl-parcel-customs[.]ru/pay/confirm.php?ref=DHL-98402-US`

#### Landing Page Behavior
* Directs the user to a counterfeit DHL payment gateway.
* Prompts the victim to input full name, billing address, credit card number, expiration date, and CVV code.
* Once submitted, the page redirects the user to the genuine `dhl.com` home page to reduce suspicion while exfiltrating credit card data to an attacker-controlled Telegram bot.

#### Threat Intel Telemetry
* **Domain:** `dh1-express-notification.com`
  * **Creation Date:** 25-Oct-2026 (Registered 48 hours prior to attack)
  * **Registrar:** Regery Services
* **Landing Domain:** `track-dhl-parcel-customs.ru`
  * **VirusTotal:** **29/88 security vendors** marked as Phishing / Carding Fraud.

---

### 6. Indicators of Compromise (IOCs)

| IOC Type | Indicator Value (Defanged) | Context / Description |
|---|---|---|
| **IPv4** | `45.142.166[.]89` | Attacker MTA Host (Latvia) |
| **Domain** | `dh1-express-notification[.]com` | Typosquatted sender domain |
| **Domain** | `parcel-redirect-center[.]click` | Reply-To domain |
| **Domain** | `track-dhl-parcel-customs[.]ru` | Credit card phishing landing domain |
| **URL** | `hxxps://track-dhl-parcel-customs[.]ru/pay/confirm.php` | Fake customs payment page |

---

### 7. SOC Containment & Remediation Playbook

1. **Brand Protection & Typosquat Detection:**
   - Configure Mail Gateway (Proofpoint / M365 Defender) with **Lookalike Domain Protection** (e.g., flag any inbound domain matching Levenshtein distance $\le 2$ from major logistics vendors: DHL, FedEx, UPS).
2. **DNS & Web Proxy Filtering:**
   - Immediately block `track-dhl-parcel-customs.ru` and `dh1-express-notification.com`.
   - Implement proactive blocking of domains registered within the last 14 days (Newly Registered Domains policy).
3. **Cardholder Remediation (If Submitted):**
   - If an employee entered corporate credit card details, immediately notify corporate finance to cancel and re-issue the compromised card.
   - Monitor corporate card accounts for unauthorized transactions.
