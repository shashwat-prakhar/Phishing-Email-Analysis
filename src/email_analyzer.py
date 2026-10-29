#!/usr/bin/env python3
"""
Phishing Email Analysis Engine
Comprehensive SOC triage tool for .eml files:
- Inspects RFC 5322 headers (From, Reply-To, Return-Path, Message-ID)
- Hop-by-hop Received chain tracer (traces origin IP)
- Email authentication validator (SPF, DKIM, DMARC)
- URL extractor, defanger, and anchor mismatch detector
- Attachment extractor and cryptographic hasher (MD5, SHA-256)
- Phishing risk scoring and MITRE ATT&CK mapping

Author: Shashwat Prakhar
GitHub: https://github.com/shashwat-prakhar/phishing-email-analysis
"""

import os
import sys
import email
from email import policy
from email.message import EmailMessage
import re
import json
import argparse
from typing import Dict, List, Any, Optional

try:
    from src.utils import (
        defang_url,
        defang_ip,
        defang_domain,
        is_private_ip,
        extract_ips,
        compute_hashes,
        extract_links_from_html,
        extract_urls_from_text,
        detect_mismatch,
    )
except ImportError:
    from utils import (
        defang_url,
        defang_ip,
        defang_domain,
        is_private_ip,
        extract_ips,
        compute_hashes,
        extract_links_from_html,
        extract_urls_from_text,
        detect_mismatch,
    )


class EmailAnalyzer:
    """Performs deep forensic and security triage on raw .eml emails."""

    SUSPICIOUS_TLDS = {
        ".top", ".xyz", ".click", ".cc", ".su", ".ru", ".buzz", ".work",
        ".live", ".online", ".icu", ".rest", ".tk", ".ml", ".ga", ".cf", ".gq"
    }

    URGENCY_KEYWORDS = [
        "urgent", "immediately", "action required", "expires in", "suspended",
        "unauthorized", "past due", "overdue", "locked", "strictly confidential",
        "wire transfer", "enable content", "enable editing", "customs fee",
        "bitcoin", "crypto", "security alert", "compromised", "verify identity"
    ]

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.raw_message: Optional[EmailMessage] = None
        self.results: Dict[str, Any] = {}
        self._load_email()

    def _load_email(self):
        """Loads and parses the raw .eml file."""
        with open(self.filepath, "rb") as f:
            self.raw_message = email.message_from_binary_file(f, policy=policy.default)

    def analyze(self) -> Dict[str, Any]:
        """Runs full analysis suite on the email."""
        headers = self._parse_headers()
        received_hops = self._trace_received_chain()
        origin_ip = self._identify_origin_ip(received_hops)
        auth = self._check_authentication()
        body_analysis = self._parse_body_and_urls()
        attachments = self._analyze_attachments()
        risk_score, severity, red_flags, mitre = self._calculate_risk(
            headers, auth, body_analysis, attachments
        )

        self.results = {
            "metadata": {
                "filename": self.filename,
                "file_size_bytes": os.path.getsize(self.filepath),
                "analyzed_by": "Phishing Email Analyzer (Shashwat Prakhar)",
            },
            "headers": headers,
            "received_chain": received_hops,
            "origin_ip": origin_ip,
            "authentication": auth,
            "urls_and_links": body_analysis["links"],
            "url_mismatches": body_analysis["mismatches"],
            "urgency_triggers": body_analysis["urgency_triggers"],
            "attachments": attachments,
            "triage": {
                "score": risk_score,
                "severity": severity,
                "verdict": "MALICIOUS" if risk_score >= 60 else ("SUSPICIOUS" if risk_score >= 30 else "BENIGN"),
                "red_flags": red_flags,
                "mitre_attack": mitre,
            },
        }
        return self.results

    def _parse_headers(self) -> Dict[str, Any]:
        """Extracts and normalizes critical email headers."""
        msg = self.raw_message

        from_raw = msg.get("From", "")
        reply_to = msg.get("Reply-To", "")
        return_path = msg.get("Return-Path", "")
        to_header = msg.get("To", "")
        subject = msg.get("Subject", "")
        date = msg.get("Date", "")
        message_id = msg.get("Message-ID", "")
        x_mailer = msg.get("X-Mailer", msg.get("User-Agent", "N/A"))
        x_originating = msg.get("X-Originating-IP", "N/A")

        # Extract email address and domain from headers
        def parse_addr_and_domain(addr_str: str):
            match = re.search(r"[\w\.-]+@([\w\.-]+)", addr_str)
            domain = match.group(1).lower() if match else ""
            return {"raw": addr_str, "domain": domain}

        from_info = parse_addr_and_domain(from_raw)
        reply_info = parse_addr_and_domain(reply_to)
        return_info = parse_addr_and_domain(return_path)

        # Check for From vs Reply-To mismatch
        mismatch_reply_to = False
        if from_info["domain"] and reply_info["domain"]:
            mismatch_reply_to = (from_info["domain"] != reply_info["domain"])

        mismatch_return_path = False
        if from_info["domain"] and return_info["domain"]:
            mismatch_return_path = (from_info["domain"] != return_info["domain"])

        return {
            "from": from_raw,
            "from_domain": from_info["domain"],
            "reply_to": reply_to,
            "reply_to_domain": reply_info["domain"],
            "return_path": return_path,
            "return_path_domain": return_info["domain"],
            "to": to_header,
            "subject": subject,
            "date": date,
            "message_id": message_id,
            "x_mailer": x_mailer,
            "x_originating_ip": x_originating,
            "from_vs_reply_to_mismatch": mismatch_reply_to,
            "from_vs_return_path_mismatch": mismatch_return_path,
        }

    def _trace_received_chain(self) -> List[Dict[str, Any]]:
        """
        Parses all 'Received' headers.
        Inverts order so Hop 1 is the initial sender/relay (bottom of header)
        and final hop is the receiving boundary gateway (top of header).
        """
        received_headers = self.raw_message.get_all("Received", [])
        hops = []

        # Chronological order: reverse of header order
        chronological_received = list(reversed(received_headers))

        for idx, r_raw in enumerate(chronological_received, 1):
            single_line = " ".join(r_raw.split())
            ips = extract_ips(single_line)
            
            # Extract 'from' and 'by'
            from_match = re.search(r"from\s+([^\s;]+)", single_line, re.IGNORECASE)
            by_match = re.search(r"by\s+([^\s;]+)", single_line, re.IGNORECASE)
            date_match = re.search(r";\s*([^;]+)$", single_line)

            hops.append({
                "hop_number": idx,
                "from_host": from_match.group(1) if from_match else "unknown",
                "by_host": by_match.group(1) if by_match else "unknown",
                "ips": ips,
                "timestamp": date_match.group(1).strip() if date_match else "unknown",
                "raw_snippet": single_line[:120] + ("..." if len(single_line) > 120 else ""),
            })

        return hops

    def _identify_origin_ip(self, hops: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Identifies the most probable external originating client IP."""
        for hop in hops:
            for ip in hop.get("ips", []):
                if not is_private_ip(ip):
                    return {
                        "ip": ip,
                        "defanged": defang_ip(ip),
                        "hop_source": hop["hop_number"],
                        "host": hop["from_host"],
                    }
        return {"ip": "unknown", "defanged": "unknown", "hop_source": None, "host": "unknown"}

    def _check_authentication(self) -> Dict[str, Any]:
        """Extracts and evaluates SPF, DKIM, and DMARC results."""
        auth_results = self.raw_message.get("Authentication-Results", "")
        received_spf = self.raw_message.get("Received-SPF", "")
        dkim_sig = self.raw_message.get("DKIM-Signature", "")

        def extract_result(protocol: str, text: str) -> str:
            match = re.search(rf"{protocol}=(pass|fail|softfail|neutral|none|temperror|permerror)", text, re.IGNORECASE)
            return match.group(1).lower() if match else "none"

        spf_status = extract_result("spf", auth_results)
        if spf_status == "none" and received_spf:
            spf_status = extract_result("spf", received_spf) or received_spf.split()[0].lower()

        dkim_status = extract_result("dkim", auth_results)
        if dkim_status == "none" and dkim_sig:
            dkim_status = "present_unverified"

        dmarc_status = extract_result("dmarc", auth_results)

        # Policy detection
        dmarc_policy_match = re.search(r"p=(none|quarantine|reject)", auth_results, re.IGNORECASE)
        dmarc_policy = dmarc_policy_match.group(1).lower() if dmarc_policy_match else "unspecified"

        # Summary reasoning
        reasons = []
        if spf_status in ["fail", "softfail"]:
            reasons.append(f"SPF {spf_status}: Sender IP is not authorized by the claiming domain's DNS SPF record.")
        elif spf_status == "pass":
            reasons.append("SPF pass: Sending IP is designated as an authorized relay by the domain SPF record.")

        if dkim_status in ["fail", "none"]:
            reasons.append(f"DKIM {dkim_status}: Cryptographic signature missing or failed integrity check.")
        elif dkim_status == "pass":
            reasons.append("DKIM pass: Cryptographic signature validated against domain public key.")

        if dmarc_status == "fail":
            reasons.append(f"DMARC fail: Domain alignment failed under policy '{dmarc_policy}'.")
        elif dmarc_status == "pass":
            reasons.append("DMARC pass: Domain alignment satisfied for From header.")

        return {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
            "dmarc_policy": dmarc_policy,
            "raw_authentication_results": auth_results,
            "evaluation": reasons,
        }

    def _parse_body_and_urls(self) -> Dict[str, Any]:
        """Extracts text, HTML, URLs, detected mismatches, and urgency triggers."""
        plain_body = ""
        html_body = ""

        if self.raw_message.is_multipart():
            for part in self.raw_message.walk():
                content_type = part.get_content_type()
                disposition = str(part.get("Content-Disposition", ""))
                if "attachment" in disposition.lower():
                    continue
                try:
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    charset = part.get_content_charset() or "utf-8"
                    decoded_text = payload.decode(charset, errors="replace")
                    if content_type == "text/plain":
                        plain_body += decoded_text + "\n"
                    elif content_type == "text/html":
                        html_body += decoded_text + "\n"
                except Exception:
                    continue
        else:
            payload = self.raw_message.get_payload(decode=True)
            if payload:
                charset = self.raw_message.get_content_charset() or "utf-8"
                plain_body = payload.decode(charset, errors="replace")

        # Collect URLs
        raw_urls = extract_urls_from_text(plain_body)
        html_links = extract_links_from_html(html_body)

        for l in html_links:
            raw_urls.append(l["href"])

        # Deduplicate & defang
        unique_urls = list(set(raw_urls))
        analyzed_links = []
        for u in unique_urls:
            # Check suspicious TLD
            has_suspicious_tld = any(u.lower().split("?")[0].endswith(tld) or (tld + "/") in u.lower() for tld in self.SUSPICIOUS_TLDS)
            analyzed_links.append({
                "url": u,
                "defanged": defang_url(u),
                "suspicious_tld": has_suspicious_tld,
            })

        # Check anchor mismatches
        mismatches = []
        for item in html_links:
            is_mismatch, detail = detect_mismatch(item["href"], item["text"])
            if is_mismatch:
                mismatches.append({
                    "anchor_text": item["text"],
                    "actual_href": item["href"],
                    "defanged_href": defang_url(item["href"]),
                    "detail": detail,
                })

        # Check urgency / social engineering keywords
        combined_text = (plain_body + " " + html_body + " " + self.raw_message.get("Subject", "")).lower()
        found_urgency = [kw for kw in self.URGENCY_KEYWORDS if kw in combined_text]

        return {
            "links": analyzed_links,
            "mismatches": mismatches,
            "urgency_triggers": found_urgency,
            "plain_preview": plain_body.strip()[:300],
        }

    def _analyze_attachments(self) -> List[Dict[str, Any]]:
        """Extracts and computes cryptographic hashes of email attachments."""
        attachments = []
        risky_extensions = {".xlsm", ".docm", ".exe", ".iso", ".vbs", ".js", ".bat", ".scr", ".hta", ".zip", ".rar", ".7z"}

        for part in self.raw_message.walk():
            filename = part.get_filename()
            disposition = str(part.get("Content-Disposition", ""))
            
            if filename or "attachment" in disposition.lower():
                safe_name = filename or "unnamed_attachment"
                payload = part.get_payload(decode=True) or b""
                hashes = compute_hashes(payload)
                
                _, ext = os.path.splitext(safe_name.lower())
                is_risky = ext in risky_extensions

                attachments.append({
                    "filename": safe_name,
                    "content_type": part.get_content_type(),
                    "size_bytes": len(payload),
                    "is_risky_extension": is_risky,
                    "extension": ext,
                    "md5": hashes["md5"],
                    "sha1": hashes["sha1"],
                    "sha256": hashes["sha256"],
                })

        return attachments

    def _calculate_risk(
        self,
        headers: Dict[str, Any],
        auth: Dict[str, Any],
        body: Dict[str, Any],
        attachments: List[Dict[str, Any]],
    ) -> (int, str, List[str], List[Dict[str, str]]):
        """Calculates security threat score (0-100) and maps to MITRE ATT&CK."""
        score = 0
        red_flags = []
        mitre = []

        # 1. Email Authentication Red Flags
        if auth["spf"] in ["fail", "softfail"]:
            score += 25
            red_flags.append(f"SPF validation failed ({auth['spf']}) - sending server not authorized.")
        if auth["dmarc"] == "fail":
            score += 25
            red_flags.append("DMARC check failed - From domain alignment rejected.")
        if auth["dkim"] in ["fail", "none"] and "microsoft" in headers["from_domain"]:
            score += 20
            red_flags.append("Corporate identity claiming Microsoft or major brand without valid DKIM signature.")

        # 2. Header Mismatches
        if headers["from_vs_reply_to_mismatch"]:
            score += 25
            red_flags.append(f"From domain ({headers['from_domain']}) differs from Reply-To domain ({headers['reply_to_domain']}).")
        if headers["from_vs_return_path_mismatch"]:
            score += 15
            red_flags.append(f"From domain differs from Return-Path bounce domain ({headers['return_path_domain']}).")

        # 3. URL and Typosquatting Red Flags
        if body["mismatches"]:
            score += 30
            red_flags.append("Hyperlink text spoofing detected (display text points to legitimate brand, href points elsewhere).")
            mitre.append({"id": "T1566.002", "technique": "Phishing: Spearphishing Link"})

        suspicious_urls = [u for u in body["links"] if u.get("suspicious_tld")]
        if suspicious_urls:
            score += 20
            red_flags.append(f"Detected suspicious high-risk TLDs in URLs ({len(suspicious_urls)} found).")

        if body["links"] and not mitre:
            mitre.append({"id": "T1566.002", "technique": "Phishing: Spearphishing Link"})

        # 4. Attachment Analysis
        if attachments:
            for att in attachments:
                if att["is_risky_extension"]:
                    score += 35
                    red_flags.append(f"High-risk macro or executable attachment detected: {att['filename']} ({att['extension']}).")
                    mitre.append({"id": "T1566.001", "technique": "Phishing: Spearphishing Attachment"})
                    mitre.append({"id": "T1204.002", "technique": "User Execution: Malicious File"})

        # 5. Social Engineering / Urgency Keywords
        if len(body["urgency_triggers"]) >= 3:
            score += 15
            red_flags.append(f"High-pressure psychological triggers detected: {', '.join(body['urgency_triggers'][:5])}")
        elif len(body["urgency_triggers"]) >= 1:
            score += 5

        # 6. BEC / Impersonation Check (Free webmail mimicking CEO)
        from_raw_lower = headers["from"].lower()
        if ("ceo" in from_raw_lower or "executive" in from_raw_lower) and "gmail.com" in headers["from_domain"]:
            score += 40
            red_flags.append("Executive impersonation (CEO title with free @gmail.com address requesting wire/confidential action).")
            mitre.append({"id": "T1566", "technique": "Phishing: Business Email Compromise (BEC)"})
            mitre.append({"id": "T1586.002", "technique": "Compromised Accounts / External Webmail Persona"})

        # Cap score at 100
        score = min(score, 100)

        # Severity
        if score >= 75:
            severity = "CRITICAL"
        elif score >= 50:
            severity = "HIGH"
        elif score >= 25:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Ensure unique MITRE techniques
        unique_mitre = []
        seen = set()
        for m in mitre:
            if m["id"] not in seen:
                seen.add(m["id"])
                unique_mitre.append(m)

        return score, severity, red_flags, unique_mitre


def format_report_terminal(data: Dict[str, Any]) -> str:
    """Formats analysis results as a clean, readable terminal report."""
    meta = data["metadata"]
    h = data["headers"]
    auth = data["authentication"]
    triage = data["triage"]
    urls = data["urls_and_links"]
    mismatches = data["url_mismatches"]
    attachments = data["attachments"]

    border = "=" * 78
    divider = "-" * 78

    lines = [
        border,
        f"  PHISHING EMAIL ANALYSIS REPORT: {meta['filename']}",
        f"  Analyzed by: {meta['analyzed_by']}",
        border,
        f" [TRIAGE VERDICT] : {triage['verdict']} (Score: {triage['score']}/100 - Severity: {triage['severity']})",
        divider,
        " [1] EMAIL HEADER FORENSICS",
        f"  * From:        {h['from']}",
        f"  * Reply-To:    {h['reply_to'] or '[None Specified]'}",
        f"  * Return-Path: {h['return_path'] or '[None Specified]'}",
        f"  * To:          {h['to']}",
        f"  * Subject:     {h['subject']}",
        f"  * Date:        {h['date']}",
        f"  * Message-ID:  {h['message_id']}",
        f"  * Origin IP:   {data['origin_ip']['defanged']} (Hop #{data['origin_ip']['hop_source']})",
        divider,
        " [2] EMAIL AUTHENTICATION RESULTS",
        f"  * SPF:         {auth['spf'].upper()}",
        f"  * DKIM:        {auth['dkim'].upper()}",
        f"  * DMARC:       {auth['dmarc'].upper()} (Policy: {auth['dmarc_policy']})",
    ]

    for ev in auth["evaluation"]:
        lines.append(f"    - {ev}")

    lines.append(divider)
    lines.append(" [3] RECEIVED HOP CHAIN (Bottom-to-Top Chronological Trace)")
    for hop in data["received_chain"]:
        lines.append(f"  Hop {hop['hop_number']}: {hop['from_host']} -> {hop['by_host']} | IPs: {', '.join(hop['ips'])}")

    lines.append(divider)
    lines.append(f" [4] URL & HYPERLINK ANALYSIS ({len(urls)} found)")
    if urls:
        for u in urls:
            flag = " [!] SUSPICIOUS TLD" if u["suspicious_tld"] else ""
            lines.append(f"  * {u['defanged']}{flag}")
    else:
        lines.append("  * None detected in message body.")

    if mismatches:
        lines.append("\n  [!] HYPERLINK SPOOFING MISMATCHES DETECTED:")
        for m in mismatches:
            lines.append(f"    - Display Text: {m['anchor_text']}")
            lines.append(f"      Actual Target: {m['defanged_href']}")

    lines.append(divider)
    lines.append(f" [5] ATTACHMENTS & PAYLOADS ({len(attachments)} found)")
    if attachments:
        for att in attachments:
            risk_label = " [CRITICAL: MALICIOUS EXTENSION]" if att["is_risky_extension"] else ""
            lines.append(f"  * File:      {att['filename']}{risk_label}")
            lines.append(f"    MIME Type: {att['content_type']}")
            lines.append(f"    Size:      {att['size_bytes']} bytes")
            lines.append(f"    MD5:       {att['md5']}")
            lines.append(f"    SHA-256:   {att['sha256']}")
    else:
        lines.append("  * No file attachments detected.")

    lines.append(divider)
    lines.append(f" [6] IDENTIFIED RED FLAGS ({len(triage['red_flags'])} detected)")
    for rf in triage["red_flags"]:
        lines.append(f"  [!] {rf}")

    lines.append(divider)
    lines.append(" [7] MITRE ATT&CK MAPPINGS")
    for m in triage["mitre_attack"]:
        lines.append(f"  * {m['id']} - {m['technique']}")

    lines.append(border)
    return "\n".join(lines)


def format_markdown_report(data: Dict[str, Any]) -> str:
    """Formats report in GitHub Flavored Markdown."""
    meta = data["metadata"]
    h = data["headers"]
    auth = data["authentication"]
    triage = data["triage"]
    urls = data["urls_and_links"]
    mismatches = data["url_mismatches"]
    attachments = data["attachments"]

    md = []
    md.append(f"# Threat Analysis Report: `{meta['filename']}`\n")
    md.append(f"> **Verdict:** `{triage['verdict']}` | **Risk Score:** `{triage['score']}/100` | **Severity:** `{triage['severity']}`  ")
    md.append(f"> **Analyzed by:** {meta['analyzed_by']}\n")

    md.append("## 1. Executive Summary")
    md.append(f"Automated email security inspection identified `{len(triage['red_flags'])}` critical indicators of malicious activity.")
    md.append(f"The message impersonates `{h['from']}` with originating IP `{data['origin_ip']['defanged']}`.\n")

    md.append("## 2. Header Forensics")
    md.append("| Header | Value | Defanged / Analysis |")
    md.append("|---|---|---|")
    md.append(f"| **From** | `{h['from']}` | Domain: `{defang_domain(h['from_domain'])}` |")
    md.append(f"| **Reply-To** | `{h['reply_to'] or 'None'}` | Domain: `{defang_domain(h['reply_to_domain'])}` |")
    md.append(f"| **Return-Path** | `{h['return_path'] or 'None'}` | Domain: `{defang_domain(h['return_path_domain'])}` |")
    md.append(f"| **Subject** | {h['subject']} | Priority / Urgency check |")
    md.append(f"| **Message-ID** | `{h['message_id']}` | Generated by mail agent |")
    md.append(f"| **Originating IP** | `{data['origin_ip']['ip']}` | `{data['origin_ip']['defanged']}` (Hop #{data['origin_ip']['hop_source']}) |\n")

    md.append("## 3. Email Authentication Validation")
    md.append("| Check | Status | SOC Interpretation |")
    md.append("|---|---|---|")
    md.append(f"| **SPF** | `{auth['spf'].upper()}` | Sender IP authorization status |")
    md.append(f"| **DKIM** | `{auth['dkim'].upper()}` | Cryptographic signature integrity |")
    md.append(f"| **DMARC** | `{auth['dmarc'].upper()}` | Policy: `{auth['dmarc_policy']}` |")
    md.append("")
    for ev in auth["evaluation"]:
        md.append(f"- {ev}")
    md.append("")

    md.append("## 4. Received Hop Trace")
    md.append("| Hop # | Sending Server (`from`) | Receiving Server (`by`) | Extracted IP(s) |")
    md.append("|---|---|---|---|")
    for hop in data["received_chain"]:
        md.append(f"| {hop['hop_number']} | `{hop['from_host']}` | `{hop['by_host']}` | `{', '.join(hop['ips'])}` |")
    md.append("")

    md.append("## 5. Extracted URLs and Links")
    if urls:
        md.append("| Defanged URL | High-Risk TLD |")
        md.append("|---|---|")
        for u in urls:
            md.append(f"| `{u['defanged']}` | `{'Yes' if u['suspicious_tld'] else 'No'}` |")
    else:
        md.append("No URLs extracted from message body.")
    md.append("")

    if mismatches:
        md.append("### Link Spoofing Detected")
        for m in mismatches:
            md.append(f"- **Visual Anchor:** `{m['anchor_text']}` -> **Actual Target:** `{m['defanged_href']}`")
        md.append("")

    md.append("## 6. Attachments & File Hashes")
    if attachments:
        md.append("| Filename | MIME Type | Size | SHA-256 Hash | Risky Extension |")
        md.append("|---|---|---|---|---|")
        for att in attachments:
            md.append(f"| `{att['filename']}` | `{att['content_type']}` | {att['size_bytes']} bytes | `{att['sha256']}` | `{'YES' if att['is_risky_extension'] else 'No'}` |")
    else:
        md.append("No file attachments included.")
    md.append("")

    md.append("## 7. Identified Red Flags & MITRE ATT&CK")
    for rf in triage["red_flags"]:
        md.append(f"- :warning: **{rf}**")
    md.append("")
    md.append("### MITRE ATT&CK Mapping")
    for m in triage["mitre_attack"]:
        md.append(f"- **{m['id']}**: {m['technique']}")
    md.append("")

    return "\n".join(md)


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Email Forensic Analysis Tool by Shashwat Prakhar",
        epilog="Example: python src/email_analyzer.py --file samples/sample_01_m365_credential_harvest.eml"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Path to single .eml file to analyze")
    group.add_argument("-d", "--dir", help="Directory containing .eml files to analyze in batch")

    parser.add_argument("--format", choices=["table", "json", "markdown"], default="table", help="Output format (default: table)")
    parser.add_argument("-o", "--output", help="Optional output file path to save results")

    args = parser.parse_args()

    files_to_analyze = []
    if args.file:
        if not os.path.isfile(args.file):
            print(f"[-] Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        files_to_analyze.append(args.file)
    elif args.dir:
        if not os.path.isdir(args.dir):
            print(f"[-] Error: Directory not found: {args.dir}", file=sys.stderr)
            sys.exit(1)
        for fname in sorted(os.listdir(args.dir)):
            if fname.lower().endswith(".eml"):
                files_to_analyze.append(os.path.join(args.dir, fname))

    all_results = []
    for fpath in files_to_analyze:
        analyzer = EmailAnalyzer(fpath)
        data = analyzer.analyze()
        all_results.append(data)

        if args.format == "table":
            print(format_report_terminal(data))
            print("\n")
        elif args.format == "markdown":
            print(format_markdown_report(data))
            print("\n")

    if args.format == "json":
        json_output = json.dumps(all_results if len(all_results) > 1 else all_results[0], indent=2)
        print(json_output)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as out:
                out.write(json_output)
    elif args.output and args.format == "markdown":
        combined_md = "\n\n---\n\n".join([format_markdown_report(d) for d in all_results])
        with open(args.output, "w", encoding="utf-8") as out:
            out.write(combined_md)
        print(f"[+] Markdown report saved to {args.output}")


if __name__ == "__main__":
    main()
