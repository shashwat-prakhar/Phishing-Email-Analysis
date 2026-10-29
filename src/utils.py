"""
Email Analysis Utilities
Helper functions for defanging, parsing, hashing, and regex extraction.
Part of the Phishing Email Analysis toolkit by Shashwat Prakhar.
"""

import re
import hashlib
import ipaddress
from typing import Tuple, List, Dict, Optional
from html.parser import HTMLParser


def defang_url(url: str) -> str:
    """
    Defangs a URL so it cannot be inadvertently clicked or auto-linked.
    Example: https://evil.com/path -> hxxps://evil[.]com/path
    """
    if not url:
        return ""
    # Replace http/https with hxxp/hxxps
    url = re.sub(r"^https://", "hxxps://", url, flags=re.IGNORECASE)
    url = re.sub(r"^http://", "hxxp://", url, flags=re.IGNORECASE)
    
    # Extract scheme + rest
    match = re.match(r"^(hxxps?://)([^/]+)(.*)$", url, flags=re.IGNORECASE)
    if match:
        scheme, domain_port, path = match.groups()
        # Defang dots in domain
        domain_defanged = domain_port.replace(".", "[.]")
        return f"{scheme}{domain_defanged}{path}"
    
    # If no scheme, defang dots
    return url.replace(".", "[.]")


def defang_ip(ip: str) -> str:
    """Defangs an IP address: 1.2.3.4 -> 1.2.3[.]4 or 1[.]2[.]3[.]4"""
    if not ip:
        return ""
    # Standard format: 1.2.3[.]4
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}[.]{parts[3]}"
    return ip.replace(".", "[.]")


def defang_domain(domain: str) -> str:
    """Defangs a domain name: example.com -> example[.]com"""
    if not domain:
        return ""
    # Replace the last dot with [.]
    parts = domain.rsplit(".", 1)
    if len(parts) == 2:
        return f"{parts[0]}[.]{parts[1]}"
    return domain.replace(".", "[.]")


def is_private_ip(ip_str: str) -> bool:
    """Check if an IPv4 address is RFC 1918 private / loopback / link-local."""
    try:
        ip = ipaddress.ip_address(ip_str.strip("[]"))
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


def extract_ips(text: str) -> List[str]:
    """Extract all valid IPv4 addresses from text."""
    pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    matches = re.findall(pattern, text)
    valid_ips = []
    for match in matches:
        try:
            ipaddress.ip_address(match)
            valid_ips.append(match)
        except ValueError:
            continue
    return valid_ips


def compute_hashes(data: bytes) -> Dict[str, str]:
    """Compute MD5, SHA1, and SHA256 hashes for binary data."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


class HTMLAnchorExtractor(HTMLParser):
    """HTML parser to extract hyperlinks with both href and anchor text."""

    def __init__(self):
        super().__init__()
        self.links: List[Dict[str, str]] = []
        self._current_href: Optional[str] = None
        self._current_text: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for attr_name, attr_val in attrs:
                if attr_name.lower() == "href" and attr_val:
                    self._current_href = attr_val.strip()
                    self._current_text = []

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._current_href:
            anchor_text = "".join(self._current_text).strip()
            self.links.append({
                "href": self._current_href,
                "text": anchor_text,
            })
            self._current_href = None
            self._current_text = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text.append(data)


def extract_links_from_html(html_content: str) -> List[Dict[str, str]]:
    """Parse HTML content to extract all links with their displayed text."""
    parser = HTMLAnchorExtractor()
    try:
        parser.feed(html_content)
    except Exception:
        pass
    return parser.links


def extract_urls_from_text(text: str) -> List[str]:
    """Extract plain text URLs."""
    pattern = r"https?://[^\s<>\"'()]+"
    return re.findall(pattern, text)


def detect_mismatch(href: str, display_text: str) -> Tuple[bool, str]:
    """
    Detects if the display text pretends to be a legitimate domain
    while the actual href directs to a completely different domain.
    """
    domain_pattern = r"(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
    match_display = re.search(domain_pattern, display_text)
    match_href = re.search(domain_pattern, href)

    if match_display and match_href:
        disp_domain = match_display.group(1).lower().replace("www.", "")
        href_domain = match_href.group(1).lower().replace("www.", "")
        if disp_domain != href_domain:
            return True, f"Display text points to '{disp_domain}', but href leads to '{href_domain}'"
    return False, ""
