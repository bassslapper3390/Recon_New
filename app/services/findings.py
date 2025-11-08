import re
import html
from typing import List, Dict, Set, Any, Optional
from collections import defaultdict
from app.models import ToolResult, PassiveResults


class Finding:
    """Represents a single finding"""
    def __init__(self, category: str, finding_type: str, value: str, source: str, severity: str = "info"):
        self.category = category
        self.finding_type = finding_type
        self.value = value
        self.source = source
        self.severity = severity  # info, low, medium, high, critical
    
    def __eq__(self, other):
        if not isinstance(other, Finding):
            return False
        # Consider findings equal if they have same category, type, and value
        return (self.category == other.category and 
                self.finding_type == other.finding_type and 
                self.value.lower() == other.value.lower())
    
    def __hash__(self):
        return hash((self.category, self.finding_type, self.value.lower()))
    
    def to_dict(self):
        return {
            "category": self.category,
            "type": self.finding_type,
            "value": self.value,
            "source": self.source,
            "severity": self.severity
        }


def sanitize_html(text: str) -> str:
    """Remove HTML tags and decode HTML entities"""
    if not text:
        return ""
    # Decode HTML entities first
    text = html.unescape(text)
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    # Clean up extra whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def extract_subdomains(text: str, domain: Optional[str] = None) -> Set[str]:
    """Extract subdomains from text"""
    subdomains = set()
    if not text:
        return subdomains
    
    # Pattern for subdomains
    if domain:
        # Clean domain (remove http://, https://, etc.)
        clean_domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        # Extract subdomains that end with the domain
        pattern = rf'\b([a-zA-Z0-9][a-zA-Z0-9-]*\.)+{re.escape(clean_domain)}\b'
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                subdomain = match[0] if match else ''
            else:
                subdomain = match
            if subdomain:
                subdomain = subdomain.strip('.,/').lower()
                if subdomain and subdomain != clean_domain.lower() and '.' in subdomain:
                    subdomains.add(subdomain)
    else:
        # Generic domain pattern
        pattern = r'\b([a-zA-Z0-9][a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}\b'
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                subdomain = match[0] if match else ''
            else:
                subdomain = match
            if subdomain:
                subdomain = subdomain.strip('.,/').lower()
                if subdomain and '.' in subdomain:
                    subdomains.add(subdomain)
    
    return subdomains


def extract_ports(text: str) -> Set[str]:
    """Extract port numbers from text"""
    ports = set()
    # Pattern for ports: "port 80", "80/tcp", ":8080", "port: 443"
    patterns = [
        r'port\s+(\d+)',
        r'(\d+)/tcp',
        r':(\d+)',
        r'port:\s*(\d+)',
        r'(\d+)\s*\([^)]+\)',  # "80 (http)"
    ]
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        ports.update(matches)
    return ports


def extract_emails(text: str) -> Set[str]:
    """Extract email addresses from text"""
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    matches = re.findall(pattern, text)
    return set(m.lower() for m in matches)


def extract_urls(text: str) -> Set[str]:
    """Extract URLs from text"""
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    matches = re.findall(pattern, text)
    return set(m for m in matches if len(m) < 500)  # Filter out very long URLs


def extract_directories(text: str) -> Set[str]:
    """Extract directory paths from text"""
    directories = set()
    # Pattern for directories: "/admin", "/api/v1", etc.
    pattern = r'/\S+'
    matches = re.findall(pattern, text)
    for match in matches:
        # Clean up the match
        dir_path = match.split()[0] if ' ' in match else match
        dir_path = dir_path.split('?')[0]  # Remove query strings
        dir_path = dir_path.split('#')[0]  # Remove fragments
        if dir_path and len(dir_path) > 1 and dir_path.startswith('/'):
            directories.add(dir_path)
    return directories


def extract_vulnerabilities(text: str) -> List[str]:
    """Extract vulnerability mentions from text"""
    vulns = []
    text_lower = text.lower()
    
    # Common vulnerability keywords
    vuln_keywords = [
        'sql injection', 'xss', 'cross-site scripting', 'csrf', 'directory listing',
        'information disclosure', 'weak ssl', 'expired certificate', 'misconfiguration',
        'default credentials', 'exposed file', 'backup file', 'sensitive data',
        'open redirect', 'path traversal', 'command injection', 'xxe', 'ssrf'
    ]
    
    for keyword in vuln_keywords:
        if keyword in text_lower:
            # Try to extract the full sentence or context
            pattern = rf'.{{0,100}}{re.escape(keyword)}.{{0,100}}'
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            for match in matches:
                cleaned = sanitize_html(match).strip()
                if cleaned and len(cleaned) < 200:
                    vulns.append(cleaned)
    
    return list(set(vulns))


def extract_ips(text: str) -> Set[str]:
    """Extract IP addresses from text"""
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    matches = re.findall(pattern, text)
    # Validate IPs
    valid_ips = set()
    for ip in matches:
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            valid_ips.add(ip)
    return valid_ips


def extract_technologies(text: str) -> Set[str]:
    """Extract technology stack information"""
    technologies = set()
    text_lower = text.lower()
    
    # Common technologies
    tech_patterns = {
        'apache': r'apache[/\s]?[\d.]+',
        'nginx': r'nginx[/\s]?[\d.]+',
        'iis': r'iis[/\s]?[\d.]+',
        'php': r'php[/\s]?[\d.]+',
        'python': r'python[/\s]?[\d.]+',
        'node': r'node\.?js[/\s]?[\d.]+',
        'wordpress': r'wordpress[/\s]?[\d.]+',
        'drupal': r'drupal[/\s]?[\d.]+',
        'joomla': r'joomla[/\s]?[\d.]+',
    }
    
    for tech, pattern in tech_patterns.items():
        if re.search(pattern, text_lower, re.IGNORECASE):
            technologies.add(tech)
    
    return technologies


def extract_findings_from_tool(tool_result: ToolResult, domain: Optional[str] = None) -> List[Finding]:
    """Extract structured findings from a tool result"""
    findings = []
    if not tool_result or not tool_result.output or not tool_result.success:
        return findings
    
    text = sanitize_html(tool_result.output)
    tool_name = tool_result.name
    
    # Extract subdomains
    if domain:
        subdomains = extract_subdomains(text, domain)
        for subdomain in subdomains:
            if subdomain != domain:
                findings.append(Finding(
                    category="Subdomains",
                    finding_type="Subdomain",
                    value=subdomain,
                    source=tool_name,
                    severity="info"
                ))
    
    # Extract ports
    ports = extract_ports(text)
    for port in ports:
        findings.append(Finding(
            category="Network",
            finding_type="Open Port",
            value=f"Port {port}",
            source=tool_name,
            severity="info"
        ))
    
    # Extract emails
    emails = extract_emails(text)
    for email in emails:
        findings.append(Finding(
            category="Information",
            finding_type="Email Address",
            value=email,
            source=tool_name,
            severity="info"
        ))
    
    # Extract URLs
    urls = extract_urls(text)
    for url in urls:
        findings.append(Finding(
            category="Endpoints",
            finding_type="URL",
            value=url,
            source=tool_name,
            severity="info"
        ))
    
    # Extract directories
    directories = extract_directories(text)
    for directory in directories:
        findings.append(Finding(
            category="Endpoints",
            finding_type="Directory",
            value=directory,
            source=tool_name,
            severity="info"
        ))
    
    # Extract vulnerabilities
    vulns = extract_vulnerabilities(text)
    for vuln in vulns:
        severity = "medium"
        if any(kw in vuln.lower() for kw in ['sql injection', 'command injection', 'xxe', 'ssrf']):
            severity = "high"
        elif any(kw in vuln.lower() for kw in ['default credentials', 'exposed', 'sensitive']):
            severity = "high"
        findings.append(Finding(
            category="Vulnerabilities",
            finding_type="Vulnerability",
            value=vuln,
            source=tool_name,
            severity=severity
        ))
    
    # Extract IPs
    ips = extract_ips(text)
    for ip in ips:
        findings.append(Finding(
            category="Network",
            finding_type="IP Address",
            value=ip,
            source=tool_name,
            severity="info"
        ))
    
    # Extract technologies
    technologies = extract_technologies(text)
    for tech in technologies:
        findings.append(Finding(
            category="Technology",
            finding_type="Technology Stack",
            value=tech,
            source=tool_name,
            severity="info"
        ))
    
    return findings


def extract_findings_from_passive(passive: PassiveResults, domain: Optional[str] = None) -> List[Finding]:
    """Extract findings from passive reconnaissance results"""
    findings = []
    
    # DNS findings
    if passive.dns:
        dns_dict = passive.dns if isinstance(passive.dns, dict) else {}
        
        # A records
        if 'A' in dns_dict and dns_dict['A']:
            for ip in dns_dict['A']:
                findings.append(Finding(
                    category="Network",
                    finding_type="DNS A Record",
                    value=ip,
                    source="DNS",
                    severity="info"
                ))
        
        # MX records
        if 'MX' in dns_dict and dns_dict['MX']:
            for mx in dns_dict['MX']:
                findings.append(Finding(
                    category="Network",
                    finding_type="DNS MX Record",
                    value=str(mx),
                    source="DNS",
                    severity="info"
                ))
        
        # TXT records
        if 'TXT' in dns_dict and dns_dict['TXT']:
            for txt in dns_dict['TXT']:
                findings.append(Finding(
                    category="Information",
                    finding_type="DNS TXT Record",
                    value=str(txt),
                    source="DNS",
                    severity="info"
                ))
    
    # WHOIS findings
    if passive.whois:
        whois_str = str(passive.whois)
        emails = extract_emails(whois_str)
        for email in emails:
            findings.append(Finding(
                category="Information",
                finding_type="Email Address",
                value=email,
                source="WHOIS",
                severity="info"
            ))
    
    # CT Logs findings
    if passive.ct_logs:
        for log_entry in passive.ct_logs:
            if isinstance(log_entry, dict):
                name_value = log_entry.get('name_value', '')
                if name_value:
                    findings.append(Finding(
                        category="Subdomains",
                        finding_type="Subdomain",
                        value=name_value,
                        source="CT Logs",
                        severity="info"
                    ))
    
    return findings


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings, keeping the one with the most sources"""
    seen = {}
    for finding in findings:
        key = (finding.category, finding.finding_type, finding.value.lower())
        if key not in seen:
            seen[key] = finding
        else:
            # Merge sources if same finding
            existing = seen[key]
            if finding.source not in existing.source:
                existing.source = f"{existing.source}, {finding.source}"
    
    return list(seen.values())


def organize_findings(findings: List[Finding]) -> Dict[str, List[Dict[str, Any]]]:
    """Organize findings by category"""
    organized = defaultdict(list)
    
    # Sort findings by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    
    for finding in findings:
        organized[finding.category].append(finding.to_dict())
    
    # Sort each category by severity
    for category in organized:
        organized[category].sort(key=lambda x: severity_order.get(x.get("severity", "info"), 4))
    
    return dict(organized)


def extract_all_findings(tools: List[ToolResult], passive: PassiveResults, domain: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    """Extract and organize all findings from tools and passive recon"""
    all_findings = []
    
    # Extract from tools
    if tools:
        for tool in tools:
            if tool:
                all_findings.extend(extract_findings_from_tool(tool, domain))
    
    # Extract from passive
    if passive:
        all_findings.extend(extract_findings_from_passive(passive, domain))
    
    # Deduplicate
    unique_findings = deduplicate_findings(all_findings)
    
    # Organize by category
    organized = organize_findings(unique_findings)
    
    return organized

