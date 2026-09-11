import asyncio
import socket
import subprocess
from urllib.parse import urlparse
import dns.resolver
import dns.zone
import dns.query
import whois
import requests
from agents.base_agent import BaseAgent, Finding, Severity


class DNSReconAgent(BaseAgent):
    name = "DNS Recon"
    description = "DNS enumeration, subdomain discovery, zone transfer attempts"

    async def run(self) -> list[Finding]:
        parsed = urlparse(self.target if "://" in self.target else f"https://{self.target}")
        domain = parsed.netloc or parsed.path

        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, self._run_sync, domain)
        return results

    def _run_sync(self, domain: str) -> list[Finding]:
        raw_data = {}

        # Basic DNS records
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                raw_data[rtype] = [str(r) for r in answers]
            except Exception:
                raw_data[rtype] = []

        # Zone transfer attempt
        zone_transfer_vuln = False
        ns_servers = raw_data.get("NS", [])
        for ns in ns_servers:
            try:
                ns_ip = str(dns.resolver.resolve(ns.rstrip("."), "A")[0])
                dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
                zone_transfer_vuln = True
                break
            except Exception:
                pass

        # Common subdomains brute force
        common_subs = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
            "blog", "shop", "portal", "vpn", "remote", "support", "login",
            "app", "mobile", "beta", "old", "backup", "db", "database",
            "internal", "intranet", "cdn", "static", "media", "assets",
        ]
        found_subs = []
        for sub in common_subs:
            try:
                fqdn = f"{sub}.{domain}"
                dns.resolver.resolve(fqdn, "A")
                found_subs.append(fqdn)
            except Exception:
                pass

        raw_data["subdomains"] = found_subs
        raw_data["zone_transfer"] = zone_transfer_vuln

        # Ask Claude to analyze findings
        analysis = self._ask_claude(
            system=(
                "You are an expert penetration tester analyzing DNS reconnaissance results. "
                "Identify security issues, misconfigurations, and attack surface. "
                "Be specific and technical."
            ),
            user=(
                f"Analyze DNS data for {domain}:\n\n"
                f"DNS Records: {raw_data}\n\n"
                "Identify all security findings. For each finding state: "
                "title, severity (Critical/High/Medium/Low/Info), what you found, "
                "why it matters, and how to fix it."
            ),
        )

        if zone_transfer_vuln:
            self._add_finding(
                title="DNS Zone Transfer Enabled",
                severity=Severity.HIGH,
                description=f"DNS zone transfer is allowed from nameservers for {domain}. "
                            "This exposes the full DNS zone, revealing all hostnames and IPs.",
                evidence=f"Successful AXFR from nameservers: {ns_servers}",
                remediation="Restrict zone transfers to authorized secondary DNS servers only. "
                            "Configure ACLs on your DNS server to allow AXFR only from trusted IPs.",
                url=self.target,
            )

        if found_subs:
            self._add_finding(
                title=f"Discovered {len(found_subs)} Active Subdomains",
                severity=Severity.INFO,
                description=f"Found {len(found_subs)} active subdomains that expand the attack surface.",
                evidence=f"Subdomains: {', '.join(found_subs)}",
                remediation="Audit each subdomain for unnecessary exposure. Remove or protect unused subdomains.",
                url=self.target,
                extra={"subdomains": found_subs},
            )

        # Add Claude's additional analysis as a finding
        if analysis.strip():
            self._add_finding(
                title="DNS Configuration Analysis",
                severity=Severity.INFO,
                description="AI-powered analysis of DNS configuration and security posture.",
                evidence=analysis[:2000],
                remediation="Review findings above for specific remediation steps.",
                url=self.target,
                extra={"raw_records": raw_data},
            )

        return self.findings


class WHOISAgent(BaseAgent):
    name = "WHOIS / IP Info"
    description = "WHOIS lookup, IP reputation, and organizational info"

    async def run(self) -> list[Finding]:
        parsed = urlparse(self.target if "://" in self.target else f"https://{self.target}")
        domain = parsed.netloc or parsed.path

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync, domain)

    def _run_sync(self, domain: str) -> list[Finding]:
        raw = {}

        # WHOIS
        try:
            w = whois.whois(domain)
            raw["registrar"] = str(w.registrar)
            raw["creation_date"] = str(w.creation_date)
            raw["expiration_date"] = str(w.expiration_date)
            raw["name_servers"] = w.name_servers
            raw["emails"] = w.emails
            raw["org"] = str(w.org)
            raw["country"] = str(w.country)

            # Check expiry soon (within 30 days)
            from datetime import datetime, timezone
            exp = w.expiration_date
            if isinstance(exp, list):
                exp = exp[0]
            if exp:
                if hasattr(exp, "tzinfo") and exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (exp - now).days
                if days_left < 30:
                    self._add_finding(
                        title="Domain Expiring Soon",
                        severity=Severity.HIGH,
                        description=f"Domain expires in {days_left} days. Expired domains can be hijacked.",
                        evidence=f"Expiration date: {exp}",
                        remediation="Renew the domain immediately and enable auto-renewal.",
                        url=self.target,
                    )
        except Exception as e:
            raw["whois_error"] = str(e)

        # IP resolution
        try:
            ip = socket.gethostbyname(domain)
            raw["ip"] = ip
        except Exception:
            ip = None

        analysis = self._ask_claude(
            system="You are an expert penetration tester analyzing WHOIS and IP data for security issues.",
            user=(
                f"Analyze WHOIS/IP data for {domain}:\n{raw}\n\n"
                "Look for: privacy issues, exposed emails (phishing targets), "
                "IP reputation risks, organizational info leakage."
            ),
        )

        self._add_finding(
            title="WHOIS & IP Reconnaissance",
            severity=Severity.INFO,
            description=f"Target information gathered via WHOIS for {domain}.",
            evidence=f"IP: {ip}\nWHOIS data: {raw}\n\nAnalysis: {analysis[:1000]}",
            remediation="Use WHOIS privacy protection. Monitor for domain hijacking.",
            url=self.target,
            extra=raw,
        )

        return self.findings


class PortScannerAgent(BaseAgent):
    name = "Port Scanner"
    description = "Open ports, running services, and banner grabbing"

    async def run(self) -> list[Finding]:
        parsed = urlparse(self.target if "://" in self.target else f"https://{self.target}")
        host = parsed.netloc or parsed.path
        # Strip port if present
        host = host.split(":")[0]

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync, host)

    def _run_sync(self, host: str) -> list[Finding]:
        open_ports = []
        dangerous_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt", 27017: "MongoDB", 9200: "Elasticsearch",
        }

        # Try nmap first, fallback to socket scan
        try:
            import nmap
            nm = nmap.PortScanner()
            nm.scan(host, "21-100,443,3306,3389,5432,6379,8080,8443,27017,9200",
                    arguments="-sV --version-intensity 3 -T4")
            for host_key in nm.all_hosts():
                for proto in nm[host_key].all_protocols():
                    for port in nm[host_key][proto].keys():
                        info = nm[host_key][proto][port]
                        if info["state"] == "open":
                            open_ports.append({
                                "port": port,
                                "service": info.get("name", "unknown"),
                                "version": info.get("version", ""),
                                "product": info.get("product", ""),
                            })
        except Exception:
            # Fallback: manual socket scan
            for port in dangerous_ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.5)
                    if s.connect_ex((host, port)) == 0:
                        open_ports.append({
                            "port": port,
                            "service": dangerous_ports[port],
                            "version": "",
                            "product": "",
                        })
                    s.close()
                except Exception:
                    pass

        high_risk = [p for p in open_ports if p["port"] in [23, 3389, 6379, 27017, 9200]]

        if high_risk:
            self._add_finding(
                title="High-Risk Services Exposed to Internet",
                severity=Severity.CRITICAL,
                description="Highly sensitive services are accessible from the internet.",
                evidence=f"Exposed services: {high_risk}",
                remediation=(
                    "Immediately restrict these services with firewall rules. "
                    "They should never be exposed publicly. Use VPN or private networks."
                ),
                url=self.target,
                extra={"ports": high_risk},
            )

        if open_ports:
            analysis = self._ask_claude(
                system="You are a security expert analyzing open ports for risks.",
                user=(
                    f"Target: {host}\nOpen ports: {open_ports}\n\n"
                    "Identify which services pose the highest risk, "
                    "what attackers could exploit, and specific remediation."
                ),
            )
            self._add_finding(
                title=f"Open Ports Summary ({len(open_ports)} found)",
                severity=Severity.MEDIUM if not high_risk else Severity.HIGH,
                description=f"{len(open_ports)} open ports found on {host}.",
                evidence=f"Open ports: {open_ports}\n\nAnalysis: {analysis[:1500]}",
                remediation="Close unnecessary ports. Restrict access via firewall. Patch all services.",
                url=self.target,
                extra={"all_ports": open_ports},
            )

        return self.findings
