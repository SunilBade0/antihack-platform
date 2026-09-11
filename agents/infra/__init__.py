import asyncio
import ssl
import socket
import urllib.parse
import requests
from datetime import datetime, timezone

from agents.base_agent import BaseAgent, Finding, Severity


def _get(url: str, timeout: int = 10) -> requests.Response:
    headers = {"User-Agent": "Mozilla/5.0 (Security-Audit-Bot/1.0)"}
    try:
        return requests.get(url, headers=headers, timeout=timeout, verify=False)
    except Exception:
        return None


class SSLAgent(BaseAgent):
    name = "SSL/TLS Inspector"
    description = "SSL/TLS certificate validity, cipher strength, and protocol version"

    async def run(self) -> list[Finding]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync)

    def _run_sync(self) -> list[Finding]:
        parsed = urllib.parse.urlparse(
            self.target if "://" in self.target else f"https://{self.target}"
        )
        host = parsed.netloc or parsed.path
        host = host.split(":")[0]
        port = parsed.port or 443

        ssl_data = {}
        issues = []

        # Try to get certificate info
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    ssl_data["cipher"] = cipher
                    ssl_data["protocol"] = version
                    ssl_data["subject"] = dict(x[0] for x in cert.get("subject", []))
                    ssl_data["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    ssl_data["san"] = cert.get("subjectAltName", [])
                    ssl_data["not_before"] = cert.get("notBefore")
                    ssl_data["not_after"] = cert.get("notAfter")

                    # Check expiry
                    exp_str = cert.get("notAfter", "")
                    if exp_str:
                        exp = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days_left = (exp - datetime.now(timezone.utc)).days
                        ssl_data["days_until_expiry"] = days_left
                        if days_left < 0:
                            issues.append({"severity": "CRITICAL", "issue": f"Certificate EXPIRED {abs(days_left)} days ago"})
                        elif days_left < 14:
                            issues.append({"severity": "CRITICAL", "issue": f"Certificate expires in {days_left} days"})
                        elif days_left < 30:
                            issues.append({"severity": "HIGH", "issue": f"Certificate expires in {days_left} days"})

                    # Check weak protocol
                    if version in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                        issues.append({"severity": "HIGH", "issue": f"Deprecated TLS version in use: {version}"})

                    # Check weak cipher
                    cipher_name = cipher[0] if cipher else ""
                    if any(w in cipher_name.upper() for w in ["RC4", "DES", "3DES", "MD5", "EXPORT", "NULL"]):
                        issues.append({"severity": "HIGH", "issue": f"Weak cipher suite: {cipher_name}"})

        except ssl.SSLCertVerificationError as e:
            issues.append({"severity": "HIGH", "issue": f"SSL certificate verification failed: {e}"})
            ssl_data["error"] = str(e)
        except ssl.SSLError as e:
            issues.append({"severity": "HIGH", "issue": f"SSL error: {e}"})
            ssl_data["error"] = str(e)
        except Exception as e:
            ssl_data["error"] = str(e)

        # Check if HTTP redirects to HTTPS
        http_redirect = False
        try:
            http_url = f"http://{host}"
            r = requests.get(http_url, timeout=5, allow_redirects=False, verify=False)
            if r.status_code in [301, 302, 307, 308]:
                loc = r.headers.get("Location", "")
                if loc.startswith("https://"):
                    http_redirect = True
            else:
                issues.append({"severity": "HIGH", "issue": "HTTP traffic not redirected to HTTPS"})
        except Exception:
            pass

        ssl_data["http_redirects_to_https"] = http_redirect

        # Check HSTS header
        try:
            r = _get(self.target)
            if r:
                hsts = r.headers.get("Strict-Transport-Security")
                ssl_data["hsts"] = hsts
                if not hsts:
                    issues.append({"severity": "MEDIUM", "issue": "HSTS header not set"})
                else:
                    if "max-age" in hsts:
                        import re
                        m = re.search(r"max-age=(\d+)", hsts)
                        if m and int(m.group(1)) < 31536000:
                            issues.append({"severity": "LOW", "issue": "HSTS max-age below recommended 1 year"})
        except Exception:
            pass

        # Ask Claude to analyze
        analysis = self._ask_claude(
            system="You are an expert in TLS/SSL security. Analyze certificate and configuration data.",
            user=(
                f"Target: {self.target}\nSSL data: {ssl_data}\nIssues found: {issues}\n\n"
                "Provide a comprehensive SSL/TLS security assessment. "
                "Identify any misconfigurations, certificate issues, and provide remediation."
            ),
        )

        # Add findings
        for issue in issues:
            sev_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
            }
            self._add_finding(
                title=f"SSL/TLS Issue: {issue['issue'][:80]}",
                severity=sev_map.get(issue["severity"], Severity.MEDIUM),
                description=issue["issue"],
                evidence=f"SSL config: {ssl_data}",
                remediation=(
                    "Update TLS configuration: use TLS 1.2+, strong cipher suites, "
                    "renew/rotate certificates, enable HSTS with min-age 1 year."
                ),
                url=self.target,
            )

        self._add_finding(
            title="SSL/TLS Configuration Summary",
            severity=Severity.INFO,
            description="Full SSL/TLS assessment completed.",
            evidence=f"Config: {ssl_data}\n\nAnalysis: {analysis[:2000]}",
            remediation="Follow Mozilla SSL Configuration Generator for recommended settings.",
            url=self.target,
            extra={"ssl_data": ssl_data, "issues": issues},
        )

        return self.findings


class TechFingerprintAgent(BaseAgent):
    name = "Tech Fingerprint"
    description = "Identify server technology stack, versions, and known vulnerabilities"

    async def run(self) -> list[Finding]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync)

    def _run_sync(self) -> list[Finding]:
        resp = _get(self.target)
        if not resp:
            return self.findings

        headers = dict(resp.headers)
        body_lower = resp.text.lower()
        tech = {}

        # Server banner
        server = headers.get("Server", "")
        if server:
            tech["server"] = server

        # X-Powered-By
        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            tech["powered_by"] = powered_by

        # Framework detection from body
        framework_signatures = {
            "WordPress": ["wp-content", "wp-includes", "wp-json"],
            "Drupal": ["drupal", "sites/all", "sites/default"],
            "Joomla": ["joomla", "com_content", "option=com_"],
            "Laravel": ["laravel_session", "_token"],
            "Django": ["csrfmiddlewaretoken", "__django"],
            "Rails": ["authenticity_token", "rails"],
            "React": ["__react", "react-dom"],
            "Angular": ["ng-version", "angular"],
            "Vue.js": ["__vue__", "vue.min.js"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap.min.css", "bootstrap.js"],
            "Next.js": ["__next", "_next/static"],
            "Nuxt.js": ["__nuxt", "_nuxt/"],
        }

        detected_tech = []
        for name, sigs in framework_signatures.items():
            if any(sig in body_lower for sig in sigs):
                detected_tech.append(name)

        tech["detected_frameworks"] = detected_tech

        # Check for version disclosure in headers
        version_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]
        version_disclosures = []
        import re
        for h in version_headers:
            val = headers.get(h, "")
            if val and re.search(r"\d+\.\d+", val):
                version_disclosures.append({"header": h, "value": val})

        tech["version_disclosures"] = version_disclosures

        # Check for sensitive response headers present / missing
        security_headers = {
            "Content-Security-Policy": None,
            "X-Frame-Options": None,
            "X-Content-Type-Options": None,
            "Referrer-Policy": None,
            "Permissions-Policy": None,
            "Strict-Transport-Security": None,
        }
        security_header_results = {}
        for h in security_headers:
            val = headers.get(h)
            security_header_results[h] = val

        missing_security_headers = [h for h, v in security_header_results.items() if not v]
        tech["security_headers"] = security_header_results
        tech["missing_security_headers"] = missing_security_headers

        # Check for debug/error info leakage
        debug_indicators = ["debug=true", "stack trace", "sql syntax", "exception in thread", "traceback"]
        debug_leaks = [d for d in debug_indicators if d in body_lower]

        # Ask Claude to analyze tech fingerprint and identify risks
        analysis = self._ask_claude(
            system=(
                "You are a penetration tester analyzing a web application's technology stack. "
                "Identify CVEs, version-specific vulnerabilities, and misconfigurations."
            ),
            user=(
                f"Target: {self.target}\n"
                f"Technology fingerprint:\n{tech}\n"
                f"Debug indicators: {debug_leaks}\n\n"
                "For each detected technology:\n"
                "1. Identify known vulnerabilities if a version is exposed\n"
                "2. Flag dangerous default configurations\n"
                "3. Provide specific remediation steps\n"
                "4. Rate the overall exposure risk"
            ),
        )

        if version_disclosures:
            self._add_finding(
                title=f"Server Version Information Disclosed ({len(version_disclosures)} headers)",
                severity=Severity.MEDIUM,
                description=(
                    "HTTP response headers expose server/framework version numbers, "
                    "helping attackers target known CVEs."
                ),
                evidence=f"Version headers: {version_disclosures}",
                remediation=(
                    "Remove or generalize Server/X-Powered-By headers. "
                    "In nginx: `server_tokens off;`. "
                    "In Apache: `ServerTokens Prod; ServerSignature Off;`."
                ),
                url=self.target,
            )

        if missing_security_headers:
            severity = Severity.HIGH if len(missing_security_headers) >= 4 else Severity.MEDIUM
            self._add_finding(
                title=f"Missing Security Headers ({len(missing_security_headers)} missing)",
                severity=severity,
                description=f"Critical security response headers are absent: {', '.join(missing_security_headers)}",
                evidence=f"Present headers: {security_header_results}",
                remediation=(
                    "Add to all responses:\n"
                    "Content-Security-Policy: default-src 'self'\n"
                    "X-Frame-Options: DENY\n"
                    "X-Content-Type-Options: nosniff\n"
                    "Referrer-Policy: strict-origin-when-cross-origin\n"
                    "Permissions-Policy: geolocation=(), camera=(), microphone=()"
                ),
                url=self.target,
            )

        if debug_leaks:
            self._add_finding(
                title="Debug/Error Information Exposed in Response",
                severity=Severity.HIGH,
                description="Application leaks internal debug information, stack traces, or SQL errors.",
                evidence=f"Debug indicators found: {debug_leaks}",
                remediation=(
                    "Disable debug mode in production. "
                    "Implement global error handlers that return generic error messages. "
                    "Never expose stack traces or SQL errors to end users."
                ),
                url=self.target,
            )

        self._add_finding(
            title=f"Technology Stack Identified: {', '.join(detected_tech) or 'Unknown'}",
            severity=Severity.INFO,
            description=f"Detected technologies: {detected_tech}. Full fingerprint completed.",
            evidence=f"Tech data: {tech}\n\nAnalysis: {analysis[:2000]}",
            remediation="Keep all frameworks and dependencies updated. Monitor CVE databases for your stack.",
            url=self.target,
            extra={"tech": tech},
        )

        return self.findings
