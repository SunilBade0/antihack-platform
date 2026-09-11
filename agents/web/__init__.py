import asyncio
import re
import urllib.parse
import requests
from bs4 import BeautifulSoup
from agents.base_agent import BaseAgent, Finding, Severity


def _get(url: str, params: dict = None, timeout: int = 10, allow_redirects: bool = True) -> requests.Response:
    headers = {
        "User-Agent": "Mozilla/5.0 (Security-Audit-Bot/1.0; contact: security@audit.local)",
        "Accept": "text/html,application/xhtml+xml,application/json,*/*",
    }
    try:
        return requests.get(url, params=params, headers=headers, timeout=timeout,
                            allow_redirects=allow_redirects, verify=False)
    except Exception:
        return None


def _post(url: str, data: dict = None, json: dict = None, timeout: int = 10) -> requests.Response:
    headers = {"User-Agent": "Mozilla/5.0 (Security-Audit-Bot/1.0)"}
    try:
        return requests.post(url, data=data, json=json, headers=headers, timeout=timeout, verify=False)
    except Exception:
        return None


class SQLInjectionAgent(BaseAgent):
    name = "SQL Injection"
    description = "SQL injection testing across GET/POST parameters and forms"

    _ERROR_PATTERNS = [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"odbc.*error",
        r"ora-\d{5}",
        r"microsoft.*ole db.*sql server",
        r"jdbc.*exception",
        r"pg::.*error",
        r"sqliteexception",
        r"syntax error.*sql",
    ]

    _PAYLOADS = [
        "'",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "'; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "1 AND SLEEP(2)--",
    ]

    async def run(self) -> list[Finding]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync)

    def _run_sync(self) -> list[Finding]:
        base = self.target

        # Collect forms and input fields
        resp = _get(base)
        if not resp:
            return self.findings

        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        vuln_params = []

        # Test URL parameters if any
        parsed = urllib.parse.urlparse(base)
        if parsed.query:
            params = dict(urllib.parse.parse_qsl(parsed.query))
            for param, val in params.items():
                for payload in self._PAYLOADS[:4]:
                    test_params = {**params, param: payload}
                    r = _get(base.split("?")[0], params=test_params)
                    if r and self._has_sql_error(r.text):
                        vuln_params.append({"type": "GET", "param": param, "payload": payload, "url": base})
                        break

        # Test forms
        for form in forms[:5]:
            action = form.get("action", base)
            if not action.startswith("http"):
                action = urllib.parse.urljoin(base, action)
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")
            form_data = {}
            for inp in inputs:
                name = inp.get("name")
                if name:
                    form_data[name] = inp.get("value", "test")

            for inp_name in list(form_data.keys()):
                for payload in self._PAYLOADS[:4]:
                    test_data = {**form_data, inp_name: payload}
                    if method == "post":
                        r = _post(action, data=test_data)
                    else:
                        r = _get(action, params=test_data)
                    if r and self._has_sql_error(r.text):
                        vuln_params.append({
                            "type": method.upper(), "param": inp_name,
                            "payload": payload, "url": action,
                        })
                        break

        if vuln_params:
            analysis = self._ask_claude(
                system="You are an expert in SQL injection vulnerabilities. Analyze findings and explain impact.",
                user=(
                    f"Found SQL injection in {self.target}:\n{vuln_params}\n\n"
                    "Explain the business impact, what data could be extracted, "
                    "and provide specific remediation steps including code examples."
                ),
            )
            self._add_finding(
                title="SQL Injection Vulnerability (Error-Based)",
                severity=Severity.CRITICAL,
                description=(
                    f"SQL injection detected in {len(vuln_params)} parameter(s). "
                    "An attacker could dump the entire database, bypass authentication, "
                    "or in some cases execute OS commands."
                ),
                evidence=f"Vulnerable parameters: {vuln_params}\n\nAnalysis: {analysis[:2000]}",
                remediation=(
                    "1. Use parameterized queries / prepared statements.\n"
                    "2. Implement input validation and allowlisting.\n"
                    "3. Apply principle of least privilege on DB accounts.\n"
                    "4. Use a WAF as defense-in-depth."
                ),
                url=self.target,
                extra={"vulnerable_params": vuln_params},
            )
        else:
            self._add_finding(
                title="SQL Injection - No Error-Based Vulnerabilities Found",
                severity=Severity.INFO,
                description="No obvious SQL injection errors triggered. Blind SQLi may still exist.",
                evidence="Tested common payloads on all discovered forms and URL parameters.",
                remediation="Implement parameterized queries as best practice regardless.",
                url=self.target,
            )

        return self.findings

    def _has_sql_error(self, text: str) -> bool:
        text_lower = text.lower()
        return any(re.search(p, text_lower) for p in self._ERROR_PATTERNS)


class XSSAgent(BaseAgent):
    name = "XSS Scanner"
    description = "Reflected and stored cross-site scripting detection"

    _PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "\" onmouseover=\"alert('XSS')",
    ]

    async def run(self) -> list[Finding]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync)

    def _run_sync(self) -> list[Finding]:
        base = self.target
        resp = _get(base)
        if not resp:
            return self.findings

        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        vuln = []

        # Test URL params
        parsed = urllib.parse.urlparse(base)
        if parsed.query:
            params = dict(urllib.parse.parse_qsl(parsed.query))
            for param in params:
                for payload in self._PAYLOADS[:3]:
                    test_p = {**params, param: payload}
                    r = _get(base.split("?")[0], params=test_p)
                    if r and payload in r.text:
                        vuln.append({"type": "Reflected", "param": param, "payload": payload, "url": base})
                        break

        # Test forms
        for form in forms[:5]:
            action = form.get("action", base)
            if not action.startswith("http"):
                action = urllib.parse.urljoin(base, action)
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")
            form_data = {}
            for inp in inputs:
                name = inp.get("name")
                if name:
                    form_data[name] = "test"

            for inp_name in list(form_data.keys()):
                for payload in self._PAYLOADS[:3]:
                    test_data = {**form_data, inp_name: payload}
                    if method == "post":
                        r = _post(action, data=test_data)
                    else:
                        r = _get(action, params=test_data)
                    if r and re.search(re.escape(payload), r.text, re.IGNORECASE):
                        vuln.append({
                            "type": "Reflected", "param": inp_name,
                            "payload": payload, "url": action,
                        })
                        break

        if vuln:
            analysis = self._ask_claude(
                system="You are an XSS expert. Explain the real-world impact.",
                user=(
                    f"Found XSS in {self.target}:\n{vuln}\n\n"
                    "Explain what an attacker could do (cookie theft, credential harvest, "
                    "defacement, malware delivery) and provide fix code examples."
                ),
            )
            self._add_finding(
                title="Cross-Site Scripting (XSS) - Reflected",
                severity=Severity.HIGH,
                description=(
                    f"Reflected XSS found in {len(vuln)} location(s). "
                    "Attackers can steal session cookies, hijack accounts, "
                    "redirect users, or deliver malware."
                ),
                evidence=f"Vulnerable inputs: {vuln}\n\nImpact analysis: {analysis[:2000]}",
                remediation=(
                    "1. HTML-encode all user input before output.\n"
                    "2. Implement Content-Security-Policy header.\n"
                    "3. Use modern frameworks with auto-escaping (React, Vue, Angular).\n"
                    "4. Set HttpOnly and Secure flags on cookies."
                ),
                url=self.target,
                extra={"vulnerabilities": vuln},
            )
        else:
            self._add_finding(
                title="XSS - No Reflected XSS Found",
                severity=Severity.INFO,
                description="No obvious reflected XSS detected. Stored/DOM-based XSS may still exist.",
                evidence="Tested common XSS payloads in forms and URL parameters.",
                remediation="Implement Content-Security-Policy and output encoding as best practices.",
                url=self.target,
            )

        return self.findings


class CSRFAgent(BaseAgent):
    name = "CSRF Scanner"
    description = "CSRF token presence and validation checks"

    async def run(self) -> list[Finding]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync)

    def _run_sync(self) -> list[Finding]:
        resp = _get(self.target)
        if not resp:
            return self.findings

        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        vuln_forms = []
        csrf_token_names = [
            "csrf", "csrftoken", "_token", "authenticity_token",
            "__requestverificationtoken", "csrf_token", "xsrf", "_csrf",
        ]

        for form in forms:
            method = form.get("method", "get").lower()
            if method != "post":
                continue

            inputs = form.find_all("input")
            has_csrf = False
            for inp in inputs:
                name = (inp.get("name") or "").lower()
                inp_type = (inp.get("type") or "").lower()
                if inp_type == "hidden" and any(t in name for t in csrf_token_names):
                    has_csrf = True
                    break

            if not has_csrf:
                action = form.get("action", self.target)
                vuln_forms.append({"action": action, "method": method})

        if vuln_forms:
            analysis = self._ask_claude(
                system="You are a CSRF expert. Explain attack scenarios for these forms.",
                user=(
                    f"Target: {self.target}\nForms missing CSRF protection: {vuln_forms}\n\n"
                    "Describe concrete attack scenarios and remediation."
                ),
            )
            self._add_finding(
                title="Missing CSRF Protection on POST Forms",
                severity=Severity.HIGH,
                description=(
                    f"{len(vuln_forms)} POST form(s) lack CSRF tokens. "
                    "Attackers can trick logged-in users into performing unintended actions."
                ),
                evidence=f"Vulnerable forms: {vuln_forms}\n\nAnalysis: {analysis[:1500]}",
                remediation=(
                    "1. Add CSRF tokens to all state-changing forms.\n"
                    "2. Validate the token server-side on every POST.\n"
                    "3. Use SameSite=Strict or Lax cookie attribute.\n"
                    "4. Check the Origin/Referer header as additional validation."
                ),
                url=self.target,
                extra={"vulnerable_forms": vuln_forms},
            )
        else:
            self._add_finding(
                title="CSRF Protection Present",
                severity=Severity.INFO,
                description="POST forms appear to have CSRF tokens.",
                evidence=f"Checked {len(forms)} forms, all POST forms have CSRF protection.",
                remediation="Continue to validate CSRF tokens server-side on every state-changing request.",
                url=self.target,
            )

        return self.findings


class SSRFAgent(BaseAgent):
    name = "SSRF Scanner"
    description = "Server-Side Request Forgery detection"

    _INDICATORS = [
        "http://169.254.169.254",  # AWS metadata
        "http://metadata.google.internal",  # GCP metadata
        "http://localhost",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "file:///etc/passwd",
    ]

    async def run(self) -> list[Finding]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync)

    def _run_sync(self) -> list[Finding]:
        resp = _get(self.target)
        if not resp:
            return self.findings

        soup = BeautifulSoup(resp.text, "html.parser")
        # Find URL-like parameters
        url_params = []
        for form in soup.find_all("form"):
            for inp in form.find_all("input"):
                name = inp.get("name", "").lower()
                if any(k in name for k in ["url", "link", "src", "path", "redirect", "callback", "next", "dest", "target"]):
                    url_params.append(inp.get("name"))

        # Also check query params
        parsed = urllib.parse.urlparse(self.target)
        for key, _ in urllib.parse.parse_qsl(parsed.query):
            if any(k in key.lower() for k in ["url", "link", "src", "path", "redirect", "callback"]):
                url_params.append(key)

        ssrf_risk_params = list(set(url_params))

        # Check for open redirect (simpler SSRF cousin)
        redirect_vuln = []
        for param in ssrf_risk_params[:5]:
            for payload in ["http://evil.example.com", "//evil.example.com"]:
                test_params = {param: payload}
                r = _get(self.target, params=test_params, allow_redirects=False)
                if r and r.status_code in [301, 302, 303, 307, 308]:
                    loc = r.headers.get("Location", "")
                    if "evil.example.com" in loc:
                        redirect_vuln.append({"param": param, "payload": payload})

        if ssrf_risk_params or redirect_vuln:
            analysis = self._ask_claude(
                system="You are an SSRF and open redirect expert.",
                user=(
                    f"Target: {self.target}\n"
                    f"URL-accepting parameters found: {ssrf_risk_params}\n"
                    f"Open redirect confirmed: {redirect_vuln}\n\n"
                    "Explain SSRF attack scenarios for cloud environments (cloud metadata, internal services). "
                    "Provide remediation."
                ),
            )
            severity = Severity.CRITICAL if redirect_vuln else Severity.HIGH
            self._add_finding(
                title="Potential SSRF / Open Redirect Vulnerability",
                severity=severity,
                description=(
                    "Parameters that accept URLs were found. These may allow SSRF attacks "
                    "to access cloud metadata, internal services, or perform open redirects."
                ),
                evidence=f"URL params: {ssrf_risk_params}\nOpen redirects: {redirect_vuln}\n\nAnalysis: {analysis[:1500]}",
                remediation=(
                    "1. Validate and allowlist URLs server-side.\n"
                    "2. Block requests to private IP ranges and metadata endpoints.\n"
                    "3. Use a DNS rebinding protection library.\n"
                    "4. Never use user input directly in server-side HTTP requests."
                ),
                url=self.target,
                extra={"url_params": ssrf_risk_params, "open_redirects": redirect_vuln},
            )

        return self.findings


class AuthAgent(BaseAgent):
    name = "Auth & Session"
    description = "Authentication bypass, weak credentials, session security"

    async def run(self) -> list[Finding]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync)

    def _run_sync(self) -> list[Finding]:
        resp = _get(self.target)
        if not resp:
            return self.findings

        findings_data = {}

        # Check for common admin/login pages
        common_admin_paths = [
            "/admin", "/admin/login", "/wp-admin", "/wp-login.php",
            "/administrator", "/login", "/signin", "/dashboard",
            "/phpmyadmin", "/cpanel", "/panel", "/control",
        ]
        exposed_admin = []
        for path in common_admin_paths:
            url = urllib.parse.urljoin(self.target, path)
            r = _get(url)
            if r and r.status_code == 200:
                exposed_admin.append(url)

        findings_data["exposed_admin"] = exposed_admin

        # Check cookie security flags
        cookies = resp.cookies
        insecure_cookies = []
        for cookie in cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly flag")
            samesite = cookie.get_nonstandard_attr("SameSite")
            if not samesite:
                issues.append("missing SameSite attribute")
            if issues:
                insecure_cookies.append({"name": cookie.name, "issues": issues})

        findings_data["insecure_cookies"] = insecure_cookies

        # Check for default credentials on admin pages
        default_creds = [("admin", "admin"), ("admin", "password"), ("admin", "123456"), ("root", "root")]
        auth_bypass = []
        for path in exposed_admin[:3]:
            soup = BeautifulSoup(_get(path).text if _get(path) else "", "html.parser")
            form = soup.find("form")
            if form:
                inputs = form.find_all("input")
                form_data = {}
                user_field = pass_field = None
                for inp in inputs:
                    name = inp.get("name", "").lower()
                    itype = inp.get("type", "text").lower()
                    if any(k in name for k in ["user", "email", "login", "name"]) or itype == "email":
                        user_field = inp.get("name")
                    elif itype == "password":
                        pass_field = inp.get("name")
                    elif inp.get("name"):
                        form_data[inp.get("name")] = inp.get("value", "")

                if user_field and pass_field:
                    for user, pwd in default_creds:
                        test_data = {**form_data, user_field: user, pass_field: pwd}
                        r = _post(path, data=test_data)
                        if r and r.status_code in [200, 302]:
                            if any(kw in r.text.lower() for kw in ["dashboard", "welcome", "logout", "admin panel"]):
                                auth_bypass.append({"url": path, "user": user, "pass": pwd})

        findings_data["auth_bypass"] = auth_bypass

        analysis = self._ask_claude(
            system="You are an authentication and session security expert.",
            user=(
                f"Target: {self.target}\n"
                f"Exposed admin pages: {exposed_admin}\n"
                f"Insecure cookies: {insecure_cookies}\n"
                f"Auth bypass with default creds: {auth_bypass}\n\n"
                "Identify all auth and session security issues. Provide specific fixes."
            ),
        )

        if auth_bypass:
            self._add_finding(
                title="Default Credentials Allow Admin Access",
                severity=Severity.CRITICAL,
                description="Default username/password combinations successfully logged into admin panels.",
                evidence=f"Working credentials: {auth_bypass}",
                remediation="Change all default credentials immediately. Implement account lockout after failed attempts.",
                url=self.target,
                extra=findings_data,
            )

        if exposed_admin:
            self._add_finding(
                title="Admin Panels Exposed to Internet",
                severity=Severity.HIGH,
                description=f"{len(exposed_admin)} admin/management pages are publicly accessible.",
                evidence=f"Exposed pages: {exposed_admin}",
                remediation=(
                    "1. Restrict admin pages to specific IP ranges.\n"
                    "2. Move admin interfaces to a non-standard path.\n"
                    "3. Require VPN access for admin functionality."
                ),
                url=self.target,
            )

        if insecure_cookies:
            self._add_finding(
                title="Insecure Cookie Configuration",
                severity=Severity.MEDIUM,
                description="Session cookies are missing security attributes, enabling theft/hijacking.",
                evidence=f"Insecure cookies: {insecure_cookies}\n\nAnalysis: {analysis[:1000]}",
                remediation=(
                    "Set Secure, HttpOnly, and SameSite=Strict on all session cookies. "
                    "Use short expiry times for session tokens."
                ),
                url=self.target,
            )

        return self.findings


class APIAgent(BaseAgent):
    name = "API Exposure"
    description = "Unprotected API endpoints, missing auth, rate limiting"

    _API_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/graphql", "/graphiql", "/api/graphql",
        "/swagger", "/swagger-ui", "/swagger-ui.html",
        "/openapi.json", "/api-docs", "/docs",
        "/rest", "/ws", "/websocket",
        "/api/users", "/api/user", "/api/admin",
        "/api/config", "/api/settings", "/api/health",
        "/api/debug", "/api/test",
    ]

    async def run(self) -> list[Finding]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync)

    def _run_sync(self) -> list[Finding]:
        found_apis = []
        exposed_docs = []
        rate_limit_missing = []

        for path in self._API_PATHS:
            url = urllib.parse.urljoin(self.target, path)
            r = _get(url)
            if not r:
                continue

            if r.status_code == 200:
                content_type = r.headers.get("Content-Type", "")
                is_api = "json" in content_type or "graphql" in path or "swagger" in path
                is_doc = any(d in path for d in ["swagger", "graphiql", "api-docs", "docs", "openapi"])

                if is_api or r.text.strip().startswith("{") or r.text.strip().startswith("["):
                    found_apis.append({"url": url, "status": r.status_code, "type": content_type})

                if is_doc:
                    exposed_docs.append(url)

                # Check rate limiting
                if is_api:
                    has_rate_limit = any(
                        h in r.headers for h in
                        ["X-RateLimit-Limit", "X-Rate-Limit", "Retry-After", "X-RateLimit-Remaining"]
                    )
                    if not has_rate_limit:
                        rate_limit_missing.append(url)

        if found_apis or exposed_docs:
            analysis = self._ask_claude(
                system="You are an API security expert.",
                user=(
                    f"Target: {self.target}\n"
                    f"Exposed API endpoints: {found_apis}\n"
                    f"Exposed API documentation: {exposed_docs}\n"
                    f"APIs missing rate limiting: {rate_limit_missing}\n\n"
                    "Identify the security risks of each finding and provide remediation."
                ),
            )

            if exposed_docs:
                self._add_finding(
                    title="API Documentation Publicly Exposed",
                    severity=Severity.HIGH,
                    description=(
                        "Swagger/OpenAPI/GraphiQL documentation is publicly accessible. "
                        "This gives attackers a complete map of all endpoints, parameters, and data models."
                    ),
                    evidence=f"Exposed docs: {exposed_docs}",
                    remediation=(
                        "1. Restrict API docs to authenticated users only.\n"
                        "2. Disable docs in production environments.\n"
                        "3. At minimum, move docs behind authentication."
                    ),
                    url=self.target,
                )

            if found_apis:
                self._add_finding(
                    title=f"Exposed API Endpoints ({len(found_apis)} found)",
                    severity=Severity.MEDIUM,
                    description=f"Found {len(found_apis)} API endpoints. Check each for authentication.",
                    evidence=f"APIs: {found_apis}\n\nAnalysis: {analysis[:1500]}",
                    remediation=(
                        "1. Require authentication on all non-public API endpoints.\n"
                        "2. Implement rate limiting on all API endpoints.\n"
                        "3. Return minimal error information in API responses."
                    ),
                    url=self.target,
                    extra={"apis": found_apis},
                )

        return self.findings


class DirectoryTraversalAgent(BaseAgent):
    name = "Directory Traversal"
    description = "Path traversal, file inclusion, and directory listing"

    _TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "../../windows/win.ini",
    ]

    _SENSITIVE_PATHS = [
        "/.git/config", "/.env", "/.env.local", "/config.php",
        "/web.config", "/wp-config.php", "/.htaccess",
        "/server-status", "/server-info",
        "/backup.zip", "/backup.sql", "/dump.sql",
        "/robots.txt", "/sitemap.xml",
    ]

    async def run(self) -> list[Finding]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync)

    def _run_sync(self) -> list[Finding]:
        traversal_found = []
        sensitive_found = []

        # Test traversal via URL params
        parsed = urllib.parse.urlparse(self.target)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        file_like_params = [k for k in params if any(
            x in k.lower() for x in ["file", "path", "page", "include", "doc", "template", "load"]
        )]

        for param in file_like_params:
            for payload in self._TRAVERSAL_PAYLOADS:
                test_p = {**params, param: payload}
                r = _get(self.target.split("?")[0], params=test_p)
                if r and ("root:" in r.text or "[extensions]" in r.text):
                    traversal_found.append({"param": param, "payload": payload})
                    break

        # Check sensitive files
        for path in self._SENSITIVE_PATHS:
            url = urllib.parse.urljoin(self.target, path)
            r = _get(url)
            if r and r.status_code == 200 and len(r.text) > 20:
                sensitive_found.append({"url": url, "size": len(r.text), "preview": r.text[:200]})

        if traversal_found:
            self._add_finding(
                title="Path Traversal Vulnerability",
                severity=Severity.CRITICAL,
                description="Directory traversal allows reading arbitrary files from the server filesystem.",
                evidence=f"Vulnerable params: {traversal_found}",
                remediation=(
                    "1. Validate and sanitize file paths strictly.\n"
                    "2. Use allowlists for permitted file names.\n"
                    "3. Run the web server with minimal filesystem permissions."
                ),
                url=self.target,
                extra={"traversal": traversal_found},
            )

        if sensitive_found:
            # Filter for truly interesting ones
            critical = [f for f in sensitive_found if any(
                x in f["url"] for x in [".env", ".git", "wp-config", "config.php", "web.config", ".sql"]
            )]
            severity = Severity.CRITICAL if critical else Severity.HIGH
            analysis = self._ask_claude(
                system="You are an expert in sensitive file exposure.",
                user=(
                    f"Target: {self.target}\nExposed files: {sensitive_found}\n\n"
                    "Explain what data is exposed and the risk for each file."
                ),
            )
            self._add_finding(
                title=f"Sensitive Files Exposed ({len(sensitive_found)} files)",
                severity=severity,
                description=f"{len(sensitive_found)} sensitive file(s) are publicly accessible.",
                evidence=f"Files: {sensitive_found}\n\nAnalysis: {analysis[:1500]}",
                remediation=(
                    "1. Remove or protect sensitive files from the web root.\n"
                    "2. Block access via .htaccess or nginx rules.\n"
                    "3. Revoke any credentials found in exposed config files."
                ),
                url=self.target,
                extra={"files": sensitive_found},
            )

        return self.findings


class SecretsAgent(BaseAgent):
    name = "Secrets Scanner"
    description = "API keys, tokens, and credentials in page source and JS files"

    _PATTERNS = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
        "GitHub Token": r"ghp_[0-9A-Za-z]{36}",
        "Generic API Key": r"""(?i)(?:api[_\-]?key|apikey|api_token)\s*[=:]\s*['"][^'"]{16,64}['"]""",
        "Generic Secret": r"""(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,64}['"]""",
        "Private Key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "Stripe Key": r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}",
        "JWT Token": r"eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*",
        "Basic Auth in URL": r"https?://[^:]+:[^@]+@[^/]+",
        "Database URL": r"(?:mysql|postgres|mongodb|redis)://[^@]+@[^/\s]+",
    }

    async def run(self) -> list[Finding]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync)

    def _run_sync(self) -> list[Finding]:
        all_secrets = []

        # Scan main page
        resp = _get(self.target)
        if not resp:
            return self.findings
        self._scan_text(self.target, resp.text, all_secrets)

        # Find and scan JS files
        soup = BeautifulSoup(resp.text, "html.parser")
        js_urls = []
        for tag in soup.find_all("script", src=True):
            src = tag["src"]
            if not src.startswith("http"):
                src = urllib.parse.urljoin(self.target, src)
            js_urls.append(src)

        for js_url in js_urls[:15]:
            r = _get(js_url)
            if r and r.status_code == 200:
                self._scan_text(js_url, r.text, all_secrets)

        if all_secrets:
            analysis = self._ask_claude(
                system="You are an expert in secret scanning and credential exposure.",
                user=(
                    f"Target: {self.target}\nSecrets found in source: {all_secrets[:20]}\n\n"
                    "Explain what can be done with each secret type and urgency of remediation."
                ),
            )
            self._add_finding(
                title=f"Hardcoded Secrets Found ({len(all_secrets)} instances)",
                severity=Severity.CRITICAL,
                description=(
                    f"{len(all_secrets)} potential secret(s) found in page source and JavaScript files. "
                    "These could allow full account takeovers or data breaches."
                ),
                evidence=f"Secrets: {all_secrets[:10]}\n\nAnalysis: {analysis[:2000]}",
                remediation=(
                    "1. Revoke all exposed credentials immediately.\n"
                    "2. Move secrets to environment variables or a secrets manager.\n"
                    "3. Audit git history for historical exposure.\n"
                    "4. Implement pre-commit hooks to prevent future leaks."
                ),
                url=self.target,
                extra={"secrets": all_secrets},
            )

        return self.findings

    def _scan_text(self, source: str, text: str, results: list):
        for secret_type, pattern in self._PATTERNS.items():
            matches = re.findall(pattern, text)
            for match in matches:
                # Redact for safety
                redacted = match[:8] + "****" + match[-4:] if len(match) > 12 else "****"
                results.append({"type": secret_type, "source": source, "redacted": redacted})
