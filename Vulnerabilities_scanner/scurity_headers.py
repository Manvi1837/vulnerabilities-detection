def check_security_headers(self, url: str) -> None:
    """Check for missing security-related HTTP headers."""
    try:
        response = self.session.get(url, verify=False)
        missing_headers = []
        required_headers = [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Strict-Transport-Security"
        ]

        for header in required_headers:
            if header not in response.headers:
                missing_headers.append(header)

        if missing_headers:
            vulnerability = {
                "type": "Security Logging & Monitoring Failure",
                "url": url,
                "missing_headers": missing_headers,
                "risk": "High"
            }
            self.report_vulnerability(vulnerability)

    except Exception as e:
        print(f"Error checking security headers for {url}: {str(e)}")
