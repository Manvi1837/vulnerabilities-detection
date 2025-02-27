import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama

def check_security_misconfigurations(self, url: str) -> None:
    """Check for common security misconfigurations."""
    try:
        response = self.session.get(url, verify=False)

        # 1. Detect Default Admin Pages
        common_admin_paths = ["/admin", "/login", "/wp-admin", "/dashboard", "/user"]
        for path in common_admin_paths:
            admin_url = urllib.parse.urljoin(url, path)
            admin_response = self.session.get(admin_url, verify=False)
            if admin_response.status_code == 200:
                self.report_vulnerability({
                    "type": "Security Misconfiguration",
                    "url": admin_url,
                    "issue": "Exposed admin/login page",
                    "risk": "Medium"
                })

        # 2. Detect Sensitive Files
        sensitive_files = ["/.env", "/.git", "/config.json", "/backup.zip", "/database.sql"]
        for file in sensitive_files:
            file_url = urllib.parse.urljoin(url, file)
            file_response = self.session.get(file_url, verify=False)
            if file_response.status_code == 200:
                self.report_vulnerability({
                    "type": "Security Misconfiguration",
                    "url": file_url,
                    "issue": "Exposed sensitive file",
                    "risk": "High"
                })

        # 3. Detect Misconfigured CORS Policies
        if "Access-Control-Allow-Origin" in response.headers and response.headers[
            "Access-Control-Allow-Origin"] == "*":
            self.report_vulnerability({
                "type": "Security Misconfiguration",
                "url": url,
                "issue": "Insecure CORS policy (allows any origin)",
                "risk": "High"
            })

    except Exception as e:
        print(f"Error checking security misconfigurations for {url}: {str(e)}")
