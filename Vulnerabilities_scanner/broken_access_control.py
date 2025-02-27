import requests
import urllib.parse
from colorama import Fore, Style

# Common restricted paths to test
COMMON_ADMIN_PATHS = [
    "/admin", "/dashboard", "/config", "/private", "/settings", "/user/1", "/api/admin"
]

# Common IDOR test cases
IDOR_PARAMS = ["id", "user", "account", "profile", "order"]

def broken_access_control_scanner(scanner, url):
    """
    Scans for Broken Access Control vulnerabilities.
    - Tests for Insecure Direct Object References (IDOR)
    - Checks unauthorized access to sensitive pages
    - Detects CORS misconfigurations
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # 🔍 1. Test for Forced Browsing (Accessing restricted pages)
        for path in COMMON_ADMIN_PATHS:
            test_url = base_url + path
            response = scanner.session.get(test_url, verify=False)

            if response.status_code == 200:
                scanner.report_vulnerability({
                    "url": test_url,
                    "issue": "Possible unauthorized access to admin pages",
                    "status_code": response.status_code
                })

        # 🔍 2. Test for IDOR by modifying query parameters
        query_params = urllib.parse.parse_qs(parsed_url.query)
        for param in IDOR_PARAMS:
            if param in query_params:
                original_value = query_params[param][0]
                test_value = str(int(original_value) + 1) if original_value.isdigit() else "testuser"

                new_query = urllib.parse.urlencode({param: test_value})
                test_url = f"{base_url}{parsed_url.path}?{new_query}"
                response = scanner.session.get(test_url, verify=False)

                if response.status_code == 200:
                    scanner.report_vulnerability({
                        "url": test_url,
                        "issue": "Potential IDOR vulnerability",
                        "parameter": param,
                        "status_code": response.status_code
                    })

        # 🔍 3. Check for CORS Misconfigurations
        response = scanner.session.options(url)
        if "Access-Control-Allow-Origin" in response.headers and response.headers["Access-Control-Allow-Origin"] == "*":
            scanner.report_vulnerability({
                "url": url,
                "issue": "CORS Misconfiguration (Allows any origin)",
                "header": "Access-Control-Allow-Origin"
            })

    except Exception as e:
        print(f"{Fore.YELLOW}[WARNING] Error checking BAC on {url}: {e}{Style.RESET_ALL}")
