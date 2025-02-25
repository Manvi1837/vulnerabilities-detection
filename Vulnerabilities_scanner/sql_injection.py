import requests
from bs4 import BeautifulSoup
import urllib.parse

def sql_injection_scanner(self, url: str) -> None:
    """Test for potential SQL injection vulnerabilities"""
    sql_payloads = ["'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]

    for payload in sql_payloads:
        try:
            # Test GET parameters
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)

            for param in params:
                test_url = url.replace(f"{param}={params[param][0]}",
                                       f"{param}={payload}")
                response = self.session.get(test_url)

                # Look for SQL error messages
                if any(error in response.text.lower() for error in
                       ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle']):
                    self.report_vulnerability({
                        'type': 'SQL Injection',
                        'url': url,
                        'parameter': param,
                        'payload': payload
                    })

        except Exception as e:
            print(f"Error testing SQL injection on {url}: {str(e)}")