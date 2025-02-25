import requests
from bs4 import BeautifulSoup
import urllib.parse

def xss_scanner(self, url: str) -> None:
    """Test for potential Cross-Site Scripting vulnerabilities"""
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')"
    ]

    for payload in xss_payloads:
        try:
            # Test GET parameters
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)

            for param in params:
                test_url = url.replace(f"{param}={params[param][0]}",
                                       f"{param}={urllib.parse.quote(payload)}")
                response = self.session.get(test_url)

                if payload in response.text:
                    self.report_vulnerability({
                        'type': 'Cross-Site Scripting (XSS)',
                        'url': url,
                        'parameter': param,
                        'payload': payload
                    })

        except Exception as e:
            print(f"Error testing XSS on {url}: {str(e)}")
