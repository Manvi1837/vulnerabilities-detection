import requests
from bs4 import BeautifulSoup


def ssrf_scanner(self, url: str) -> None:
    """Test for potential Server-Side Request Forgery (SSRF) vulnerabilities"""
    try:
        response = self.session.get(url, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all forms on the page
        forms = soup.find_all('form')

        # List of internal/private IPs and metadata URLs to test
        test_urls = [
            "http://127.0.0.1",
            "http://localhost",
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://169.254.169.254/latest/meta-data/",  # AWS Metadata
            "http://169.254.169.254/latest/user-data/",  # AWS User Data
            "http://metadata.google.internal/computeMetadata/v1/",  # Google Cloud Metadata
        ]

        for form in forms:
            action = form.get('action', url)
            inputs = form.find_all('input')

            # Identify potential URL input fields
            url_params = [input_tag for input_tag in inputs if 'url' in input_tag.get('name', '').lower()]

            if url_params:
                for test_url in test_urls:
                    data = {input_tag.get('name'): test_url for input_tag in url_params}

                    # Add Metadata Headers (Google Cloud requires a header for access)
                    headers = {"Metadata-Flavor": "Google"} if "google" in test_url else {}

                    response = self.session.post(action, data=data, headers=headers, verify=False)

                    # If private IPs or metadata services are accessible, flag as vulnerable
                    if any(ip in response.text.lower() for ip in test_urls) or response.status_code == 200:
                        self.report_vulnerability({
                            'type': 'SSRF Vulnerability',
                            'url': url,
                            'form_action': action,
                            'parameters_tested': list(data.keys()),
                            'tested_url': test_url,
                            'potential_exploit': True
                        })
    except Exception as e:
        print(f"Error testing SSRF on {url}: {str(e)}")
