import requests
from bs4 import BeautifulSoup
import urllib.parse

def csrf_scanner(self, url: str) -> None:
    """Test for potential Cross-Site Request Forgery (CSRF) vulnerabilities"""
    try:
        response = self.session.get(url, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all forms on the page
        forms = soup.find_all('form')

        for form in forms:
            # Extract form method (POST, GET, etc.) and action (target URL)
            method = form.get('method', 'GET').upper()
            action = form.get('action', url)
            inputs = form.find_all('input')

            # Check if there's an anti-CSRF token in the form
            csrf_token = None
            csrf_filed_names=['csrf', 'token', 'authenticity_token', '_csrf', 'xsrf', 'x-csrf-token']
            for input_tag in inputs:
                if input_tag.get('name') and any(
                    key in input_tag.get('name').lower() for key in csrf_filed_names
                ):  # Common names for CSRF tokens
                    csrf_token = input_tag.get('value')
                    break

            # If the form is a POST and doesn't have a CSRF token, it's potentially vulnerable
            if method == 'POST' and not csrf_token:
                self.report_vulnerability({
                    'type': 'CSRF Vulnerability',
                    'url': url,
                    'form_action': action,
                    'csrf_token_missing': True
                })

            # Try submitting the form without the CSRF token (simulate CSRF attack)
            if csrf_token:
                # Find the action URL and build a POST request to simulate CSRF
                data = {input_tag.get('name'): input_tag.get('value') for input_tag in inputs if
                        input_tag.get('name')}
                data = {key: value for key, value in data.items() if value}  # Clean empty fields

                # Remove the CSRF token from the data to simulate a CSRF attack
                if csrf_token in data.values():
                    data = {key: value for key, value in data.items() if value != csrf_token}

                # Send the form data without the CSRF token
                response = self.session.post(action, data=data, verify=False)

                # If the request succeeds (200 OK), it indicates a CSRF vulnerability
                if response.status_code == 200:
                    self.report_vulnerability({
                        'type': 'CSRF Vulnerability',
                        'url': url,
                        'form_action': action,
                        'csrf_token_missing': False
                    })

    except Exception as e:
        print(f"Error testing CSRF on {url}: {str(e)}")

# Check SQL, XSS, Sensitive Info functions as before...
# Scan function as before...