# import re
#
# import requests
# from bs4 import BeautifulSoup
# import urllib.parse
#
# def sensitive_info_scanner(self, url: str) -> None:
#     """Check for exposed sensitive information"""
#     sensitive_patterns = {
#         'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
#         'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
#         'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
#         'api_key': r'api[_-]?key[_-]?([\'"|`])([a-zA-Z0-9]{32,45})\1'
#     }
#
#     try:
#         response = self.session.get(url)
#
#         for info_type, pattern in sensitive_patterns.items():
#             matches = re.finditer(pattern, response.text)
#             for match in matches:
#                 self.report_vulnerability({
#                     'type': 'Sensitive Information Exposure',
#                     'url': url,
#                     'info_type': info_type,
#                     'pattern': pattern
#                 })
#
#     except Exception as e:
#         print(f"Error checking sensitive information on {url}: {str(e)}")
import re
import requests
from bs4 import BeautifulSoup


def sensitive_info_scanner(self, url: str) -> None:
    """Check for exposed sensitive information"""

    # Patterns for detecting sensitive information
    sensitive_patterns = {
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'api_key': r'api[_-]?key[_-]?([\'"|`])([a-zA-Z0-9]{32,45})\1'
    }

    try:
        # Fetch the webpage content
        response = self.session.get(url)

        # Parse HTML with BeautifulSoup to identify phone numbers in safe contexts (e.g., contact sections)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all anchor tags that could contain 'tel:' links (these are typically phone numbers)
        tel_links = soup.find_all('a', href=re.compile(r'tel:'))

        # Extract phone numbers from these 'tel:' links
        safe_numbers = set(link['href'].replace('tel:', '') for link in tel_links)

        # Scan the page content for sensitive data
        for info_type, pattern in sensitive_patterns.items():
            matches = re.finditer(pattern, response.text)
            for match in matches:
                # For phone numbers, check if the number is in the list of known safe numbers
                if info_type == 'phone' and match.group(0) in safe_numbers:
                    continue  # Skip this match as it's considered safe

                # Report any found vulnerability
                self.report_vulnerability({
                    'type': 'Sensitive Information Exposure',
                    'url': url,
                    'info_type': info_type,
                    'pattern': pattern
                })

    except Exception as e:
        print(f"Error checking sensitive information on {url}: {str(e)}")
