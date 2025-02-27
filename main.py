# Required packages
import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
import sys
from wappalyzer import Wappalyzer, WebPage
from typing import List, Dict, Set
from Vulnerabilities_scanner.broken_access_control import broken_access_control_scanner
from Vulnerabilities_scanner.csrf_scanner import csrf_scanner
from Vulnerabilities_scanner.insecure_design import insecure_design_scanner
from Vulnerabilities_scanner.scurity_headers import check_security_headers
from Vulnerabilities_scanner.secuiry_misconfigurations import check_security_misconfigurations
from Vulnerabilities_scanner.sensitive_info import sensitive_info_scanner
from Vulnerabilities_scanner.sql_injection import sql_injection_scanner
from Vulnerabilities_scanner.ssrf_scanner import ssrf_scanner
from Vulnerabilities_scanner.vulnerable_components_scan import check_vulnerable_dependencies, \
    check_outdated_web_components
from Vulnerabilities_scanner.xss_scanner import xss_scanner


class WebSecurityScanner:
    def __init__(self, target_url: str, max_depth: int = 3):
        """
        Initialize the security scanner with a target URL and maximum crawl depth.

        Args:
            target_url: The base URL to scan
            max_depth: Maximum depth for crawling links (default: 3)
        """
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()

        # Initialize colorama for cross-platform colored output
        colorama.init()

    def normalize_url(self, url: str) -> str:
        """Normalize the URL to prevent duplicate checks"""
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def crawl(self, url: str, depth: int = 0) -> None:
        """
        Crawl the website to discover pages and endpoints.

        Args:
            url: Current URL to crawl
            depth: Current depth in the crawl tree
        """
        if depth > self.max_depth or url in self.visited_urls:
            return

        try:
            self.visited_urls.add(url)
            response = self.session.get(url, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all links in the page
            links = soup.find_all('a', href=True)
            for link in links:
                next_url = urllib.parse.urljoin(url, link['href'])
                if next_url.startswith(self.target_url):
                    self.crawl(next_url, depth + 1)

        except Exception as e:
            print(f"Error crawling {url}: {str(e)}")

    def security_headers_scan(self, url: str) -> None:
        check_security_headers(self,url)

    def check_ssrf(self,url:str)->None:
        ssrf_scanner(self,url)

    def check_csrf(self, url: str) -> None:
        csrf_scanner(self, url)
        """Test for potential Cross-Site Request Forgery (CSRF) vulnerabilities"""

    def check_sql_injection(self, url: str) -> None:
        """Test for potential SQL injection vulnerabilities"""
        sql_injection_scanner(self,url)

    def check_sensitive_info(self, url: str) -> None:
        """Check for exposed sensitive information"""
        sensitive_info_scanner(self,url)

    def check_xss(self, url: str) -> None:
        """Test for potential Cross-Site Scripting vulnerabilities"""
        xss_scanner(self,url)

    def check_broken_access_control(self, url: str) -> None:
        """Check for Broken Access Control vulnerabilities."""
        broken_access_control_scanner(self, url)

    def check_insecure_design(self, url: str) -> None:
        """Check for Insecure Design vulnerabilities"""
        insecure_design_scanner(self, url)

    def check_vulnerable_components(self,url:str) -> None:
        """Run both dependency and outdated component checks"""
        check_vulnerable_dependencies(self)
        check_outdated_web_components(self, url)

    def scanner_security_misconfigurations(self,url:str)->None:
        check_security_misconfigurations(self,url)

    def scan(self) -> List[Dict]:
        """
        Main scanning method that coordinates the security checks

        Returns:
            List of discovered vulnerabilities
        """
        print(f"\n{colorama.Fore.BLUE}Starting security scan of {self.target_url}{colorama.Style.RESET_ALL}\n")

        # First, crawl the website
        self.crawl(self.target_url)

        # Then run security checks on all discovered URLs
        with ThreadPoolExecutor(max_workers=5) as executor:
            for url in self.visited_urls:
                executor.submit(self.check_sql_injection, url)
                executor.submit(self.check_xss, url)
                executor.submit(self.check_sensitive_info, url)
                executor.submit(self.check_csrf, url)
                executor.submit(self.check_ssrf, url)
                executor.submit(self.check_broken_access_control, url)
                executor.submit(self.check_insecure_design, url)
                executor.submit(self.check_vulnerable_components,url)
                executor.submit(self.security_headers_scan, url)
                executor.submit(self.scanner_security_misconfigurations, url)

        return self.vulnerabilities

    def report_vulnerability(self, vulnerability: Dict) -> None:
        """Record and display found vulnerabilities"""
        self.vulnerabilities.append(vulnerability)
        print(f"{colorama.Fore.RED}[VULNERABILITY FOUND]{colorama.Style.RESET_ALL}")
        for key, value in vulnerability.items():
            print(f"{key}: {value}")
        print()

if __name__ == "__main__":
    target_url = "http://testphp.vulnweb.com/"
    scanner = WebSecurityScanner(target_url)
    vulnerabilities = scanner.scan()

        # Print summary
    print(f"\n{colorama.Fore.GREEN}Scan Complete!{colorama.Style.RESET_ALL}")
    print(f"Total URLs scanned: {len(scanner.visited_urls)}")
    print(f"Vulnerabilities found: {len(vulnerabilities)}")

# this is for testing
# testing branch