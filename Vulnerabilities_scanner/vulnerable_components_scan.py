import subprocess
from concurrent.futures import ThreadPoolExecutor
import sys
from wappalyzer import Wappalyzer, WebPage

def check_vulnerable_dependencies(self) -> None:
    """Check for vulnerable Python dependencies using 'safety'"""
    print("\nChecking for vulnerable dependencies...\n")
    result = subprocess.run(["safety", "check"], capture_output=True, text=True)
    print(result.stdout)
    if "vulnerable" in result.stdout.lower():
        self.report_vulnerability({
            "type": "Vulnerable Dependencies",
            "details": result.stdout
        })


def check_outdated_web_components(self, url: str) -> None:
    """Check for outdated web components using Wappalyzer"""
    print(f"\nScanning {url} for outdated components...\n")
    try:
        webpage = WebPage.new_from_url(url)
        wappalyzer = Wappalyzer.latest()
        technologies = wappalyzer.analyze(webpage)
        print("Detected Technologies:", technologies)

        outdated_components = [tech for tech in technologies if "version" in tech.lower()]
        if outdated_components:
            self.report_vulnerability({
                "type": "Outdated Components",
                "details": outdated_components
            })
    except Exception as e:
        print(f"Error scanning components: {str(e)}")
