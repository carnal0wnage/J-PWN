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


def check_cve_2022_0540_v1(url):
    '''
    Checks for CVE-2022-0540 Variant 1, a potential Remote Code Execution vulnerability in Jira.
    '''
    check_cve_2022_0540_v1_url = f"{url}InsightPluginShowGeneralConfiguration.jspa;"
    vulnerabilities = ''

    try:
        print(f"\n{Fore.YELLOW}INFO: Checking for CVE-2022-0540 (Insight Variant){Style.RESET_ALL}")
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {check_cve_2022_0540_v1_url}")
        response = requests.get(check_cve_2022_0540_v1_url, allow_redirects=False, verify=False)

        # Check for the vulnerability
        if response.status_code == 200:
            response_text = response.text
            print(response_text) #DEBUG

            if ("General Insight Configuration" in response_text):
                vulnerabilities += (f"+ [Potential RCE] - CVE-2022-0540 Variant 1: Manual exploitation required | URL: {check_cve_2022_0540_v1_url}")
                print(f"\n{Fore.GREEN}+ [Potential RCE] - CVE-2022-0540 Variant 1: [MANUAL REVIEW REQUIRED]{Style.RESET_ALL}")
                print(f"  URL: {check_cve_2022_0540_v1_url}")
                print(f"  Note: Exploitation requires manual steps.")
                print(f"  See: https://blog.viettelcybersecurity.com/cve-2022-0540-authentication-bypass-in-seraph/")
            else:
                print(f"{Fore.BLUE}\n- Received 200 but did not match regex [Manually Review] {check_cve_2022_0540_v1_url}")
                print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}") 
        elif response.status_code == 302:
            print(f"{Fore.YELLOW}\n- No CVE-2022-0540 vulnerability detected on: {check_cve_2022_0540_v1_url}")
            location = response.headers.get("Location", "No Location header found")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}") 
            print(f"{Fore.YELLOW}- Location Header: {location}")
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}")
        else:
            print(f"{Fore.YELLOW}\n- No CVE-2022-0540 vulnerability detected on: {check_cve_2022_0540_v1_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")

    except Exception as e:
            print(f"{Fore.RED}\n* CVE-2022-0540 An error occurred while checking {check_cve_2022_0540_v1_url}: {e}{Style.RESET_ALL}")
    return vulnerabilities
