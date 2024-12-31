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

def check_cve_2020_14181(url):
    '''
    Checks for CVE-2020-14181 Username Enumeration
    '''
    cve_2020_14181_url = f"{url}secure/ViewUserHover.jspa?username=ishouldntexist"
    vulnerabilities = ''
        
    try:
        print(f"\n{Fore.YELLOW}INFO: Checking for CVE-2020-14181{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {cve_2020_14181_url}")
        response = requests.get(cve_2020_14181_url, allow_redirects=False, verify=False)

        # Check for the vulnerability
        if response.status_code == 200 and "User does not exist" in response.text:
            response_text = response.text

            vulnerabilities += (f"+ [Username Enumeration] CVE-2020-14181 Detected| URL: {cve_2020_14181_url}")
            print(f"\n{Fore.GREEN}+ [Username Enumeration] CVE-2020-14181 Detected {Style.RESET_ALL}")
            print(f"  URL: {cve_2020_14181_url}")
           
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}\n- No CVE-2020-14181 vulnerability detected on: {cve_2020_14181_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")
        elif response.status_code == 302:
            location = response.headers.get("Location", "No Location header found") 
            print(f"{Fore.YELLOW}- Redirection Detected (302) for: {cve_2020_14181_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- Location Header: {location}")
            print(f"{Fore.YELLOW}- This program doesnt follow 302 - Try: curl -k -v \'{cve_2020_14181_url}\'{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}\n- No CVE-2020-14181 vulnerability detected on: {cve_2020_14181_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")

    except Exception as e:
            print(f"{Fore.RED}*  An error occurred while checking {cve_2020_14181_url}: {e}{Style.RESET_ALL}")
    return vulnerabilities