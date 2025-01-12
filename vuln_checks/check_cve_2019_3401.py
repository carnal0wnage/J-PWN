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

def check_cve_2019_3401(url):
    '''
    Checks for CVE-2019-3401
    '''
    open_popular_filter_url = f"{url.rstrip('/')}/secure/ManageFilters.jspa?filterView=search&Search=Search&filterView=search&sortColumn=favcount&sortAscending=false"
    vulnerabilities = ''
    headers = {
    'X-Atlassian-Token': 'no-check'
    }
        
    try:
        print(f"{Fore.YELLOW}\nINFO: Checking for CVE-2019-3401 Unauthenticated Popular Filters with Shared Content")
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {open_popular_filter_url}")
        response = requests.get(open_popular_filter_url, headers=headers, allow_redirects=False, verify=False)

        if response.status_code == 200 and "Shared With" in response.text or "Share with" in response.text or "共享给" in response.text:
            vulnerabilities += (f"+ [Info Disclosure] CVE-2019-3401 Found | URL: {open_popular_filter_url}")
            print(f"\n{Fore.GREEN}+ CVE-2019-3401 Unauthenticated Popular Filter with Shared Content [Manually Inspect] {Style.RESET_ALL}")
            print(f"  URL: {open_popular_filter_url}")
        elif response.status_code == 200 :
            print(f"\n{Fore.YELLOW}[-] Not Vulnerable to CVE-2019-3401 | No Shared Popular Filters found {Style.RESET_ALL}")
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}\n- Unauthenticated Popular Filter vulnerability detected on: {open_popular_filter_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")
        elif response.status_code == 302:
            location = response.headers.get("Location", "No Location header found")
            if "login.jsp" not in location:
                print(f"{Fore.BLUE}- Following Redirect: {location}{Style.RESET_ALL}")
                redirected_response = requests.get(location, headers=headers, verify=False)
                if redirected_response.status_code == 200 and any(keyword in redirected_response.text for keyword in ["Shared With", "Share with", "共享给", "Viewers"]):
                    vulnerabilities += f"+ [Info Disclosure] CVE-2019-3401 Found via Redirect | URL: {location}"
                    print(f"\n{Fore.GREEN}+ CVE-2019-3401 Unauthenticated Popular Filter with Shared Content [Manually Inspect] (via Redirect){Style.RESET_ALL}")
                    print(f"  URL: {location}")
                else:
                    print(f"\n{Fore.YELLOW}[-] Not Vulnerable to CVE-2019-3401 after Redirect | No Shared Popular Filters found{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}- Detected redirect to login page - Not VULN{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}- Location Header: {location}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}\n- No CVE-2019-3401  vulnerability detected on: {open_popular_filter_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")

    except Exception as e:
            print(f"{Fore.RED}*  An error occurred while checking {open_popular_filter_url}: {e}{Style.RESET_ALL}")
    return vulnerabilities