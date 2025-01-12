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

def check_unauthenticated_popular_dashboard(url):
    '''
    Checks for Unauthenticated Popular Dashboard 
    '''
    check_unauthenticated_popular_dashboard_url = f"{url.rstrip('/')}/secure/ConfigurePortalPages!default.jspa?view=popular"
    vulnerabilities = ''
    headers = {
        'X-Atlassian-Token': 'no-check'
    }
        
    try:
        print(f"{Fore.YELLOW}\nINFO: IN DEVELOPMENT - Unauthenticated Popular Dashboard")
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {check_unauthenticated_popular_dashboard_url}")
        response = requests.get(check_unauthenticated_popular_dashboard_url, headers=headers, allow_redirects=False, verify=False)

        # Check for the vulnerability
        if response.status_code == 200 and "Shared With" in response.text or "Share with" in response.text or "共享给" in response.text:
            response_text = response.text
            # print(response_text) #DEBUG
            vulnerabilities += (f"+ [Info Disclosure] Unauthenticated Popular Dashboard Found | URL: {check_unauthenticated_popular_dashboard_url}")
            print(f"\n{Fore.GREEN}+ [Info Disclosure] Unauthenticated Popular Dashboard Found [Manually Inspect] {Style.RESET_ALL}")
            print(f"  URL: {check_unauthenticated_popular_dashboard_url}")
        elif response.status_code == 200 :
            print(f"\n{Fore.YELLOW}[-] No Unauthenticated Popular Dashboard vulnerability  | No Shared Popular Dashboards found {Style.RESET_ALL}")
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}\n- No Unauthenticated Popular Dashboard vulnerability detected on: {check_unauthenticated_popular_dashboard_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")
        elif response.status_code == 302:
            location = response.headers.get("Location", "No Location header found") 
            print(f"{Fore.YELLOW}- Redirection Detected (302) for: {check_unauthenticated_popular_dashboard_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- Location Header: {location}")
            print(f"{Fore.YELLOW}- This program doesnt follow 302 - Try: curl -k -v \'{check_unauthenticated_popular_dashboard_url}\'{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}\n- No Unauthenticated Popular Dashboard vulnerability detected on: {check_unauthenticated_popular_dashboard_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")

    except Exception as e:
            print(f"{Fore.RED}*  An error occurred while checking {check_unauthenticated_popular_dashboard_url}: {e}{Style.RESET_ALL}")
    return vulnerabilities