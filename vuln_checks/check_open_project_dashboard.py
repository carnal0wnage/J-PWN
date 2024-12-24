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

def check_open_project_dashboard(url):
    '''
    Checks for open service desk. You should mannually attempt to signup
    '''
    open_project_dashboard_url = f"{url}secure/ConfigurePortalPages!default.jspa?view=popular"
    vulnerabilities = ''
        
    try:
        print(f"{Fore.YELLOW}\nINFO: IN DEVELOPMENT - Open Project Dashboard")
        response = requests.get(open_project_dashboard_url, allow_redirects=False, verify=False)

        # Check for the vulnerability
        if response.status_code == 200:
            response_text = response.text
            # print(response_text) #DEBUG


            vulnerabilities += (f"+ [Info Disclosure] Open Project Dashboard Found | URL: {open_project_dashboard_url}")
            print(f"\n{Fore.GREEN}+ Open Project Dashboard Found [Manually Inspect] {Style.RESET_ALL}")
            print(f"  URL: {open_project_dashboard_url}")
           
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}\n- No Open Project Dashboard vulnerability detected on: {open_project_dashboard_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")
        elif response.status_code == 302:
            location = response.headers.get("Location", "No Location header found") 
            print(f"{Fore.YELLOW}- Redirection Detected (302) for: {open_project_dashboard_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- Location Header: {location}")
            print(f"{Fore.YELLOW}- This program doesnt follow 302 - Try: curl -k -v \'{open_project_dashboard_url}\'{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}\n- No Open Project Dashboard vulnerability detected on: {open_project_dashboard_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")

    except Exception as e:
            print(f"{Fore.RED}*  An error occurred while checking {open_project_dashboard_url}: {e}{Style.RESET_ALL}")
    return vulnerabilities