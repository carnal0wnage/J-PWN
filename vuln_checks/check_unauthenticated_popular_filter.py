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

def check_unauthenticated_popular_filter(url):
    '''
    Checks for unauthenticated popular filter
    '''
    open_popular_filter_url = f"{url.rstrip('/')}/secure/ManageFilters.jspa?filterView=search&Search=Search&filterView=search&sortColumn=favcount&sortAscending=false"
    vulnerabilities = ''
    headers = {
        'X-Atlassian-Token': 'no-check'
    }
        
    try:
        print(f"{Fore.YELLOW}\nINFO: IN DEVELOPMENT - Unauthenticated Popular Filter")
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {open_popular_filter_url}")
        response = requests.get(open_popular_filter_url, headers=headers, allow_redirects=False, verify=False)

        # Check for the vulnerability
        if response.status_code == 200:
            response_text = response.text
            # print(response_text) #DEBUG


            vulnerabilities += (f"+ [Info Disclosure] Unauthenticated Popular Dashboar Filter Found | URL: {open_popular_filter_url}")
            print(f"\n{Fore.GREEN}+ Unauthenticated Popular Dashboard Filter [Manually Inspect] {Style.RESET_ALL}")
            print(f"  URL: {open_popular_filter_url}")
           
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}\n- Unauthenticated Popular Filter vulnerability detected on: {open_popular_filter_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")
        elif response.status_code == 302:
            location = response.headers.get("Location", "No Location header found") 
            print(f"{Fore.YELLOW}- Redirection Detected (302) for: {open_popular_filter_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- Location Header: {location}")
            print(f"{Fore.YELLOW}- This program doesnt follow 302 - Try: curl -k -v \'{open_popular_filter_url}\'{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}\n- Unauthenticated Popular Dashboard Filter vulnerability detected on: {open_popular_filter_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")

    except Exception as e:
            print(f"{Fore.RED}*  An error occurred while checking {open_popular_filter_url}: {e}{Style.RESET_ALL}")
    return vulnerabilities