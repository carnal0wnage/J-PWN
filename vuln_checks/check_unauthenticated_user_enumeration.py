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

def check_unauthenticated_user_enumeration(url):
    '''
    Checks for open service desk. You should mannually attempt to signup
    '''
    unauthenticated_user_enumeration_url = f"{url}secure/popups/UserPickerBrowser.jspa"
    vulnerabilities = ''
        
    try:
        print(f"{Fore.YELLOW}\nINFO: Checking for Unauthenticated User Enumeration (UserPickerBrowser.jspa)")
        response = requests.get(unauthenticated_user_enumeration_url, allow_redirects=False, verify=False)

        # Check for the vulnerability
        if response.status_code == 200:
            response_text = response.text
            # print(response_text) #DEBUG


            vulnerabilities += (f"+ [Info Disclosure] UnauthenticatedUser Enumeration Found | URL: {unauthenticated_user_enumeration_url}")
            print(f"\n{Fore.GREEN}+ Unauthenticated User Enumeration [Manually Inspect] {Style.RESET_ALL}")
            print(f"  URL: {unauthenticated_user_enumeration_url}")
           
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}\n- No Unauthenticated User Enumeration vulnerability detected on: {unauthenticated_user_enumeration_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")
        elif response.status_code == 302:
            location = response.headers.get("Location", "No Location header found") 
            print(f"{Fore.YELLOW}- Redirection Detected (302) for: {unauthenticated_user_enumeration_url}{Style.RESET_ALL}")
            if "login.jsp?permissionViolation=true" in location:
                print(f"{Fore.YELLOW}- Detected redirect to login.jsp - Not VULN")
            else:
                print(f"{Fore.YELLOW}- Location Header: {location}")
                print(f"{Fore.YELLOW}- This program doesnt follow 302 - Try: curl -k -v \'{unauthenticated_user_enumeration_url}\'{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}\n- No Unauthenticated User Enumeration vulnerability detected on: {unauthenticated_user_enumeration_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")

    except Exception as e:
            print(f"{Fore.RED}*  An error occurred while checking {unauthenticated_user_enumeration_url}: {e}{Style.RESET_ALL}")
    return vulnerabilities