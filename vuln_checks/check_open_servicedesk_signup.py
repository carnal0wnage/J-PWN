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

def check_open_servicedesk_signup(url):
    '''
    Checks for open service desk. You should mannually attempt to signup
    '''
    service_desk_url = f"{url}servicedesk/customer/user/signup"
    vulnerabilities = ''
        
    try:
        print(f"{Fore.YELLOW}\nINFO: Checking for Open Service Desk Signup")
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {service_desk_url}")
        response = requests.get(service_desk_url, allow_redirects=False, verify=False)

        # Check for the vulnerability
        if response.status_code == 200:
            response_text = response.text
            # print(response_text) #DEBUG


            vulnerabilities += (f"+ Open Service Desk Signup Found: Manual exploitation required [try to signup and log in] | URL: {service_desk_url}")
            print(f"\n{Fore.GREEN}+ Open Service Desk Signup Found: Manual exploitation required [try to signup and log in]{Style.RESET_ALL}")
            print(f"  URL: {service_desk_url}")
            print(f"  Note: Exploitation requires manual steps.")
            print(f"  Note: Refer to: https://medium.com/@intideceukelaire/hundreds-of-internal-servicedesks-exposed-due-to-covid-19-ecd0baec87bd")
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}\n- No Open Service Desk vulnerability detected on: {service_desk_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")
        elif response.status_code == 302:
            location = response.headers.get("Location", "No Location header found") 
            print(f"{Fore.YELLOW}- Redirection Detected (302) for: {service_desk_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- Location Header: {location}")
            print(f"{Fore.YELLOW}- This program doesnt follow 302 - Try: curl -k -v \'{service_desk_url}\'{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}\n- No Open Service Desk vulnerability detected on: {service_desk_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")

    except Exception as e:
            print(f"{Fore.RED}*  An error occurred while checking {service_desk_url}: {e}{Style.RESET_ALL}")
    return vulnerabilities