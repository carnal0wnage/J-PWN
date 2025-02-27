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

def check_open_jira_signup(url):
    '''
    Checks for open Jira signup. Manually attempt to signup
    '''
    signup_url = f"{url.rstrip('/')}/secure/Signup!default.jspa"
    vulnerabilities  = ''
    headers = {
        'X-Atlassian-Token': 'no-check'
    }

    try:
        print(f"{Fore.YELLOW}\nINFO: Checking for Open JIRA Signup")
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {signup_url}")
        response = requests.get(signup_url, headers=headers, allow_redirects=False, verify=False)

        # Check for the vulnerability
        if response.status_code == 200:
            response_text = response.text
            # print(response_text) #DEBUG
            if ("Sorry, you can&#39;t sign up to this Jira" in response_text or "Sorry, you can&#39;t sign up to this JIRA site" in response_text or "No puede registrarse" in response_text or "Извините, в данный момент" in response_text):
                print(f"{Fore.YELLOW}\n- No Open Signup vulnerability detected on: {signup_url}") 
                # print(f"  URL: {contact_admin_url}")
            else:
 
                vulnerabilities += (f"+ [Initial Access] Open Signup Page: Manual exploitation required [try to signup and log in] | URL: {signup_url}")
                print(f"\n{Fore.GREEN}+ [Initial Access] Open Signup Page Found: Manual exploitation required [try to signup and log in]{Style.RESET_ALL}")
                print(f"  URL: {signup_url}")
                print(f"  Note: Exploitation requires manual steps.")
                #print(response_text)
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}\n- No Open Jira Signup detected on: {signup_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")
        elif response.status_code == 302:
            location = response.headers.get("Location", "No Location header found") 
            print(f"{Fore.YELLOW}- Redirection Detected (302) for: {signup_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- Location Header: {location}")
            print(f"{Fore.YELLOW}- This program doesnt follow 302 - Try: curl -k -v \'{signup_url}\'{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}\n- No Open Jira Signup detected on: {signup_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")

    except Exception as e:
            print(f"{Fore.RED}*  An error occurred while checking {signup_url}: {e}{Style.RESET_ALL}")
    return vulnerabilities
