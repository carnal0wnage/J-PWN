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

def check_unauthenticated_screens(base_url):
    """
    Checks for unauthenticated access to Screens via /rest/api/2/screens.
    """
    print(f"\n{Fore.YELLOW}INFO: Checking for Unauthenticated Access to Screens{Style.RESET_ALL}")
    
    vulnerabilities = ''  # Initialize a string to store discovered vulnerabilities

    try:
        # Construct the target URL
        check_unauth_screens_url = f"{base_url.rstrip('/')}/rest/api/2/screens"
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {check_unauth_screens_url}")

        # Send the request
        response = requests.get(check_unauth_screens_url, allow_redirects=False, verify=False)

        # Check if the response indicates unauthenticated access
        if response.status_code == 200:
            try:
                data = response.json()  # Parse the JSON response

                if isinstance(data, list) and data:  # Ensure data is a non-empty list
                    vulnerabilities += f"+ [Info Disclosure] Unauthenticated Access to Screens: {check_unauth_screens_url}"
                    print(f"{Fore.GREEN}[+] [Info Disclosure] Unauthenticated Access to Screens: {check_unauth_screens_url}{Style.RESET_ALL}")
                    print("\n  Screens Details:")

                    # Print details for each screen
                    for screen in data:
                        screen_id = screen.get("id", "N/A")
                        screen_name = screen.get("name", "N/A")
                        screen_description = screen.get("description", "N/A")

                        print(f"    - ID: {screen_id}")
                        print(f"      Name: {screen_name}")
                        print(f"      Description: {screen_description}\n")
                else:
                    print(f"{Fore.YELLOW}- No screens found (Empty Results).{Style.RESET_ALL}")
            except json.JSONDecodeError:
                print(f"{Fore.RED}- Failed to parse JSON response from: {check_unauth_screens_url}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}- No Unauthenticated Access to Screens Found{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Code: {response.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}* An error occurred while checking {base_url}: {e}{Style.RESET_ALL}")

    return vulnerabilities  # Return the discovered vulnerabilities
