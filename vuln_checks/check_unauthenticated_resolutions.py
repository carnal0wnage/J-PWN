import argparse
import requests
from urllib.parse import urlparse
import colorama
from colorama import Fore, Style
import time
import os
import sys
import random
import json
from urllib.parse import urlparse
import urllib3

def check_unauthenticated_resolutions(url):
    resolution_url = f"{url}rest/api/2/resolution"
    vulnerabilities = ''  # Local vulnerabilities list

    try:
        response = requests.get(resolution_url, verify=False)

        if response.status_code == 200:
            vulnerabilities += (f"+ Unauthenticated access to JIRA resolutions | URL : {resolution_url}")

            data = response.json()

            print(f"\n{Fore.GREEN}+ Unauthenticated Access to JIRA Resolutions Detected{Style.RESET_ALL}")
            print(f"  URL: {resolution_url}")
            print("\n  Resolutions Details:")

            if data:
                for resolution in data:
                    resolution_id = resolution.get("id", "N/A")
                    name = resolution.get("name", "N/A")
                    description = resolution.get("description", "N/A")
                    self_url = resolution.get("self", "N/A")

                    print(f"    - ID: {resolution_id}")
                    print(f"      Name: {name}")
                    print(f"      Description: {description}")
                    print(f"      API URL: {self_url}")
            else:
                print("    No resolutions found.")
        else:
            print(f"{Fore.YELLOW}\n- No unauthenticated access to JIRA resolutions detected on: {resolution_url}{Style.RESET_ALL}")

    except requests.exceptions.JSONDecodeError:
        print(f"{Fore.RED}- Failed to parse JSON response from: {resolution_url}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred while checking {resolution_url}: {e}{Style.RESET_ALL}")

    return vulnerabilities  # Return the vulnerabilities

