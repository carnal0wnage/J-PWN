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

# Check for unauthenticated access to JIRA admin projects

def check_unauthenticated_admin_projects(url):
    admin_projects_url = f"{url.rstrip('/')}/rest/menu/latest/admin?maxResults=1000"
    vulnerabilities = ''  # Local vulnerabilities list
    headers = {
        'X-Atlassian-Token': 'no-check'
    }

    try:
        print(f"{Fore.YELLOW}\nINFO: Checking for Unauthenticated Access to JIRA Admin Projects{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {admin_projects_url}")
        response = requests.get(admin_projects_url, headers=headers, allow_redirects=False, verify=False)

        # Check for unauthenticated access and parse the response
        if response.status_code == 200:
            vulnerabilities += (f"+ [Info Disclosure] Unauthenticated access to JIRA admin projects | URL : {admin_projects_url}")

            data = response.json()

            print(f"\n{Fore.GREEN}+ Unauthenticated Access to JIRA Admin Projects Detected{Style.RESET_ALL}")
            print(f"  URL: {admin_projects_url}")
            print("\n  Admin Projects Details:")
            
            if data:
                for project in data:
                    key = project.get("key", "N/A")
                    link = project.get("link", "N/A")
                    label = project.get("label", "N/A")
                    tooltip = project.get("tooltip", "N/A")
                    local = project.get("local", "N/A")
                    self_field = project.get("self", "N/A")
                    app_type = project.get("applicationType", "N/A")

                    print(f"    - Key: {key}")
                    print(f"      Link: {link}")
                    print(f"      Label: {label}")
                    print(f"      Tooltip: {tooltip}")
                    print(f"      Local: {local}")
                    print(f"      Self: {self_field}")
                    print(f"      Application Type: {app_type}")
            else:
                print("    No admin projects found.")
        else:
            print(f"{Fore.YELLOW}\n- No unauthenticated access to JIRA admin projects detected on: {admin_projects_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Code: {response.status_code}{Style.RESET_ALL}")
    except json.JSONDecodeError:
        print(f"{Fore.RED}- Failed to parse JSON response from: {admin_projects_url}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred while checking {admin_projects_url}: {e}{Style.RESET_ALL}")

    return vulnerabilities