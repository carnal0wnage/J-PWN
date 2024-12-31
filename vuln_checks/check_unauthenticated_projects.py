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

def check_unauthenticated_projects(url):
    """
    Checks for unauthenticated access to JIRA projects via /rest/api/2/project.
    """
    project_url = f"{url.rstrip('/')}/rest/api/2/project?maxResults=100"
    vulnerabilities = ''  # Local vulnerabilities list

    try:
        print(f"{Fore.YELLOW}\nINFO: Checking for Unauthenticated Access to JIRA Projects{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {project_url}")
        response = requests.get(project_url, verify=False)

        if response.status_code == 200:
            # Parse the JSON response
            data = response.json()

            if isinstance(data, list) and not data:  # Check for an empty list
                print(f"{Fore.YELLOW}- No projects found (Empty Results).{Style.RESET_ALL}")
                pass
                # return "empty results"
            elif isinstance(data, list) and data:
                # If data is not empty, continue processing
                vulnerabilities += f"+ [Info Disclosure] Unauthenticated access to JIRA projects | URL : {project_url}"

                print(f"\n{Fore.GREEN}+ Unauthenticated Access to JIRA Projects Detected{Style.RESET_ALL}")
                print(f"  URL: {project_url}")
                print("\n  Projects Details:")

                for project in data:
                    project_id = project.get("id", "N/A")
                    key = project.get("key", "N/A")
                    name = project.get("name", "N/A")
                    project_type = project.get("projectTypeKey", "N/A")
                    self_url = project.get("self", "N/A")

                    print(f"    - ID: {project_id}")
                    print(f"      Key: {key}")
                    print(f"      Name: {name}")
                    print(f"      Type: {project_type}")
                    print(f"      API URL: {self_url}\n")
        else:
            print(f"{Fore.YELLOW}- No unauthenticated access to JIRA projects detected on: {project_url}{Style.RESET_ALL}")

    except requests.exceptions.JSONDecodeError:
        print(f"{Fore.RED}- Failed to parse JSON response from: {project_url}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred while checking {project_url}: {e}{Style.RESET_ALL}")

    return vulnerabilities  # Return the vulnerabilities
