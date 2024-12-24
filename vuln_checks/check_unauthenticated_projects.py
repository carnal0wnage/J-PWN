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
    project_url = f"{url}rest/api/2/project?maxResults=100"
    vulnerabilities = ''  # Local vulnerabilities list

    try:
        response = requests.get(project_url, verify=False)

        if response.status_code == 200:
            vulnerabilities += (f"+ Unauthenticated access to JIRA projects | URL : {project_url}")

            data = response.json()

            print(f"\n{Fore.GREEN}+ Unauthenticated Access to JIRA Projects Detected{Style.RESET_ALL}")
            print(f"  URL: {project_url}")
            print("\n  Projects Details:")

            if data:
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
                print("    No projects found.")
        else:
            print(f"{Fore.YELLOW}\n- No unauthenticated access to JIRA projects detected on: {project_url}{Style.RESET_ALL}")

    except requests.exceptions.JSONDecodeError:
        print(f"{Fore.RED}- Failed to parse JSON response from: {project_url}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred while checking {project_url}: {e}{Style.RESET_ALL}")

    return vulnerabilities  # Return the vulnerabilities
