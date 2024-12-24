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

# Check for unauthenticated access to JIRA project categories
def check_unauthenticated_project_categories(url):
    project_category_url = f"{url}rest/api/2/projectCategory?maxResults=1000"
    vulnerabilities = ''  # Local vulnerabilities list

    try:
        response = requests.get(project_category_url, verify=False)

        # Check for unauthenticated access and parse the response
        if response.status_code == 200:
            vulnerabilities += (f"+ Unauthenticated access to JIRA project categories | URL : {project_category_url}")

            data = response.json()

            print(f"\n{Fore.GREEN}+ Unauthenticated Access to JIRA Project Categories Detected\n++ Manually check these for Unauthenticated Access ++{Style.RESET_ALL}")
            print(f"  URL: {project_category_url}")
            print("\n  Project Categories Details:")
            
            if data:
                for category in data:
                    category_self = category.get("self", "N/A")
                    category_id = category.get("id", "N/A")
                    description = category.get("description", "N/A")
                    name = category.get("name", "N/A")

                    print(f"    - ID: {category_id}")
                    print(f"      Name: {name}")
                    print(f"      Description: {description}")
                    print(f"      API URL: {category_self}")
            else:
                print("    No project categories found.")
        else:
            print(f"{Fore.YELLOW}\n- No unauthenticated access to JIRA project categories detected on: {project_category_url}{Style.RESET_ALL}")
    except json.JSONDecodeError:
        print(f"{Fore.RED}- Failed to parse JSON response from: {project_category_url}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred while checking {project_category_url}: {e}{Style.RESET_ALL}")
    return vulnerabilities
