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

def check_unauthenticated_dashboard_access(url):
    dashboard_url = f"{url}rest/api/2/dashboard?maxResults=100"
    vulnerabilities = ''  # Local vulnerabilities list

    try:
        print(f"{Fore.YELLOW}\nINFO: Checking for Unauthenticated Access to JIRA Dashboards{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {dashboard_url}")
        response = requests.get(dashboard_url, verify=False)

        # Check for unauthenticated access and parse the response
        if response.status_code == 200:
            vulnerabilities += (f"+ [Info Disclosure] Unauthenticated access to JIRA dashboards | URL : {dashboard_url}")

            data = response.json()
            start_at = data.get("startAt", "N/A")
            max_results = data.get("maxResults", "N/A")
            total_dashboards = data.get("total", "N/A")
            dashboards = data.get("dashboards", [])

            print(f"\n{Fore.GREEN}+ Unauthenticated Access to JIRA Dashboards Detected{Style.RESET_ALL}")
            print(f"  URL: {dashboard_url}")
            print(f"  Start At: {start_at}")
            print(f"  Max Results: {max_results}")
            print(f"  Total Dashboards: {total_dashboards}")
            print("\n  Dashboard Details:")
            
            if dashboards:
                for dashboard in dashboards:
                    dashboard_id = dashboard.get("id", "N/A")
                    name = dashboard.get("name", "N/A")
                    self_url = dashboard.get("self", "N/A")
                    view_url = dashboard.get("view", "N/A")
                    print(f"    - ID: {dashboard_id}")
                    print(f"      Name: {name}")
                    print(f"      API URL: {self_url}")
                    print(f"      View URL: {view_url}")
            else:
                print("    No dashboards found.")
        else:
            print(f"{Fore.YELLOW}\n- No unauthenticated access to JIRA dashboards detected on: {dashboard_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Code: {response.status_code}{Style.RESET_ALL}")
    except json.JSONDecodeError:
        print(f"{Fore.RED}- Failed to parse JSON response from: {dashboard_url}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred while checking {dashboard_url}: {e}{Style.RESET_ALL}")
    # print(f"dashboard vulns: {vulnerabilities}")
    return vulnerabilities  # Return the list of vulnerabilities