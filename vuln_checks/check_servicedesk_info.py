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


def check_servicedesk_info(url):
    print(f"{Fore.YELLOW}\n[INFO] JIRA Service Desk Checks{Style.RESET_ALL}")
    servicedesk_url = f"{url.rstrip('/')}/rest/servicedeskapi/info"
    vulnerabilities = ''

    try:
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {servicedesk_url}")
        response = requests.get(servicedesk_url, allow_redirects=False, verify=False)

        if response.status_code == 200:
            print(f"{Fore.GREEN}+ Service Desk Found & API is accessible at: {url}{Style.RESET_ALL}")

            data = response.json()

            version = data.get("version", "N/A")
            platform_version = data.get("platformVersion", "N/A")
            build_date = data.get("buildDate", {}).get("friendly", "N/A")
            build_changeset = data.get("buildChangeSet", "N/A")
            is_licensed = data.get("isLicensedForUse", False)

            print("\nService Desk Information:")
            print(f"  Version           : {version}")
            print(f"  Platform Version  : {platform_version}")
            print(f"  Build Date        : {build_date}")
            print(f"  Build Change Set  : {build_changeset}")
            print(f"  Licensed for Use  : {is_licensed}")
        else:
            print(f"{Fore.YELLOW}- Unable to access Service Desk API at: {servicedesk_url}{Style.RESET_ALL}")

    except requests.exceptions.JSONDecodeError:
        print(f"{Fore.RED}- Failed to parse JSON response from: {servicedesk_url}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred while checking {servicedesk_url}: {e}{Style.RESET_ALL}")
    return vulnerabilities 