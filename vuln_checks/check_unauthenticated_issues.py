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


def check_unauthenticated_issues(url):
    """
    Checks for Unauthenticated Issues with content vulnerability in Jira and parses the response.
    """
    check_unauthenticated_issues_url = f"{url.rstrip('/')}/rest/api/2/search?jql=ORDER%20BY%20Created&maxResults=2"
    vulnerabilities = ''
    headers = {
        'X-Atlassian-Token': 'no-check'
    }

    try:
        print(f"{Fore.YELLOW}\nINFO: Checking for Unauthenticated Issues with Content{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {check_unauthenticated_issues_url}")
        response = requests.get(check_unauthenticated_issues_url, headers=headers, allow_redirects=False, verify=False)

        # Check for the vulnerability
        if response.status_code == 200:
            response_json = response.json()  # Parse the JSON response

            total_issues = response_json.get("total", 0)
            issues = response_json.get("issues", [])

            if total_issues == 0:
                print(f"{Fore.YELLOW}- No unauthenticated issues detected [HTTP 200 but 0 results] at: {check_unauthenticated_issues_url}{Style.RESET_ALL}")
            else:
                vulnerabilities += f"+ [Info Disclosure] Unauthenticated Issues Detected | URL: {check_unauthenticated_issues_url}"
                print(f"{Fore.GREEN}+ [Info Disclosure] Unauthenticated Issues Detected{Style.RESET_ALL}")
                print(f"  URL: {check_unauthenticated_issues_url}")
                print(f"  Total Issues: {total_issues} - Printing first 2 for validation\n")

                # Iterate through each issue and print details
                for issue in issues:
                    issue_id = issue.get("id", "N/A")
                    issue_key = issue.get("key", "N/A")
                    summary = issue.get("fields", {}).get("summary", "N/A")
                    description = issue.get("fields", {}).get("description", "N/A")
                    status = issue.get("fields", {}).get("status", {}).get("name", "N/A")
                    priority = issue.get("fields", {}).get("priority", {}).get("name", "N/A")
                    reporter = issue.get("fields", {}).get("reporter", {}).get("displayName", "N/A")
                    created = issue.get("fields", {}).get("created", "N/A")

                    print(f"Issue ID      : {issue_id}")
                    print(f"Issue Key     : {issue_key}")
                    print(f"Summary       : {summary}")
                    print(f"Description   : {description}")
                    print(f"Status        : {status}")
                    print(f"Priority      : {priority}")
                    print(f"Reporter      : {reporter}")
                    print(f"Created Date  : {created}")
                    print("-" * 50)

        elif response.status_code == 403:
            print(f"{Fore.YELLOW}- HTTP Status Code 403: Access Denied at: {check_unauthenticated_issues_url}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}- No unauthenticated issues detected at: {check_unauthenticated_issues_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}* An error occurred while checking {check_unauthenticated_issues_url}: {e}{Style.RESET_ALL}")

    return vulnerabilities

