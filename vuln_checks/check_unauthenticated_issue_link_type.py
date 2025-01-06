import requests
from urllib.parse import urlparse
from colorama import Fore, Style

def check_unauthenticated_issue_link_type(base_url):
    """
    Checks for unauthenticated access to the Issue Link Type API via /rest/api/2/issueLinkType.
    """
    print(f"\n{Fore.YELLOW}INFO: Checking for Unauthenticated Access to Issue Link Type API{Style.RESET_ALL}")
    
    vulnerabilities = ''  # Initialize a string to store discovered vulnerabilities

    try:
        # Construct the target URL
        issue_link_type_url = f"{base_url.rstrip('/')}/rest/api/2/issueLinkType"
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {issue_link_type_url}")

        # Send the request
        response = requests.get(issue_link_type_url, allow_redirects=False, verify=False)

        # Check if the response indicates unauthenticated access
        if response.status_code == 200:
            vulnerabilities += f"+ [Info Disclosure] Unauthenticated access to Issue Link Types | URL : {issue_link_type_url}"
            print(f"{Fore.GREEN}[+] [Info Disclosure] Unauthenticated Access to Issue Link Types: {issue_link_type_url}{Style.RESET_ALL}")

            # Parse and print issue link type details
            try:
                data = response.json()
                issue_link_types = data.get("issueLinkTypes", [])
                print("\n  Issue Link Type Details:")

                if issue_link_types:
                    for link_type in issue_link_types:
                        link_id = link_type.get("id", "N/A")
                        name = link_type.get("name", "N/A")
                        inward = link_type.get("inward", "N/A")
                        outward = link_type.get("outward", "N/A")
                        self_url = link_type.get("self", "N/A")

                        print(f"    - ID: {link_id}")
                        print(f"      Name: {name}")
                        print(f"      Inward: {inward}")
                        print(f"      Outward: {outward}")
                        print(f"      API URL: {self_url}\n")
                else:
                    print("    No issue link types found.")
            except json.JSONDecodeError:
                print(f"{Fore.RED}* Failed to parse JSON response from: {issue_link_type_url}{Style.RESET_ALL}")
        elif response.status_code == 200:
            print(f"{Fore.YELLOW}- HTTP 200 but no relevant issue link types found.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}- No unauthenticated access to Issue Link Types found{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Code: {response.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}* An error occurred while checking {base_url}: {e}{Style.RESET_ALL}")

    return vulnerabilities  # Return the discovered vulnerabilities
