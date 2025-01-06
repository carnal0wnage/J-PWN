import requests
from urllib.parse import urlparse
from colorama import Fore, Style

def check_unauthenticated_greenhopper_user_config(base_url):
    """
    Checks for unauthenticated access to the Greenhopper User Config API via /rest/greenhopper/1.0/userData/userConfig.
    """
    print(f"\n{Fore.YELLOW}INFO: IN DEVELOPMENT - Checking for Unauthenticated Access to Greenhopper User Config API{Style.RESET_ALL}")
    
    vulnerabilities = ''  # Initialize a string to store discovered vulnerabilities

    try:
        # Construct the target URL
        user_config_url = f"{base_url.rstrip('/')}/rest/greenhopper/1.0/userData/userConfig"
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {user_config_url}")

        # Send the request
        response = requests.get(user_config_url, allow_redirects=False, verify=False)

        # Check if the response indicates unauthenticated access
        if response.status_code == 200 and any(key in response.text for key in ["canCreateBoard", "displayName", "canCreateIssue", "hasProjectsAccessible", "hasFiltersAccessible", "canCreateProject", "name", "avatarUrl"]):
            vulnerability_detail = f"+ [INFO DISCLOSURE] Unauthenticated Access to Greenhopper User Config: {user_config_url}"
            vulnerabilities += vulnerability_detail
            print(f"{Fore.GREEN}[+] [INFO DISCLOSURE] Unauthenticated Access to Greenhopper User Config: {user_config_url}{Style.RESET_ALL}")

            # Optionally, print the response details for manual inspection
            try:
                data = response.json()
                print("\n  User Config Details Found:")
                for user in data:
                    username = user.get("username", "Unknown Username")
                    email = user.get("emailAddress", "Unknown Email")
                    display_name = user.get("displayName", "Unknown Display Name")
                    active = user.get("active", "Unknown Status")
                    print(f"    - Username: {username}")
                    print(f"      Email: {email}")
                    print(f"      Display Name: {display_name}")
                    print(f"      Active: {active}")
            except json.JSONDecodeError:
                print(f"{Fore.RED}* Failed to parse JSON response from: {user_config_url}{Style.RESET_ALL}")
        elif response.status_code == 200: 
            print(f"{Fore.YELLOW}- HTTP 200 but empty response {Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Code: {response.status_code}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}- No Unauthenticated Access to Greenhopper User Config Found{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Code: {response.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}* An error occurred while checking {base_url}: {e}{Style.RESET_ALL}")

    return vulnerabilities  # Return the discovered vulnerabilities
