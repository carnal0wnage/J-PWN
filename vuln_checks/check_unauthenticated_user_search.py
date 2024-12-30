import requests
from urllib.parse import urlparse
from colorama import Fore, Style

def check_unauthenticated_user_search(base_url):
    """
    Checks for unauthenticated access to the User Search API via /rest/api/2/user/search.
    """
    print(f"\n{Fore.YELLOW}INFO: Checking for Unauthenticated Access to User Search API{Style.RESET_ALL}")
    
    vulnerabilities = ''  # Initialize a string to store discovered vulnerabilities

    try:
        # Construct the target URL
        user_search_url = f"{base_url.rstrip('/')}/rest/api/2/user/search?username=.&maxResults=1000"
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {user_search_url}")

        # Send the request
        response = requests.get(user_search_url, allow_redirects=False, verify=False)

        # Check if the response indicates unauthenticated access
        if response.status_code == 200 and any(key in response.text for key in ["name", "key", "emailAddress"]):
            vulnerability_detail = f"[INFO DISCLOSURE] Unauthenticated Access to User Search: {user_search_url}"
            vulnerabilities += vulnerability_detail
            print(f"{Fore.GREEN}[+] [INFO DISCLOSURE] Unauthenticated Access to User Search: {user_search_url}{Style.RESET_ALL}")

            # Optionally, print the response details for manual inspection
            try:
                data = response.json()
                print("\n  User Details Found:")
                for user in data:
                    username = user.get("name", "Unknown Username")
                    email = user.get("emailAddress", "Unknown Email")
                    display_name = user.get("displayName", "Unknown Display Name")
                    active = user.get("active", "Unknown Status")
                    print(f"    - Username: {username}")
                    print(f"      Email: {email}")
                    print(f"      Display Name: {display_name}")
                    print(f"      Active: {active}")
            except json.JSONDecodeError:
                print(f"{Fore.RED}* Failed to parse JSON response from: {user_search_url}{Style.RESET_ALL}")
        elif response.status_code == 200: 
            print(f"{Fore.YELLOW}- HTTP 200 but empty response {Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Code: {response.status_code}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}- No Unauthenticated Access to User Search Found{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Code: {response.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}* An error occurred while checking {base_url}: {e}{Style.RESET_ALL}")

    return vulnerabilities  # Return the discovered vulnerabilities
