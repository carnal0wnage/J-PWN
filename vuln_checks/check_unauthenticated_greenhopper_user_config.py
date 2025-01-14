import requests
import json
from colorama import Fore, Style

def check_unauthenticated_greenhopper_user_config(base_url):
    """
    Checks for unauthenticated access to the Greenhopper User Config API via /rest/greenhopper/1.0/userData/userConfig.
    """
    print(f"\n{Fore.YELLOW}INFO: Checking for Unauthenticated Access to Greenhopper User Config API{Style.RESET_ALL}")
    
    vulnerabilities = ''  # Initialize a string to store discovered vulnerabilities
    headers = {
        'X-Atlassian-Token': 'no-check'
    }

    try:
        # Construct the target URL
        user_config_url = f"{base_url.rstrip('/')}/rest/greenhopper/1.0/userData/userConfig"
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {user_config_url}")

        # Send the request
        response = requests.get(user_config_url, headers=headers, allow_redirects=False, verify=False)

        # Handle the response
        if response.status_code == 200:
            try:
                data = response.json()
                required_fields = [
                    'canCreateBoard', 'canCreateIssue', 
                    'hasProjectsAccessible', 'hasFiltersAccessible', 'canCreateProject'
                ]

                if all(field in data for field in required_fields):
                    # Mark as vulnerable if all required fields are present
                    vulnerability_detail = f"+ [INFO DISCLOSURE] Unauthenticated Access to Greenhopper User Config: {user_config_url}"
                    vulnerabilities += vulnerability_detail
                    print(f"{Fore.GREEN}[+] [INFO DISCLOSURE] Unauthenticated Access to Greenhopper User Config: {user_config_url}{Style.RESET_ALL}")

                    # Print the parsed details
                    print("\n  User Config Details Found:")
                    print(f"    - Can Create Board: {data.get('canCreateBoard', False)}")
                    print(f"    - Can Create Issue: {data.get('canCreateIssue', False)}")
                    print(f"    - Has Projects Accessible: {data.get('hasProjectsAccessible', False)}")
                    print(f"    - Has Filters Accessible: {data.get('hasFiltersAccessible', False)}")
                    print(f"    - Can Create Project: {data.get('canCreateProject', False)}")
                else:
                    # Report that config data is missing even though the response is 200
                    print(f"{Fore.YELLOW}- HTTP 200: Config data not fully present in response{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}- Missing expected fields in the config data{Style.RESET_ALL}")

            except json.JSONDecodeError:
                print(f"{Fore.RED}* Failed to parse JSON response from: {user_config_url}{Style.RESET_ALL}")

        elif response.status_code == 404:
            print(f"{Fore.YELLOW}- Not Found (404): No access to Greenhopper User Config{Style.RESET_ALL}")
        elif response.status_code == 401:
            print(f"{Fore.YELLOW}- Unauthorized (401): Authentication required for Greenhopper User Config{Style.RESET_ALL}")
        elif response.status_code == 302:
            location = response.headers.get("Location", "No Location header found")
            print(f"{Fore.YELLOW}- Redirected (302) to {location}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}- HTTP {response.status_code}: No Unauthenticated Access to Greenhopper User Config Found{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}* An error occurred while checking {base_url}: {e}{Style.RESET_ALL}")

    return vulnerabilities  # Return the discovered vulnerabilities
