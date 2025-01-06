import requests
from urllib.parse import urlparse
from colorama import Fore, Style

def check_unauthenticated_priority_access(base_url):
    """
    Checks for unauthenticated access to the Priority API via /rest/api/2/priority.
    """
    print(f"\n{Fore.YELLOW}INFO: Checking for Unauthenticated Access to Priority API{Style.RESET_ALL}")
    
    vulnerabilities = ''  # Initialize a string to store discovered vulnerabilities

    try:
        # Construct the target URL
        priority_url = f"{base_url.rstrip('/')}/rest/api/2/priority"
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {priority_url}")

        # Send the request
        response = requests.get(priority_url, allow_redirects=False, verify=False)

        # Check if the response indicates unauthenticated access
        if response.status_code == 200:
            vulnerabilities += f"+ [Info Disclosure] Unauthenticated access to Priority API | URL : {priority_url}"
            print(f"{Fore.GREEN}[+] [Info Disclosure] Unauthenticated Access to Priority API: {priority_url}{Style.RESET_ALL}")

            # Parse and print priority details
            try:
                data = response.json()
                print("\n  Priority Details:")

                if data:
                    for priority in data:
                        priority_id = priority.get("id", "N/A")
                        name = priority.get("name", "N/A")
                        description = priority.get("description", "N/A")
                        status_color = priority.get("statusColor", "N/A")
                        icon_url = priority.get("iconUrl", "N/A")
                        self_url = priority.get("self", "N/A")

                        print(f"    - ID: {priority_id}")
                        print(f"      Name: {name}")
                        print(f"      Description: {description}")
                        print(f"      Status Color: {status_color}")
                        print(f"      Icon URL: {icon_url}")
                        print(f"      API URL: {self_url}\n")
                else:
                    print("    No priorities found.")
            except json.JSONDecodeError:
                print(f"{Fore.RED}* Failed to parse JSON response from: {priority_url}{Style.RESET_ALL}")
        elif response.status_code == 200:
            print(f"{Fore.YELLOW}- HTTP 200 but no relevant priorities found.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}- No unauthenticated access to Priority API found{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Code: {response.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}* An error occurred while checking {base_url}: {e}{Style.RESET_ALL}")

    return vulnerabilities  # Return the discovered vulnerabilities