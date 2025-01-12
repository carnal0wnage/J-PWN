import requests
from colorama import Fore, Style

def check_anonymous_permissions(url):
    """
    Checks for unauthorized access to the /rest/api/2/mypermissions endpoint.
    Marks as vulnerable if 'havePermission': true is found in any permission.
    Handles 302, 404, and 401 errors appropriately.
    """
    mypermissions_url = f"{url.rstrip('/')}/rest/api/2/mypermissions"
    vulnerabilities = ''
    headers = {
        'X-Atlassian-Token': 'no-check'
    }

    try:
        print(f"{Fore.YELLOW}\nINFO: Checking for Unauthorized Access to MyPermissions{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {mypermissions_url}")
        response = requests.get(mypermissions_url, headers=headers, allow_redirects=False, verify=False)

        if response.status_code == 200:
            data = response.json()
            permissions = data.get("permissions", {})
            vulnerable_permissions = []

            for key, details in permissions.items():
                if details.get("havePermission"):
                    vulnerable_permissions.append({
                        "id": details.get("id"),
                        "key": details.get("key"),
                        "name": details.get("name"),
                        "description": details.get("description")
                    })

            if vulnerable_permissions:
                vulnerabilities += f"+ [Info Disclosure] Unauthorized access to MyPermissions | URL: {mypermissions_url}\n"
                print(f"\n{Fore.GREEN}+ Vulnerable: The following permissions have 'havePermission': true [Manually Inspect]{Style.RESET_ALL}")
                for permission in vulnerable_permissions:
                    print(f"  - ID: {permission['id']}")
                    print(f"    Key: {permission['key']}")
                    print(f"    Name: {permission['name']}")
                    print(f"    Description: {permission['description']}")
            else:
                print(f"\n{Fore.YELLOW}[-] Not Vulnerable: No permissions with 'havePermission': true found{Style.RESET_ALL}")
        elif response.status_code == 302:
            location = response.headers.get("Location", "No Location header found")
            print(f"{Fore.YELLOW}- Redirection Detected (302) for: {mypermissions_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- Location Header: {location}{Style.RESET_ALL}")
        elif response.status_code == 404:
            print(f"{Fore.YELLOW}- Not Found (404): The endpoint {mypermissions_url} does not exist{Style.RESET_ALL}")
        elif response.status_code == 401:
            print(f"{Fore.YELLOW}- Unauthorized (401): Access denied to {mypermissions_url}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}- Unexpected Status Code {response.status_code} for: {mypermissions_url}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}* An error occurred while checking {mypermissions_url}: {e}{Style.RESET_ALL}")
    
    return vulnerabilities
