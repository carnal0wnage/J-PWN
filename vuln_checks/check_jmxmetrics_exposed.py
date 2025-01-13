import requests
from colorama import Fore, Style

def check_jmxmetrics_exposed(url):
    """
    Checks if JMX metrics and other monitoring endpoints are exposed.
    Targets the following endpoints:
    - /rest/api/2/monitoring/jmx/areMetricsExposed
    - /rest/api/2/monitoring/ipd
    - /rest/api/2/monitoring/jmx/getAvailableMetrics
    Marks as vulnerable if metrics or data are exposed.
    Handles 302, 404, and 401 errors appropriately.
    """
    endpoints = [
        "/rest/api/2/monitoring/jmx/areMetricsExposed",
        "/rest/api/2/monitoring/ipd",
        "/rest/api/2/monitoring/jmx/getAvailableMetrics"
    ]
    vulnerabilities = ''
    headers = {
        'X-Atlassian-Token': 'no-check'
    }

    for endpoint in endpoints:
        try:
            full_url = f"{url.rstrip('/')}{endpoint}"
            print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {full_url}")
            response = requests.get(full_url, headers=headers, allow_redirects=False, verify=False)

            if response.status_code == 200:
                if endpoint == "/rest/api/2/monitoring/jmx/areMetricsExposed":
                    data = response.json()
                    if data.get("exposed", False):
                        vulnerabilities += f"+ [Info Disclosure] JMX Metrics Exposed | URL: {full_url}\n"
                        print(f"\n{Fore.GREEN}+ Vulnerable: JMX Metrics are exposed{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.BLUE}[-] Not Vulnerable: JMX Metrics are not exposed{Style.RESET_ALL}")
                else:
                    print(f"\n{Fore.GREEN}+ Vulnerable: Data retrieved from {endpoint}{Style.RESET_ALL}")
                    print(f"  URL: {full_url}")
                    print(f"  Response: {response.json()}")  # Print the response for manual inspection
                    vulnerabilities += f"+ [Info Disclosure] Data exposed on {endpoint} | URL: {full_url}\n"
            elif response.status_code == 302:
                location = response.headers.get("Location", "No Location header found")
                print(f"{Fore.YELLOW}- Redirection Detected (302) for: {full_url}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}- Location Header: {location}{Style.RESET_ALL}")
            elif response.status_code == 404:
                print(f"{Fore.YELLOW}- Not Found (404): The endpoint {full_url} does not exist{Style.RESET_ALL}")
            elif response.status_code == 401:
                print(f"{Fore.YELLOW}- Unauthorized (401): Access denied to {full_url}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}- Unexpected Status Code {response.status_code} for: {full_url}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}* An error occurred while checking {full_url}: {e}{Style.RESET_ALL}")

    return vulnerabilities

