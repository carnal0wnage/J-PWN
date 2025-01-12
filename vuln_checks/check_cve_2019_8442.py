import requests
from urllib.parse import urlparse
import colorama
from colorama import Fore, Style
import time
import os
import sys
import json
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import urllib3

def process_vulnerabilities(vulnerabilities):
    """
    Processes vulnerabilities, printing them as they are added.
    """
    try:
        if not vulnerabilities:
            print(f"{Fore.YELLOW}- No vulnerabilities found so far.{Style.RESET_ALL}")
            return
        
        print(f"{Fore.GREEN}\n+ New Vulnerability Added:{Style.RESET_ALL}")
        # Print the last added vulnerability
        print(f"{vulnerabilities[-1]}")
        
        print(f"{Fore.BLUE}\n+ All Vulnerabilities Found So Far:{Style.RESET_ALL}")
        for vuln in vulnerabilities:
            print(f"{vuln}")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred while processing vulnerabilities: {e}{Style.RESET_ALL}")


def check_cve_2019_8442(url):
    """
    Checks for CVE-2019-8442 and returns discovered vulnerabilities.
    """
    print(f"{Fore.YELLOW}\nINFO: Checking for CVE-2019-8442")
    
    vulnerabilities = []  # Initialize the list to store discovered vulnerabilities
    headers = {
        'X-Atlassian-Token': 'no-check'
    }

    # List of URLs to check
    urls_to_check = [
        f"{url.rstrip('/')}/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml",
        f"{url.rstrip('/')}/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/jira-webapp-dist/pom.xml",
        f"{url.rstrip('/')}/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.properties",
    ]
    
    for target_url in urls_to_check:
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {target_url}")
        try:
            # Stream response to handle large files
            response = requests.get(target_url, verify=False, headers=headers, allow_redirects=False, stream=True)
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")

            contains_dependency = False  # Flag to check for the keyword
            
            for chunk in response.iter_lines(decode_unicode=True):
                if response.status_code == 200 and "dependency" in chunk:
                    contains_dependency = True
                    break  # Stop further processing if keyword is found
                
            if response.status_code == 200:
                if contains_dependency:
                    vulnerability_detail = (
                        f"+ [Information Disclosure] CVE-2019-8442: "
                        f"https://jira.atlassian.com/browse/JRASERVER-69241 "
                        f"Visit the affected URL; the server leaks some server information. | URL: {target_url}"
                    )
                    vulnerabilities.append(vulnerability_detail)
                    # process_vulnerabilities(vulnerabilities)  # Process the updated list
                else:
                    print(f"{Fore.BLUE}- NEEDS MANUAL REVIEW - No sensitive information detected at {target_url}{Style.RESET_ALL}")
            
            elif response.status_code == 302:
                location = response.headers.get("Location", "No Location header found") 
                # print(f"{Fore.YELLOW}- Redirection Detected (302) for: {target_url}{Style.RESET_ALL}")
                if "login.jsp?os_destination=" in location:
                    print(f"{Fore.YELLOW}- Detected redirect to login.jsp - Not VULN")
                else:
                    print(f"{Fore.YELLOW}- Location Header: {location}")
                    print(f"{Fore.YELLOW}- This program doesn't follow 302 - Try: curl -k -v '{target_url}'{Style.RESET_ALL}")
            else:
                print(f"{Fore.BLUE}- No vulnerability detected at {target_url}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}* An error occurred while checking {target_url}: {e}{Style.RESET_ALL}")
    
    return vulnerabilities  # Return the full vulnerabilities list
