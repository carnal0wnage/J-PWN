import requests
from urllib.parse import urlparse
import colorama
from colorama import Fore, Style
import time
import os
import sys
import json
from urllib.parse import urlparse
import urllib3


def check_cve_2019_11581(url):
    '''
    Checks for CVE-2019-11581, a potential Remote Code Execution vulnerability in Jira.
    '''
    contact_admin_url = f"{url.rstrip('/')}/secure/ContactAdministrators!default.jspa"
    vulnerabilities = ''

    try:
        print(f"\n{Fore.YELLOW}INFO: Checking for CVE-2019-11581{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {contact_admin_url}")
        response = requests.get(contact_admin_url, verify=False)

        # Check for the vulnerability
        if response.status_code == 200:
            response_text = response.text
            # print(response_text) DEBUG

            if ("administrator has not yet configured" in response_text or 
                "no ha configurado" in response_text or "noch nicht konfiguriert" in response_text or "не настроил эту контактную форму" in response_text or "管理员尚未配置此联系表" in response_text or "你还没有为联系表单配置" in response_text or "관리자는 아직 이러한 문의 양식을 구성하지 않았습니다" in response_text):
                print(f"{Fore.YELLOW}\n- No CVE-2019-11581 vulnerability detected on: {contact_admin_url}") 
                print(f"{Fore.YELLOW}\t **The contact form is not configured and most likely NOT vulnerable.**{Style.RESET_ALL}")
                # print(f"  URL: {contact_admin_url}")
            else:
                vulnerabilities += (f"+ [Potential RCE] - CVE-2019-11581: Manual exploitation required | URL: {contact_admin_url}")
                print(f"\n{Fore.GREEN}+ [Potential RCE] - CVE-2019-11581 Detected - The contact form is configured and potential vulnerable [MANUAL REVIEW REQUIRED]{Style.RESET_ALL}")
                print(f"  URL: {contact_admin_url}")
                print(f"  Note: Exploitation requires manual steps.")
                print(f"  Note: For this issue to be exploitable at least one of the following conditions must be met:")
                print(f"  1. An SMTP server has been configured in Jira and the Contact Administrators Form is enabled")
                print(f"  2. or an SMTP server has been configured in Jira and an attacker has \"JIRA Administrators\" access.")
                print(f"  Note:Refer to: https://jira.atlassian.com/browse/JRASERVER-69532 && https://hackerone.com/reports/706841")
                #print(response_text)
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}")

        else:
            print(f"{Fore.YELLOW}- No CVE-2019-11581 vulnerability detected on: {contact_admin_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")

    except Exception as e:
            print(f"{Fore.RED}* CVE-2019-11581 An error occurred while checking {contact_admin_url}: {e}{Style.RESET_ALL}")
    return vulnerabilities
