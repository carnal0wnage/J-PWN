import requests
from urllib.parse import urlparse
from colorama import Fore, Style
import threading

def check_issue_key(base_url, issue_id, vulnerabilities):
    """
    Checks a single issue key for enumeration vulnerability and parses the response for successful attempts.
    """
    issue_key = f"{base_url.rstrip('/')}/rest/api/2/issue/{issue_id}/?fields=attachment"
    headers = {
        'X-Atlassian-Token': 'no-check'
    }

    try:
        response = requests.get(issue_key, headers=headers, allow_redirects=False, verify=False)
        
        # Check if the response indicates successful access
        if response.status_code == 200:
            data = response.json()
            
            # Check if the "attachment" field is present and not empty
            attachments = data.get("fields", {}).get("attachment", [])

            if attachments:
                print(f"{Fore.GREEN}[+] Attachments found in issue {issue_id}:{Style.RESET_ALL}")
                for attachment in attachments:
                    filename = attachment.get("filename", "Unknown filename")
                    content_url = attachment.get("content", "No content URL")
                    print(f"  - Filename: {filename}")
                    print(f"  - Content URL: {content_url}")
                    vulnerability_detail = f"+ Attachments found in issue {issue_id} URL:{content_url}"
                    vulnerabilities.append(vulnerability_detail)
                return True  # Positive result indicating attachments exist
            else:
                print(f"{Fore.YELLOW}- No attachments found in issue {issue_id}{Style.RESET_ALL}")
                return False
        elif response.status_code == 404:
            #pass
            print(f"{Fore.YELLOW}- Issue {issue_id} Does Not Exist: HTTP Code: {response.status_code}{Style.RESET_ALL}") #Let's not print 404s
        elif response.status_code == 401:
            #pass
            print(f"{Fore.YELLOW}- Issue {issue_id} Unauthorized:  HTTP Code: {response.status_code}{Style.RESET_ALL}") #or 401's
        else:
            print(f"{Fore.YELLOW}- Issue {issue_id} unknown error! HTTP Code: {response.status_code}{Style.RESET_ALL}")
            return False
    except Exception as e:
        print(f"{Fore.RED}* An error occurred while checking issue {issue_id}: {e}{Style.RESET_ALL}")
        return False

def check_cve_actions_operations_enumeration_threaded(base_url, start_id=10000, end_id=20000, num_threads=10):
    """
    Uses threading to brute-force enumeration of issue keys from start_id to end_id.
    """
    print(f"\n{Fore.YELLOW}INFO: Issue with Attachment with threading start_id:{start_id} end_id:{end_id}{Style.RESET_ALL}")
    
    issue_key = f"{base_url.rstrip('/')}/rest/api/2/issue/<issue_id>/?fields=attachment"

    print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {issue_key}")

    vulnerabilities = []  # List to store discovered vulnerabilities
    threads = []

    # Worker function for threads
    def worker(issue_range):
        for issue_id in issue_range:
            check_issue_key(base_url, issue_id, vulnerabilities)

    # Split the range of issue IDs into chunks for each thread
    total_issues = end_id - start_id + 1
    print(f"\n{Fore.YELLOW}INFO: Total issues to check: {total_issues}{Style.RESET_ALL}")
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

def check_download_public_issue_attachment(base_url, path, start_id=10000, end_id=20000, num_threads=10):
    """
    Entry point for the enumeration check within the j-pwn.py main program.
    """
    full_url = base_url + path
    vulnerabilities = check_cve_actions_operations_enumeration_threaded(full_url, start_id, end_id, num_threads)

    # Print all found vulnerabilities at the end
    if vulnerabilities:
        print(f"{Fore.GREEN}\nFound vulnerabilities:{Style.RESET_ALL}")
        for vuln in vulnerabilities:
            print(vuln)
    else:
        print(f"{Fore.YELLOW}\nNo pubicly available attachments found{Style.RESET_ALL}")