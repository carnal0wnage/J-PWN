import requests
from urllib.parse import urlparse
from colorama import Fore, Style
import string
import itertools
import threading

def projectkey_brute(url, path, start_id=2, end_id=2, num_threads=5):
    """
    Brute force the projectKeys parameter at /rest/api/2/project/{project_key}
    to check for unauthenticated project key enumeration.
    Uses threading to improve performance.
    """
    vulnerabilities = []
    chars = string.ascii_uppercase  # Use uppercase letters A-Z
    headers = {
        'X-Atlassian-Token': 'no-check'
    }

    def worker(project_key_combinations):
        """
        Worker function for each thread to check a list of project key combinations.
        """
        for project_key in project_key_combinations:
            url_to_test = f"{url.rstrip('/')}{path.rstrip('/')}/rest/api/2/project/{project_key}"
            print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {url_to_test}")
            try:
                response = requests.get(url_to_test, headers=headers, allow_redirects=False, verify=False)
                if response.status_code == 200:
                    vulnerabilities.append(f"+ [Info Disclosure - ProjectKey Enumeration] Found ProjectKey: {project_key} | URL: {url_to_test}")
                    print(f"\n{Fore.GREEN}+ Found ProjectKey: {project_key} | URL: {url_to_test}{Style.RESET_ALL}")
                elif response.status_code == 404:
                    #print(f"{Fore.YELLOW}- No access for ProjectKey: {project_key}{Style.RESET_ALL}")
                    pass
                elif response.status_code == 403:
                    print(f"{Fore.YELLOW}- No access for ProjectKey: {project_key}{Style.RESET_ALL}")
                elif response.status_code == 302:
                    location = response.headers.get("Location", "No Location header found")
                    print(f"{Fore.YELLOW}- Redirection Detected for ProjectKey: {project_key}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}- Location Header: {location}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}- No ProjectKey Enumeration vulnerability detected for ProjectKey: {project_key}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}* An error occurred while checking {url_to_test}: {e}{Style.RESET_ALL}")

    # Generate all combinations of project keys within the specified range
    all_combinations = []
    for length in range(start_id, end_id + 1):
        all_combinations.extend([''.join(comb) for comb in itertools.product(chars, repeat=length)])

    # Divide the project key combinations among the specified number of threads
    chunk_size = len(all_combinations) // num_threads
    threads = []

    try:
        for i in range(num_threads):
            start_index = i * chunk_size
            end_index = (i + 1) * chunk_size if i < num_threads - 1 else len(all_combinations)
            thread = threading.Thread(target=worker, args=(all_combinations[start_index:end_index],))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()
            
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[INFO] Interrupted by user. Exiting gracefully...{Style.RESET_ALL}")
        for thread in threads:
            if thread.is_alive():
                thread.join()  # Ensure all threads are cleanly stopped

    return vulnerabilities  # Return the discovered vulnerabilities
