import requests
from colorama import Fore, Style

# Check for unauthenticated access to JIRA project categories
def check_unauthenticated_project_categories(url):
    project_category_url = f"{url.rstrip('/')}/rest/api/2/projectCategory?maxResults=1000"
    vulnerabilities = ''  # Local vulnerabilities list
    headers = {
        'X-Atlassian-Token': 'no-check'
    }

    try:
        print(f"{Fore.YELLOW}\nINFO: Checking for Unauthenticated Access to JIRA Project Categories{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[Testing URL]{Style.RESET_ALL}: {project_category_url}")
        response = requests.get(project_category_url, headers=headers, allow_redirects=False, verify=False)

        # Check for unauthenticated access and parse the response
        if response.status_code == 200:
            data = response.json()

            # Check if the returned data is an empty list
            if not data:
                print(f"{Fore.YELLOW}- No Project Categories found (Empty Results).{Style.RESET_ALL}")
                return vulnerabilities

            vulnerabilities += f"+ [Info Disclosure] Unauthenticated access to JIRA project categories | URL : {project_category_url}"

            print(f"\n{Fore.GREEN}+ Unauthenticated Access to JIRA Project Categories Detected{Style.RESET_ALL}")
            print(f"  URL: {project_category_url}")
            print("\n  Project Categories Details:")

            if data:
                for category in data:
                    category_self = category.get("self", "N/A")
                    category_id = category.get("id", "N/A")
                    description = category.get("description", "N/A")
                    name = category.get("name", "N/A")

                    print(f"    - ID: {category_id}")
                    print(f"      Name: {name}")
                    print(f"      Description: {description}")
                    print(f"      API URL: {category_self}")
            else:
                print("    No project categories found.")
        else:
            print(f"{Fore.YELLOW}\n- No unauthenticated access to JIRA project categories detected on: {project_category_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Code: {response.status_code}{Style.RESET_ALL}")
    except json.JSONDecodeError:
        print(f"{Fore.RED}- Failed to parse JSON response from: {project_category_url}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred while checking {project_category_url}: {e}{Style.RESET_ALL}")
    
    return vulnerabilities  # Return the discovered vulnerabilities