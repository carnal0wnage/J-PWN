""" Main module for j-pwn  """
import argparse
from urllib.parse import urlparse
import urllib3

import colorama
from colorama import Fore, Style
import requests
import time
import os
import sys
import random

# import each module from vuln_checks/
from vuln_checks import *

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

colorama.init()



def banner():
    """ Display tool banner """

    print("""

             ██╗      ██████╗ ██╗    ██╗███╗   ██╗
             ██║      ██╔══██╗██║    ██║████╗  ██║
             ██║█████╗██████╔╝██║ █╗ ██║██╔██╗ ██║
        ██   ██║╚════╝██╔═══╝ ██║███╗██║██║╚██╗██║
        ╚█████╔╝      ██║     ╚███╔███╔╝██║ ╚████║
         ╚════╝       ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
         ** Hack the Planet ** [carnal0wnage]


        """)

def run_single_check(module_name, url):
    """ Dynamically run a single check module by name """
    try:
        module = globals()[module_name]
        print(f"{Fore.BLUE}[INFO] Running single module: {module_name}{Style.RESET_ALL}")
        check_result = module(url)
        if check_result:
            print(f"{Fore.GREEN}[RESULT] Vulnerability found by {module_name}:{Style.RESET_ALL}")
            print(check_result)
        else:
            print(f"{Fore.YELLOW}[INFO] No vulnerabilities found by {module_name}{Style.RESET_ALL}")
    except KeyError:
        print(f"{Fore.RED}[ERROR] Module {module_name} not found.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] An error occurred while running {module_name}: {e}{Style.RESET_ALL}")


def test_jira_vulns(url):
    """ Run all the checks """

    vulnerabilities= []

    cve20185230 = f"{url}issues/" #https://hackerone.com/reports/380354 https://jira.atlassian.com/browse/JRASERVER-67289 /issues/?jql=assignee%20in%20(membersOf(jira-users))

    xss = f"{url}pages/%3CIFRAME%20SRC%3D%22javascript%3Aalert(‘XSS’)%22%3E.vm"

    cve20193402 = f"{url}secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=x2rnu%3Cscript%3Ealert(1)%3C%2fscript%3Et1nmk&Search=Search"


    #todo /rest/api/2/user/search?username=.&maxResults=1000
    #     /rest/api/2/user/search?username=.&includeInactive=true
    #     /rest/api/latest/user/search?query=+&maxResults=1000
    #todo /rest/project-templates/1.0/createshared https://jira.atlassian.com/browse/JRASERVER-70926

    #todo secure/SetupMode!default.jspa https://github.com/projectdiscovery/nuclei-templates/blob/54d78a0552a78cccafa3435bbdd42dff4b568c27/http/misconfiguration/installer/jira-setup.yaml
    # (CVE-2020-36289) /secure/QueryComponentRendererValue!Default.jspa?assignee=user:admin
    #todo secure/SetupMode!default.jspa check that jira is in setup mode
    #todo /rest/api/2/mypermissions  Returns all permissions in the system and whether the currently logged in user has them. need to query for "havePermission": true,
    # todo /rest/api/2/project https://docs.atlassian.com/software/jira/docs/api/REST/7.6.1/#api/2/project-getAllProjects


    # Check for unauthenticated access to JIRA dashboards
    # {url}rest/api/2/dashboard?maxResults=100
    check_result = check_unauthenticated_dashboard_access(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for unauthenticated access to JIRA project categories
    # {url}rest/api/2/projectCategory?maxResults=1000
    check_result = check_unauthenticated_project_categories(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for unauthenticated access to projects
    # {url}rest/api/2/project?maxResults=100
    check_result = check_unauthenticated_projects(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for unauthenticated access to JIRA resolutions
    # {url}rest/api/2/resolution
    check_result = check_unauthenticated_resolutions(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for unauthenticated access to JIRA admin projects
    # {url}rest/menu/latest/admin?maxResults=1000
    check_result = check_unauthenticated_admin_projects(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Checks for open Jira signup. Manually attempt to signup
    # {url}secure/Signup!default.jspa
    check_result = check_open_jira_signup(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for Unauthenticated popular dashboard
    # {url}secure/ConfigurePortalPages!default.jspa?view=popular
    check_result = check_unauthenticated_popular_dashboard(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for Unauthenticated User Enumeration (UserPickerBrowser.jspa)
    # {url}secure/popups/UserPickerBrowser.jspa
    check_result = check_unauthenticated_user_enumeration(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for Unauthenticated Installed Gadgets
    # {url}rest/config/1.0/directory
    check_result = check_unauthenticated_installed_gadgets(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # NOT WORKING
    # Check for Unauthenticated projectkey enumeration
    # {url}rest/api/2/user/assignable/multiProjectSearch?projectKeys=admin
    #check_result = check_unauthenticated_projectkey_enumeration(url)
    #if check_result:  # Only append if check_result is not empty
    #    vulnerabilities.append(check_result)

    # Check for Unauthenticated Issues (with content)
    # {url}rest/api/2/search?jql=ORDER%20BY%20Created
    check_result = check_unauthenticated_issues(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for Unauthenticated Screens
    # {url}/rest/api/2/screens
    check_result = check_unauthenticated_screens(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # check for unauthenticated greenhopper userconfig
    # {url}/rest/greenhopper/1.0/userData/userConfig
    check_result = check_unauthenticated_greenhopper_user_config(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)


    # Checks for unauthenticated access to the Issue Link Type API
    # {url}/rest/api/2/issueLinkType
    check_result = check_unauthenticated_issue_link_type(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    
    # Checks for unauthenticated access to the Priority API
    # {url]/rest/api/2/priority
    check_result = check_unauthenticated_priority_access(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # -----------------------------------------------------------
    # let's do CVE checks yo
    # -----------------------------------------------------------

   # Check for CVE-2017-9506 SSRF
    # {url}/plugins/servlet/oauth/users/icon-uri?consumerUri=
    check_result = check_cve_2017_9506(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for CVE-2018-20824 (XSS vulnerability in Wallboard)
    # {url}plugins/servlet/Wallboard/?dashboardId=10000&dashboardId=10000&cyclePeriod=alert(document.cookie))
    check_result = check_cve_2018_20824(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for cve-2019-3401
    # {url}secure/ManageFilters.jspa?filterView=search&Search=Search&filterView=search&sortColumn=favcount&sortAscending=false
    check_result = check_cve_2019_3401(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for CVE-2019-3402 DISABLED DUE TO ALWAYS RETURNING POSITIVE
    # {url}secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=x2rnu%3Cscript%3Ealert(\"XSS_TEST\")%3C%2fscript%3Et1nmk&Search=Search
    #check_result = check_cve_2019_3402(url)
    #if check_result:  # Only append if check_result is not empty
    #    vulnerabilities.append(check_result)

    # Check for CVE-2019-3403
    # {url}rest/api/2/user/picker?query=admin
    check_result = check_cve_2019_3403(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for CVE-2019-8442
    # {url}s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml
    check_result = check_cve_2019_8442(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for CVE-2019-8449
    # {url}rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true
    check_result = check_cve_2019_8449(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for CVE-2019-8451
    # {url}/plugins/servlet/gadgets/makeRequest?url=
    check_result = check_cve_2019_8451(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for CVE-2019-11581
    # {url}secure/ContactAdministrators!default.jspa
    check_result = check_cve_2019_11581(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for CVE-2020-14178
    # {url]browse.PROJECTNAME(KEY)
    check_result = check_cve_2020_14178(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for CVE-2020-14179
    # {url]secure/QueryComponent!Default.jspa
    check_result = check_cve_2020_14179(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for CVE-2020-14181
    # {url}secure/ViewUserHover.jspa?username=ishouldntexist
    check_result = check_cve_2020_14181(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for CVE-2020-29453
    # {url.rstrip('/')}/s/1xqVb9EKKmXG4pzui1gHeg0yrna/_/%2e/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml",
    # {url.rstrip('/')}/s/1xqVb9EKKmXG4pzui1gHeg0yrna/_/%2e/META-INF/maven/com.atlassian.jira/jira-webapp-dist/pom.xml",
    # {url.rstrip('/')}/s/1xqVb9EKKmXG4pzui1gHeg0yrna/_/%2e/WEB-INF/web.xml"
    # {url.rstrip('/')}/s/1xqVb9EKKmXG4pzui1gHeg0yrna/_/%2e/WEB-INF/classes/seraph-config.xml"
    check_result = check_cve_2020_29453(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for CVE-2021-26086
    # f"{url.rstrip('/')}/s/cfx/_/;/WEB-INF/web.xml",
    # f"{url.rstrip('/')}/s/cfx/_/;/WEB-INF/classes/seraph-config.xml",
    # f"{url.rstrip('/')}/s/cfx/_/;/WEB-INF/decorators.xml",
    # f"{url.rstrip('/')}/s/cfx/_/;/META-INF/maven/com.atlassian.jira/jira-webapp-dist/pom.properties",
    # f"{url.rstrip('/')}/s/cfx/_/;/META-INF/maven/com.atlassian.jira/jira-webapp-dist/pom.xml",
    # f"{url.rstrip('/')}/s/cfx/_/;/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml",
    #f"{url.rstrip('/')}/s/cfx/_/;/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.properties",
    check_result = check_cve_2021_26086(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for CVE-2022-0540 Variant 1
    # {url}InsightPluginShowGeneralConfiguration.jspa;
    check_result = check_cve_2022_0540_v1(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for CVE-2022-0540 variant 2
    # {url}secure/WBSGanttManageScheduleJobAction.jspa;"
    check_result = check_cve_2022_0540_v2(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for CVE-2023-26255
    # {url}/plugins/servlet/snjCustomDesignConfig?fileName=../../../../etc/passwd&fileMime=$textMime"
    check_result = check_cve_2023_26255(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for CVE-2023-26256
    # {url}/plugins/servlet/snjFooterNavigationConfig?fileName=../../../../etc/passwd&fileMime=$textMime"
    check_result = check_cve_2023_26256(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)



    # -----------------------------------------------------------
    # Service Desk Checks and Modules go here
    # -----------------------------------------------------------

    # {url}rest/servicedeskapi/info
    check_servicedesk_info(url)

    # Checks for open service desk login. Manually attempt to signup
    # {url}servicedesk/customer/user/login
    check_result = check_open_servicedesk_login(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Checks for open service desk signup. Manually attempt to signup
    # {url}servicedesk/customer/user/signup
    check_result = check_open_servicedesk_signup(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)


    # -----------------------------------------------------------
    # Process all the vulnerabilities
    # -----------------------------------------------------------
    
    # print(vulnerabilities) #debug
    process_vulnerabilities(vulnerabilities)


# -----------------------------------------------------------
# Function to process the vulnerabilities and print them at the end to the terminal
# -----------------------------------------------------------
def process_vulnerabilities(vulnerabilities):
    """ Processes vulnerabilities, printing them as they are added """
    try:
        if not vulnerabilities:
            print(f"{Fore.YELLOW}- No vulnerabilities found so far.{Style.RESET_ALL}")
            return

        print(f"{Fore.BLUE}\n+ Vulnerabilities Found:{Style.RESET_ALL}")
        for vuln in vulnerabilities:
            print(f"{vuln}")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred while processing vulnerabilities: {e}{Style.RESET_ALL}")



def check_jira(url, path):
    """ Checks if JIRA is running at the given URL and retries with /jira/ if necessary """
    # Parse the URL to check its components
    parsed_url = urlparse(url)

    if not parsed_url.scheme:  # No scheme provided (e.g., just an IP or domain)
        url = "https://" + url  # Default to https:// if no scheme is provided
    else:  # Scheme is present (e.g., http://example.com or https://example.com)
        url = f"{parsed_url.scheme}://{parsed_url.netloc}"  # Keep the provided scheme and netloc

    print(f"{Fore.YELLOW}[Scanning] : {url}{Style.RESET_ALL}")

    try:
        # Prepare the full URL
        full_url = url + path
        print(f"Checking: {full_url}")
        response = requests.get(full_url + 'rest/api/2/serverInfo', timeout=10, verify=False)

        # Check if the initial response is successful
        if response.status_code == 200 and "serverTitle" in response.json():
            print(f"{Fore.GREEN}+ JIRA is running on:", url, f"{Style.RESET_ALL}")
            data = response.json()

            base_url = data.get("baseUrl", "N/A")
            version = data.get("version", "N/A")
            deployment_type = data.get("deploymentType", "N/A")
            build_number = data.get("buildNumber", "N/A")
            build_date = data.get("buildDate", "N/A")
            server_title = data.get("serverTitle", "N/A")

            print("\nJIRA Server Information:")
            print(f"  Base URL        : {base_url}")
            print(f"  Version         : {version}")
            print(f"  Deployment Type : {deployment_type}")
            print(f"  Build Number    : {build_number}")
            print(f"  Build Date      : {build_date}")
            print(f"  Server Title    : {server_title}")

            print(f"{Fore.YELLOW}\n- Running Vuln Checks{Style.RESET_ALL}")
            # Run all the checks
            test_jira_vulns(full_url)
        else:
            print(f"{Fore.RED}- Initial request failed: HTTP {response.status_code}{Style.RESET_ALL}")
            # Retry with /jira/ if the original path was blank or "/"
            if path.strip() in ["", "/"]:
                print(f"{Fore.YELLOW}- Retrying with path: /jira/{Style.RESET_ALL}")
                retry_url = url + "/jira/"
                response = requests.get(retry_url + 'rest/api/2/serverInfo', timeout=10, verify=False)

                if response.status_code == 200 and "serverTitle" in response.json():
                    print(f"{Fore.GREEN}+ JIRA is running on (retry):", retry_url, f"{Style.RESET_ALL}")
                    data = response.json()

                    base_url = data.get("baseUrl", "N/A")
                    version = data.get("version", "N/A")
                    deployment_type = data.get("deploymentType", "N/A")
                    build_number = data.get("buildNumber", "N/A")
                    build_date = data.get("buildDate", "N/A")
                    server_title = data.get("serverTitle", "N/A")

                    print("\nJIRA Server Information (retry):")
                    print(f"  Base URL        : {base_url}")
                    print(f"  Version         : {version}")
                    print(f"  Deployment Type : {deployment_type}")
                    print(f"  Build Number    : {build_number}")
                    print(f"  Build Date      : {build_date}")
                    print(f"  Server Title    : {server_title}")

                    print(f"{Fore.YELLOW}\n- Running Vuln Checks (retry){Style.RESET_ALL}")
                    # Run all the checks
                    test_jira_vulns(retry_url)
                else:
                    print(f"{Fore.RED}- Retry failed: HTTP {response.status_code}{Style.RESET_ALL}")
                    print(f"- JIRA is not running on: {url}")
                    print(f"- try python3 j-pwn.py --single {url} -p /jira/")
            else:
                print(f"{Fore.RED}- JIRA is not running on: {url}{Style.RESET_ALL}")
                print(f"- try python3 j-pwn.py --single {url} -p /jira/")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred while checking {url}: {e}{Style.RESET_ALL}")


def parse_and_check_jira(file_path):
    """ Parses a text file with URLs and paths, then calls check_jira for each entry """
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()

        for line in lines:
            # Skip empty lines or lines with only whitespace
            if not line.strip():
                continue

            # Split the line into URL and path
            try:
                parts = line.strip().split(',')
                url = parts[0].strip()  # The first part is the URL
                path = parts[1].strip() if len(parts) > 1 and parts[1].strip() else "/"  # Default path if empty
                print(f"{Fore.BLUE}\n[INFO] Processing: URL = {url}, Path = {path}{Style.RESET_ALL}")
                check_jira(url, path)  # Call the check_jira function
            except IndexError:
                print(f"{Fore.RED}- Error parsing line: {line.strip()}{Style.RESET_ALL}")
    except FileNotFoundError:
        print(f"{Fore.RED}- File not found: {file_path}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred while processing the file: {e}{Style.RESET_ALL}")


def main():
    """ Hack the planet """
    try:
        banner()
        parser = argparse.ArgumentParser(description="Check if JIRA is running on a server or list of servers")
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--single", "-s", metavar="URL", help="Check if JIRA is running on a single server")
        parser.add_argument("--path", "-p", metavar="PATH", default="/", help="Specify the API path to check (default: /)")
        group.add_argument("--list", "-l", metavar="FILE", help="Check if JIRA is running on a list of servers")
        # Additional arguments for specific modules
        parser.add_argument("--module", "-m", metavar="MODULE", help="Specify the single module to run (e.g., check_open_jira_signup)")
        parser.add_argument("--start_id", type=int, default=10000, help="Start ID for issue enumeration (default: 10000)")
        parser.add_argument("--end_id", type=int, default=20000, help="End ID for issue enumeration (default: 20000)")

        args = parser.parse_args()

        if args.single:
            if args.module:
                if args.module == "check_cve_2020_14185":
                    start_id = args.start_id if args.start_id else 10000
                    end_id = args.end_id if args.end_id else 20000
                    check_cve_2020_14185(args.single, start_id, end_id)
                elif args.module == "check_download_public_issue_attachment":
                    start_id = args.start_id if args.start_id else 10000
                    end_id = args.end_id if args.end_id else 20000
                    check_download_public_issue_attachment(args.single, start_id, end_id)
                else:
                    run_single_check(args.module, args.single)
            else:
                check_jira(args.single, args.path)
        elif args.list:
            parse_and_check_jira(args.list)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Detected CTRL+C exiting...{Style.RESET_ALL}")
        sys.exit(0)

if __name__ == "__main__":
    main()
