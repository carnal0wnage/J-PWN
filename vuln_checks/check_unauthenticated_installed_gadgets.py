import requests
from urllib.parse import urlparse
import colorama
from colorama import Fore, Style
import time
import os
import sys
import json
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import urllib3

def check_unauthenticated_installed_gadgets(url):
    '''
    Checks for Unauthenticated Installed Gadgets
    '''
    unauthenticated_installed_gadgets_url = f"{url.rstrip('/')}/rest/config/1.0/directory"
    vulnerabilities = ''
        
    try:
        # print(f"{Fore.YELLOW}\nChecking for  Unauthenticated Installed Gadgets")
        response = requests.get(unauthenticated_installed_gadgets_url, allow_redirects=False, verify=False)

        # Check for the vulnerability
        if response.status_code == 200 and "jaxbDirectoryContents" in response.text:
            response_text = response.text
            # Parse the XML response
            try:
                root = ET.fromstring(response.text)
            except ET.ParseError as e:
                print(f"{Fore.RED}- Failed to parse XML response: {e}{Style.RESET_ALL}")
                return vulnerabilities


            vulnerabilities += (f"+ [Info Disclosure] Unauthenticated Installed Gadgets Found | URL: {unauthenticated_installed_gadgets_url}")
            print(f"\n{Fore.GREEN}+ [Info Disclosure] Unauthenticated Installed Gadgets [Manually Inspect] {Style.RESET_ALL}")
            print(f"  URL: {unauthenticated_installed_gadgets_url}")

            # Parse categories
            print(f"{Fore.BLUE}Categories:{Style.RESET_ALL}")
            for category in root.findall(".//categories"):
                category_name = category.find("name")
                if category_name is not None:
                    print(f"  - {category_name.text}")
                else:
                    print(f"  - [No Name Found]")

            # Parse gadgets
            print(f"\n{Fore.BLUE}Gadgets:{Style.RESET_ALL}")
            for gadget in root.findall(".//gadgets"):
                title = gadget.find("title").text if gadget.find("title") is not None else "Unknown Title"
                author_name = gadget.find("authorName").text if gadget.find("authorName") is not None else "Unknown Author"
                description = gadget.find("description").text if gadget.find("description") is not None else "No Description"
                thumbnail_uri = gadget.find("thumbnailUri").text if gadget.find("thumbnailUri") is not None else "No Thumbnail"
                categories = ", ".join([cat.text for cat in gadget.findall("categories") if cat.text is not None]) or "No Categories"

                print(f"  - Title: {title}")
                print(f"    Author: {author_name}")
                print(f"    Description: {description}")
                print(f"    Thumbnail: {thumbnail_uri}")
                print(f"    Categories: {categories}\n")

        elif response.status_code == 302:
            location = response.headers.get("Location", "No Location header found") 
            print(f"{Fore.YELLOW}- Redirection Detected (302) for: {unauthenticated_installed_gadgets_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- Location Header: {location}")
            print(f"{Fore.YELLOW}- This program doesnt follow 302 - Try: curl -k -v \'{unauthenticated_installed_gadgets_url}\'{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}\n- No Unauthenticated Installed Gadgets vulnerability detected on: {unauthenticated_installed_gadgets_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}- HTTP Status Code: {response.status_code}{Style.RESET_ALL}")

    except Exception as e:
            print(f"{Fore.RED}*  An error occurred while checking {unauthenticated_installed_gadgets_url}: {e}{Style.RESET_ALL}")
    return vulnerabilities