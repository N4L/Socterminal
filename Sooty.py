#!/usr/bin/env python3
"""
    Title:      SocTerminal
    Desc:       The SOC Analysts all-in-one CLI tool to automate and speed up workflow.
    Author:     Akshay Nehate
    Version:    0.1.1
    GitHub URL: https://github.com/akshay-nehate/Socterminal
"""

import base64
from unfurl import core
from prettytable import PrettyTable
import hashlib
import html.parser
import re
import json
import time
import os
import socket
import strictyaml
import urllib.parse
import requests
from ipwhois import IPWhois
import tkinter
import sys
import whois
from pprint import pprint
from tabulate import tabulate
from bs4 import BeautifulSoup
from Modules import iplists
from Modules import phishtank
from Modules import TitleOpen
from datetime import datetime, date
import msvcrt  # for Windows
import webbrowser
from tkinter import filedialog
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

try:
    import win32com.client
except:
    print('Cant install Win32com package')

versionNo = '0.1.1'

try:
    f = open("config.yaml", "r")
    configvars = strictyaml.load(f.read())
    f.close()
except FileNotFoundError:
    print("Config.yaml not found. Check the example config file and rename to 'config.yaml'.")

linksFoundList = []
linksRatingList = []
linksSanitized = []
linksDict = {}

def press_any_key():
    print("Press ENTER to continue... (or type 'fb' to create a github issue)")
    key = msvcrt.getch()  # wait for user input
    if key.decode() != '\x03':  # check for Ctrl+C interrupt
        feedback = input()
        if feedback.lower() == 'fb':
            issue_url = 'https://github.com/akshay-nehate/Socterminal/issues/new?assignees=&labels=&template=bug_report.md&title='

            webbrowser.open(issue_url)
    mainMenu()

def switchMenu(choice):
    if choice == '1':
        FangDefangMenu()
    if choice == '2':
        decoderMenu()
    if choice == '3':
        repChecker()
    if choice == '4':
        dnsMenu()
    if choice == '5':
        hashMenu()
    if choice == '6':
        phishingMenu()
    if choice == '7':
        urlscanio()
    if choice == '9':
        extrasMenu()
    if choice == '0':
        sys.exit("Exiting Sooty... done")
    else:
        mainMenu()

def FangDefangSwitch(choice):
    if choice == '1':
        urlSanitise()
    if choice == '2':
        urlDeSanitise()
    if choice == '3':
        mainMenu()

def decoderSwitch(choice):
    if choice == '1':
        proofPointDecoder()
    if choice == '2':
        urlDecoder()
    if choice == '3':
        safelinksDecoder()
    if choice == '4':
        unshortenUrl()
    if choice == '5':
        b64Decoder()
    if choice == '6':
        cisco7Decoder()
    if choice == '7':
        unfurlUrl()
    if choice == '0':
        mainMenu()

def dnsSwitch(choice):
    if choice == '1':
        reverseDnsLookup()
    if choice == '2':
        dnsLookup()
    if choice == '3':
        whoIs()

    if choice == '0':
        mainMenu()

def hashSwitch(choice):
    if choice == '1':
        hashFile()
    if choice == '2':
        hashText()
    if choice == '3':
        hashRating()
    if choice == '4':
        hashAndFileUpload()
    if choice == '0':
        mainMenu()

def phishingSwitch(choice):
    if choice == '1':
        analyzePhish()
    if choice == '2':
        analyzeEmailInput()
    if choice == '3':
        emailTemplateGen()
    if choice == '4':
        phishtankModule()
    if choice == '9':
        haveIBeenPwned()
    else:
        mainMenu()

def extrasSwitch(choice):
    if choice == '1':
        aboutSooty()
    if choice == '2':
        contributors()
    if choice == '3':
        extrasVersion()
    if choice == '4':
        wikiLink()
    if choice == '5':
        ghLink()
    else:
        mainMenu()

def decodev1(rewrittenurl):
    match = re.search(r'u=(.+?)&k=', rewrittenurl)
    if match:
        urlencodedurl = match.group(1)
        htmlencodedurl = urllib.parse.unquote(urlencodedurl)
        url = html.unescape(htmlencodedurl)
        url = re.sub("http://", "", url)
        if url not in linksFoundList:
            linksFoundList.append(url)

def decodev2(rewrittenurl):
    match = re.search(r'u=(.+?)&[dc]=', rewrittenurl)
    if match:
        specialencodedurl = match.group(1)
        trans = str.maketrans('-_', '%/')
        urlencodedurl = specialencodedurl.translate(trans)
        htmlencodedurl = urllib.parse.unquote(urlencodedurl)
        url = html.unescape(htmlencodedurl)
        url = re.sub("http://", "", url)
        if url not in linksFoundList:
            linksFoundList.append(url)

def decodev3(rewrittenurl):
    match = re.search(r'v3/__(?P<url>.+?)__;', rewrittenurl)
    if match:
        url = match.group('url')
        if re.search(r'\*(\*.)?', url):
            url = re.sub('\*', '+', url)
            if url not in linksFoundList:
                linksFoundList.append(url)

def titleLogo():
    TitleOpen.titleOpen()
    os.system('cls||clear')

def mainMenu():
    # Create a new Console instance
    console = Console()

    # Create a new Table instance
    table = Table(show_header=True, header_style="bold magenta")

    # Add columns to the table
    table.add_column("Item Number", style="dim", width=12)
    table.add_column("Menu Item", justify="left")

    # Add rows to the table
    table.add_row("1", "Sanitise URLs")
    table.add_row("2", "Decoders (PP, URL, SafeLinks)")
    table.add_row("3", "Reputation Checker")
    table.add_row("4", "DNS Tools")
    table.add_row("5", "Hashing Function")
    table.add_row("6", "Phishing Analysis")
    table.add_row("7", "URL scan")
    table.add_row("0", "Exit")

    # Print the table to the console using the Console class
    console.print(table)
    # Prompt the user to select a menu item
    item_num = Prompt.ask("Enter the item number of the menu item you want to select: ")

    # Display the user's selection
    console.print(f"You selected menu item number {item_num}")
    
    # Pass User Input
    switchMenu(item_num)

    #border = "+" + "-"*46 + "+"
    #title = "|{:^46}|".format("S  O  C - T  E R M I N A L")
    #options = "|{:<44} {:>2}|"
    #print("\n" + border)
    #print(title)
    #print(border)
    #print(options.format("OPTION 1: Sanitise URL For emails", "1"))
    #print(options.format("OPTION 2: Decoders (PP, URL, SafeLinks)", "2"))
    #print(options.format("OPTION 3: Reputation Checker", "3"))
    #print(options.format("OPTION 4: DNS Tools", "4"))
    #print(options.format("OPTION 5: Hashing Function", "5"))
    #print(options.format("OPTION 6: Phishing Analysis", "6"))
    #print(options.format("OPTION 7: URL scan", "7"))
    #print(options.format("OPTION 9: Extras", "9"))
    #print(options.format("OPTION 0: Exit Tool", "0"))
    #print(border)
    #switchMenu(input())


def urlSanitise():
    print("\n" + "="*80)
    print("|{:^78}|".format("U R L   S A N I T I S E   T O O L"))
    print("|" + "-"*78 + "|")
    urls = str(input("|{:<8}|".format("Enter comma seprated URL,Emails OR IPs to sanitize: ")).strip()).split(',')
    print("|" + "="*78 + "|")
    for url in urls:
        x = re.sub(r"\.", "[.]", url)
        x = re.sub("http://", "hxxp://", x)
        x = re.sub("https://", "hxxps://", x)
        input_str = "Input URL: " + url
        output_str = "Sanitized : " + x
        max_str_len = max(len(input_str), len(output_str))
        input_str = "|{:<78}|".format(input_str.ljust(max_str_len, " "))
        output_str = "|{:<78}|".format(output_str.ljust(max_str_len, " "))
        print(output_str)
        print("|" + "="*78 + "|\n")
    press_any_key()

def urlDeSanitise():
    print("\n" + "="*80)
    print("|{:^78}|".format("U R L   S A N I T I S E   T O O L"))
    print("|" + "-"*78 + "|")
    urls = str(input("|{:<8}|".format("Enter comma seprated URL,Emails OR IPs to DEsanitize: ")).strip()).split(',')
    print("|" + "="*78 + "|")
    for url in urls:
        x = re.sub(r"\[\.\]", ".", url)
        x = re.sub("hxxp://", "http://", x)
        x = re.sub("hxxps://", "https://", x)
        input_str = "Input URL: " + url
        output_str = "DeFanged : " + x
        max_str_len = max(len(input_str), len(output_str))
        input_str = "|{:<78}|".format(input_str.ljust(max_str_len, " "))
        output_str = "|{:<78}|".format(output_str.ljust(max_str_len, " "))
        print(output_str)
        print("|" + "="*78 + "|\n")
    press_any_key()

def FangDefangMenu():
    print("+{:-<78}+".format(""))
    print("|{:^78}|".format("U R L   F A N G - D E F A N G   M E N U"))
    print("|{:-<78}|".format(""))
    print("|{:^78}|".format("What would you like to do?"))
    print("|{:<78}|".format(""))
    print("|{:<78}|".format("OPTION 1: DEFANG URL"))
    print("|{:<78}|".format("OPTION 2: FANG URL"))
    print("|{:<78}|".format("OPTION 0: Exit to Main Menu"))
    print("+{:-<78}+".format(""))
    FangDefangSwitch(input())


def decoderMenu():
    print("+---------------------------------+")
    print("|          D E C O D E R S        |")
    print("+---------------------------------+")
    print("| What would you like to do?      |")
    print("| 1: ProofPoint Decoder           |")
    print("| 2: URL Decoder                  |")
    print("| 3: Office SafeLinks Decoder     |")
    print("| 4: URL unShortener              |")
    print("| 5: Base64 Decoder               |")
    print("| 6: Cisco Password 7 Decoder     |")
    print("| 7: Unfurl URL                   |")
    print("| 0: Exit to Main Menu            |")
    print("+---------------------------------+")
    decoderSwitch(input())


def proofPointDecoder():
    print("\n ---------------------------------- ")
    print(" P R O O F P O I N T - D E C O D E R ")
    print(" ------------------------------------ ")
    rewrittenurl = str(input(" Enter ProofPoint Link(no []): ").strip())
    match = re.search(r'https://urldefense.proofpoint.com/(v[0-9])/', rewrittenurl)
    matchv3 = re.search(r'urldefense.com/(v3)/', rewrittenurl)
    if match:
        if match.group(1) == 'v1':
            decodev1(rewrittenurl)
            for each in linksFoundList:
                #print(" --------------------------------- ")
                print(' Decoded Link: %s' % each)
                print(" ----------------------------------- ")
                linksFoundList.clear()
        elif match.group(1) == 'v2':
            decodev2(rewrittenurl)
            for each in linksFoundList:
                #print(" --------------------------------- ")
                print('\n Decoded Link: %s' % each)
                print(" ----------------------------------- ")
                linksFoundList.clear()

    if matchv3 is not None:
        if matchv3.group(1) == 'v3':
            decodev3(rewrittenurl)
            for each in linksFoundList:
                #print(" --------------------------------- ")
                print('\n Decoded Link: %s' % each)
                print(" ----------------------------------- ")
                linksFoundList.clear()
        else:
            print(' No valid URL found in input: ', rewrittenurl)

    mainMenu()
    
def urlDecoder():
    print("\n --------------------------------- ")
    print("       U R L   D E C O D E R      ")
    print(" --------------------------------- ")
    url = str(input(' Enter URL: ').strip())
    decodedUrl = urllib.parse.unquote(url)
    print(decodedUrl)
    mainMenu()

def safelinksDecoder():
    print("\n --------------------------------- ")
    print(" S A F E L I N K S   D E C O D E R  ")
    print(" --------------------------------- ")
    url = str(input(' Enter URL: ').strip())
    dcUrl = urllib.parse.unquote(url)
    dcUrl = dcUrl.replace('https://nam02.safelinks.protection.outlook.com/?url=', '')
    print(dcUrl)
    mainMenu()

def urlscanio():
    print("\n --------------------------------- ")
    print("\n        U R L S C A N . I O        ")
    print("\n --------------------------------- ")
    url_to_scan = str(input('\nEnter url: ').strip())

    try:
        type_prompt = str(input('\nSet scan visibility to Public? \nType "1" for Public or "2" for Private: '))
        if type_prompt == '1':
            scan_type = 'public'
        else:
            scan_type = 'private'
    except:
        print('Please make a selection again.. ')

    headers = {
        'Content-Type': 'application/json',
        'API-Key': configvars.data['URLSCAN_IO_KEY'],
    }

    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data='{"url": "%s", "%s": "on"}' % (url_to_scan, scan_type)).json()

    try:
        if 'successful' in response['message']:
            print('\nNow scanning %s. Check back in around 1 minute.' % url_to_scan)
            uuid_variable = str(response['uuid']) # uuid, this is the factor that identifies the scan
            time.sleep(45) # sleep for 45 seconds. The scan takes awhile, if we try to retrieve the scan too soon, it will return an error.
            scan_results = requests.get('https://urlscan.io/api/v1/result/%s/' % uuid_variable).json() # retrieving the scan using the uuid for this scan

            task_url = scan_results['task']['url']
            verdicts_overall_score = scan_results['verdicts']['overall']['score']
            verdicts_overall_malicious = scan_results['verdicts']['overall']['malicious']
            task_report_URL = scan_results['task']['reportURL']

            print("\nurlscan.io Report:")
            print("\nURL: " + task_url)
            print("\nOverall Verdict: " + str(verdicts_overall_score))
            print("Malicious: " + str(verdicts_overall_malicious))
            print("urlscan.io: " + str(scan_results['verdicts']['urlscan']['score']))
            if scan_results['verdicts']['urlscan']['malicious']:
                print("Malicious: " + str(scan_results['verdicts']['urlscan']['malicious'])) # True
            if scan_results['verdicts']['urlscan']['categories']:
                print("Categories: ")
            for line in scan_results['verdicts']['urlscan']['categories']:
                print("\t"+ str(line)) # phishing
            for line in scan_results['verdicts']['engines']['verdicts']:
                print(str(line['engine']) + " score: " + str(line['score'])) # googlesafebrowsing
                print("Categories: ")
                for item in line['categories']:
                    print("\t" + item) # social_engineering
            print("\nSee full report for more details: " + str(task_report_URL))
            print('')
        else:
            print(response['message'])
    except:
        print(' Error reaching URLScan.io')

def unshortenUrl():
    print("\n --------------------------------- ")
    print("   U R L   U N S H O R T E N E R  ")
    print(" --------------------------------- ")
    link = str(input(' Enter URL: ').strip())
    req = requests.get(str('https://unshorten.me/s/' + link))
    print(req.text)

    decoderMenu()

def b64Decoder():
    url = str(input(' Enter URL: ').strip())

    try:
        b64 = str(base64.b64decode(url))
        a = re.split("'", b64)[1]
        print(" B64 String:     " + url)
        print(" Decoded String: " + a)
    except:
        print(' No Base64 Encoded String Found')

    decoderMenu()

def cisco7Decoder():
    pw = input(' Enter Cisco Password 7: ').strip()

    key = [0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41,
           0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c,
           0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53, 0x55, 0x42]

    try:
        # the first 2 characters of the password are the starting index in the key array
        index = int(pw[:2],16)

        # the remaining values are the characters in the password, as hex bytes
        pw_text = pw[2:]
        pw_hex_values = [pw_text[start:start+2] for start in range(0,len(pw_text),2)]

        # XOR those values against the key values, starting at the index, and convert to ASCII
        pw_chars = [chr(key[index+i] ^ int(pw_hex_values[i],16)) for i in range(0,len(pw_hex_values))]

        pw_plaintext = ''.join(pw_chars)
        print("Password: " + pw_plaintext)

    except Exception as e:
        print(e)

    decoderMenu()

def unfurlUrl():
    url_to_unfurl = str(input('Enter URL to Unfurl: ')).strip()
    unfurl_instance = core.Unfurl()
    unfurl_instance.add_to_queue(data_type='url', key=None, value=url_to_unfurl)
    unfurl_instance.parse_queue()
    print(unfurl_instance.generate_text_tree())

    decoderMenu()

def repChecker():
    from rich.console import Console
    from rich.table import Table
    console = Console()

    console.rule("[bold blue]Reputation Checker:[/bold blue]")
    # Prompt the user to enter an input string
    input_str = input("Enter an IP address, URL, or email address: ")
    # Define regular expressions for detecting IP addresses, URLs, and email addresses
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    url_pattern = re.compile(r'https?://\S+')
    email_pattern = re.compile(r'\S+@\S+\.\S+')
    # Check if the input matches any of the patterns
    if ip_pattern.match(input_str):
        #ipw = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', input_str).group(0)
        # Print the detected input type
        print("Detected input type:", input_str)
        try:
            whoIsPrint(input_str)

            console = Console()

            console.rule("[bold blue]VirusTotal Report:[/bold blue]")

            url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
            params = {'apikey':configvars.data['VT_API_KEY'],'ip':input_str}
            response = requests.get(url, params=params)

            if response.status_code == 200:
                report = response.json()
                if report["response_code"] == 1:
                    detected_urls = report.get("detected_urls", [])
                    if not detected_urls:
                        console.print(f"{input_str} has not been reported for malicious activity.")
                    else:
                        console.print(f"{input_str} has been reported for malicious activity by [bold red]{len(detected_urls)}[/bold red] sources.")
                        table = Table(show_header=True, header_style="bold magenta")
                        table.add_column("URL")
                        table.add_column("Positives")
                        table.add_column("Total")
                        for url in detected_urls:
                            table.add_row(url['url'], str(url['positives']), str(url['total']))
                        console.print(table)
                    table = Table(show_header=True, header_style="bold magenta")
                    table.add_column("Field")
                    table.add_column("Value")
                    for field, value in report.items():
                        table.add_row(str(field), str(value))
                    console.print(table)
                else:
                    console.print(f"Error: {report['verbose_msg']}")
            else:
                console.print(f"Error: {response.status_code} {response.reason}")

            console.rule("[bold blue]Tor Node Check:[/bold blue]")

            try:
                url = f"https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip={input_str}"
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200 and input_str in response.text:
                        console.print(f"[bold green]{input_str} is a Tor node.[/bold green]")
                    else:
                        console.print(f"[bold red]{input_str} is not a Tor node.[/bold red]")
                except requests.exceptions.RequestException as e:
                    console.print(f"An error occurred: {e}")
            except Exception as e:
                console.print("There is an error with checking for Tor exit nodes:\n" + str(e))




        except ValueError:
            print("Invalid IP address format.")
        except KeyError:
            print("WHOIS results are incomplete or invalid.")
    else:
        print("Input is not an IP address.")    
        


#        whoIsPrint(ipw)
        wIP = socket.gethostbyname(input_str)
        now = datetime.now()
        today = now.strftime("%m-%d-%Y")#

        if not os.path.exists('output/'+today):
            os.makedirs('output/'+today)
        f= open('output/'+today+'/'+str(input_str) + ".txt","a+")#

        print("\n VirusTotal Report:")
        f.write("\n --------------------------------- ")
        f.write("\n VirusTotal Report:")
        f.write("\n --------------------------------- \n")#
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        #params = {'apikey': configvars.data['VT_API_KEY'], 'resource': wIP}
        params = {'apikey':configvars.data['VT_API_KEY'],'ip':ipw}
        response = requests.get(url, params=params)
        if response.status_code == 200:
            report = response.json()
            if report["response_code"] == 1:
                detected_urls = report.get("detected_urls", [])
                if not detected_urls:
                    print(f"{ipw} has not been reported for malicious activity.")
                else:
                    print(f"{ipw} has been reported for malicious activity by {len(detected_urls)} sources.")
                    for url in detected_urls:
                        print(f"{url['url']} - {url['positives']}/{url['total']} antivirus programs detected this threat.")
                pretty_report = json.dumps(report, indent=4)
                print(pretty_report)
                f.write(pretty_report)          
            else:
                print(f"Error: {report['verbose_msg']}")
        else:
            print(f"Error: {response.status_code} {response.reason}")#
        try:
            url = f"https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip={ipw}"
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200 and ipw in response.text:
                    print(f"{ipw} is a Tor node.")
                else:
                    print(f"{ipw} is not a Tor node.")
            except requests.exceptions.RequestException as e:
                print(f"An error occurred: {e}")
        except Exception as e:
            print("There is an error with checking for Tor exit nodes:\n" + str(e))#

#        print("\n ABUSEIPDB Report:")
#        f.write("\n\n ---------------------------------")
#        f.write("\n ABUSEIPDB Report:")
#        f.write("\n ---------------------------------\n")#

#        try:
#            AB_URL = 'https://api.abuseipdb.com/api/v2/check'
#            days = '180'#

#            querystring = {
#                'ipAddress': wIP,
#                'maxAgeInDays': days
#            }#

#            headers = {
#                'Accept': 'application/json',
#                'Key': configvars.data['AB_API_KEY']
#            }
#            response = requests.request(method='GET', url=AB_URL, headers=headers, params=querystring)
#            if response.status_code == 200:
#                req = response.json()#

#                print("   IP:          " + str(req['data']['ipAddress']))
#                print("   Reports:     " + str(req['data']['totalReports']))
#                print("   Abuse Score: " + str(req['data']['abuseConfidenceScore']) + "%")
#                print("   Last Report: " + str(req['data']['lastReportedAt']))
#                f.write("\n\n IP:        " + str(req['data']['ipAddress']))
#                f.write("\n Reports:     " + str(req['data']['totalReports']))
#                f.write("\n Abuse Score: " + str(req['data']['abuseConfidenceScore']) + "%")
#                f.write("\n Last Report: " + str(req['data']['lastReportedAt']))
#                f.close()#

#            else:
#                print("   Error Reaching ABUSE IPDB")
#        except:
#            print('   IP Not Found')#

#            print("\n\nChecking against IP blacklists: ")
#            iplists.main(ipw)
#            mainMenu()
#        
#    elif url_pattern.match(input_str):
#        domain_name = re.search(r'(?<=://)[\w.-]+', input_str).group(0)
#        # Print the detected input type
#        print("Detected input type:", domain_name)
#        
#    elif email_pattern.match(input_str):
#        email = re.search(r'\S+@\S+\.\S+', input_str).group(0)
#        # Print the detected input type
#        print("Detected input type:", email)
#        
#    else:#

#        # Print the detected input type
#        print("None valid Detected input type:", input_str)

def dnsMenu():
    print("+{:-^38}+".format(""))
    print("|{:^38}|".format("DNS TOOLS"))
    print("+{:-^38}+".format(""))
    print("|{:^38}|".format("What would you like to do?"))
    print("+{:-^38}+".format(""))
    print("|{:<38}|".format("1. Reverse DNS Lookup"))
    print("|{:<38}|".format("2. DNS Lookup"))
    print("|{:<38}|".format("3. WHOIS Lookup"))
    print("|{:<38}|".format("0. Exit to Main Menu"))
    print("+{:-^38}+".format(""))
    dnsSwitch(input())



def reverseDnsLookup():
    d = str(input(" Enter IP to check: ").strip())
    try:
        s = socket.gethostbyaddr(d)
        print('\n ' + s[0])
    except:
        print(" Hostname not found")
    dnsMenu()

def dnsLookup():
    d = str(input(" Enter Domain Name to check: ").strip())
    d = re.sub("http://", "", d)
    d = re.sub("https://", "", d)
    try:
        s = socket.gethostbyname(d)
        print('\n ' + s)
    except:
        print("Website not found")
    dnsMenu()

def whoIs():
    ip = str(input(' Enter IP / Domain: ').strip())
    whoIsPrint(ip)

    dnsMenu()

def whoIsPrint(ip):
    try:
        from rich.console import Console
        from rich.table import Table
        from ipwhois import IPWhois

        console = Console()

        w = IPWhois(ip)
        w = w.lookup_whois()

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Field", style="dim")
        table.add_column("Value")

        table.add_row("CIDR", w["nets"][0]["cidr"])
        table.add_row("Name", w["nets"][0]["name"])
        table.add_row("Handle", w["nets"][0]["handle"])
        table.add_row("Range", w["nets"][0]["range"])
        table.add_row("Descr", w["nets"][0]["description"])
        table.add_row("Country", w["nets"][0]["country"])
        table.add_row("State", w["nets"][0]["state"])
        table.add_row("City", w["nets"][0]["city"])
        table.add_row("Address", str(w["nets"][0]["address"]).replace("\n", ", "))
        table.add_row("Post Code", w["nets"][0]["postal_code"])
        table.add_row("Emails", ", ".join(w["nets"][0]["emails"]))
        table.add_row("Created", w["nets"][0]["created"])
        table.add_row("Updated", w["nets"][0]["updated"])
        table.add_row("Abuse Email", w["nets"][0]["emails"][0])

        console.print("\n[bold magenta]WHOIS REPORT:[/bold magenta]\n")
        console.print(table)

        now = datetime.now() # current date and time
        today = now.strftime("%m-%d-%Y")
        if not os.path.exists('output/'+today):
            os.makedirs('output/'+today)
        f= open('output/'+today+'/'+str(ip.split()) + ".txt","a+")

        f.write("\n ---------------------------------")
        f.write("\n WHO IS REPORT:")
        f.write("\n ---------------------------------\n")
        f.write("\n CIDR:      " + str(w['nets'][0]['cidr']))
        f.write("\n Name:      " + str(w['nets'][0]['name']))
        f.write("  Handle:    " + str(w['nets'][0]['handle']))
        f.write("\n Range:     " + str(w['nets'][0]['range']))
        f.write("\n Descr:     " + str(w['nets'][0]['description']))
        f.write("\n Country:   " + str(w['nets'][0]['country']))
        f.write("\n State:     " + str(w['nets'][0]['state']))
        f.write("\n City:      " + str(w['nets'][0]['city']))
        f.write("\n Address:   " + addr)
        f.write("\n Post Code: " + str(w['nets'][0]['postal_code']))
        f.write("  Emails:    " + str(w['nets'][0]['emails']))
        f.write("\n Created:   " + str(w['nets'][0]['created']))
        f.write("\n Updated:   " + str(w['nets'][0]['updated']))
        f.write("\n Abuse Email: " + abuse_email)
        f.write("  description:   " + str(w['nets'][1]['description']))
        f.write("  address:   " + str(w['nets'][1]['address']))
        f.write("  emails:   " + str(w['nets'][1]['emails']))
        f.write("  updated:   " + str(w['nets'][1]['updated']))

        f.close();
        c = 0
    except:
        print("\n  IP Not Found - Checking Domains")
        ip = re.sub('https://', '', ip)
        ip = re.sub('http://', '', ip)
        try:
            if c == 0:
                s = socket.gethostbyname(ip)
                print( '  Resolved Address: %s' % s)
                c = 1
                whoIsPrint(s)
        except:
            print(' IP or Domain not Found')
    return

def hashMenu():
    print("+{:-^55}+".format(""))
    print("|{:^55}|".format("HASHING FUNCTIONS"))
    print("+{:-^55}+".format(""))
    print("|{:^55}|".format("What would you like to do?"))
    print("+{:-^55}+".format(""))
    print("|{:<55}|".format("1. Hash a file"))
    print("|{:<55}|".format("2. Input and hash text"))
    print("|{:<55}|".format("3. Check a hash for known malicious activity"))
    print("|{:<55}|".format("4. Hash a file, check a hash for malicious activity"))
    print("|{:<55}|".format("0. Exit to Main Menu"))
    print("+{:-^55}+".format(""))
    hashSwitch(input())


def hashFile():
    root = tkinter.Tk()
    root.filename = tkinter.filedialog.askopenfilename(initialdir="/", title="Select file")
    hasher = hashlib.md5()
    with open(root.filename, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    print(" MD5 Hash: " + hasher.hexdigest())
    root.destroy()
    hashMenu()

def hashText():
    userinput = input(" Enter the text to be hashed: ")
    print(" MD5 Hash: " + hashlib.md5(userinput.encode("utf-8")).hexdigest())
    hashMenu()

def hashRating():
    apierror = False
    # VT Hash Checker
    fileHash = str(input(" Enter Hash of file: ").strip())
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': configvars.data['VT_API_KEY'], 'resource': fileHash}
    response = requests.get(url, params=params)

    try:  # EAFP
        result = response.json()
    except:
        apierror = True
        print("Error: Invalid API Key")

    if not apierror:
        if result['response_code'] == 0:
            print("\n Hash was not found in Malware Database")
        elif result['response_code'] == 1:
            print(" VirusTotal Report: " + str(result['positives']) + "/" + str(result['total']) + " detections found")
            print("   Report Link: " + "https://www.virustotal.com/gui/file/" + fileHash + "/detection")
        else:
            print("No Reponse")
    hashMenu()

def hashAndFileUpload():
    root = tkinter.Tk()
    root.filename = tkinter.filedialog.askopenfilename(initialdir="/", title="Select file")
    hasher = hashlib.md5()
    with open(root.filename, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    fileHash = hasher.hexdigest()
    print(" MD5 Hash: " + fileHash)
    root.destroy()
    apierror = False
    # VT Hash Checker
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': configvars.data['VT_API_KEY'], 'resource': fileHash}
    response = requests.get(url, params=params)

    try:  # EAFP
        result = response.json()
    except:
        apierror = True
        print("Error: Invalid API Key")
    if not apierror:
        if result['response_code'] == 0:
            print("\n Hash was not found in Malware Database")
        elif result['response_code'] == 1:
            print(" VirusTotal Report: " + str(result['positives']) + "/" + str(result['total']) + " detections found")
            print("   Report Link: " + "https://www.virustotal.com/gui/file/" + fileHash + "/detection")
        else:
            print("No Response")
    hashMenu()

def phishingMenu():
    print("+{:-^62}+".format(""))
    print("|{:^62}|".format("P H I S H I N G   T O O L S"))
    print("+{:-^62}+".format(""))
    print("|{:<62}|".format("What would you like to do?"))
    print("|{:<62}|".format("OPTION 1: Analyze an Email"))
    print("|{:<62}|".format("OPTION 2: Analyze an Email Address for Known Activity"))
    print("|{:<62}|".format("OPTION 3: Generate an Email Template based on Analysis"))
    print("|{:<62}|".format("OPTION 4: Analyze a URL with Phishtank"))
    print("|{:<62}|".format("OPTION 9: HaveIBeenPwned"))
    print("|{:<62}|".format("OPTION 0: Exit to Main Menu"))
    print("+{:-^62}+".format(""))
    phishingSwitch(input())


def analyzePhish():
    try:
        file = tkinter.filedialog.askopenfilename(initialdir="/", title="Select file")
        with open(file, encoding='Latin-1') as f:
            msg = f.read()

        # Fixes issue with file name / dir name exceptions
        file = file.replace('//', '/')  # dir
        file2 = file.replace(' ', '')   # file name (remove spaces / %20)
        os.rename(file, file2)
        outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
        msg = outlook.OpenSharedItem(file)
    except Exception as e:
        print(' Error Opening File',e)

    print("\n Extracting Headers...")
    try:
        print("   FROM:      ", str(msg.SenderName), ", ", str(msg.SenderEmailAddress))
        print("   TO:        ", str(msg.To))
        print("   SUBJECT:   ", str(msg.Subject))
        print("   NameBehalf:", str(msg.SentOnBehalfOfName))
        print("   CC:        ", str(msg.CC))
        print("   BCC:       ", str(msg.BCC))
        print("   Sent On:   ", str(msg.SentOn))
        print("   Created:   ", str(msg.CreationTime))
        s = str(msg.Body)
    except:
        print('   Header Error')
        f.close()

    print("\n Extracting Links... ")
    try:
        match = r"((www\.|http://|https://)(www\.)*.*?(?=(www\.|http://|https://|$)))"
        a = re.findall(match, msg.Body, re.M | re.I)
        for b in a:
            match = re.search(r'https://urldefense.proofpoint.com/(v[0-9])/', b[0])
            if match:
                if match.group(1) == 'v1':
                    decodev1(b[0])
                elif match.group(1) == 'v2':
                    decodev2(b[0])
            else:
                if b[0] not in linksFoundList:
                    linksFoundList.append(b[0])
        if len(a) == 0:
            print(' No Links Found...')
    except:
        print('   Links Error')
        f.close()

    for each in linksFoundList:
        print('   %s' % each)

    print("\n Extracting Emails Addresses... ")
    try:
        match = r'([\w0-9._-]+@[\w0-9._-]+\.[\w0-9_-]+)'
        emailList = list()
        a = re.findall(match, s, re.M | re.I)

        for b in a:
            if b not in emailList:
                emailList.append(b)
                print(" ", b)
            if len(emailList) == 0:
                print('   No Emails Found')

        if len(a) == 0:
            print('   No Emails Found...')
    except:
        print('   Emails Error')
        f.close()

    print("\n Extracting IP's...")
    try:
        ipList = []
        foundIP = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s)
        ipList.append(foundIP)

        if not ipList:
            for each in ipList:
                print(each)
        else:
            print('   No IP Addresses Found...')
    except:
        print('   IP error')

    try:
        analyzeEmail(msg.SenderEmailAddress)
    except:
        print('')

    phishingMenu()

def haveIBeenPwned():
    print("\n --------------------------------- ")
    print(" H A V E   I   B E E N   P W N E D  ")
    print(" --------------------------------- ")

    try:
        acc = str(input(' Enter email: ').strip())
        haveIBeenPwnedPrintOut(acc)
    except:
        print('')
    phishingMenu()

def haveIBeenPwnedPrintOut(acc):
    try:
        url = 'https://haveibeenpwned.com/api/v3/breachedaccount/%s' % acc
        userAgent = 'Sooty'
        headers = {'Content-Type': 'application/json', 'hibp-api-key': configvars.data['HIBP_API_KEY'], 'user-agent': userAgent}
        try:
            req = requests.get(url, headers=headers)
            response = req.json()
            lr = len(response)
            if lr != 0:
                print('\n The account has been found in the following breaches: ')
                for each in range(lr):
                    breach = 'https://haveibeenpwned.com/api/v3/breach/%s' % response[each]['Name']
                    breachReq = requests.get(breach, headers=headers)
                    breachResponse = breachReq.json()

                    breachList = []
                    print('\n   Title:        %s' % breachResponse['Title'])
                    print('   Domain:       %s' % breachResponse['Domain'])
                    print('   Breach Date:  %s' % breachResponse['BreachDate'])
                    print('   Pwn Count:    %s' % breachResponse['PwnCount'])
                    for each in breachResponse['DataClasses']:
                        breachList.append(each)
                    print('   Data leaked: %s' % breachList)
        except:
            print(' No Entries found in Database')
    except:
        print('')

def analyzeEmailInput():
    print("\n --------------------------------- ")
    print("    E M A I L   A N A L Y S I S    ")
    print(" --------------------------------- ")
    try:
        email = str(input(' Enter Email Address to Analyze: ').strip())
        analyzeEmail(email)
        phishingMenu()
    except:
        print("   Error Scanning Email Address")

def analyzeEmail(email):

    try:
        url = 'https://emailrep.io/'
        userAgent = 'Sooty'
        summary = '?summary=true'
        url = url + email + summary
        if 'API Key' not in configvars.data['EMAILREP_API_KEY']:
            erep_key = configvars.data['EMAILREP_API_KEY']
            headers = {'Content-Type': 'application/json', 'Key': configvars.data['EMAILREP_API_KEY'], 'User-Agent': userAgent}
            response = requests.get(url, headers=headers)
        else:
            response = requests.get(url)
        req = response.json()
        emailDomain = re.split('@', email)[1]

        print('\n Email Analysis Report ')
        if response.status_code == 400:
            print(' Invalid Email / Bad Request')
        if response.status_code == 401:
            print(' Unauthorized / Invalid API Key (for Authenticated Requests)')
        if response.status_code == 429:
            print(' Too many requests, ')
        if response.status_code == 200:
            now = datetime.now() # current date and time
            today = now.strftime("%m-%d-%Y")
            if not os.path.exists('output/'+today):
                os.makedirs('output/'+today)
            f = open('output/'+today+'/'+str(email) + ".txt","w+")
            f.write("\n --------------------------------- ")
            f.write('\n   Email Analysis Report : ')
            f.write("\n ---------------------------------\n ")

            print('   Email:       %s' % req['email'])
            print('   Reputation:  %s' % req['reputation'])
            print('   Suspicious:  %s' % req['suspicious'])
            print('   Spotted:     %s' % req['references'] + ' Times')
            print('   Blacklisted: %s' % req['details']['blacklisted'])
            print('   Last Seen:   %s' % req['details']['last_seen'])
            print('   Known Spam:  %s' % req['details']['spam'])

            f.write('  Email:       %s' % req['email'])
            f.write('\n   Reputation:  %s' % req['reputation'])
            f.write('\n   Suspicious:  %s' % req['suspicious'])
            f.write('\n   Spotted:     %s' % req['references'] + ' Times')
            f.write('\n   Blacklisted: %s' % req['details']['blacklisted'])
            f.write('\n   Last Seen:   %s' % req['details']['last_seen'])
            f.write('\n   Known Spam:  %s' % req['details']['spam'])

            print('\n Domain Report ')
            print('   Domain:        @%s' % emailDomain)
            print('   Domain Exists: %s' % req['details']['domain_exists'])
            print('   Domain Rep:    %s' % req['details']['domain_reputation'])
            print('   Domain Age:    %s' % req['details']['days_since_domain_creation'] + ' Days')
            print('   New Domain:    %s' % req['details']['new_domain'])
            print('   Deliverable:   %s' % req['details']['deliverable'])
            print('   Free Provider: %s' % req['details']['free_provider'])
            print('   Disposable:    %s' % req['details']['disposable'])
            print('   Spoofable:     %s' % req['details']['spoofable'])

            f.write("\n\n --------------------------------- ")
            f.write('\n   Domain Report ')
            f.write("\n --------------------------------- \n")
            f.write('\n   Domain:        @%s' % emailDomain)
            f.write('\n   Domain Exists: %s' % req['details']['domain_exists'])
            f.write('\n   Domain Rep:    %s' % req['details']['domain_reputation'])
            f.write('\n   Domain Age:    %s' % req['details']['days_since_domain_creation'] + ' Days')
            f.write('\n   New Domain:    %s' % req['details']['new_domain'])
            f.write('\n   Deliverable:   %s' % req['details']['deliverable'])
            f.write('\n   Free Provider: %s' % req['details']['free_provider'])
            f.write('\n   Disposable:    %s' % req['details']['disposable'])
            f.write('\n   Spoofable:     %s' % req['details']['spoofable'])


            print('\n Malicious Activity Report ')
            print('   Malicious Activity: %s' % req['details']['malicious_activity'])
            print('   Recent Activity:    %s' % req['details']['malicious_activity_recent'])
            print('   Credentials Leaked: %s' % req['details']['credentials_leaked'])
            print('   Found in breach:    %s' % req['details']['data_breach'])

            f.write("\n\n --------------------------------- ")
            f.write('\n   Malicious Activity Report ')
            f.write("\n --------------------------------- \n")
            f.write('\n   Malicious Activity: %s' % req['details']['malicious_activity'])
            f.write('\n   Recent Activity:    %s' % req['details']['malicious_activity_recent'])
            f.write('\n   Credentials Leaked: %s' % req['details']['credentials_leaked'])
            f.write('\n   Found in breach:    %s' % req['details']['data_breach'])

            if (req['details']['data_breach']):
                try:
                    url = 'https://haveibeenpwned.com/api/v3/breachedaccount/%s' % email
                    headers = {'Content-Type': 'application/json', 'hibp-api-key': configvars.data['HIBP_API_KEY'], 'user-agent': userAgent}

                    try:
                        reqHIBP = requests.get(url, headers=headers)
                        response = reqHIBP.json()
                        lr = len(response)
                        if lr != 0:
                            print('\nThe account has been found in the following breaches: ')
                            for each in range(lr):
                                breach = 'https://haveibeenpwned.com/api/v3/breach/%s' % response[each]['Name']
                                breachReq = requests.get(breach, headers=headers)
                                breachResponse = breachReq.json()
                                breachList = []
                                print('   Title:        %s' % breachResponse['Title'])
                                print('   Breach Date:  %s' % breachResponse['BreachDate'])
                                f.write('\n   Title:        %s' % breachResponse['Title'])
                                f.write('\n   Breach Date:  %s' % breachResponse['BreachDate'])

                                for each in breachResponse['DataClasses']:
                                    breachList.append(each)
                                print('   Data leaked: %s' % breachList,'\n')
                                f.write('\n   Data leaked: %s' % breachList,'\n')
                    except:
                        print(' Error')
                except:
                    print(' No API Key Found')
            print('\n Profiles Found ')
            f.write("\n\n --------------------------------- ")
            f.write('\n   Profiles Found ')
            f.write("\n --------------------------------- \n")

            if (len(req['details']['profiles']) != 0):
                profileList = (req['details']['profiles'])
                for each in profileList:
                    print('   - %s' % each)
                    f.write('\n   - %s' % each)
            else:
                print('   No Profiles Found For This User')
                f.write(' \n  No Profiles Found For This User')

            print('\n Summary of Report: ')
            f.write("\n\n --------------------------------- ")
            f.write('\n   Summary of Report: ')
            f.write("\n ---------------------------------\n ")
            repSum = req['summary']
            repSum = re.split(r"\.\s*", repSum)
            for each in repSum:
                print('   %s' % each)
                f.write('\n   %s' % each)
            f.close()


    except:
        print(' Error Analyzing Submitted Email')
        f.write('\n Error Analyzing Submitted Email')
        f.close()


def virusTotalAnalyze(result, sanitizedLink):
    linksDict['%s' % sanitizedLink] = str(result['positives'])
    #print(str(result['positives']))

def emailTemplateGen():
    print('\n--------------------')
    print('  Phishing Response')
    print('--------------------')

    try:
        file = tkinter.filedialog.askopenfilename(initialdir="/", title="Select file")
        with open(file, encoding='Latin-1') as f:
            msg = f.read()
        file = file.replace('//', '/')  # dir
        file2 = file.replace(' ', '')  # file name (remove spaces / %20)
        os.rename(file, file2)
        outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
        msg = outlook.OpenSharedItem(file)
    except:
        print(' Error importing email for template generator')

    url = 'https://emailrep.io/'
    email = msg.SenderEmailAddress
    url = url + email
    responseRep = requests.get(url)
    req = responseRep.json()
    f = msg.To.split(' ', 1)[0]

    try:
        match = r"((www\.|http://|https://)(www\.)*.*?(?=(www\.|http://|https://|$)))"
        a = re.findall(match, msg.Body, re.M | re.I)
        for b in a:
            match = re.search(r'https://urldefense.proofpoint.com/(v[0-9])/', b[0])
            if match:
                if match.group(1) == 'v1':
                    decodev1(b[0])
                elif match.group(1) == 'v2':
                    decodev2(b[0])
            else:
                if b[0] not in linksFoundList:
                    linksFoundList.append(b[0])
        if len(a) == 0:
            print(' No Links Found...')
    except:
        print('   Links Error')
        f.close()

    for each in linksFoundList:
        x = re.sub(r"\.", "[.]", each)
        x = re.sub("http://", "hxxp://", x)
        x = re.sub("https://", "hxxps://", x)
        sanitizedLink = x

    if 'API Key' not in configvars.data['VT_API_KEY']:
        try:  # EAFP
            url = 'https://www.virustotal.com/vtapi/v2/url/report'
            for each in linksFoundList:
                link = each
                params = {'apikey': configvars.data['VT_API_KEY'], 'resource': link}
                response = requests.get(url, params=params)
                result = response.json()
                if result['response_code'] == 0:
                    print(" [Warn] URL not found in VirusTotal database!")
                    continue
                if response.status_code == 200:
                    virusTotalAnalyze(result, sanitizedLink)

        except:
            print("\n Threshold reached for VirusTotal: "
                  "\n   60 seconds remaining...")
            time.sleep(15)
            print('   45 seconds remaining...')
            time.sleep(15)
            print('   30 seconds remaining...')
            time.sleep(15)
            print('   15 seconds remaining...')
            time.sleep(15)
            virusTotalAnalyze(result, sanitizedLink)
    else:
        print('No API Key set, results will not show malicious links')

    rc = 'potentially benign'
    threshold = '1'

    if req['details']['spam'] or req['suspicious'] or req['details']['blacklisted'] or req['details']['malicious_activity']:
        rc = 'potentially suspicious'

    for key, value in linksDict.items():
        if int(value) >= int(threshold):
            rc = 'potentially malicious'

    if responseRep.status_code == 200:
        print('\nHi %s,' % f,)
        print('\nThanks for your recent submission.')
        print('\nI have completed my analysis of the submitted mail and have classed it is as %s.' % rc)
        print('\nThe sender has a reputation score of %s,' % req['reputation'], 'for the following reasons: ')

        if req['details']['spam']:
            print(' - The sender has been reported for sending spam in the past.')
        if req['suspicious']:
            print(' - It has been marked as suspicious on reputation checking websites.')
        if req['details']['free_provider']:
            print(' - The sender is using a free provider.')
        if req['details']['days_since_domain_creation'] < 365:
            print(' - The domain is less than a year old.')
        if req['details']['blacklisted']:
            print(' - It has been blacklisted on several sites.')
        if req['details']['data_breach']:
            print(' - Has been seen in data breaches')
        if req['details']['credentials_leaked']:
            print(' - The credentials have been leaked for this address')
        if req['details']['malicious_activity']:
            print(' - This sender has been flagged for malicious activity.')

        malLink = 0     # Controller for mal link text
        for each in linksDict.values():
            if int(threshold) <= int(each):
                malLink = 1

        if malLink == 1:
            print('\nThe following potentially malicious links were found embedded in the body of the mail:')
            for key, value in linksDict.items():
                if int(value) >= int(threshold):
                    print(' - %s' % key)

        print('\nAs such, I would recommend the following: ')

        if 'suspicious' in rc:
            print(' - Delete and Ignore the mail for the time being.')

        if 'malicious' in rc:
            print(' - If you clicked any links or entered information into any displayed webpages let us know asap.')

        if 'spam' in rc:
            print(' - If you were not expecting the mail, please delete and ignore.')
            print(' - We would advise you to use your email vendors spam function to block further mails.')

        if 'task' in rc:
            print(' - If you completed any tasks asked of you, please let us know asap.')
            print(' - If you were not expecting the mail, please delete and ignore.')

        if 'benign' in rc:
            print(' - If you were not expecting this mail, please delete and ignore.')
            print('\nIf you receive further mails from this sender, you can use your mail vendors spam function to block further mails.')

        if 'suspicious' or 'malicious' or 'task' in rc:
            print('\nI will be reaching out to have this sender blocked to prevent the sending of further mails as part of our remediation effort.')
            print('For now, I would recommend to simply delete and ignore this mail.')
            print('\nWe appreciate your diligence in reporting this mail.')

        print('\nRegards,')

def phishtankModule():
    if "phishtank" in configvars.data:
        url = input(' Enter the URL to be checked: ').strip()
        download, appname, api = (
            configvars.data["phishtank"]["download"],
            configvars.data["phishtank"]["appname"],
            configvars.data["phishtank"]["api"],
        )
        phishtank.main(download, appname, api, url)
    else:
        print("Missing configuration for phishtank in the config.yaml file.")

def extrasMenu():
    print("+{:-^62}+".format(""))
    print("|{:^62}|".format("E X T R A S"))
    print("+{:-^62}+".format(""))
    print("|{:<62}|".format("What would you like to do?"))
    print("|{:<62}|".format("OPTION 1: About SOOTY"))
    print("|{:<62}|".format("OPTION 2: Contributors"))
    print("|{:<62}|".format("OPTION 3: Version"))
    print("|{:<62}|".format("OPTION 4: Wiki"))
    print("|{:<62}|".format("OPTION 5: GitHub Repo"))
    print("|{:<62}|".format("OPTION 0: Exit to Main Menu"))
    print("+{:-^62}+".format(""))
    extrasSwitch(input())


def aboutSooty():
    print(' Socterminal is a tool developed and targeted to help automate some tasks that SOC Analysts perform.')
    extrasMenu()

def contributors():
    print(' CONTRIBUTORS')

    extrasMenu()

def extrasVersion():
    print(' Current Version: ' + versionNo)
    extrasMenu()

def wikiLink():
    print('\n The Sooty Wiki can be found at the following link:')
    print(' https://github.com/akshay-nehate/Sooty/wiki')
    extrasMenu()

def ghLink():
    print('\n The Sooty Repo can be found at the following link:')
    print(' https://github.com/akshay-nehate/Sooty')
    extrasMenu()

if __name__ == '__main__':
    titleLogo()
    mainMenu()
