#!/bin/python3.9
from tkinter import *
import urllib.request
import json
import os
import urllib
import hashlib
from tkinter import filedialog
import time

logo ='''
╔═══╗     ╔╗ ╔╗         ╔╗         
║╔═╗║     ║║ ║║         ║║         
║╚═╝║╔╗ ╔╗║╚═╝║╔══╗ ╔══╗║╚═╗╔══╗╔═╗
║╔══╝║║ ║║║╔═╗║╚ ╗║ ║══╣║╔╗║║╔╗║║╔╝
║║   ║╚═╝║║║ ║║║╚╝╚╗╠══║║║║║║║═╣║║ 
╚╝   ╚═╗╔╝╚╝ ╚╝╚═══╝╚══╝╚╝╚╝╚══╝╚╝ 
     ╔═╝║                          
     ╚══╝
'''
def main():

    try:
        Tk().withdraw()
        os.system('cls' if os.name == 'nt' else 'clear') 
        print(logo)
        mode_select = input("Mode Select: \n1: File Hasher.\n2: Virus Total Report.\n\nSelection: ") 
        api_key = "f3f7b1243956a1d954a684f325d267b8480078e1bc96104aee03cf2bc3bed5fb"
        if mode_select == '1': 
            os.system('cls' if os.name == 'nt' else 'clear')
            file_path = filedialog.askopenfilename() or input("Enter path of the file location: ")
            sample = open(file_path, 'rb').read()
            os.system('cls' if os.name == 'nt' else 'clear')
            print("File: " + file_path + "\n\n" + "MD5: " + hashlib.md5(sample).hexdigest() + '\n\n' + "SHA-256: " + hashlib.sha256(sample).hexdigest()+ '\n\n' + "SHA-1: " + hashlib.sha1(sample).hexdigest())
            os.system("pause")

        if mode_select == '2':
            os.system('cls' if os.name == 'nt' else 'clear')
            option_select = input("Virus Total Report Options\n1: File Upload.\n2: Manual Hash Entry.\n\nSelection: ")
            if option_select == '1':
                try:
                    os.system('cls' if os.name == 'nt' else 'clear')
                    file_path = filedialog.askopenfilename()
                    sample = open(file_path, 'rb').read()
                    hash_value = hashlib.md5(sample).hexdigest()
                    vt_url = "https://www.virustotal.com/vtapi/v2/file/report?apikey="+api_key+"&resource="+hash_value
                    request = urllib.request.urlopen(vt_url)
                    json_response = json.loads(request.read())
                    if json_response['response_code']:
                        results = {"detections": json_response['positives'], "total": json_response['total'], "perma_link": json_response['permalink'], "scan_date": json_response['scan_date'], "scan_results": json_response['scans']}               
                        print("Total Results: " , results["total"],"\nTotal Detections: " , results["detections"],"\nScan Date: " , results["scan_date"],"\nPermanent Link: " , results["perma_link"],"\n\nVirusTotal Results:\n")
                        for (av_name, av_value) in results["scan_results"].items():
                            print (av_name, av_value, '\n')
                        os.system("pause")
                    else:
                        print ("No AV Detections For: " + hash_value) 
                        os.system("pause")
                except TypeError:
                    file_path = input("Enter file path: ")
                    vt_url = "https://www.virustotal.com/vtapi/v2/file/report?apikey="+api_key+"&resource="+file_path
                    request = urllib.request.urlopen(vt_url)
                    json_response = json.loads(request.read())
                    if json_response['response_code']:
                        results = {"detections": json_response['positives'], "total": json_response['total'], "perma_link": json_response['permalink'], "scan_date": json_response['scan_date'], "scan_results": json_response['scans']}               
                        print("Total Results: " , results["total"],"\nTotal Detections: " , results["detections"],"\nScan Date: " , results["scan_date"],"\nPermanent Link: " , results["perma_link"],"\n\nVirusTotal Results:\n")
                        for (av_name, av_value) in results["scan_results"].items():
                            print (av_name, av_value, '\n')
                        os.system("pause")
                    else:
                        print ("No AV Detections For: " + file_path)
                        os.system("pause") 
            if option_select == '2':
                os.system('cls' if os.name == 'nt' else 'clear')
                manual_entry = input("Enter the hash you wish to be scanned: ")
                vt_url = "https://www.virustotal.com/vtapi/v2/file/report?apikey="+api_key+"&resource="+manual_entry 
                request = urllib.request.urlopen(vt_url)
                json_response = json.loads(request.read())
                if json_response['response_code']:
                    results = {"detections": json_response['positives'], "total": json_response['total'], "perma_link": json_response['permalink'], "scan_date": json_response['scan_date'], "scan_results": json_response['scans']}               
                    print("Total Results: " , results["total"],"\nTotal Detections: " , results["detections"],"\nScan Date: " , results["scan_date"],"\nPermanent Link: " , results["perma_link"],"\n\nVirusTotal Results:\n")
                    for (av_name, av_value) in results["scan_results"].items():
                        print (av_name, av_value, '\n')
                    os.system("pause")

                else:
                    print ("No AV Detections For: " + hash_value) 
                    os.system("pause")

    except KeyboardInterrupt:
        os.system('cls' if os.name == 'nt' else 'clear')
        main()
        print('Program Terminated...Exiting.')
        time.sleep(1)
        os.system('cls' if os.name == 'nt' else 'clear')
main()