#!/usr/bin/env python3

import sys
import os
import validators
import ipaddress
import urllib.parse
import re
import json

# -------------------------- INFO --------------------------

def basic():
	global proceed
	proceed = False
	print("Domain Extractor v3.0 ( github.com/ivan-sincek/domain-extractor )")
	print("")
	print("Usage:   python3 domain_extractor.py -f file               -o out")
	print("Example: python3 domain_extractor.py -f malicious_urls.txt -o results.json")

def advanced():
	basic()
	print("")
	print("DESCRIPTION")
	print("    Extract valid or partially valid domain names and IPs from URLs")
	print("FILE")
	print("    File with URLs you want to extract data from")
	print("    -f <file> - malicious_urls.txt | etc.")
	print("OUT")
	print("    Output file")
	print("    -o <out> - results.json | etc.")

# ------------------- MISCELENIOUS BEGIN -------------------

def unique(sequence):
	seen = set()
	return [x for x in sequence if not (x in seen or seen.add(x))]

def read_file(file):
	tmp = []
	with open(file, "r", encoding = "UTF-8") as stream:
		for line in stream:
			line = line.strip()
			if line:
				tmp.append(line)
	stream.close()
	return unique(tmp)

def jdump(data):
	return json.dumps(data, indent = 4, ensure_ascii = False)

def write_file(data, out):
	confirm = "yes"
	if os.path.isfile(out):
		print(("'{0}' already exists").format(out))
		confirm = input("Overwrite the output file (yes): ")
	if confirm.lower() == "yes":
		open(out, "w").write(data)
		print(("Results have been saved to '{0}'").format(out))

# -------------------- MISCELENIOUS END --------------------

# -------------------- VALIDATION BEGIN --------------------

# my own validation algorithm

proceed = True

def print_error(msg):
	print(("ERROR: {0}").format(msg))

def error(msg, help = False):
	global proceed
	proceed = False
	print_error(msg)
	if help:
		print("Use -h for basic and --help for advanced info")

args = {"file": None, "out": None}

def validate(key, value):
	global args
	value = value.strip()
	if len(value) > 0:
		if key == "-f" and args["file"] is None:
			args["file"] = value
			if not os.path.isfile(args["file"]):
				error("File does not exists")
			elif not os.access(args["file"], os.R_OK):
				error("File does not have read permission")
			elif not os.stat(args["file"]).st_size > 0:
				error("File is empty")
			else:
				args["file"] = read_file(args["file"])
				if not args["file"]:
					error("No URLs were found")
		elif key == "-o" and args["out"] is None:
			args["out"] = value

def check(argc, args):
	count = 0
	for key in args:
		if args[key] is not None:
			count += 1
	return argc - count == argc / 2

argc = len(sys.argv) - 1

if argc == 0:
	advanced()
elif argc == 1:
	if sys.argv[1] == "-h":
		basic()
	elif sys.argv[1] == "--help":
		advanced()
	else:
		error("Incorrect usage", True)
elif argc % 2 == 0 and argc <= len(args) * 2:
	for i in range(1, argc, 2):
		validate(sys.argv[i], sys.argv[i + 1])
	if args["file"] is None or args["out"] is None or not check(argc, args):
		error("Missing a mandatory option (-f, -o)", True)
else:
	error("Incorrect usage", True)

# --------------------- VALIDATION END ---------------------

# ----------------------- TASK BEGIN -----------------------

def validate_ip(ip):
	success = True
	try:
		ipaddress.ip_address(ip)
	except ValueError:
		success = False
	return success

def extract(urls):
	results = []
	for url in urls:
		entry = {"original": url, "decoded": None, "hosts": []}
		url = urllib.parse.unquote(url).strip()
		if url:
			entry["decoded"] = url
			matches = re.findall(r"(?![\.\:\/\?\#\[\]\@\!\$\&\'\(\)\*\+\,\;\=])[^\s\:\/\?\#\[\]\@\!\$\&\'\(\)\*\+\,\;\=]+(?<![\.\:\/\?\#\[\]\@\!\$\&\'\(\)\*\+\,\;\=])", url)
			if matches:
				for match in matches:
					if (validators.domain(match) or validate_ip(match)) and match not in entry["hosts"]:
						entry["hosts"].append(match)
		results.append(entry)
	return results

if proceed:
	print("#####################################################################")
	print("#                                                                   #")
	print("#                       Domain Extractor v3.0                       #")
	print("#                                   by Ivan Sincek                  #")
	print("#                                                                   #")
	print("# Extract valid or partially valid domain names and IPs from URLs.  #")
	print("# GitHub repository at github.com/ivan-sincek/domain-extractor.     #")
	print("#                                                                   #")
	print("#####################################################################")
	write_file(jdump(extract(args["file"])), args["out"])

# ------------------------ TASK END ------------------------
