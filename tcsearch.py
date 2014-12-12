## Changelog
## Source: https://code.google.com/p/tcdiscover/
## Aug 2013: Most parts rewritten to work with real files instead of an image.
## Made for the DC3 Forensics Challenge 2013

import os
import math
import array
import re
import logging

headers = []
	
def check_size(fn):
	#262144 is the min size because of the headers and backup headers
	if ((os.path.getsize(fn) % 512) == 0) and (os.path.getsize(fn) > 262144): return True
	else: return False

def calculate_entropy(fn):
	"""
	Calculate the entropy of a file based on the fist 2MB.
	"""
	occurences = []
	entropy = 0
	logger = logging.getLogger("tcsandd.tcsearch.calculate_entropy")
	for i in range(256):
		occurences.append(0)
	try:
		with open(fn, "rb") as f:
			data = f.read(2048*1024)
			for i in range(len(data)):
				# Do stuff with byte.
				occurences[ord(data[i])] += 1
        
		#print occurences
		#size = os.path.getsize(fn)
		size = len(data)
		for x in occurences:
			if (x != 0):
				p_x = float(x) / size
				entropy -= p_x*math.log(p_x, 2)
	except IOError, e: logger.error("IOError: " + str(e))
	return entropy

def convert_header_to_hex(s):
	"""
	Converts any pieces of the scalpel/foremost config file from ascii to hex
	"""
	finalString = ""
	x = 0
	
	while x < len(s):
		if s[x:x+2] == "\\x": # found a hex value
			finalString += s[x+2:x+4]
			x += 4
		elif s[x] == "?": #translate the wildcard correctly
			finalString += "[0-9a-f]"
			x += 1
		else: # a non hex value, so encode it
			finalString += s[x].encode("hex")
			x += 1
			
	return finalString

def read_headers(config_file):
	"""
	Creates the magic header list based on defaults or based on a scalpel/foremost config file
	"""
	global headers
	if config_file == "":
		# Use standard list of common headers (pkzip, jpg, png)
		headervals = ("504b0304","ffd8ff","89504e470D0a1a0a")
		headers = []
		for header in headervals:
			headers.append(re.compile(header))
		
	else:
		lines = open(config_file).readlines()	
		headervals = [convert_header_to_hex(line.split()[3]) for line in lines if line[0] != "#" and line != "\n"]
		headers = []
		for header in headervals:
			headers.append(re.compile(header))
	#print headers

def check_header(fn):
	"""
	Search file for common file headers
	"""
	global headers
	logger = logging.getLogger("tcsandd.tcsearch.check_header")
	try:
		with open(fn, "rb") as f:
			byte = f.read(16) # read first 16 bytes
			hexval = str(byte.encode("hex")).lower()
			for header in headers:
				if header.match(hexval):
					return True
	except IOError, e: logger.error("IOError: " + str(e))
	
	return False

def search_file(diretory,config):
	"""
	Searches for a TC file
	The suspect file size modulo 512 must equal zero.
	The suspect file size is at least 19 KB in size
	The suspect file has entropy more then 7.6.
	The suspect file must not contain a common file header.
	"""
	filelist = []
	logger = logging.getLogger("tcsandd.tcsearch.search_file")
	read_headers(config)
	for path,dirs,files in os.walk(diretory):
		for f in files:
			try:
				if (check_size(os.path.join(path,f))):
					#print str(f) + ": True"
					if(check_header(os.path.join(path,f))):
						logger.debug(str(os.path.join(path,f)) + ": File is known file type")
					else:
						e = calculate_entropy(os.path.join(path,f))
						if e > 7.6:
							logger.info(str(os.path.join(path,f)) + ": Probably encrypted file, entropy: " + str(e) + ", file size: " + str(os.path.getsize(os.path.join(path,f))))
							filelist.append(os.path.join(path,f))
						else:
							logger.debug(str(os.path.join(path,f)) + ": Entropy is below 7.6")
				else:
					logger.debug(str(os.path.join(path,f)) + ": File size or mod doesn't match")
			except UnicodeEncodeError, e: logger.error("UnicodeEncodeError: " + str(e))
			except WindowsError, e: logger.error("WindowsError: " + str(e))
	return filelist
