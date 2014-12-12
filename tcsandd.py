## Permission is hereby granted, free of charge, to any person
## obtaining a copy of this software and associated documentation
## files (the "Software"), to deal in the Software without
## restriction, including without limitation the rights to use,
## copy, modify, merge, publish, distribute, sublicense, and/or sell
## copies of the Software, and to permit persons to whom the
## Software is furnished to do so, subject to the following
## conditions:
##
## The above copyright notice and this permission notice shall be
## included in all copies or substantial portions of the Software.
##
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
## EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
## OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
## NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
## HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
## WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
## FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
## OTHER DEALINGS IN THE SOFTWARE.
## --
## Changelog
## Aug 2013: Initial version. Made for the DC3 Forensics Challenge 2013


import sys
import os
import optparse
from tcsearch import * 
import truecrypt7
import logging
from Tkinter import *
import tkMessageBox
import tkFileDialog 
import itertools


class GUI(Tk):
	def __init__(self,parent):
		Tk.__init__(self,parent)
		self.parent = parent
		self.initialize()

	def initialize(self):
		self.grid()
		self.logger = logging.getLogger("tcsandd.GUI")
		
		#Selecting 1 file
		select_one_button = Button(self,text=u"Select 1 File", command=self.select_one)
		select_one_button.grid(column=0,row=0,columnspan=1,sticky='W')
		
		clear_one_button = Button(self,text=u"Clear", command=self.clear_one)
		clear_one_button.grid(column=2,row=0,columnspan=1,sticky='E')
		
		self.select_one_text = StringVar()
		self.select_one_text.set("")
		
		select_one_label = Label(self,textvariable=self.select_one_text, anchor="w")
		select_one_label.grid(column=1,row=0,columnspan=1,sticky='W')
		
		#Selecting filelist
		select_filelist_button = Button(self,text=u"Select file list", command=self.select_filelist)
		select_filelist_button.grid(column=0,row=1,columnspan=1,sticky='W')
		
		clear_filelist_button = Button(self,text=u"Clear", command=self.clear_filelist)
		clear_filelist_button.grid(column=2,row=1,columnspan=1,sticky='E')
		
		self.select_filelist_text = StringVar()
		self.select_filelist_text.set("")
		
		select_filelist_label = Label(self,textvariable=self.select_filelist_text, anchor="w")
		select_filelist_label.grid(column=1,row=1,columnspan=1,sticky='W')
		
		#Selecting directory
		select_dir_button = Button(self,text=u"Select directory", command=self.select_dir)
		select_dir_button.grid(column=0,row=2,columnspan=1,sticky='W')

		clear_dir_button = Button(self,text=u"Clear", command=self.clear_dir)
		clear_dir_button.grid(column=2,row=2,columnspan=1,sticky='E')
		
		self.select_dir_text = StringVar()
		self.select_dir_text.set("")
		
		select_dir_label = Label(self,textvariable=self.select_dir_text, anchor="w")
		select_dir_label.grid(column=1,row=2,columnspan=1,sticky='W')
		
		#Selecting header config file
		select_header_button = Button(self,text=u"Select Header Config File", command=self.select_header)
		select_header_button.grid(column=0,row=3,columnspan=1,sticky='W')

		clear_header_button = Button(self,text=u"Clear", command=self.clear_header)
		clear_header_button.grid(column=2,row=3,columnspan=1,sticky='E')		

		self.select_header_text = StringVar()
		self.select_header_text.set("")
		
		select_header_label = Label(self,textvariable=self.select_header_text, anchor="w")
		select_header_label.grid(column=1,row=3,columnspan=1,sticky='W')
		
		#Setting password
		clear_pw_entry_button = Button(self,text=u"Clear", command=self.clear_pw_entry)
		clear_pw_entry_button.grid(column=2,row=4,columnspan=1,sticky='E')		

		password_label = Label(self,text=u"Specify a password", anchor="w")
		password_label.grid(column=0,row=4,columnspan=1,sticky='W')

		self.pw_entry_text = StringVar()
		self.pw_entry_text.set("")
		
		self.pw_entry = Entry(self,textvariable=self.pw_entry_text)
		self.pw_entry.grid(column=1,row=4,sticky='W')
		#self.pwentry.bind("<Button-1>", self.pw_reset)
		
		#Selecting dictionary
		select_dictionary_button = Button(self,text=u"Select Dictionary", command=self.select_dictionary)
		select_dictionary_button.grid(column=0,row=5,columnspan=1,sticky='W')

		clear_dictionary_button = Button(self,text=u"Clear", command=self.clear_dictionary)
		clear_dictionary_button.grid(column=2,row=5,columnspan=1,sticky='E')		

		self.select_dictionary_text = StringVar()
		self.select_dictionary_text.set("")
		
		select_dictionary_label = Label(self,textvariable=self.select_dictionary_text, anchor="w")
		select_dictionary_label.grid(column=1,row=5,columnspan=1,sticky='W')
		
		#Selecting regular
		clear_regular_button = Button(self,text=u"Clear", command=self.clear_regular)
		clear_regular_button.grid(column=2,row=6,columnspan=1,sticky='E')		

		regular_label = Label(self,text=u"Specify characters:", anchor="w")
		regular_label.grid(column=0,row=6,columnspan=1,sticky='W')
		
		self.regular_entry_text = StringVar()
		self.regular_entry_text.set("")
		
		self.regular_entry = Entry(self,textvariable=self.regular_entry_text)
		self.regular_entry.grid(column=1,row=6,sticky='W')
		
		#Setting max password length
		clear_length_button = Button(self,text=u"Clear", command=self.clear_length)
		clear_length_button.grid(column=2,row=7,columnspan=1,sticky='E')		

		length_label = Label(self,text=u"Max length:", anchor="w")
		length_label.grid(column=0,row=7,columnspan=1,sticky='W')
		
		self.length_entry_text = StringVar()
		self.length_entry_text.set("")
		
		self.length_entry = Entry(self,textvariable=self.length_entry_text)
		self.length_entry.grid(column=1,row=7,sticky='W')

		#Selecting keyfile directory
		select_keyfiledir_button = Button(self,text=u"Select keyfile directory", command=self.select_keyfiledir)
		select_keyfiledir_button.grid(column=0,row=8,columnspan=1,sticky='W')

		clear_keyfiledir_button = Button(self,text=u"Clear", command=self.clear_keyfiledir)
		clear_keyfiledir_button.grid(column=2,row=8,columnspan=1,sticky='E')
		
		self.select_keyfiledir_text = StringVar()
		self.select_keyfiledir_text.set("")
		
		select_keyfiledir_label = Label(self,textvariable=self.select_keyfiledir_text, anchor="w")
		select_keyfiledir_label.grid(column=1,row=8,columnspan=1,sticky='W')

		#Selecting output file
		clear_output_button = Button(self,text=u"Clear", command=self.clear_output)
		clear_output_button.grid(column=2,row=9,columnspan=1,sticky='E')		

		select_output_button = Button(self,text=u"Select Output File", command=self.select_output)
		select_output_button.grid(column=0,row=9,columnspan=1,sticky='W')

		self.select_output_text = StringVar()
		self.select_output_text.set("")
		
		select_output_label = Label(self,textvariable=self.select_output_text, anchor="w")
		select_output_label.grid(column=1,row=9,columnspan=1,sticky='W')
		
		self.search_only_var = IntVar()
		self.search_only_check = Checkbutton(self, text="Search Only", variable=self.search_only_var)
		self.search_only_check.grid(column=0,row=10,columnspan=1,sticky='W')

		self.bruteforce_keyfiles_var = IntVar()
		self.bruteforce_keyfiles_check = Checkbutton(self, text="Brute Force keyfiles", variable=self.bruteforce_keyfiles_var)
		self.bruteforce_keyfiles_check.grid(column=1,row=10,columnspan=1,sticky='W')

		#Other buttons
		compute_button = Button(self,text=u"Run", command=self.run_app)
		compute_button.grid(column=0,row=11,columnspan=3,sticky='WE')

		clearall_button = Button(self,text=u"Clear all values", command=self.clear_app)
		clearall_button.grid(column=0,row=12,columnspan=3,sticky='WE')

		self.grid_columnconfigure(0,weight=1)
		self.resizable(True,False)
	
	def pw_reset(self,event):
		self.pwentry_text.set("")
	
	def run_app(self):
		compute(self.pw_entry_text.get(), self.select_dictionary_text.get(), self.regular_entry_text.get(), self.select_output_text.get(), self.select_one_text.get(), self.select_dir_text.get(), self.select_header_text.get(), self.length_entry_text.get(), self.search_only_var.get(), self.select_filelist_text.get(),self.select_keyfiledir_text.get(), self.bruteforce_keyfiles_var.get())
		tkMessageBox.showinfo("Done", "Done")

	def clear_one(self):
		self.select_one_text.set("")

	def clear_filelist(self):
		self.select_filelist_text.set("")

	def clear_pw_entry(self):
		self.pw_entry_text.set("")

	def clear_dictionary(self):
		self.select_dictionary_text.set("")

	def clear_regular(self):
		self.regular_entry_text.set("")

	def clear_output(self):
		self.select_output_text.set("")

	def clear_dir(self):
		self.select_dir_text.set("")

	def clear_header(self):
		self.select_header_text.set("")

	def clear_length(self):
		self.length_entry_text.set("")

	def clear_keyfiledir(self):
		self.select_keyfiledir_text.set("")

	def clear_app(self):
		self.pw_entry_text.set("")
		self.select_dictionary_text.set("")
		self.regular_entry_text.set("")
		self.select_output_text.set("")
		self.select_one_text.set("")
		self.select_dir_text.set("")
		self.select_header_text.set("")
		self.length_entry_text.set("")
		self.select_filelist_text.set("")
		self.select_keyfiledir_text.set("")

	def select_one(self):
		options = {}
		options['filetypes'] = [('All files', '*')]
		fl = tkFileDialog.askopenfilename(**options)
		if fl != '':
			self.select_one_text.set(fl)
					
	def select_filelist(self):
		options = {}
		options['filetypes'] = [('All files', '*')]
		fl = tkFileDialog.askopenfilename(**options)
		if fl != '':
			self.select_filelist_text.set(fl)
					
	def select_header(self):
		options = {}
		options['filetypes'] = [('Config files', '*.conf'),('All files', '*')]
		fl = tkFileDialog.askopenfilename(**options)
		if fl != '':
			self.select_header_text.set(fl)
					
	def select_dictionary(self):
		options = {}
		options['filetypes'] = [('All files', '*')]
		fl = tkFileDialog.askopenfilename(**options)
		if fl != '':
			self.select_dictionary_text.set(fl)
					
	def select_output(self):
		options = {}
		options['filetypes'] = [('All files', '*')]
		fl = tkFileDialog.asksaveasfilename(**options)
		if fl != '':
			self.select_output_text.set(fl)
					
	def select_dir(self):
		options = {}
		#options['initialdir'] = 'C:\\'
		options['mustexist'] = True
		fl = tkFileDialog.askdirectory(**options)
		if fl != '':
			self.select_dir_text.set(fl)
					
	def select_keyfiledir(self):
		options = {}
		#options['initialdir'] = 'C:\\'
		options['mustexist'] = True
		fl = tkFileDialog.askdirectory(**options)
		if fl != '':
			self.select_keyfiledir_text.set(fl)
					

def read_file_into_list(filename):
	"""
	Read each line of a file to a list
	"""
	f = open(filename)
	lines = [line.rstrip('\n') for line in f]
	f.close()
	return lines

def dict_attack(filename, dictionary, output, keyfilelist):
	"""
	Dictionary attack against a TC file
	"""
	logger = logging.getLogger("tcsandd.dict_attack")
	passwords = read_file_into_list(dictionary)
	for pw in passwords:
		logger.info("Trying file: " + filename + " with password: " + pw)
		if (truecrypt7.decrypt(filename, output, pw, keyfilelist)):
			logger.info("TC volume: " + filename)
			logger.info("Password found: " + pw)
			logger.info("Decrypted copy saved to: " + output)
			return True
	return False

def regular_attack(filename, chars, length, output, keyfilelist):
	"""
	Generated attack against a TC file
	"""
#	chars = string.digits + string.letters
	logger = logging.getLogger("tcsandd.regular_attack")
	try:
		MAX_CHARS = int(length)
	except ValueError:
		MAX_CHARS = 1
		logger.error("The specified length: " + length + " is not a number, using 1")
	for nletters in range(MAX_CHARS):
		for word in itertools.product(chars, repeat=nletters + 1):
			pw = ''.join(word)
			logger.info("Trying file: " + filename + " with password: " + pw)
			if (truecrypt7.decrypt(filename, output, pw, keyfilelist)):
				logger.info("TC volume: " + filename)
				logger.info("Password found: " + pw)
				logger.info("Decrypted copy saved to: " + output)
				return True
	return False

def compute(password, dictionary, regular, output, single, path, config, length, search_only, fl, keyfiledir, bf_keyfiles):
	logger = logging.getLogger("tcsandd.compute")
	#make a list of keyfiles
	keyfilelist = []
	if(keyfiledir !="" and os.path.exists(keyfiledir)):
		logger.info("Creating keyfile list")
		for path,dirs,files in os.walk(keyfiledir):
			for f in files:
				keyfilelist.append(os.path.join(path,f))
		logger.info("Keyfiles: " + str(keyfilelist))
	else:
		keyfilelist = None
		logger.info("No keyfiles specified")

	if(search_only):
		if (os.path.exists(path)):
			filelist = search_file(path, config)
			logger.info("Found files: " + str(filelist))
			f = open("foundfiles.txt",'w')
			f.write("\n".join(filelist))
			f.close()
		else:
			logger.error("The specified path: " + path + " doesn't exists")
		
	elif (password == '' and dictionary == '' and regular == ''):
		logger.error("Specify at least 1 password type.")
				
	elif (single != ''):
		if (output == ""): output = single + ".decrypted"
		if (not os.path.exists(single)):
			logger.error("Specified file %s doesn't exists" % single)
		elif (password != ''):
			logger.info("Trying file: " + single + " with password: " + password)
			if(bf_keyfiles and keyfilelist):
				for n in range(len(keyfilelist)):
					for kfl in itertools.permutations(keyfilelist, n + 1):
						logger.info("Trying file: " + single + " with keyfilelist: " + str(kfl))
						truecrypt7.decrypt(single, output, password, kfl)
			else:
				truecrypt7.decrypt(single, output, password, keyfilelist)
		elif (dictionary != ''):
			if (os.path.exists(dictionary)):
				logger.info("Dictionary found!")
				if(bf_keyfiles and keyfilelist):
					for n in range(len(keyfilelist)):
						for kfl in itertools.permutations(keyfilelist, n + 1):
							logger.info("Trying file: " + single + " with keyfilelist: " + str(kfl))
							dict_attack(single, dictionary, output, kfl)
				else:
					dict_attack(single, dictionary, output, keyfilelist)
			else:
				logger.error("Dictionary doesn't exists, and other password options are not specified")
		elif (regular != ''):
			if(bf_keyfiles and keyfilelist):
				for n in range(len(keyfilelist)):
					for kfl in itertools.permutations(keyfilelist, n + 1):
						logger.info("Trying file: " + single + " with keyfilelist: " + str(kfl))
						regular_attack(single, regular, length, output, kfl)
			else:
				regular_attack(single, regular, length, output, keyfilelist)
					
	elif (fl != '' or path != ''):
		filelist = []
		error = False
		if (os.path.exists(fl)):
			filelist = read_file_into_list(fl)
		elif (os.path.exists(path)):
			logger.error("Specified file %s doesn't exists" % fl)
			filelist = search_file(path, config)
			logger.info("Found files: " + str(filelist))
			logger.info("Trying to decrypt them")
		else:
			logger.error("Specified file %s doesn't exists" % fl)
			logger.error("The specified path: " + path + " doesn't exists")
			error = True
			
		if(not error):
			for f in filelist:
				if (password != ''):
					logger.info("Trying file: " + f + " with password: " + password)
					if(bf_keyfiles and keyfilelist):
						for n in range(len(keyfilelist)):
							for kfl in itertools.permutations(keyfilelist, n + 1):
								logger.info("Trying file: " + f + " with keyfilelist: " + str(kfl))
								truecrypt7.decrypt(f, f + ".decrypted", password, kfl)
					else:
						truecrypt7.decrypt(f, f + ".decrypted", password, keyfilelist)
				elif (dictionary != ''):
					if (os.path.exists(dictionary)):
						logger.info("Dictionary found!")
						if(bf_keyfiles and keyfilelist):
							for n in range(len(keyfilelist)):
								for kfl in itertools.permutations(keyfilelist, n + 1):
									logger.info("Trying file: " + f + " with keyfilelist: " + str(kfl))
									dict_attack(f, dictionary, f + ".decrypted", kfl)
						else:
							dict_attack(f, dictionary, f + ".decrypted", keyfilelist)
					else:
						logger.error("Dictionary doesn't exists, and other password options are not specified")
				elif (regular != ''):
					if(bf_keyfiles and keyfilelist):
						for n in range(len(keyfilelist)):
							for kfl in itertools.permutations(keyfilelist, n + 1):
								logger.info("Trying file: " + f + " with keyfilelist: " + str(kfl))
								regular_attack(f, regular, length, f + ".decrypted", kfl)
					else:
						regular_attack(f, regular, length, f + ".decrypted", keyfilelist)
					
def main():
	usage = "Usage: %prog [options]"
	parser = optparse.OptionParser(usage=usage)
	# Uncomment the first line to accept a usermane as a parameter. If Local Auth in Netwitness is used.
	parser.add_option('-G', '--gui', action='store_true', dest='gui', default=False, help='Start GUI')
	parser.add_option('-S', '--search_only', action='store_true', dest='search_only', default=False, help='Search only')
	parser.add_option('-v', '--verbose', action='store_true', dest='verbose', default=False, help='Verbose output')

	parser.add_option('-s', '--single', action='store', dest="single", default='', help='Specify a single file')
	parser.add_option('-f', '--filelist', action='store', dest="filelist", default='', help='File for file list')
	parser.add_option('-p', '--path', action='store', dest='path', default='.', help='Path to search, default is the current directory')
	parser.add_option('-c', '--config', action='store', dest='config', default='', help='Path to Foremost / Scalpel config file')

	parser.add_option('-P', '--password', action='store', dest='password', default='', help='Single password to try')
	parser.add_option('-d', '--dictionary', action='store', dest='dictionary', default='', help='Dictionary to use for password attacks')
	parser.add_option('-r', '--regular', action='store', dest='regular', default='', help='Characters for password generation')
	parser.add_option('-l', '--length', action='store', dest='length', default='1', help='Maximum password length, default: 1')
	parser.add_option('-k', '--keyfiledir', action='store', dest='keyfiledir', default='', help='Directory of keyfiles')
	parser.add_option('-B', '--brutekeys', action='store_true', dest='brutekeys', default=False, help='Bruteforce keyfiles')
	
	parser.add_option('-o', '--output', action='store', dest='output', default='', help='Output file (only in case of a single file specified)')
	options, args = parser.parse_args()
	
	logger = logging.getLogger("tcsandd")
	if (options.verbose):
		logger.setLevel(logging.DEBUG)
	else:
		logger.setLevel(logging.INFO)
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	# create the logging file handler
	fh = logging.FileHandler("tcsandd.log")
	fh.setFormatter(formatter)
	# create the logging console handler
	console = logging.StreamHandler()
	console.setFormatter(formatter)
	# add handler to logger object
	logger.addHandler(fh)
	logger.addHandler(console)
	
	if (options.gui):
		logger.info("Starting GUI")
		
		app = GUI(None)
		app.title('TC Search and Decrypt')
		app.mainloop()
		
	else:
		compute(options.password, options.dictionary, options.regular, options.output, options.single, options.path, options.config, options.length, options.search_only, options.filelist, options.keyfiledir, options.brutekeys)
	
if __name__ == '__main__':
	main()



