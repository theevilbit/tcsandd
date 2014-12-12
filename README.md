TrueCrypt Search and Decrypt
============================

I developed this python script / tool for the 2013 DC3 Forensic Challenge. It will search for TC encrypted files in a folder or drive, and then will try to decrypt them.

I used some of the source code from the following resources:

https://code.google.com/p/tcdiscover/
http://blog.bjrn.se/2008/01/truecrypt-explained.html
http://blog.bjrn.se/2008/02/truecrypt-explained-truecrypt-5-update.html

The codes above were rewritten to support TrueCrypt version 7, keyfile support was added.

The tool is very fast in searching TC volumes. The search logic is the following:
a. The suspect file size modulo 512 must equal zero.
b. The suspect file size is at least 256kB in size (this is the size of the headers + backup headers)
c. The suspect file must not contain a common file header.
d. The suspect file has entropy more then 7.6.

The search is actually looking for encrypted files, as it’s impossible to tell if a file is a TC volume until the correct password is supplied. Thus it can be used to look for other encrypted files like FreeOTFE.
Based on these rules, the search will find any possible encrypted file, not only TC. Proving that a file is actually a TC volume is impossible without decryption. If running it on the entire file system, it will find about 300 files, which are not real TC volumes at all, which is a very good false positive rate, considering that there are more than 200.000 files on a normal computer. (This is only if we have the provided foremost configuration file set, to filter out known headers). An example Foremost header configuration file provided with the source code.

The password tries are very slow compared to other tools like OTFBrutus (http://www.tateu.net/software/dl.php?f=OTFBrutusGUI), and the reason is that the hash and encryptions implemented in python are not so optimal. If we have only a couple of passwords to try, then the tool is good, but if not it will run for long time. The tool can decrypt an entire TC volume (hidden as well) once the password is found.

Licence: MIT, except the parts which were taken from other sources. see above.