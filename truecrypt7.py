## truecrypt5.py - partial TrueCrypt 5 implementation in Python.
## Copyright (c) 2008 Bjorn Edstrom <be@bjrn.se>
##
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
## Jan 4 2008: Initial version. Plenty of room for improvements.
## Feb 13 2008: Added TrueCrypt 5 volume support.
## Source: http://www.bjrn.se/code/pytruecrypt/truecrypt5py.txt
## Aug 2013: Rewritten by Csaba Fitzl to work with TC 7 for the DC3 Forensics Challenge 2013

import sys
import os
import logging

from rijndael import Rijndael
from serpent import Serpent
from twofish import Twofish
from xts import *
from keystrengthening7 import *
import keyfile

#
# Utilities.
#

import struct
import time
import binascii

def CRC32(data):
    """Compute CRC-32."""
    crc = binascii.crc32(data)
    # Convert from signed to unsigned word32.
    return crc % 0x100000000

def BE16(x):
    """Bytes to 16 bit big endian word."""
    return struct.unpack(">H", x)[0]

def BE32(x):
    """Bytes to 32 bit big endian word."""
    return struct.unpack(">L", x)[0]

def BE64(x):
    """Bytes to 64 bit big endian word."""
    a, b = struct.unpack(">LL", x)
    return (a<<32) | b

def Win32FileTime2UnixTime(filetime):
    """Converts a win32 FILETIME to a unix timestamp."""
    return filetime / 10000000 - 11644473600

#
# Ciphers.
#

Cascades = [
    [Rijndael],
    [Serpent],
    [Twofish],
    [Twofish, Rijndael],
    [Serpent, Twofish, Rijndael],
    [Rijndael, Serpent],
    [Rijndael, Twofish, Serpent],
    [Serpent, Twofish]
]

#
# TrueCrypt
#

TC_SECTOR_SIZE = 512
TC_HIDDEN_HEADER_OFFSET = 65536
TC_BACKUP_HEADER = 65536 * 2

def Decrypt(ciphers, i, n, ciphertext):
    assert len(ciphertext) == 16
    for cipher1, cipher2 in reversed(ciphers):
        ciphertext = XTSDecrypt(cipher1, cipher2, i, n, ciphertext)
    return ciphertext

def DecryptMany(ciphers, n, blocks):
    length = len(blocks)
    assert length % 16 == 0
    data = ''
    for i in xrange(length / 16):
        data += Decrypt(ciphers, i, n, blocks[0:16])
        blocks = blocks[16:]
    return data

class TrueCryptVolume7:
    """Object representing a TrueCrypt 5 volume."""
    def __init__(self, fileobj, password, keyfiles = None, logger = logging.getLogger("tcsandd.truecrypt7.TrueCryptVolume7")):

        self.fileobj = fileobj
        self.decrypted_header = None
        self.cipher = None
        self.hidden_size = 0
        self.logger = logger
        self.keyfiles = keyfiles
        
        if (keyfiles): password = keyfile.keyfile_process(keyfiles, password)
		
        #logger.debug(password)
        for volume_type in ["normal", "hidden"]:
            fileobj.seek(0)
            if volume_type == "hidden":
                fileobj.seek(-TC_HIDDEN_HEADER_OFFSET, 2)

            logger.info("Is this a " + volume_type + " volume?")
            
            salt = fileobj.read(64)
            header = fileobj.read(448)
            
            assert len(salt) == 64
            assert len(header) == 448

            HMACs = [
                (HMAC_SHA512, 1000, "SHA-512"),
                (HMAC_RIPEMD160, 2000, "RIPEMD-160"),
                (HMAC_WHIRLPOOL, 1000, "Whirlpool")
            ]
            for hmac, iterations, hmac_name in HMACs:
                logger.debug("Trying " + hmac_name)
                #print password.encode('hex')
                header_keypool = PBKDF2(hmac, password, salt, iterations, 32*6)

                # Key strengthening done. Try all cipher algorithm combos.
                for cascade in Cascades:
                    cipherlist1, cipherlist2 = [], []
                    
                    if len(cascade) == 1:
                        key1a = header_keypool[0:32]
                        
                        key1b = header_keypool[32:64]

                        algo1, = cascade
                        cipherlist1 = [ algo1(key1a) ]
                        cipherlist2 = [ algo1(key1b) ]                        
                    elif len(cascade) == 2:
                        key1a = header_keypool[0:32]
                        key2a = header_keypool[32:64]

                        key1b = header_keypool[64:96]
                        key2b = header_keypool[96:128]

                        algo1, algo2 = cascade
                        cipherlist1 = [ algo1(key1a), algo2(key2a) ]
                        cipherlist2 = [ algo1(key1b), algo2(key2b) ]                        
                    elif len(cascade) == 3:
                        key1a = header_keypool[0:32]
                        key2a = header_keypool[32:64]
                        key3a = header_keypool[64:96]

                        key1b = header_keypool[96:128]
                        key2b = header_keypool[128:160]
                        key3b = header_keypool[160:192]

                        algo1, algo2, algo3 = cascade
                        cipherlist1 = [ algo1(key1a), algo2(key2a), algo3(key3a) ]
                        cipherlist2 = [ algo1(key1b), algo2(key2b), algo3(key3b) ]                        

                    self.cipherlist = zip(cipherlist1, cipherlist2)

                    logger.debug("..." +  str([ciph.get_name() for ciph in cipherlist1]) )

                    decrypted_header = DecryptMany(self.cipherlist, 0, header)
                    if TCIsValidVolumeHeader(decrypted_header):
                        # Success.
                        self.decrypted_header = decrypted_header
                        master_keypool = decrypted_header[192:]

                        cipherlist1, cipherlist2 = [], []
                        
                        if len(cascade) == 1:
                            key1a = master_keypool[0:32]
                            
                            key1b = master_keypool[32:64]

                            algo1, = cascade
                            cipherlist1 = [ algo1(key1a) ]
                            cipherlist2 = [ algo1(key1b) ]                        
                        elif len(cascade) == 2:
                            key1a = master_keypool[0:32]
                            key2a = master_keypool[32:64]

                            key1b = master_keypool[64:96]
                            key2b = master_keypool[96:128]

                            algo1, algo2 = cascade
                            cipherlist1 = [ algo1(key1a), algo2(key2a) ]
                            cipherlist2 = [ algo1(key1b), algo2(key2b) ]                        
                        elif len(cascade) == 3:
                            key1a = master_keypool[0:32]
                            key2a = master_keypool[32:64]
                            key3a = master_keypool[64:96]

                            key1b = master_keypool[96:128]
                            key2b = master_keypool[128:160]
                            key3b = master_keypool[160:192]

                            algo1, algo2, algo3 = cascade
                            cipherlist1 = [ algo1(key1a), algo2(key2a), algo3(key3a) ]
                            cipherlist2 = [ algo1(key1b), algo2(key2b), algo3(key3b) ]                        

                        self.cipherlist = zip(cipherlist1, cipherlist2)
                        if volume_type == "hidden":
						    self.hidden_size = BE64(decrypted_header[28:28+8])

                        logger.info("Success!")
                        return
        # Failed attempt.
        raise KeyError, "incorrect password (or not a truecrypt volume)"

    def __repr__(self):
        if not self.decrypted_header:
            return "<TrueCryptVolume7>"
        return "<TrueCryptVolume7 %s %s>" % (self.cipher1.get_name(), self.info_hash)

def TCIsValidVolumeHeader(header):
    magic = header[0:4]
    checksum = BE32(header[8:12])
    return magic == 'TRUE' and CRC32(header[192:448]) == checksum

def TCReadSector(tc, index):
    """Read a sector from the volume."""
    assert index > 0
    tc.fileobj.seek(0, 2)
    file_len = tc.fileobj.tell()

    # For a regular (non-hidden) volume the file system starts at byte
    # 131072. However for a hidden volume, the start of the file system
    # is not at byte 131072 . Starting from the end of the volume, namely
    # byte file_len, we subtract the backup header. We then subtract the size of the
    # hidden volume.
    mod = 131072 - TC_SECTOR_SIZE 
    last_sector_offset = TC_BACKUP_HEADER
    if tc.hidden_size:
        mod = file_len - tc.hidden_size - TC_BACKUP_HEADER
        # We subtract another sector from mod because the index starts
        # at 1 and not 0.
        mod -= TC_SECTOR_SIZE
        #last_sector_offset = TC_SECTOR_SIZE + TC_BACKUP_HEADER
    seekto = mod + TC_SECTOR_SIZE * index

    # last_sector_offset is the beginning of the last sector relative
    # the end of the file. For a regular non-hidden volume this is simply
    # TC_BACKUP_HEADER bytes from the end of the file.
    if seekto > file_len - last_sector_offset:
        return ''

    tc.fileobj.seek(seekto)
    data = tc.fileobj.read(TC_SECTOR_SIZE)

    # In TrueCrypt 5 the dataunit index is always a function of the
    # offset in the volume file, even for hidden volumes. This means
    # the first dataunit index for hidden volumes is not 1. For
    # regular volumes, mod/512 will be 0. For hidden volumes mod/512
    # is the dataunit index of the first sector, minus 1
    # (so mod/512 + 1 is the first dataunit).
    return DecryptMany(tc.cipherlist, mod/512 + index, data)
          

def TCSectorCount(tc):
    """How many sectors can we read with TCReadSector?"""
    volume_size = 0
    if tc.hidden_size:
        volume_size = tc.hidden_size
    else:
        tc.fileobj.seek(0, 2)
        volume_size = tc.fileobj.tell()
        # Minus the headers.
        volume_size -= 131072
        volume_size -= 131072		
    return volume_size / TC_SECTOR_SIZE

def decrypt(filein, outfile, password, keyfiles):
    logger = logging.getLogger("tcsandd.truecrypt7.decrypt")
    if os.path.exists(outfile):
        logger.error("outfile %s already exists. use another " \
              "filename and try again (we don't want to overwrite " \
              "files by mistake)" % outfile)
        return False

    try:
        fileobj = file(filein, "rb")
    except IOError:
        logger.error("File %s doesn't exist" % filein)
        return False

    tc = None
    try:
        tc = TrueCryptVolume7(fileobj, password, keyfiles)
    except KeyError:
        logger.error("Incorrect password or not a TrueCrypt volume")
        fileobj.close()
        return False
    except KeyboardInterrupt:
        logger.error("Aborting...")
        fileobj.close()
        return False

    outfileobj = file(outfile, "ab")
    num_sectors = TCSectorCount(tc)
    #print str(num_sectors)
    num_written = 0
    try:
        for i in xrange(1, num_sectors + 1):
            if i % 100 == 0:
                logger.info("Decrypting sector %d of %d." % (i, num_sectors))
            #skip first and last 2*65535 (volume headers and backup volume headers)
            #if (i >= ignore_sectors) and (i < num_sectors + 1 - ignore_sectors):
            outfileobj.write(TCReadSector(tc, i))
            num_written += 1
    except KeyboardInterrupt:
        print "Aborted decryption."
        pass
    outfileobj.close()
    logger.info("Wrote %d sectors (%d bytes)." % (num_written, num_written * TC_SECTOR_SIZE))
    fileobj.close()
    return True
