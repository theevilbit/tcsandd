## keystrengthening5.py - PBKDF2 algorithm.
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
## Feb 13 2008: Added SHA-512 support.
## Source: http://www.bjrn.se/code/pytruecrypt/keystrengthening5py.txt

import struct
import math

import sha
import whirlpool
import hashlib

#
# Hash funcs.
#

def HASH_SHA1(data):
    return sha.new(data).digest()

def HASH_SHA512(data):
    return hashlib.sha512(data).digest()

def HASH_WHIRLPOOL(data):
    return whirlpool.new(data).digest()

def HASH_RIPEMD160(data):
    hashobj = hashlib.new('ripemd160')
    hashobj.update(data)
    return hashobj.digest()

def hexdigest(S):
    tmp = ''
    for s in S:
        tmp += '%02x' % ord(s)
    return tmp

#
# HMAC funcs.
# http://en.wikipedia.org/wiki/HMAC
#

def HMAC(hash_func, hash_block_size, key, message):
    if len(key) > hash_block_size:
        key = hash_func(key)
    if len(key) < hash_block_size:
        key += '\x00' * (hash_block_size - len(key))
    assert len(key) == hash_block_size
    ipad = ''
    opad = ''
    for i in xrange(hash_block_size):
        ipad += chr(0x36 ^ ord(key[i]))
        opad += chr(0x5c ^ ord(key[i]))
    return hash_func(opad + hash_func(ipad + message))

def HMAC_SHA1(key, message):
    return HMAC(HASH_SHA1, 64, key, message)

def HMAC_SHA512(key, message):
    return HMAC(HASH_SHA512, 128, key, message)
    
def HMAC_RIPEMD160(key, message):
    return HMAC(HASH_RIPEMD160, 64, key, message)
    
def HMAC_WHIRLPOOL(key, message):
    return HMAC(HASH_WHIRLPOOL, 64, key, message)

#
# PBKDF2.
# http://www.ietf.org/rfc/rfc2898.txt
#

def xor_string(str1, str2):
    # TODO: slow!
    str3 = ''
    for i in xrange(len(str1)):
        str3 += chr(ord(str1[i]) ^ ord(str2[i]))
    return str3

def PBKDF2(hmacfunc, password, salt, iterations, derivedlen):
    """Derive keys using the PBKDF2 key strengthening algorithm."""
    hLen = len(hmacfunc('', '')) # digest size
    l = int(math.ceil(derivedlen / float(hLen)))
    r = derivedlen - (l - 1) * hLen
    def F(P, S, c, i):
        U_prev = hmacfunc(P, S + struct.pack('>L', i))
        res = U_prev
        for cc in xrange(2, c+1):
            U_c = hmacfunc(P, U_prev)
            res = xor_string(res, U_c)
            U_prev = U_c
        return res
    tmp = ''
    i = 1
    while True:
        tmp += F(password, salt, iterations, i)
        if len(tmp) > derivedlen:
            break
        i += 1
    return tmp[0:derivedlen]

