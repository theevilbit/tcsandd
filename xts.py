## xts.py - The XTS cryptographic mode.
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
## Feb 13 2008: Initial version. Plenty of room for improvements.
## Source: http://www.bjrn.se/code/pytruecrypt/xtspy.txt

from gf2n import *
import struct

def gf2pow128powof2(n):
    """2^n in GF(2^128)."""
    if n < 128:
        return 2**n
    return reduce(gf2pow128mul, (2 for x in xrange(n)), 1)

## C = E_K1(P xor (E_K2(n) mul (a pow i))) xor (E_K2(n) mul (a pow i))
def XTSDecrypt(cipher1, cipher2, i, n, block):
    """Perform a XTS decrypt operation."""

    def str2int(str):
        N = 0
        for c in reversed(str):
            N <<= 8
            N |= ord(c)
        return N

    def int2str(N):
        str = ''
        while N:
            str += chr(N & 0xff)
            N >>= 8
        return str

    def xorstring16(a, b):
        new = ''
        for p in xrange(16):
            new += chr(ord(a[p]) ^ ord(b[p]))
        return new

    # e_k2_n = E_K2(n)
    n_txt = struct.pack('< Q', n) + '\x00' * 8
    e_k2_n = cipher2.encrypt(n_txt)

    # a_i = (a pow i)
    a_i = gf2pow128powof2(i)

    # e_mul_a = E_K2(n) mul (a pow i)
    e_mul_a = gf2pow128mul(str2int(e_k2_n), a_i)
    e_mul_a = int2str(e_mul_a)
    e_mul_a = '\x00' * (16 - len(e_mul_a)) + e_mul_a

    # C = E_K1(P xor e_mul_a) xor e_mul_a
    return xorstring16(e_mul_a, cipher1.decrypt(xorstring16(e_mul_a, block)))

def XTSDecryptMany(cipher1, cipher2, n, blocks):
    length = len(blocks)
    assert length % 16 == 0
    data = ''
    for i in xrange(length / 16):
        data += XTSDecrypt(cipher1, cipher2, i, n, blocks[0:16])
        blocks = blocks[16:]
    return data
