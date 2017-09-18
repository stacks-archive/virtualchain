#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Virtualchain
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016-2017 by Blockstack.org
    
    This file is part of Virtualchain
    
    Virtualchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    Virtualchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Virtualchain.  If not, see <http://www.gnu.org/licenses/>.
"""

# depending on whether or not we're talking to 
# -testnet/-regtest or mainnet, determine which human-readible 
# prefix to use
import os

if os.environ.get("BLOCKSTACK_TESTNET", None) == "1" or os.environ.get("BLOCKSTACK_TESTNET3", None) == "1":
    bech32_prefix = 'tb'

else:
    bech32_prefix = 'bc'

bech32_witver = '1'

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# taken from BIP173
def bech32_polymod(values):
  GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
  chk = 1
  for v in values:
    b = (chk >> 25)
    chk = (chk & 0x1ffffff) << 5 ^ v
    for i in range(5):
      chk ^= GEN[i] if ((b >> i) & 1) else 0
  return chk


# taken from BIP173
def bech32_hrp_expand(s):
  return [ord(x) >> 5 for x in s] + [0] + [ord(x) & 31 for x in s]


# taken from BIP173
def bech32_verify_checksum(hrp, data):
  return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1


# taken from BIP173
def bech32_create_checksum(hrp, data):
  values = bech32_hrp_expand(hrp) + data
  polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
  return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


# taken from https://github.com/sipa/bech32/blob/master/ref/python/segwit_addr.py
def bech32_encode(hrp, data):
    """Compute a Bech32 string given HRP and data values."""
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])


# taken from https://github.com/sipa/bech32/blob/master/ref/python/segwit_addr.py
def bech32_decode(bech):
    """Validate a Bech32 string, and determine HRP and data."""
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return (None, None)
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return (None, None)
    if not all(x in CHARSET for x in bech[pos+1:]):
        return (None, None)
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos+1:]]
    if not bech32_verify_checksum(hrp, data):
        return (None, None)
    return (hrp, data[:-6])


# taken from https://github.com/sipa/bech32/blob/master/ref/python/segwit_addr.py
def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


# taken from https://github.com/sipa/bech32/blob/master/ref/python/segwit_addr.py
def segwit_addr_decode(addr, hrp=bech32_prefix):
    """
    Decode a segwit address.
    Returns (version, hash_bin) on success
    Returns (None, None) on error
    """
    hrpgot, data = bech32_decode(addr)
    if hrpgot != hrp:
        return (None, None)
    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        return (None, None)
    if data[0] > 16:
        return (None, None)
    if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
        return (None, None)
    return (data[0], ''.join([chr(x) for x in decoded]))


# taken from https://github.com/sipa/bech32/blob/master/ref/python/segwit_addr.py
def segwit_addr_encode(witprog_bin, hrp=bech32_prefix, witver=bech32_witver):
    """
    Encode a segwit script hash to a bech32 address.
    Returns the bech32-encoded string on success
    """
    witprog_bytes = [ord(c) for c in witprog_bin]
    ret = bech32_encode(hrp, [int(witver)] + convertbits(witprog_bytes, 8, 5))
    assert segwit_addr_decode(hrp, ret) is not (None, None)
    return ret
