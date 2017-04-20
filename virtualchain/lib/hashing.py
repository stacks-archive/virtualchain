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
from binascii import hexlify, unhexlify
import hashlib
from hashlib import sha256

def hex_to_int(s):
    try:
        return int(s, 16)
    except:
        raise ValueError("Value must be in hex format")

def is_hex(s):
    # make sure that s is a string
    if not isinstance(s, str):
        return False
    # if there's a leading hex string indicator, strip it
    if s[0:2] == '0x':
        s = s[2:]
    # try to cast the string as an int
    try:
        i = hex_to_int(s)
    except ValueError:
        return False
    else:
        return True


def count_bytes(hex_s):
    """ Calculate the number of bytes of a given hex string.
    """
    assert(is_hex(hex_s))
    return len(hex_s)/2


def flip_endian(s):
    if is_hex:
        return hexlify(unhexlify(s)[::-1])
    return s[::-1]


def bin_hash160(s, hex_format=False):
    """ s is in hex or binary format
    """
    if hex_format and is_hex(s):
        s = unhexlify(s)
    return hashlib.new('ripemd160', bin_sha256(s)).digest()


def hex_hash160(s, hex_format=False):
    """ s is in hex or binary format
    """
    if hex_format and is_hex(s):
        s = unhexlify(s)
    return hexlify(bin_hash160(s))


def bin_sha256(bin_s):
    return sha256(bin_s).digest()


def bin_double_sha256(bin_s):
    return bin_sha256(bin_sha256(bin_s))


def reverse_hash(hash, hex_format=True):
    """ hash is in hex or binary format
    """
    if not hex_format:
        hash = hexlify(hash)
    return "".join(reversed([hash[i:i+2] for i in range(0, len(hash), 2)]))


def hex_to_bin_reversed(s):
    return unhexlify(s.encode('utf8'))[::-1]


def bin_to_hex_reversed(s):
    return hexlify(s[::-1])
