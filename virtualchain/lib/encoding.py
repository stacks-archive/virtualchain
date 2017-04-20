#!/usr/bin/env python2
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

import binascii

# Derived from pybitcointools (https://github.com/vbuterin/pybitcointools)
# Written originally by Vitalik Buterin

# Base switching
code_strings = {
    2: '01',
    10: '0123456789',
    16: '0123456789abcdef',
    32: 'abcdefghijklmnopqrstuvwxyz234567',
    58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    256: ''.join([chr(x) for x in range(256)])
}

def get_code_string_bases():
    """
    Get the set of supported code strings
    """
    return code_strings.keys()[:]


def get_code_string(base):
    """
    Get the code string for a given numeric base.
    Raise ValueError for unknown base
    """
    if base in code_strings:
        return code_strings[base]
    else:
        raise ValueError("Invalid base!")


def lpad(msg, symbol, length):
    """
    Left-pad a given string (msg) with a character (symbol) for a given number of bytes (length).
    Return the padded string
    """
    if len(msg) >= length:
        return msg
    return symbol * (length - len(msg)) + msg


def changebase(string, frm, to, minlen=0):
    """
    Change a string's characters from one base to another.
    Return the re-encoded string
    """
    if frm == to:
        return lpad(string, get_code_string(frm)[0], minlen)

    return encode(decode(string, frm), to, minlen)


def bytes_to_hex_string(b):
    """
    Portable byte list to hex
    """
    return b.encode('hex')

def safe_from_hex(s):
    """
    Portable hex string to bytes
    """
    return s.decode('hex')


def from_int_representation_to_bytes(a):
    """
    Portable string to int
    """
    return str(a)


def from_int_to_byte(a):
    """
    Portable string to byte
    """
    return chr(a)


def from_byte_to_int(a):
    """
    Portable byte to int
    """
    return ord(a)


def from_bytes_to_string(s):
    """
    Portable bytes to string
    """
    return s


def from_string_to_bytes(a):
    """
    Portable string to bytes
    """
    return a


def safe_hexlify(a):
    """
    Portable bytes to hex
    """
    return binascii.hexlify(a)


def num_to_var_int(x):
    """
    (bitcoin-specific): convert an integer into a variable-length integer
    """
    x = int(x)
    if x < 253:
        return from_int_to_byte(x)

    elif x < 65536:
        return from_int_to_byte(253) + encode(x, 256, 2)[::-1]

    elif x < 4294967296:
        return from_int_to_byte(254) + encode(x, 256, 4)[::-1]

    else:
        return from_int_to_byte(255) + encode(x, 256, 8)[::-1]


def encode(val, base, minlen=0):
    """
    Given an integer value (val) and a numeric base (base),
    encode it into the string of symbols with the given base.
    (with minimum length minlen)

    Returns the (left-padded) re-encoded val as a string.
    """

    base, minlen = int(base), int(minlen)
    code_string = get_code_string(base)
    result = ""
    while val > 0:
        result = code_string[val % base] + result
        val //= base
    return code_string[0] * max(minlen - len(result), 0) + result


def decode(string, base):
    """
    Given a string (string) and a numeric base (base),
    decode the string into an integer.

    Returns the integer
    """

    base = int(base)
    code_string = get_code_string(base)
    result = 0
    if base == 16:
        string = string.lower()
    while len(string) > 0:
        result *= base
        result += code_string.find(string[0])
        string = string[1:]
    return result


def json_is_base(obj, base):
    """
    Given a primitive compound Python object
    (i.e. a dict, string, int, or list) and a numeric base,
    verify whether or not the object and all relevant
    sub-components have the given numeric base.
    
    Return True if so.
    Return False if not.
    """

    alpha = get_code_string(base)
    if isinstance(obj, (str, unicode)):
        for i in range(len(obj)):
            if alpha.find(obj[i]) == -1:
                return False

        return True

    elif isinstance(obj, (int, long, float)) or obj is None:
        return True

    elif isinstance(obj, list):
        for i in range(len(obj)):
            if not json_is_base(obj[i], base):
                return False

        return True

    else:
        for x in obj:
            if not json_is_base(obj[x], base):
                return False

        return True


def json_changebase(obj, changer):
    """
    Given a primitive compound Python object (i.e. a dict,
    string, int, or list) and a changer function that takes
    a primitive Python object as an argument, apply the
    changer function to the object and each sub-component.

    Return the newly-reencoded object.
    """

    if isinstance(obj, (str, unicode)):
        return changer(obj)

    elif isinstance(obj, (int, long)) or obj is None:
        return obj

    elif isinstance(obj, list):
        return [json_changebase(x, changer) for x in obj]

    elif isinstance(obj, dict):
        return dict((x, json_changebase(obj[x], changer)) for x in obj)

    else:
        raise ValueError("Invalid object")

