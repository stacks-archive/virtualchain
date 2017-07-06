#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Virtualchain
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org
    
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

import keylib
import os
import binascii
import jsonschema
import re
from opcodes import *
from jsonschema import ValidationError

from ....lib import hashing, encoding, ecdsalib

MAX_DATA_LEN = 40       # 40 bytes per data output

OP_BASE58CHECK_PATTERN = r'^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$'
OP_ADDRESS_PATTERN = OP_BASE58CHECK_PATTERN
OP_PRIVKEY_PATTERN = OP_BASE58CHECK_PATTERN
OP_HEX_PATTERN = r'^([0-9a-fA-F]+)$'
OP_SCRIPT_PATTERN = OP_HEX_PATTERN

PRIVKEY_SINGLESIG_SCHEMA_WIF = {
    'type': 'string',
    'pattern': OP_PRIVKEY_PATTERN
}

PRIVKEY_SINGLESIG_SCHEMA_HEX = {
    'type': 'string',
    'pattern': OP_HEX_PATTERN
}

PRIVKEY_SINGLESIG_SCHEMA = {
    'anyOf': [
        PRIVKEY_SINGLESIG_SCHEMA_WIF,
        PRIVKEY_SINGLESIG_SCHEMA_HEX
    ],
}

PRIVKEY_MULTISIG_SCHEMA = {
    'type': 'object',
    'properties': {
        'address': {
            'type': 'string',
            'pattern': OP_ADDRESS_PATTERN,
        },
        'redeem_script': {
            'type': 'string',
            'pattern': OP_SCRIPT_PATTERN,
        },
        'private_keys': {
            'type': 'array',
            'items': PRIVKEY_SINGLESIG_SCHEMA
        },
    },
    'required': [
        'address',
        'redeem_script',
        'private_keys'
    ],
}


# depending on whether or not we're talking to 
# -testnet/-regtest or mainnet, determine which private
# and public key classes to use.

if os.environ.get("BLOCKSTACK_TESTNET", None) == "1" or os.environ.get("BLOCKSTACK_TESTNET3", None) == "1":

    version_byte = 111
    multisig_version_byte = 196

    # using testnet keys
    class TestnetPublicKey(keylib.ECPublicKey):
        _version_byte = 111

    class TestnetPrivateKey(keylib.ECPrivateKey):
        _pubkeyhash_version_byte = 111

    BitcoinPrivateKey = TestnetPrivateKey
    BitcoinPublicKey = TestnetPublicKey

else:

    version_byte = 0
    multisig_version_byte = 5

    # using mainnet keys
    BitcoinPrivateKey = keylib.ECPrivateKey
    BitcoinPublicKey = keylib.ECPublicKey


def bin_hash160_to_address(bin_hash160, version_byte=version_byte):
    return keylib.b58check.b58check_encode(bin_hash160, version_byte=version_byte)


def hex_hash160_to_address(hash160, version_byte=version_byte):
    return bin_hash160_to_address(binascii.unhexlify(hash160), version_byte=version_byte)


def address_to_bin_hash160(address):
    return keylib.b58check.b58check_decode(address)


def address_to_hex_hash160(address):
    return binascii.hexlify(address_to_bin_hash160(address))


def btc_script_to_hex(script):
    """ Parse the string representation of a script and return the hex version.
        Example: "OP_DUP OP_HASH160 c629...a6db OP_EQUALVERIFY OP_CHECKSIG"
    """

    hex_script = ''
    parts = script.split(' ')
    for part in parts:
        if part[0:3] == 'OP_':
            value = OPCODE_VALUES.get(part)
            assert value, "Unrecognized opcode {}".format(part)

            hex_script += "%0.2x" % value

        elif isinstance(part, (int)):
            hex_script += '%0.2x' % part

        elif hashing.is_hex(part):
            hex_script += '%0.2x' % hashing.count_bytes(part) + part

        else:
            raise Exception('Invalid script - only opcodes and hex characters allowed.')

    return hex_script


def btc_script_deserialize(script):
    """
    Given a script (hex or bin), decode it into its list of opcodes and data.
    Return a list of strings and ints.

    Based on code in pybitcointools (https://github.com/vbuterin/pybitcointools)
    by Vitalik Buterin
    """

    if isinstance(script, str) and re.match('^[0-9a-fA-F]*$', script):
       script = binascii.unhexlify(script)

    # output buffer
    out = []
    pos = 0

    while pos < len(script):
        # next script op...
        code = encoding.from_byte_to_int(script[pos])

        if code == 0:
            # empty (OP_0)
            out.append(None)
            pos += 1

        elif code <= 75:
            # numeric constant 
            out.append(script[pos+1:pos+1+code])
            pos += 1 + code

        elif code <= 78:
            # OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4, followed by length and data
            # push the data itself
            szsz = pow(2, code - 76)
            sz = encoding.decode(script[pos+szsz: pos:-1], 256)
            out.append(script[pos + 1 + szsz : pos + 1 + szsz + sz])
            pos += 1 + szsz + sz

        elif code <= 96:
            # OP_1NEGATE, OP_RESERVED, OP_1 thru OP_16
            # pass -1 for OP_1NEGATE
            # pass 0 for OP_RESERVED (shouldn't be used anyway)
            # pass 1 thru 16 for OP_1 thru OP_16
            out.append(code - 80)
            pos += 1

        else:
            # literal
            out.append(code)
            pos += 1

    # make sure each string is hex'ed
    out = encoding.json_changebase(out, lambda x: encoding.safe_hexlify(x))
    return out


def _btc_script_serialize_unit(unit):
    """
    Encode one item of a BTC script
    Return the encoded item (as a string)

    Based on code from pybitcointools (https://github.com/vbuterin/pybitcointools)
    by Vitalik Buterin
    """
    
    if isinstance(unit, int):
        if unit < 16:
            # OP_1 thru OP_16
            return encoding.from_int_to_byte(unit + 80)
        else:
            # pass literal
            return encoding.from_int_to_byte(unit)

    elif unit is None:
        # None means OP_0
        return b'\x00'

    else:
        if len(unit) <= 75:
            # length + payload
            return encoding.from_int_to_byte(len(unit))+unit

        elif len(unit) < 256:
            # OP_PUSHDATA1 + length (1 byte) + payload
            return encoding.from_int_to_byte(76) + encoding.from_int_to_byte(len(unit)) + unit

        elif len(unit) < 65536:
            # OP_PUSHDATA2 + length (2 bytes, big-endian) + payload
            return encoding.from_int_to_byte(77) + encoding.encode(len(unit), 256, 2)[::-1] + unit
        else:
            # OP_PUSHDATA4 + length (4 bytes, big-endian) + payload
            return encoding.from_int_to_byte(78) + encoding.encode(len(unit), 256, 4)[::-1] + unit


def btc_script_serialize(_script):
    """
    Given a deserialized script (i.e. an array of ints and strings), or an existing script,
    turn it back into a hex script

    Based on code from pybitcointools (https://github.com/vbuterin/pybitcointools)
    by Vitalik Buterin
    """
    script = _script
    if encoding.json_is_base(_script, 16):
        # hex-to-bin all hex strings in this script
        script = encoding.json_changebase(_script, lambda x: binascii.unhexlify(x))

    # encode each item and return the concatenated list
    return encoding.safe_hexlify( ''.join(map(_btc_script_serialize_unit, script)) )


def make_payment_script( address ):
    """
    High-level API call (meant to be blockchain agnostic)
    Make a pay-to-address script.
    * If the address is a pubkey hash, then make a p2pkh script.
    * If the address is a script hash, then make a p2sh script.
    """
    vb = keylib.b58check.b58check_version_byte(address)

    if vb == version_byte:
        hash160 = binascii.hexlify( keylib.b58check.b58check_decode(address) )
        script = 'OP_DUP OP_HASH160 {} OP_EQUALVERIFY OP_CHECKSIG'.format(hash160)
        script_hex = btc_script_to_hex(script)
        return script_hex

    elif vb == multisig_version_byte:
        hash160 = binascii.hexlify( keylib.b58check.b58check_decode(address) )
        script = 'OP_HASH160 {} OP_EQUAL'.format(hash160)
        script_hex = btc_script_to_hex(script)
        return script_hex

    else:
        raise ValueError("Unrecognized address '%s'" % address )


def make_data_script( data ):
    """
    High-level API call (meant to be blockchain agnostic)
    Make a data-bearing transaction output.
    Data must be a hex string
    Returns a hex string.
    """
    assert len(data) < MAX_DATA_LEN * 2, "Data hex string is too long"     # note: data is a hex string
    assert len(data) % 2 == 0, "Data hex string is not even length"
    return "6a{:02x}{}".format(len(data)/2, data)


def calculate_change_amount(inputs, send_amount, fee):
    """
    High-level API call (meant to be blockchain agnostic)
    Find out how much change there exists between a set of tx inputs, the send amount and the tx fee.
    @inputs must be a list of transaction inputs, i.e. [{'script_hex': str, 'value': int}]
    """
    # calculate the total amount coming into the transaction from the inputs
    total_amount_in = sum([input['value'] for input in inputs])

    # change = whatever is left over from the amount sent & the transaction fee
    change_amount = total_amount_in - send_amount - fee

    # check to ensure the change amount is a non-negative value and return it
    if change_amount < 0:
        raise ValueError('Not enough inputs for transaction (total: {}, to spend: {}, fee: {}).'.format(total_amount_in, send_amount, fee))

    return change_amount


def script_hex_to_address( script_hex ):
    """
    High-level API call (meant to be blockchain agnostic)
    Examine a script (hex-encoded) and extract an address.
    Return the address on success
    Return None on error
    """
    # TODO: make this support more than bitcoin-like scripts
    if script_hex.startswith("76a914") and script_hex.endswith("88ac") and len(script_hex) == 50:
        # p2pkh script
        hash160_bin = binascii.unhexlify(script_hex[6:-4])
        return bin_hash160_to_address(hash160_bin, version_byte=version_byte)

    elif script_hex.startswith("a914") and script_hex.endswith("87") and len(script_hex) == 46:
        # p2sh script
        hash160_bin = binascii.unhexlify(script_hex[4:-2])
        return bin_hash160_to_address(hash160_bin, version_byte=multisig_version_byte)

    return None


def btc_make_p2sh_address( script_hex ):
    """
    Make a P2SH address from a hex script
    """
    h = hashing.bin_hash160(binascii.unhexlify(script_hex))
    addr = bin_hash160_to_address(h, version_byte=multisig_version_byte)
    return addr


def btc_is_p2sh_address( address ):
    """
    Is the given address a p2sh address?
    """
    vb = keylib.b58check.b58check_version_byte( address )
    if vb == multisig_version_byte:
        return True
    else:
        return False
    

def btc_is_p2pkh_address( address ):
    """
    Is the given address a p2pkh address?
    """
    vb = keylib.b58check.b58check_version_byte( address )
    if vb == version_byte:
        return True
    else:
        return False


def btc_is_p2sh_script( script_hex ):
    """
    Is the given script a p2sh script?
    """
    if script_hex.startswith("a914") and script_hex.endswith("87") and len(script_hex) == 46:
        return True
    else:
        return False


def address_reencode( address, blockchain="bitcoin", **blockchain_opts ):
    """
    High-level API call (meant to be blockchain-agnostic)
    Depending on whether or not we're in testnet 
    or mainnet, re-encode an address accordingly.
    """
    if blockchain == "bitcoin":
        # re-encode bitcoin address
        network = blockchain_opts.get('network', None)
        vb = keylib.b58check.b58check_version_byte( address )

        if network == 'mainnet':
            if vb == 0 or vb == 111:
                vb = 0

            elif vb == 5 or vb == 196:
                vb = 5

            else:
                raise ValueError("Unrecognized address %s" % address)
        
        elif network == 'testnet':
            if vb == 0 or vb == 111:
                vb = 111
            
            elif vb == 5 or vb == 196:
                vb = 196

            else:
                raise ValueError("Unrecognized address %s" % address)

        else:
            if os.environ.get("BLOCKSTACK_TESTNET") == "1" or os.environ.get("BLOCKSTACK_TESTNET3") == "1":
                if vb == 0 or vb == 111:
                    # convert to testnet p2pkh
                    vb = 111

                elif vb == 5 or vb == 196:
                    # convert to testnet p2sh
                    vb = 196

                else:
                    raise ValueError("unrecognized address %s" % address)

            else:
                if vb == 0 or vb == 111:
                    # convert to mainnet p2pkh
                    vb = 0

                elif vb == 5 or vb == 196:
                    # convert to mainnet p2sh
                    vb = 5

                else:
                    raise ValueError("unrecognized address %s" % address)

        return keylib.b58check.b58check_encode( keylib.b58check.b58check_decode(address), vb )

    else:
        # not supported
        raise ValueError("Unsupported blockchain '{}'".format(blockchain))


def is_multisig(privkey_info):
    """
    High-level API call (meant to be blockchain agnostic)
    Does the given private key info represent
    a multisig bundle?
    """
    try:
        jsonschema.validate(privkey_info, PRIVKEY_MULTISIG_SCHEMA)
        return True
    except ValidationError as e:
        return False


def is_multisig_address(addr):
    """
    High-level API call (meant to be blockchain agnostic)
    Is the given address a multisig address?
    """
    return btc_is_p2sh_address(addr)


def is_multisig_script(script_hex):
    """
    High-level API call (meant to be blockchain-agnostic)
    Is the given script hex a multisig script?
    """
    return btc_is_p2sh_script(script_hex)


def is_singlesig(privkey_info):
    """
    High-level API call (meant to be blockchain agnostic)
    Does the given private key info represent
    a single signature bundle? (i.e. one private key)?
    """
    try:
        jsonschema.validate(privkey_info, PRIVKEY_SINGLESIG_SCHEMA)
        return True
    except ValidationError as e:
        return False


def is_singlesig_address(addr):
    """
    High-level API call (meant to be blockchain agnostic)
    Is the given address a single-sig address?
    """
    return btc_is_p2pkh_address(addr)


def get_privkey_address(privkey_info):
    """
    High-level API call (meant to be blockchain agnostic)
    Get the address for a given private key info bundle
    (be it multisig or singlesig)

    Return the address on success
    Raise exception on error
    """

    if is_singlesig(privkey_info):
        return address_reencode( ecdsalib.ecdsa_private_key(privkey_info).public_key().address() )
    
    if is_multisig(privkey_info):
        redeem_script = str(privkey_info['redeem_script'])
        return btc_make_p2sh_address(redeem_script)

    raise ValueError("Invalid private key info")
