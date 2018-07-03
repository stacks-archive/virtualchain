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
from bech32 import *
from jsonschema import ValidationError

from ....lib import hashing, encoding, ecdsalib
from ....lib.config import get_features

MAX_DATA_LEN = 80       # 80 bytes per data output

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
        'segwit': {
            'type': 'boolean'
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
    # b58 addresses only!
    return keylib.b58check.b58check_encode(bin_hash160, version_byte=version_byte)


def hex_hash160_to_address(hash160, version_byte=version_byte):
    # b58 addresses only!
    return bin_hash160_to_address(binascii.unhexlify(hash160), version_byte=version_byte)


def address_to_bin_hash160(address):
    # b58 addresses only!
    return keylib.b58check.b58check_decode(address)


def address_to_hex_hash160(address):
    # b58 addresses only!
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
            if not value:
                raise ValueError("Unrecognized opcode {}".format(part))

            hex_script += "%0.2x" % value

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
            # literal numeric constant, followed by a slice of data.
            # push the slice of data.
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
            # raw opcode
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
        # cannot be less than -1, since btc_script_deserialize() never returns such numbers
        if unit < -1:
            raise ValueError('Invalid integer: {}'.format(unit))

        if unit < 16:
            if unit == 0:
                # OP_RESERVED
                return encoding.from_int_to_byte(OPCODE_VALUES['OP_RESERVED'])
            else:
                # OP_1 thru OP_16, or OP_1NEGATE
                return encoding.from_int_to_byte(unit + 80)
        else:
            # pass as numeric literal or raw opcode
            return encoding.from_int_to_byte(unit)

    elif unit is None:
        # None means OP_0
        return b'\x00'

    else:
        if len(unit) <= 75:
            # length + payload
            return encoding.from_int_to_byte(len(unit)) + unit

        elif len(unit) < 256:
            # OP_PUSHDATA1 + length (1 byte) + payload
            return encoding.from_int_to_byte(OPCODE_VALUES['OP_PUSHDATA1']) + encoding.from_int_to_byte(len(unit)) + unit

        elif len(unit) < 65536:
            # OP_PUSHDATA2 + length (2 bytes, big-endian) + payload
            return encoding.from_int_to_byte(OPCODE_VALUES['OP_PUSHDATA2']) + encoding.encode(len(unit), 256, 2)[::-1] + unit
        else:
            # OP_PUSHDATA4 + length (4 bytes, big-endian) + payload
            return encoding.from_int_to_byte(OPCODE_VALUES['OP_PUSHDATA4']) + encoding.encode(len(unit), 256, 4)[::-1] + unit


def btc_script_serialize(_script):
    """
    Given a deserialized script (i.e. an array of Nones, ints, and strings), or an existing script,
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


def btc_make_payment_script( address, segwit=None, **ignored ):
    """
    Make a pay-to-address script.
    """
    
    if segwit is None:
        segwit = get_features('segwit')

    # is address bech32-encoded?
    witver, withash = segwit_addr_decode(address)
    if witver is not None and withash is not None:
        # bech32 segwit address
        if not segwit:
            raise ValueError("Segwit is disabled")

        if len(withash) == 20:
            # p2wpkh
            script_hex = '0014' + withash.encode('hex')
            return script_hex
            
        elif len(withash) == 32:
            # p2wsh
            script_hex = '0020' + withash.encode('hex')
            return script_hex

        else:
            raise ValueError("Unrecognized address '%s'" % address )

    else:
        # address is b58check-encoded
        vb = keylib.b58check.b58check_version_byte(address)
        if vb == version_byte:
            # p2pkh
            hash160 = binascii.hexlify( keylib.b58check.b58check_decode(address) )
            script = 'OP_DUP OP_HASH160 {} OP_EQUALVERIFY OP_CHECKSIG'.format(hash160)
            script_hex = btc_script_to_hex(script)
            return script_hex

        elif vb == multisig_version_byte:
            # p2sh
            hash160 = binascii.hexlify( keylib.b58check.b58check_decode(address) )
            script = 'OP_HASH160 {} OP_EQUAL'.format(hash160)
            script_hex = btc_script_to_hex(script)
            return script_hex

        else:
            raise ValueError("Unrecognized address '%s'" % address )


def btc_make_data_script( data, **ignored ):
    """
    Make a data-bearing transaction output.
    Data must be a hex string
    Returns a hex string.
    """
    if len(data) >= MAX_DATA_LEN * 2:
        raise ValueError("Data hex string is too long")     # note: data is a hex string

    if len(data) % 2 != 0:
        raise ValueError("Data hex string is not even length")

    return "6a{:02x}{}".format(len(data)/2, data)


def btc_script_hex_to_address( script_hex, segwit=None ):
    """
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

    elif script_hex.startswith('0014') and len(script_hex) == 44:
        # p2wpkh script (bech32 address)
        hash160_bin = binascii.unhexlify(script_hex[4:])
        return segwit_addr_encode(hash160_bin) 

    elif script_hex.startswith('0020') and len(script_hex) == 68:
        # p2wsh script (bech32 address)
        sha256_bin = binascii.unhexlify(script_hex[4:])
        return segwit_addr_encode(sha256_bin)

    return None


def btc_make_p2sh_address( script_hex ):
    """
    Make a P2SH address from a hex script
    """
    h = hashing.bin_hash160(binascii.unhexlify(script_hex))
    addr = bin_hash160_to_address(h, version_byte=multisig_version_byte)
    return addr


def btc_make_p2wpkh_address( pubkey_hex ):
    """
    Make a p2wpkh address from a hex pubkey
    """
    pubkey_hex = keylib.key_formatting.compress(pubkey_hex)
    hash160_bin = hashing.bin_hash160(pubkey_hex.decode('hex'))
    return segwit_addr_encode(hash160_bin)


def btc_make_p2sh_p2wpkh_redeem_script( pubkey_hex ):
    """
    Make the redeem script for a p2sh-p2wpkh witness script
    """
    pubkey_hash = hashing.bin_hash160(pubkey_hex.decode('hex')).encode('hex')
    redeem_script = btc_script_serialize(['0014' + pubkey_hash])
    return redeem_script


def btc_make_p2sh_p2wpkh_address( witness_script_hex ):
    """
    Make a p2sh address for a p2wpkh witness script hex
    """
    redeem_script = btc_make_p2sh_p2wpkh_redeem_script(witness_script_hex)
    p2sh_addr = btc_make_p2sh_address(redeem_script)
    return p2sh_addr


def btc_make_p2wsh_address( witness_script_hex ):
    """
    Make a p2wsh address from a witness script
    """
    witness_hash_bin = hashing.bin_sha256(witness_script_hex.decode('hex'))
    return segwit_addr_encode(witness_hash_bin)


def btc_make_p2sh_p2wsh_redeem_script( witness_script_hex ):
    """
    Make the redeem script for a p2sh-p2wsh witness script
    """
    witness_script_hash = hashing.bin_sha256(witness_script_hex.decode('hex')).encode('hex')
    redeem_script = btc_script_serialize(['0020' + witness_script_hash])
    return redeem_script


def btc_make_p2sh_p2wsh_address( witness_script_hex ):
    """
    Make a p2sh address for a p2wsh witness script hex
    """
    redeem_script = btc_make_p2sh_p2wsh_redeem_script(witness_script_hex)
    p2sh_addr = btc_make_p2sh_address(redeem_script)
    return p2sh_addr


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


def btc_is_p2wpkh_address( address ):
    """
    Is the given address a p2wpkh address?
    """
    wver, whash = segwit_addr_decode(address)
    if whash is None:
        return False

    if len(whash) != 20:
        return False

    return True


def btc_is_p2wsh_address( address ):
    """
    Is the given address a p2wsh address?
    """
    wver, whash = segwit_addr_decode(address)
    if whash is None:
        return False
    
    if len(whash) != 32:
        return False

    return True


def btc_is_segwit_address(address):
    """
    Is the given address a segwit (bech32) address?
    """
    return btc_is_p2wpkh_address(address) or btc_is_p2wsh_address(address)


def btc_is_p2sh_script( script_hex ):
    """
    Is the given scriptpubkey a p2sh script?
    """
    if script_hex.startswith("a914") and script_hex.endswith("87") and len(script_hex) == 46:
        return True
    else:
        return False


def btc_is_p2wsh_script( script_hex ):
    """
    Is the given scriptpubkey a p2wsh script?
    """
    if script_hex.startswith('00') and len(script_hex) == 66:
        return True
    else:
        return False


def btc_address_reencode( address, **blockchain_opts ):
    """
    Depending on whether or not we're in testnet 
    or mainnet, re-encode an address accordingly.
    """
    # re-encode bitcoin address
    network = blockchain_opts.get('network', None)
    opt_version_byte = blockchain_opts.get('version_byte', None)

    if btc_is_segwit_address(address):
        # bech32 address
        hrp = None
        if network == 'mainnet':
            hrp = 'bc'

        elif network == 'testnet':
            hrp = 'tb'

        else:
            if os.environ.get('BLOCKSTACK_TESTNET') == '1' or os.environ.get('BLOCKSTACK_TESTNET3') == '1':
                hrp = 'tb'

            else:
                hrp = 'bc'

        wver, whash = segwit_addr_decode(address)
        return segwit_addr_encode(whash, hrp=hrp, witver=wver)

    else:
        # base58 address
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
            if opt_version_byte is not None:
                vb = opt_version_byte

            elif os.environ.get("BLOCKSTACK_TESTNET") == "1" or os.environ.get("BLOCKSTACK_TESTNET3") == "1":
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


def btc_is_multisig(privkey_info, **blockchain_opts):
    """
    Does the given private key info represent
    a multisig bundle?

    For Bitcoin, this is true for multisig p2sh (not p2sh-p2wsh)
    """
    try:
        jsonschema.validate(privkey_info, PRIVKEY_MULTISIG_SCHEMA)
        return not privkey_info.get('segwit', False)
    except ValidationError as e:
        return False


def btc_is_multisig_segwit(privkey_info):
    """
    Does the given private key info represent
    a multisig bundle?

    For Bitcoin, this is true for multisig p2sh (not p2sh-p2wsh)
    """
    try:
        jsonschema.validate(privkey_info, PRIVKEY_MULTISIG_SCHEMA)
        if len(privkey_info['private_keys']) == 1:
            return False

        return privkey_info.get('segwit', False)
    except ValidationError as e:
        return False


def btc_is_multisig_address(addr, **blockchain_opts):
    """
    Is the given address a multisig address?
    """
    return btc_is_p2sh_address(addr) or btc_is_p2wsh_address(addr)


def btc_is_multisig_script(script_hex, **blockchain_opts):
    """
    Is the given script hex a multisig script?
    """
    return btc_is_p2sh_script(script_hex) or btc_is_p2wsh_script(script_hex)


def btc_is_singlesig(privkey_info, **blockchain_opts):
    """
    Does the given private key info represent
    a single signature bundle? (i.e. one private key)?

    i.e. is this key a private key string?
    """
    try:
        jsonschema.validate(privkey_info, PRIVKEY_SINGLESIG_SCHEMA)
        return True
    except ValidationError as e:
        return False


def btc_get_singlesig_privkey(privkey_info, **blockchain_opts):
    """
    Get the single-sig private key from the private key info
    """
    if btc_is_singlesig(privkey_info):
        return privkey_info

    elif btc_is_singlesig_segwit(privkey_info):
        return privkey_info['private_keys'][0]

    return None


def btc_is_singlesig_address(addr, **blockchain_opts):
    """
    Is the given address a single-sig address?
    """
    return btc_is_p2pkh_address(addr)


def btc_is_singlesig_segwit(privkey_info):
    """
    Is the given key bundle a p2sh-p2wpkh key bundle?
    """
    try:
        jsonschema.validate(privkey_info, PRIVKEY_MULTISIG_SCHEMA)
        if len(privkey_info['private_keys']) > 1:
            return False

        return privkey_info.get('segwit', False)
    except ValidationError:
        return False


def btc_get_privkey_address(privkey_info, **blockchain_opts):
    """
    Get the address for a given private key info bundle
    (be it multisig or singlesig)

    Return the address on success
    Raise exception on error
    """
    
    from .multisig import make_multisig_segwit_address_from_witness_script

    if btc_is_singlesig(privkey_info):
        return btc_address_reencode( ecdsalib.ecdsa_private_key(privkey_info).public_key().address() )
    
    if btc_is_multisig(privkey_info) or btc_is_singlesig_segwit(privkey_info):
        redeem_script = str(privkey_info['redeem_script'])
        return btc_make_p2sh_address(redeem_script)
    
    if btc_is_multisig_segwit(privkey_info):
        return make_multisig_segwit_address_from_witness_script(str(privkey_info['redeem_script']))

    raise ValueError("Invalid private key info")
