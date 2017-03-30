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

import pybitcoin
import keylib
import bitcoin
import os

MAX_DATA_LEN = 40       # 40 bytes per data output

# depending on whether or not we're talking to 
# -testnet/-regtest or mainnet, determine which private
# and public key classes to use.

if os.environ.get("BLOCKSTACK_TESTNET", None) == "1":

    version_byte = 111
    multisig_version_byte = 196

    # using testnet keys
    class TestnetPublicKey(pybitcoin.BitcoinPublicKey):
        _version_byte = 111

    class TestnetPrivateKey(pybitcoin.BitcoinPrivateKey):
        _pubkeyhash_version_byte = 111 
    
    BitcoinPrivateKey = TestnetPrivateKey
    BitcoinPublicKey = TestnetPublicKey

    def hex_hash160_to_address( hexhash, version_byte=111 ):
        """
        Convert a 160-bit hash to a p2pkh address
        """
        return pybitcoin.hex_hash160_to_address( hexhash, version_byte=version_byte )

else:

    version_byte = 0
    multisig_version_byte = 5

    # using mainnet keys
    BitcoinPrivateKey = pybitcoin.BitcoinPrivateKey
    BitcoinPublicKey = pybitcoin.BitcoinPublicKey
    
    hex_hash160_to_address = pybitcoin.hex_hash160_to_address


def make_payment_script( address ):
    """
    Make a pay-to-address script.
    * If the address is a pubkey hash, then make a p2pkh script.
    * If the address is a script hash, then make a p2sh script.
    """
    vb = pybitcoin.b58check_version_byte(address)

    if vb == version_byte:
        return pybitcoin.make_pay_to_address_script( address )

    elif vb == multisig_version_byte:
        return bitcoin.mk_scripthash_script( address )

    else:
        raise ValueError("Unrecognized address '%s'" % address )


def make_data_script( data ):
    """
    Make a data-bearing transaction output.
    Data must be a hex string
    """
    assert len(data) < MAX_DATA_LEN * 2, "Data hex string is too long"     # note: data is a hex string
    assert len(data) % 2 == 0, "Data hex string is not even length"
    return "6a{:02x}{}".format(len(data)/2, data)


def calculate_change_amount(inputs, send_amount, fee):
    """
    Find out how much change there exists between a set of tx inputs, the send amount and the tx fee.
    @inputs must be a list of transaction inputs, i.e. [{'script_hex': str, 'value': int}]
    """
    # calculate the total amount  coming into the transaction from the inputs
    total_amount_in = sum([input['value'] for input in inputs])
    # change = whatever is left over from the amount sent & the transaction fee
    change_amount = total_amount_in - send_amount - fee
    # check to ensure the change amount is a non-negative value and return it
    if change_amount < 0:
        raise ValueError('Not enough inputs for transaction (total: {}, to spend: {}, fee: {}).'.format(total_amount_in, send_amount, fee))
    return change_amount


def script_hex_to_address( script_hex ):
    """
    Examine a scriptPubkey and extract an address.
    """
    if script_hex.startswith("76a914") and script_hex.endswith("88ac") and len(script_hex) == 50:
        # p2pkh script
        return pybitcoin.script_hex_to_address( script_hex, version_byte=version_byte )

    elif script_hex.startswith("a914") and script_hex.endswith("87") and len(script_hex) == 46:
        # p2sh script
        return bitcoin.script_to_address( script_hex, vbyte=multisig_version_byte )

    else:
        raise ValueError("Nonstandard script %s" % script_hex)


def make_p2sh_address( script ):
    """
    Make a P2SH address
    """
    addr = bitcoin.p2sh_scriptaddr(script, multisig_version_byte)
    return addr


def is_p2sh_address( address ):
    """
    Is the given address a p2sh address?
    """
    vb = pybitcoin.b58check_version_byte( address )
    if vb == multisig_version_byte:
        return True
    else:
        return False
    

def is_p2sh_script( script_hex ):
    """
    Is the given script a p2sh script?
    """
    if script_hex.startswith("a914") and script_hex.endswith("87") and len(script_hex) == 46:
        return True
    else:
        return False


def address_reencode( address ):
    """
    Depending on whether or not we're in testnet 
    or mainnet, re-encode an address accordingly.
    """
    vb = pybitcoin.b58check_version_byte( address )

    if os.environ.get("BLOCKSTACK_TESTNET") == "1":
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

    return pybitcoin.b58check_encode( pybitcoin.b58check_decode(address), vb )


