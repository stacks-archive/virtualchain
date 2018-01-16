#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Virtualchain
    ~~~~~
    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015-2018 by Blockstack.org
    
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
from bitcoin_blockchain import btc_make_payment_script, btc_make_data_script, btc_script_hex_to_address

def script_hex_to_address( script_hex, blockchain='bitcoin', **blockchain_opts):
    """
    High-level API call (meant to be blockchain agnostic)
    Examine a script (hex-encoded) and extract an address.
    Return the address on success
    Return None on error
    """
    if blockchain == 'bitcoin':
        return btc_script_hex_to_address(script_hex, **blockchain_opts)
    else:
        raise ValueError("Unknown blockchain '{}'".format(blockchain))


def make_payment_script(address, blockchain='bitcoin', **blockchain_opts):
    """
    High-level API call (meant to be blockchain agnostic)
    Make a pay-to-address script.
    """
    
    if blockchain == 'bitcoin':
        return btc_make_payment_script(address, **blockchain_opts)
    else:
        raise ValueError("Unknown blockchain '{}'".format(blockchain))


def make_data_script( data, blockchain='bitcoin', **blockchain_opts):
    """
    High-level API call (meant to be blockchain agnostic)
    Make a data-bearing transaction output.
    Data must be a hex string
    Returns a hex string.
    """
    if blockchain == 'bitcoin':
        return btc_make_data_script(data, **blockchain_opts)
    else:
        raise ValueError("Unknown blockchain '{}'".format(blockchain))
