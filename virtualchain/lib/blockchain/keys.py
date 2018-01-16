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

from bitcoin_blockchain.keys import btc_is_multisig, btc_is_multisig_address, \
        btc_is_multisig_script, btc_is_singlesig, btc_get_singlesig_privkey, \
        btc_is_singlesig_address, btc_get_privkey_address

def is_multisig(privkey_info, blockchain='bitcoin', **blockchain_opts):
    """
    Is the given private key bundle a multisig bundle?
    """
    if blockchain == 'bitcoin':
        return btc_is_multisig(privkey_info, **blockchain_opts)
    else:
        raise ValueError('Unknown blockchain "{}"'.format(blockchain))


def is_multisig_address(addr, blockchain='bitcoin', **blockchain_opts):
    """
    Is the given address a multisig address?
    """
    if blockchain == 'bitcoin':
        return btc_is_multisig_address(addr, **blockchain_opts)
    else:
        raise ValueError('Unknown blockchain "{}"'.format(blockchain))


def is_multisig_script(script, blockchain='bitcoin', **blockchain_opts):
    """
    Is the given script a multisig script?
    """
    if blockchain == 'bitcoin':
        return btc_is_multisig_script(script, **blockchain_opts)
    else:
        raise ValueError('Unknown blockchain "{}"'.format(blockchain))


def is_singlesig(privkey_info, blockchain='bitcoin', **blockchain_opts):
    """
    Is the given private key bundle a single-sig key bundle?
    """
    if blockchain == 'bitcoin':
        return btc_is_singlesig(privkey_info, **blockchain_opts)
    else:
        raise ValueError('Unknown blockchain "{}"'.format(blockchain))


def get_singlesig_privkey(privkey_info, blockchain='bitcoin', **blockchain_opts):
    """
    Given a private key bundle, get the (single) private key
    """
    if blockchain == 'bitcoin':
        return btc_get_singlesig_privkey(privkey_info, **blockchain_opts)
    else:
        raise ValueError('Unknown blockchain "{}"'.format(blockchain))


def is_singlesig_address(addr, blockchain='bitcoin', **blockchain_opts):
    """
    Is the given address a single-sig address?
    """
    if blockchain == 'bitcoin':
        return btc_is_singlesig_address(addr, **blockchain_opts)
    else:
        raise ValueError('Unknown blockchain "{}"'.format(blockchain))


def get_privkey_address(privkey_info, blockchain='bitcoin', **blockchain_opts):
    """
    Get the address from a private key bundle
    """
    if blockchain == 'bitcoin':
        return btc_get_privkey_address(privkey_info, **blockchain_opts)
    else:
        raise ValueError('Unknown blockchain "{}"'.format(blockchain))

