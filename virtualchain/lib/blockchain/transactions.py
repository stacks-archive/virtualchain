#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Virtualchain
    ~~~~~
    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org
    
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

from bitcoin_blockchain import BlockchainDownloader, SPVClient

import os
import time
import random
from decimal import *

from ..config import get_logger

log = get_logger("virtualchain")

from bitcoin_blockchain.bits import *
from bitcoin_blockchain.blocks import get_bitcoin_virtual_transactions

def get_virtual_transactions(blockchain_name, blockchain_opts, first_block_height, last_block_height, tx_filter=None, **hints):
    """
    Get the sequence of virtualchain transactions from a particular blockchain over a given range of block heights.
    Returns a list of tuples in the format of [(block height, [txs])], where
    each tx in [txs] is the parsed transaction.  The parsed transaction will conform to... # TODO write a spec for this
    
    Each transaction has at least the following fields:
    
    `version`: the version of the transaction
    `txindex`: the index into the block where this tx occurs
    `ins`: a list of transaction inputs, where each member is a dict with:
        `outpoint`: a dict of {'hash': txid of transaction that fed it in, 'index': the index into the feeder tx's outputs list}
        `script`: the signature script for this input
    `outs`: a list of transaction outputs, where each member is a dict with:
        `value`: the amount of currency units spent (in the fundamental units of the chain)
        `script`: the spending script for this input
    `senders`: a list of information in 1-to-1 correspondence with each input regarding the transactions that funded it:
        `value`: the amount of currency units sent (in fundamental units of the chain) 
        `script_pubkey`: the spending script for the sending transaction
    
    Returns [(block height, [txs])] on success
    Returns None on error.
    Raises ValueError on unknown blockchain
    """
    if blockchain_name == 'bitcoin':
        return get_bitcoin_virtual_transactions(blockchain_opts, first_block_height, last_block_height, tx_filter=tx_filter, **hints)

    else:
        raise ValueError("Unknown blockchain {}".format(blockchain_name))


def tx_parse(blockchain_name, raw_tx):
    """
    Parse a raw transaction, based on the type of blockchain it's from
    Returns a tx dict on success (see get_virtual_transactions)
    Raise ValueError for unknown blockchain
    Raise some other exception for invalid raw_tx (implementation-specific)
    """
    if blockchain_name == 'bitcoin':
        return btc_tx_deserialize(raw_tx)
    else:
        raise ValueError("Unknown blockchain {}".format(blockchain_name))


def tx_is_data_script(blockchain_name, out_script):
    """
    Given a blockchain name and an output script (tx['outs'][x]['script']),
    determine whether or not it is a data-bearing script---i.e. one with data for the state engine.

    Return True if so
    Reurn False if not
    """
    if blockchain_name == 'bitcoin':
        return btc_tx_output_script_has_data(out_script)

    else:
        raise ValueError('Unknown blockchain {}'.format(blockchain_name))
