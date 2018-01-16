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


def tx_parse(raw_tx, blockchain='bitcoin', **blockchain_opts):
    """
    Parse a raw transaction, based on the type of blockchain it's from
    Returns a tx dict on success (see get_virtual_transactions)
    Raise ValueError for unknown blockchain
    Raise some other exception for invalid raw_tx (implementation-specific)
    """
    if blockchain == 'bitcoin':
        return btc_tx_deserialize(raw_tx, **blockchain_opts)
    else:
        raise ValueError("Unknown blockchain {}".format(blockchain))


def tx_output_has_data(output, blockchain='bitcoin', **blockchain_opts):
    """
    Give a blockchain name and a tx output, determine whether or not it is a
    data-bearing script--i.e. one with data for the state engine.

    Return True if so
    Return False if not
    """
    if blockchain == 'bitcoin':
        return btc_tx_output_has_data(output, **blockchain_opts)
    else:
        return ValueError('Unknown blockchain "{}"'.format(blockchain))
    

def tx_is_data_script(out_script, blockchain='bitcoin', **blockchain_opts):
    """
    Given a blockchain name and an output script (tx['outs'][x]['script']),
    determine whether or not it is a data-bearing script---i.e. one with data for the state engine.

    Return True if so
    Reurn False if not
    """
    if blockchain == 'bitcoin':
        return btc_tx_output_script_has_data(out_script, **blockchain_opts)
    else:
        raise ValueError('Unknown blockchain "{}"'.format(blockchain))


def tx_extend(partial_tx_hex, new_inputs, new_outputs, blockchain='bitcoin', **blockchain_opts):
    """
    Add a set of inputs and outputs to a tx.
    Return the new tx on success
    Raise on error
    """
    if blockchain == 'bitcoin':
        return btc_tx_extend(partial_tx_hex, new_inputs, new_outputs, **blockchain_opts)
    else:
        raise ValueError('Unknown blockchain "{}"'.format(blockchain))


def tx_sign_input(tx_hex, idx, prevout_script, prevout_amount, private_key_info, blockchain='bitcoin', **blockchain_opts):
    """
    Sign a given input in a transaction, given the previous output script and previous output amount.
    Different blockchains can require additional fields; pass thse in **blockchain_opts.

    Return the serialized tx with the given input signed on success
    Raise on error
    """
    if blockchain == 'bitcoin':
        return btc_tx_sign_input(tx_hex, idx, prevout_script, prevout_amount, private_key_info, **blockchain_opts)
    else:
        raise ValueError('Unknown blockchain "{}"'.format(blockchain))


def tx_sign_all_unsigned_inputs(privkey_info, prev_outputs, unsigned_tx_hex, blockchain='bitcoin', **blockchain_opts):
    """
    Sign all unsigned inputs to a given transaction with the given private key.  Also, pass in the list of previous outputs to the transaction so they
    can be paired with the right input (i.e. prev_outputs is a list of tx outputs that are in 1-to-1 correspondance with the inputs in the serialized tx)
    
    Different blockchains can require additional fields; pass thse in **blockchain_opts.

    Return the signed transaction on success
    Raise on error
    """
    if blockchain == 'bitcoin':
        return btc_tx_sign_all_unsigned_inputs(privkey_info, prev_outputs, unsigned_tx_hex, **blockchain_opts)
    else:
        raise ValueError('Unknown blockchain "{}"'.format(blockchain))
    

def calculate_change_amount(inputs, send_amount, fee):
    """
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


