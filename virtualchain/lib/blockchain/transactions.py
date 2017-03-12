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

import traceback

import sys 
from .bitcoin_blockchain import JSONRPCException, BlockchainDownloader, SPVClient

import logging
import os
import time
import types
import random
import copy
import bitcoin
import binascii
import json
import pybitcoin
import pprint
from decimal import *
import cPickle as pickle

import session
log = session.get_logger("virtualchain")

from bitcoin_blockchain.bits import *

def get_virtual_transactions( blockchain_opts, first_block_height, last_block_height, spv_last_block=None, first_block_hash=None, tx_filter=None ):
    """
    Get the sequence of virtualchain transactions from the blockchain.
    Each transaction returned will be a `nulldata` transaction.
    It will be formatted like a bitcoind RPC transaction, as returned by `getrawtransaction`,
    but with the following additions and differences:
    * output values will be in satoshis
    * `fee` will be defined, and will be the total amount sent (in satoshis)
    * `txindex` will be defined, and will be the offset in the block where the tx occurs
    * `senders` will be defined as a list, and will contain the following information
        * `script_pubkey`: an output scriptPubKey hex script
        * `amount`: a value in satoshis
        * `addresses`: a list of zero or more addresses
      This list corresponds to the list of outputs that funded the given transaction's inputs.
      That is, senders[i] corresponds to the output that funded vin[i], found in transaction vin[i]['txid']
    * `nulldata` will be define as the hex string that encodes the OP_RETURN payload

    @blockchain_opts must be a dict with the following keys:
    * `bitcoind_server`: hostname of the bitcoind peer
    * `bitcoind_port`: RPC port of the bitcoind peer
    * `bitcoind_p2p_port`: p2p port of the bitcoind peer
    * `bitcoind_user`: username to authenticate
    * `bitcoind_passwd`: password for authentication
    * `bitcoind_spv_path`: path on disk to where SPV headers should be stored

    Returns a list of [(block number), [txs]] on success
    Returns None on error
    """

    headers_path = blockchain_opts['bitcoind_spv_path']
    bitcoind_server = "%s:%s" % (blockchain_opts['bitcoind_server'], blockchain_opts['bitcoind_p2p_port'])
    spv_last_block = spv_last_block if spv_last_block is not None else last_block_height - 1

    if headers_path is None:
        log.error("FATAL: bitcoind_spv_path not defined in blockchain options")
        os.abort()

    if not os.path.exists(headers_path):
        log.debug("Will download SPV headers to %s" % headers_path)

    # synchronize SPV headers
    SPVClient.init( headers_path )

    rc = None

    for i in xrange(0, 100000000000, 1):
        # basically try forever
        try:
            rc = SPVClient.sync_header_chain( headers_path, bitcoind_server, spv_last_block )
            if not rc:
                delay = min( 3600, 2**i + ((2**i) * random.random()) )
                log.error("Failed to synchronize SPV headers (%s) up to %s.  Try again in %s seconds" % (headers_path, last_block_height, delay))
                time.sleep( delay )
                continue

            else:
                break

        except SystemExit, s:
            log.error("Aborting on SPV header sync")
            os.abort()

        except Exception, e:
            log.exception(e)
            delay = min( 3600, 2**i + ((2**i) * random.random()) )
            log.debug("Try again in %s seconds" % delay)
            time.sleep( delay )
            continue

    downloader = None
    for i in xrange(0, 10000000000000, 1):
        # basically try forever
        try:
            
            # fetch all blocks
            downloader = BlockchainDownloader( blockchain_opts, blockchain_opts['bitcoind_spv_path'], first_block_height, last_block_height - 1, \
                                       p2p_port=blockchain_opts['bitcoind_p2p_port'], tx_filter=tx_filter )

            if first_block_height > last_block_height - 1:
                downloader.loop_exit()
                break

            rc = downloader.run()
            if not rc:
                delay = min( 3600, 2**i + ((2**i) * random.random()) )
                log.error("Failed to fetch %s-%s; trying again in %s seconds" % (first_block_height, last_block_height, delay))
                time.sleep( delay )
                continue
            else:
                break

        except SystemExit, s:
            log.error("Aborting on blockchain sync")
            os.abort()

        except Exception, e:
            log.exception(e)
            delay = min( 3600, 2**i + ((2**i) * random.random()) )
            log.debug("Try again in %s seconds" % delay)
            time.sleep( delay )
            continue            

    if not rc or downloader is None:
        log.error("Failed to fetch blocks %s-%s" % (first_block_height, last_block_height))
        return None

    # extract
    block_info = downloader.get_block_info()
    return block_info


