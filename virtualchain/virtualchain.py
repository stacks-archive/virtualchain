#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
     Virtualchain
     ~~~~~
     copyright: (c) 2014-15 by Halfmoon Labs, Inc.
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
     along with Virtualchain. If not, see <http://www.gnu.org/licenses/>.
"""

import argparse
import os
import sys
import subprocess
import signal
import json
import datetime
import traceback
import time
import random
import errno

from ConfigParser import SafeConfigParser

from .lib import config, workpool, indexer
from .lib.blockchain import session
from pybitcoin import BitcoindClient, ChainComClient

log = session.get_logger("virtualchain")

# global instance of our implementation's state engine
state_engine = None

# global flag indicating that we're running
running = False


def sync_virtualchain(bitcoind_opts, last_block, state_engine):
    """
    Synchronize the virtual blockchain state up until a given block.

    Obtain the operation sequence from the blockchain, up to and including last_block.
    That is, go and fetch each block we haven't seen since the last call to this method,
    extract the operations from them, and record in the given working_dir where we left
    off while watching the blockchain.

    Store the state engine state, consensus snapshots, and last block to the working directory.
    Return 0 on success
    Raise an exception on error
    """

    start = datetime.datetime.now()
    attempts = 1

    while True:
        try:

            # advance state
            indexer.StateEngine.build(bitcoind_opts, last_block+1, state_engine)
            break

        except Exception, e:
            # probably offline; exponential back-off
            log.exception(e)
            attempts += 1
            time.sleep(min(300, 2**(attempts) + random.randint(0, 2**(attempts-1))))
            continue

    time_taken = "%s seconds" % (datetime.datetime.now() - start).seconds
    log.info(time_taken)

    return 0


def stop_sync_virtualchain(state_engine):
    """
    Forcibly stop synchronizing the virtual chain.
    """
    state_engine.stop_build()


def stop_virtualchain():
    """
    Hint to stop running the virtual blockchain.
    This may take a while, especially if it is in the
    middle of indexing.
    """
    global running
    running = False


def run_virtualchain( state_engine ):

    """
    Continuously and periodically feed new blocks into the state engine.
    This method loops pretty much forever; consider calling
    it from a thread or in a subprocess.  You can stop
    it with stop_virtualchain(), but it only sets a
    hint to stop indexing (so it may take a few 10s of seconds).

    Return 0 on success (i.e. on exit)
    Return 1 on failure
    """

    global running

    connect_bitcoind = session.get_connect_bitcoind()
    config_file = config.get_config_filename()
    bitcoin_opts = config.get_bitcoind_config(config_file)

    arg_bitcoin_opts, argparser = config.parse_bitcoind_args(return_parser=True)

    # command-line overrides config file
    for (k, v) in arg_bitcoin_opts.items():
        bitcoin_opts[k] = v

    log.debug("multiprocessing config = (%s, %s)" % (config.configure_multiprocessing(bitcoin_opts)))

    try:

        bitcoind = connect_bitcoind(bitcoin_opts)

    except Exception, e:
        log.exception(e)
        return 1

    _, last_block_id = indexer.get_index_range(bitcoind)

    running = True
    while running:

        # keep refreshing the index
        sync_virtualchain(bitcoin_opts, last_block_id, state_engine )

        time.sleep(config.REINDEX_FREQUENCY)

        _, last_block_id = indexer.get_index_range(bitcoind)


def setup_virtualchain(impl=None, testset=False, bitcoind_connection_factory=None, index_worker_env=None):
    """
    Set up the virtual blockchain.
    Use the given virtual blockchain core logic.
    """

    global connect_bitcoind

    if impl is not None:
        config.set_implementation(impl, testset)

    if bitcoind_connection_factory is not None:
        workpool.set_connect_bitcoind( bitcoind_connection_factory )

    if index_worker_env is not None: 
        # expect a dict
        if type(index_worker_env) != dict:
            raise Exception("index_worker_env must be a dictionary")

        workpool.set_default_worker_env( index_worker_env )


def virtualchain_set_opfields( op, **fields ):
    """
    Pass along virtualchain-reserved fields to a virtualchain operation.
    This layer of indirection is meant to help with future compatibility,
    so virtualchain implementations do not try to set operation fields
    directly.
    """

    # warn about unsupported fields
    for f in fields.keys():
        if f not in indexer.RESERVED_KEYS:
            log.warning("Unsupported virtualchain field '%s'" % f)

    # propagate reserved fields
    for f in fields.keys():
        if f in indexer.RESERVED_KEYS:
            op[f] = fields[f]

    return op


def connect_bitcoind( opts ):
    """
    Top-level method to connect to bitcoind,
    using either a built-in default, or a module
    to be loaded at runtime whose path is referred
    to by the environment variable
    VIRTUALCHAIN_MOD_CONNECT_BLOCKCHAIN.
    """
    connect_bitcoind_factory = workpool.multiprocess_connect_bitcoind()
    return connect_bitcoind_factory( opts )

if __name__ == '__main__':

    import impl_ref
    setup_virtualchain(impl_ref)
    run_virtualchain()
