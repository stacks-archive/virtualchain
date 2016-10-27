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

from .lib import config, indexer
from .lib.blockchain import session

log = session.get_logger("virtualchain")

# global instance of our implementation's state engine
state_engine = None

# global flag indicating that we're running
running = False


def sync_virtualchain(bitcoind_opts, last_block, state_engine, expected_snapshots={}, tx_filter=None ):
    """
    Synchronize the virtual blockchain state up until a given block.

    Obtain the operation sequence from the blockchain, up to and including last_block.
    That is, go and fetch each block we haven't seen since the last call to this method,
    extract the operations from them, and record in the given working_dir where we left
    off while watching the blockchain.

    Store the state engine state, consensus snapshots, and last block to the working directory.
    Return True on success
    Return False if we're supposed to stop indexing
    Abort the program on error.  The implementation should catch timeouts and connection errors
    """

    rc = False
    start = datetime.datetime.now()
    while True:
        try:

            # advance state
            rc = indexer.StateEngine.build(bitcoind_opts, last_block + 1, state_engine, expected_snapshots=expected_snapshots, tx_filter=tx_filter )
            break
        
        except Exception, e:
            log.exception(e)
            log.error("Failed to synchronize chain; exiting to safety")
            os.abort()

    time_taken = "%s seconds" % (datetime.datetime.now() - start).seconds
    log.info(time_taken)

    return rc


def setup_virtualchain(impl=None, bitcoind_connection_factory=None, index_worker_env=None):
    """
    Set up the virtual blockchain.
    Use the given virtual blockchain core logic.
    """

    global connect_bitcoind

    if impl is not None:
        config.set_implementation(impl)


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
    # connect_bitcoind_factory = workpool.multiprocess_connect_bitcoind()
    connect_bitcoind_factory = session.connect_bitcoind_impl
    return connect_bitcoind_factory( opts )

