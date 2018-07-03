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


import os
import argparse
from ConfigParser import SafeConfigParser
import logging
import time

DEBUG = False
if os.environ.get("BLOCKSTACK_DEBUG") == "1" or os.environ.get("BLOCKSTACK_TEST") == "1":
    DEBUG = True

""" virtualchain daemon configs
"""

# RPC_TIMEOUT = 5  # seconds

BLOCK_BATCH_SIZE = 10

VIRTUALCHAIN_BTC_DEFAULT_SEGWIT = False

def get_features(feature_name):
    if feature_name == 'segwit':
        return VIRTUALCHAIN_BTC_DEFAULT_SEGWIT

    raise ValueError("Unrecognized feature '{}'".format(feature_name))


def set_features(feature_name, value):
    global VIRTUALCHAIN_BTC_DEFAULT_SEGWIT

    if feature_name == 'segwit':
        if value not in [True, False]:
            raise ValueError("Invalid value (must be True/False)")

        VIRTUALCHAIN_BTC_DEFAULT_SEGWIT = value
        return 

    raise ValueError("Unrecognized feature '{}'".format(feature_name))


def get_logger(name=None):
    """
    Get virtualchain's logger
    """

    level = logging.CRITICAL
    if DEBUG:
        logging.disable(logging.NOTSET)
        level = logging.DEBUG

    if name is None:
        name = "<unknown>"

    log = logging.getLogger(name=name)
    log.setLevel( level )
    console = logging.StreamHandler()
    console.setLevel( level )
    log_format = ('[%(asctime)s] [%(levelname)s] [%(module)s:%(lineno)d] (' + str(os.getpid()) + '.%(thread)d) %(message)s' if DEBUG else '%(message)s')
    formatter = logging.Formatter( log_format )
    console.setFormatter(formatter)
    log.propagate = False

    if len(log.handlers) > 0:
        for i in xrange(0, len(log.handlers)):
            log.handlers.pop(0)
    
    log.addHandler(console)
    return log

log = get_logger("virtualchain")

if not __debug__:
    log.error('FATAL: __debug__ must be set')
    os.abort()


def get_first_block_id(impl):
    """
    facade to implementation's first block
    """
    return impl.get_first_block_id()


def get_config_filename(impl, working_dir):
    """
    Get the absolute path to the config file.
    """
    config_filename = impl.get_virtual_chain_name() + ".ini"
    return os.path.join(working_dir, config_filename)


def get_db_filename(impl, working_dir):
    """
    Get the absolute path to the last-block file.
    """
    db_filename = impl.get_virtual_chain_name() + ".db"
    return os.path.join(working_dir, db_filename)


def get_snapshots_filename(impl, working_dir):
    """
    Get the absolute path to the chain's consensus snapshots file.
    """
    snapshots_filename = impl.get_virtual_chain_name() + ".snapshots"
    return os.path.join(working_dir, snapshots_filename)


def get_backups_directory(impl, working_dir):
    """
    Get the absolute path to the chain's backups directory
    """
    backup_dir = os.path.join( working_dir, 'backups')
    return backup_dir


def get_lockfile_filename(impl, working_dir):
    """
    Get the absolute path to the chain's indexing lockfile
    """
    lockfile_name = impl.get_virtual_chain_name() + ".lock"
    return os.path.join(working_dir, lockfile_name)


def get_bitcoind_config(config_file=None, impl=None):
    """
    Set bitcoind options globally.
    Call this before trying to talk to bitcoind.
    """

    loaded = False

    bitcoind_server = None
    bitcoind_port = None
    bitcoind_user = None
    bitcoind_passwd = None
    bitcoind_timeout = None
    bitcoind_regtest = None
    bitcoind_p2p_port = None
    bitcoind_spv_path = None

    regtest = None

    if config_file is not None:

        parser = SafeConfigParser()
        parser.read(config_file)

        if parser.has_section('bitcoind'):

            if parser.has_option('bitcoind', 'server'):
                bitcoind_server = parser.get('bitcoind', 'server')

            if parser.has_option('bitcoind', 'port'):
                bitcoind_port = int(parser.get('bitcoind', 'port'))

            if parser.has_option('bitcoind', 'p2p_port'):
                bitcoind_p2p_port = int(parser.get('bitcoind', 'p2p_port'))

            if parser.has_option('bitcoind', 'user'):
                bitcoind_user = parser.get('bitcoind', 'user')

            if parser.has_option('bitcoind', 'passwd'):
                bitcoind_passwd = parser.get('bitcoind', 'passwd')

            if parser.has_option('bitcoind', 'spv_path'):
                bitcoind_spv_path = parser.get('bitcoind', 'spv_path')

            if parser.has_option('bitcoind', 'regtest'):
                regtest = parser.get('bitcoind', 'regtest')
            else:
                regtest = 'no'

            if parser.has_option('bitcoind', 'timeout'):
                bitcoind_timeout = float(parser.get('bitcoind', 'timeout'))

            if regtest.lower() in ["yes", "y", "true", "1", "on"]:
                bitcoind_regtest = True
            else:
                bitcoind_regtest = False
            
            loaded = True

    if not loaded:

        bitcoind_server = 'bitcoin.blockstack.com'
        bitcoind_port = 8332
        bitcoind_user = 'blockstack'
        bitcoind_passwd = 'blockstacksystem'
        bitcoind_regtest = False
        bitcoind_timeout = 300
        bitcoind_p2p_port = 8333
        bitcoind_spv_path = os.path.expanduser("~/.virtualchain-spv-headers.dat")

    default_bitcoin_opts = {
        "bitcoind_user": bitcoind_user,
        "bitcoind_passwd": bitcoind_passwd,
        "bitcoind_server": bitcoind_server,
        "bitcoind_port": bitcoind_port,
        "bitcoind_timeout": bitcoind_timeout,
        "bitcoind_regtest": bitcoind_regtest,
        "bitcoind_p2p_port": bitcoind_p2p_port,
        "bitcoind_spv_path": bitcoind_spv_path
    }

    return default_bitcoin_opts


