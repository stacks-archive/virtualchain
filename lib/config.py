#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    virtualchain
    ~~~~~
    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

import os
from ConfigParser import SafeConfigParser

from ..impl import *

DEBUG = True
TESTNET = False
TESTSET = True

""" constants
"""
AVERAGE_MINUTES_PER_BLOCK = 10
DAYS_PER_YEAR = 365.2424
HOURS_PER_DAY = 24
MINUTES_PER_HOUR = 60
SECONDS_PER_MINUTE = 60
MINUTES_PER_YEAR = DAYS_PER_YEAR*HOURS_PER_DAY*MINUTES_PER_HOUR
SECONDS_PER_YEAR = int(round(MINUTES_PER_YEAR*SECONDS_PER_MINUTE))
BLOCKS_PER_YEAR = int(round(MINUTES_PER_YEAR/AVERAGE_MINUTES_PER_BLOCK))
AVERAGE_BLOCKS_PER_HOUR = MINUTES_PER_HOUR/AVERAGE_MINUTES_PER_BLOCK

""" virtualchain daemon configs
"""

VERSION = 'v0.1-beta'
RPC_TIMEOUT = 5  # seconds 

# how often do we retry RPCs when talking to bitcoind?
MULTIPROCESS_RPC_RETRY = 3

""" block indexing configs
"""

REINDEX_FREQUENCY = 10  # in seconds

""" consensus hash configs
"""

BLOCKS_CONSENSUS_HASH_IS_VALID = 4*AVERAGE_BLOCKS_PER_HOUR

""" Validation 
"""

def get_working_dir():
   """
   Get the absolute path to the working directory.
   """
   from os.path import expanduser
   home = expanduser("~")
   
   working_dir = os.path.join(home, "." + get_virtual_chain_name())

   if not os.path.exists(working_dir):
      os.makedirs(working_dir)

   return working_dir


def get_config_filename():
   """
   Get the absolute path to the config file.
   """
   working_dir = get_working_dir()
   config_filename = get_virtual_chain_name() + ".ini"
   
   return os.path.join(working_dir, config_filename )


def get_db_filename():
   """
   Get the absolute path to the chain's database file.
   """
   working_dir = get_working_dir()
   db_filename = get_virtual_chain_name() + ".db"
   
   return os.path.join( working_dir, db_filename )


def get_snapshots_filename():
   """
   Get the absolute path to the chain's consensus snapshots file.
   """
   working_dir = get_working_dir()
   snapshots_filename = get_virtual_chain_name() + ".snapshots"
   
   return os.path.join( working_dir, snapshots_filename )


def configure_multiprocessing( bitcoind_opts ):
   """
   Given the set of bitcoind options (i.e. the location of the bitcoind server),
   come up with some good multiprocessing parameters.
   
   Return (number of processes, number of blocks per process)
   Return (None, None) if we could make no inferences from the bitcoind opts.
   """
   
   if bitcoind_opts is None:
      return (None, None)
   
   if bitcoind_opts.get("bitcoind_server", None) is None:
      return (None, None)
   
   if bitcoind["bitcoind_server"] in ["localhost", "127.0.0.1", "::1"]:
      # running locally 
      return (1, 64)
   
   else:
      # running remotely 
      return (8, 8)
   

def get_bitcoind_config( config_file=None ):
   """
   Set bitcoind options globally.
   Call this before trying to talk to bitcoind.
   """
   
   loaded = False 
   
   bitcoind_server = None 
   bitcoind_port = None 
   bitcoind_user = None 
   bitcoind_passwd = None 
   bitcoind_use_https = None
   
   if config_file is not None:
         
      parser = SafeConfigParser()
      parser.read(config_file)

      if parser.has_section('bitcoind'):

         if parser.has_option('bitcoind', 'use_https'):
            use_https = parser.get('bitcoind', 'use_https')
         else:
            use_https = 'no'

         if use_https.lower() == "yes" or use_https.lower() == "y":
            bitcoind_use_https = True
         else:
            bitcoind_use_https = False
            
         loaded = True

   if not loaded:
      
      bitcoind_server = DEFAULT_bitcoind_server
      bitcoind_port = '8332'
      bitcoind_user = 'openname'
      bitcoind_passwd = 'opennamesystem'
      bitcoind_use_https = True
        
   default_bitcoin_opts = {
      "bitcoind_user": bitcoind_user,
      "bitcoind_passwd": bitcoind_passwd,
      "bitcoind_server": bitcoind_server,
      "bitcoind_port": bitcoind_port,
      "bitcoind_use_https": bitcoind_use_https
   }
      
   return default_bitcoin_opts


def parse_bitcoind_args( return_parser=False, parser=None ):
    """
    Get bitcoind command-line arguments.
    Optionally return the parser used to do so as well.
    """
    
    opts = {}
    
    if parser is None:
       parser = argparse.ArgumentParser( description='Blockstore Core Daemon version {}'.format(config.VERSION))

    parser.add_argument(
        '--bitcoind-server',
        help='the hostname or IP address of the bitcoind RPC server')
    parser.add_argument(
        '--bitcoind-port', type=int,
        help='the bitcoind RPC port to connect to')
    parser.add_argument(
        '--bitcoind-user',
        help='the username for bitcoind RPC server')
    parser.add_argument(
        '--bitcoind-passwd',
        help='the password for bitcoind RPC server')
    parser.add_argument(
        "--bitcoind-use-https", action='store_true',
        help='use HTTPS to connect to bitcoind')
    
    args, _ = parser.parse_known_args()
    
    # propagate options 
    for (argname, config_name) in zip( ["bitcoind_server", "bitcoind_port", "bitcoind_user", "bitcoind_passwd"], \
                                       ["BITCOIND_SERVER", "BITCOIND_PORT", "BITCOIND_USER", "BITCOIND_PASSWD"] ):
        
        if hasattr( args, argname ) and getattr( args, argname ) is not None:
            
            opts[ argname ] = getattr( args, argname )
            setattr( config, config_name, getattr( args, argname ) )
            
    if args.bitcoind_use_https:
       config.BITCOIND_USE_HTTPS = True 
       opts['bitcoind_use_https'] = True
    
    if return_parser:
       return opts, parser 
    else:
       return opts
    
    