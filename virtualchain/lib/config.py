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


import os
import argparse
from ConfigParser import SafeConfigParser

DEBUG = True
TESTSET = False
IMPL = None             # class, package, or instance that implements the virtual chain state

""" virtualchain daemon configs
"""

RPC_TIMEOUT = 5  # seconds 

MULTIPROCESS_RPC_RETRY = 10

REINDEX_FREQUENCY = 10  # in seconds

AVERAGE_MINUTES_PER_BLOCK = 10
DAYS_PER_YEAR = 365.2424
HOURS_PER_DAY = 24
MINUTES_PER_HOUR = 60
SECONDS_PER_MINUTE = 60
MINUTES_PER_YEAR = DAYS_PER_YEAR*HOURS_PER_DAY*MINUTES_PER_HOUR
SECONDS_PER_YEAR = int(round(MINUTES_PER_YEAR*SECONDS_PER_MINUTE))
BLOCKS_PER_YEAR = int(round(MINUTES_PER_YEAR/AVERAGE_MINUTES_PER_BLOCK))
EXPIRATION_PERIOD = BLOCKS_PER_YEAR*1
AVERAGE_BLOCKS_PER_HOUR = MINUTES_PER_HOUR/AVERAGE_MINUTES_PER_BLOCK

BLOCKS_CONSENSUS_HASH_IS_VALID = 4*AVERAGE_BLOCKS_PER_HOUR


def get_first_block_id():
   """
   facade to implementation's first block 
   """
   global IMPL 
   
   return IMPL.get_first_block_id()


def get_working_dir():
   """
   Get the absolute path to the working directory.
   """
   global IMPL 
   
   from os.path import expanduser
   home = expanduser("~")
  
   working_dir = None
   if hasattr( IMPL, "working_dir" ):
       working_dir = IMPL.working_dir

   else:
       working_dir = os.path.join(home, "." + IMPL.get_virtual_chain_name(testset=TESTSET))

   if not os.path.exists(working_dir):
      os.makedirs(working_dir)

   return working_dir


def get_config_filename():
   """
   Get the absolute path to the config file.
   """
   global IMPL 
   
   working_dir = get_working_dir()
   config_filename = IMPL.get_virtual_chain_name(testset=TESTSET) + ".ini"
   
   return os.path.join(working_dir, config_filename )


def get_db_filename():
   """
   Get the absolute path to the last-block file.
   """
   global IMPL 
   
   working_dir = get_working_dir()
   lastblock_filename = IMPL.get_virtual_chain_name(testset=TESTSET) + ".db"
   
   return os.path.join( working_dir, lastblock_filename )


def get_lastblock_filename():
   """
   Get the absolute path to the last-block file.
   """
   global IMPL 
   
   working_dir = get_working_dir()
   lastblock_filename = IMPL.get_virtual_chain_name(testset=TESTSET) + ".lastblock"
   
   return os.path.join( working_dir, lastblock_filename )


def get_snapshots_filename():
   """
   Get the absolute path to the chain's consensus snapshots file.
   """
   global IMPL 
   
   working_dir = get_working_dir()
   snapshots_filename = IMPL.get_virtual_chain_name(testset=TESTSET) + ".snapshots"
   
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
  
   if bitcoind_opts.has_key("multiprocessing_num_procs") and bitcoind_opts.has_key("multiprocessing_num_blocks"):
      return bitcoind_opts["multiprocessing_num_procs"], bitcoind_opts["multiprocessing_num_blocks"]

   if bitcoind_opts.get("bitcoind_server", None) is None:
      return (None, None)
   
   if bitcoind_opts["bitcoind_server"] in ["localhost", "127.0.0.1", "::1"]:
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
    
    global IMPL 
    
    opts = {}
    
    if parser is None:
       parser = argparse.ArgumentParser( description='%s version %s' % (IMPL.get_virtual_chain_name(testset=TESTSET), IMPL.get_virtual_chain_version()))

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
    
    
def get_implementation():
   """
   Get the implementation of the virtual chain state.
   """
   global IMPL 
   return IMPL 

    
def set_implementation( impl, testset ):
   """
   Set the package, class, or bundle of methods 
   that implements the virtual chain's core logic.
   This method must be called before anything else.
   """
   global IMPL 
   global TESTSET
   
   IMPL = impl
   TESTSET = testset
   
