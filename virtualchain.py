#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    virtualchain
    ~~~~~
    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
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

from ConfigParser import SafeConfigParser

from txjsonrpc.netstring import jsonrpc

from .lib import config
from .lib import workpool
from .lib.blockchain import session
from pybitcoin import BitcoindClient, ChainComClient

log = session.log

# global instance of our implementation's database indexer
db = None 

# global flag indicating that we're running
running = False

# global factory method for connecting to bitcoind 
# (can be overwritten to mock a blockchain)
connect_bitcoind = session.connect_bitcoind


def signal_handler(signal, frame):
    """
    Handle Ctrl+C (SIGINT)
    """
    impl = config.get_implementation()
    
    log.info('\n')
    log.info('Exiting %s' % impl.get_virtual_chain_name())
    sys.exit(0)


def json_traceback():
    """
    Return a traceback as a JSON object.
    """
    exception_data = traceback.format_exc().splitlines()
    return {
        "error": exception_data[-1],
        "traceback": exception_data
    }


def get_db():
   """
   Get or instantiate the virtual chain's state database.
   """
   
   global db 
   impl = config.get_implementation()
   
   if db is None:
      
      # load! 
      opcodes = impl.get_opcodes()
      magic_bytes = impl.get_magic_bytes()
      db_state = impl.get_db_state()
      opcode_order = impl.get_op_processing_order()
      
      db = indexer.VirtualChainDB( magic_bytes, opcodes, state=db_state, op_order=opcode_order )
      return db
   
   else:
      return db


def refresh_index( bitcoind_opts, last_block):
    """
    Obtain the operation sequence from the blockchain, up to and including last_block.
    That is, go and fetch each block we haven't seen since the last call to this method,
    extract the operations from them, and record in the given working_dir where we left 
    off while watching the blockchain.
    
    Store the operations database, consensus snapshots, and last block to the working directory.
    Return 0 on success 
    Raise an exception on error
    """
    
    start = datetime.datetime.now()
    
    # advance the database 
    db = get_db()
    db.build( bitcoind_opts, last_block+1 )
    
    time_taken = "%s seconds" % (datetime.datetime.now() - start).seconds
    log.info(time_taken)
    
    return 0
 

def stop_virtualchain():
   """
   Hint to stop running the virtual blockchain.
   This may take a while, especially if it is in the
   middle of indexing.
   """
   global running 
   running = False 
   

def run_virtualchain():
   """
   Run the virtual blockchain.
   Continuously and periodically update the database.
   This method loops pretty much forever; consider calling 
   it from a thread or in a subprocess.  You can stop 
   it with stop_virtualchain(), but it only sets a 
   hint to stop indexing (so it may take a few 10s of seconds).
   
   Return 0 on success (i.e. on exit)
   Return 1 on failure
   """
   
   global running 
   global connect_bitcoind
   
   config_file = config.get_config_filename()
   bitcoin_opts = config.get_bitcoind_config( config_file )
   
   arg_bitcoin_opts, argparser = config.parse_bitcoind_args( return_parser=True )

   # command-line overrides config file
   for (k, v) in arg_bitcoin_opts.items():
      bitcoin_opts[k] = v
   
   log.debug("multiprocessing config = (%s, %s)" % (config.configure_multiprocessing( bitcoin_opts )))
   
   try:
      
      bitcoind = connect_bitcoind( bitcoin_opts )
      
   except Exception, e:
      log.exception(e)
      return 1

   _, last_block_id = indexer.get_index_range( bitcoind )
   
   running = True 
   while running:
      
      # keep refreshing the index
      refresh_index( bitcoin_opts, last_block_id )
      
      time.sleep( config.REINDEX_FREQUENCY )
      
      _, last_block_id = indexer.get_index_range( bitcoind )



def setup_virtualchain( impl_module, bitcoind_connection_factory=session.connect_bitcoind ):
   """
   Set up the virtual blockchain.
   Use the given virtual blockchain core logic.
   """
   
   global connect_bitcoind 
   
   config.set_implementation( impl_module )
   connect_bitcoind=bitcoind_connection_factory
   

if __name__ == '__main__':
    
   import impl_ref
   setup_virtualchain( impl_ref )
   run_virtualchain()
