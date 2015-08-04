#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    virtualchain
    ~~~~~
    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

from multiprocessing import Pool

from config import DEBUG, configure_multiprocessing

import logging
import os
import sys
import signal
import blockchain

# bitcoind just for this process
process_local_bitcoind = None

def multiprocess_bitcoind( bitcoind_opts, reset=False ):
   """
   Get a per-process bitcoind client.
   """
   
   global process_local_bitcoind
   
   if reset: 
      process_local_bitcoind = None 
   
   if process_local_bitcoind is None:
      # this proces does not yet have a bitcoind client.
      # make one.
      process_local_bitcoind = blockchain.session.connect_bitcoind( bitcoind_opts )
      
   return process_local_bitcoind


def multiprocess_batch_size( bitcoind_opts ):
   """
   How many blocks can we be querying at once?
   """
   num_workers, worker_batch_size = configure_multiprocessing( bitcoind_opts )
   return num_workers * worker_batch_size