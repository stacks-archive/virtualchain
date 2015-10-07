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


from multiprocessing import Pool

from config import DEBUG, configure_multiprocessing

import logging
import os
import sys
import signal
import blockchain
from multiprocessing import Pool

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
      from ..virtualchain import connect_bitcoind
      process_local_bitcoind = connect_bitcoind( bitcoind_opts )
      
   return process_local_bitcoind


def multiprocess_batch_size( bitcoind_opts ):
   """
   How many blocks can we be querying at once?
   """
   num_workers, worker_batch_size = configure_multiprocessing( bitcoind_opts )
   return num_workers * worker_batch_size


def multiprocess_pool( bitcoind_opts ):
   """
   Given bitcoind options, create a multiprocess pool 
   for querying it.
   """
   num_workers, worker_batch_size = configure_multiprocessing( bitcoind_opts )
   return Pool( processes=num_workers )

    
