#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    virtualchain
    ~~~~~
    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

__version__ = '0.1.0'

import config 
import blockchain 
import indexer 
import workpool 

from config import *
from blockchain import *
from indexer import VirtualChainDB, get_index_range
from workpool import multiprocess_bitcoind, multiprocess_batch_size
