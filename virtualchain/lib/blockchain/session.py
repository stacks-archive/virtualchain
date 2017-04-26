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

import logging
import os
import httplib
import ssl
import socket

from ..config import get_logger
log = get_logger("virtualchain_session")

# various SSL compat measures
create_ssl_authproxy = False 
do_wrap_socket = False

if hasattr( ssl, "_create_unverified_context" ):
   ssl._create_default_https_context = ssl._create_unverified_context
   create_ssl_authproxy = True 

if not hasattr( ssl, "create_default_context" ):
   create_ssl_authproxy = False
   do_wrap_socket = True


# disable debug logging from bitcoinrpc
bitcoinrpc_logger = logging.getLogger("BitcoinRPC")
bitcoinrpc_logger.setLevel(logging.CRITICAL)

class BitcoindConnection( httplib.HTTPSConnection ):
   """
   Wrapped SSL connection, if we can't use SSLContext.
   """

   def __init__(self, host, port, timeout=None ):
   
      httplib.HTTPSConnection.__init__(self, host, port )
      self.timeout = timeout
        
   def connect( self ):
      
      sock = socket.create_connection((self.host, self.port), self.timeout)
      if self._tunnel_host:
         self.sock = sock
         self._tunnel()
         
      self.sock = ssl.wrap_socket( sock, cert_reqs=ssl.CERT_NONE )


def is_int(i):
    """
    Is the given object a long or an int?
    """
    return isinstance(i, (int,long))


def is_valid_int(i):
    """
    Is the given object an integer?
    """
    if is_int(i):
        return True
    elif isinstance(i, str):
        try:
            int_i = int(i)
        except:
            return False
        else:
            return True
    return False


def create_bitcoind_connection( rpc_username, rpc_password, server, port, use_https, timeout ):
    """
    Creates an RPC client to a bitcoind instance.
    It will have ".opts" defined as a member, which will be a dict that stores the above connection options.
    """
    
    from .bitcoin_blockchain import AuthServiceProxy

    global do_wrap_socket, create_ssl_authproxy
        
    log.debug("[%s] Connect to bitcoind at %s://%s@%s:%s, timeout=%s" % (os.getpid(), 'https' if use_https else 'http', rpc_username, server, port, timeout) )
    
    protocol = 'https' if use_https else 'http'
    if not server or len(server) < 1:
        raise Exception('Invalid bitcoind host address.')
    if not port or not is_valid_int(port):
        raise Exception('Invalid bitcoind port number.')
    
    authproxy_config_uri = '%s://%s:%s@%s:%s' % (protocol, rpc_username, rpc_password, server, port)
    
    if use_https:
        # TODO: ship with a cert
        if do_wrap_socket:
           # ssl._create_unverified_context and ssl.create_default_context are not supported.
           # wrap the socket directly 
           connection = BitcoindConnection( server, int(port), timeout=timeout )
           ret = AuthServiceProxy(authproxy_config_uri, connection=connection)
           
        elif create_ssl_authproxy:
           # ssl has _create_unverified_context, so we're good to go 
           ret = AuthServiceProxy(authproxy_config_uri, timeout=timeout)
        
        else:
           # have to set up an unverified context ourselves 
           ssl_ctx = ssl.create_default_context()
           ssl_ctx.check_hostname = False
           ssl_ctx.verify_mode = ssl.CERT_NONE
           connection = httplib.HTTPSConnection( server, int(port), context=ssl_ctx, timeout=timeout )
           ret = AuthServiceProxy(authproxy_config_uri, connection=connection)
          
    else:
        ret = AuthServiceProxy(authproxy_config_uri)

    # remember the options 
    bitcoind_opts = {
       "bitcoind_user": rpc_username,
       "bitcoind_passwd": rpc_password,
       "bitcoind_server": server,
       "bitcoind_port": port,
       "bitcoind_use_https": use_https,
       "bitcoind_timeout": timeout
    }
    
    setattr( ret, "opts", bitcoind_opts )
    return ret


def connect_bitcoind_impl( bitcoind_opts ):
    """
    Create a connection to bitcoind, using a dict of config options.
    """

    if 'bitcoind_port' in bitcoind_opts.keys() and bitcoind_opts['bitcoind_port'] is None:
        log.error("No port given")
        raise ValueError("No RPC port given (bitcoind_port)")

    if 'bitcoind_timeout' in bitcoind_opts.keys() and bitcoind_opts['bitcoind_timeout'] is None:
        # default
        bitcoind_opts['bitcoind_timeout'] = 300

    try:
        int(bitcoind_opts['bitcoind_port'])
    except:
        log.error("Not an int: '%s'" % bitcoind_opts.get('bitcoind_port'))
        raise

    try:
        float(bitcoind_opts.get('bitcoind_timeout', 300))
    except:
        log.error("Not a float: '%s'" % bitcoind_opts.get('bitcoind_timeout', 300))
        raise

    return create_bitcoind_connection( bitcoind_opts['bitcoind_user'], bitcoind_opts['bitcoind_passwd'], \
                                       bitcoind_opts['bitcoind_server'], int(bitcoind_opts['bitcoind_port']), \
                                       bitcoind_opts.get('bitcoind_use_https', False), float(bitcoind_opts.get('bitcoind_timeout', 300)) )
 

