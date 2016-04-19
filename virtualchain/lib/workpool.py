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
    along with Virtualchain.  If not, see <http://www.gnu.org/licenses/>.
"""


from multiprocessing import Pool

from config import DEBUG, configure_multiprocessing

import os
import sys
import signal
import time
import subprocess
import threading
import fcntl
import errno
import select
import random
import netstring
import traceback
import cPickle as pickle
import blockchain.session
import copy
import imp
import platform 

log = blockchain.session.get_logger("virtualchain")

default_worker_env = {}


class WorkFuture(object):

    def __init__(self, key, wp):

        self.sem = threading.Event()
        self.result = None
        self.key = key
        self.wp = wp
        self.pid = -1

    def wait(self, timeout=None):
        """
        Wait (possibly forever) for there to be a result.
        Return True if ready
        Return False if not ready
        """

        if self.result is not None:
            return self.result

        self.sem.wait(timeout)

    def get(self, timeout=None):
        """
        Wait (possibly forever) and get a result.
        Return None if no result is yet present
        """
        self.sem.wait(timeout)

        if isinstance(self.result, Exception):
            # something crashed. Throw whatever it was
            raise self.result

        return self.result

    def ready(self):
        """
        Does the future have a result?
        """
        return self.sem.is_set()

    def put_result(self, result):
        """
        Put a result, and wake up anyone blocked on the future.
        """
        self.result = result
        self.sem.set()


class WorkIOBuf(object):

    def __init__(self, proc):

        self.proc = proc
        self.stdout_decoder = netstring.Decoder()
        self.write_carryover = ""

    def readmsgs(self, rfd):
        """
        Get lines from stdout.
        Return None on EOF
        """
        buf = ""
        while True:
            try:
                rd = os.read(rfd.fileno(), 4096)
                if len(rd) == 0:
                    if len(buf) == 0:
                        # EOF
                        return None

                    else:
                        # EOF; process what we have
                        break

                buf += rd
            except (IOError, OSError), e:
                if e.errno == errno.EWOULDBLOCK:
                    # can't ready anymore
                    break
                elif e.errno == errno.EPIPE:
                    # process is dead
                    return None

                else:
                    raise

        ret = []
        for msg in self.stdout_decoder.feed(buf):
            ret.append(msg)

        return ret

    def write_or_carry(self, wfd, nm):
        """
        Write all of the netstring message (nm) to the file descriptor wfd,
        but save anything we didn't write in the event of an EWOULDBLOCK.
        Return True if we wrote all of nm
        Return False if we did not.
        Return None on EPIPE
        """

        nm = nm[:]
        while len(nm) > 0:
            try:
                nw = os.write(wfd.fileno(), nm)
                nm = nm[nw:]
            except (IOError, OSError), e:
                if e.errno == errno.EWOULDBLOCK:
                    # can't write anymore
                    self.write_carryover = nm
                    return False

                elif e.errno == errno.EPIPE:
                    # process is dead
                    return None

                else:
                    raise

        # success!
        self.write_carryover = ""
        return True

    def flush(self, wfd):
        """
        Try to send all of the carryover.
        Return True on success
        Return False if there is still stuff left
        Return None if the process died
        """
        rc = self.write_or_carry(wfd, self.write_carryover)
        if rc:
            return True

        if rc is None:
            return None

        return False

    def writemsg(self, wfd, msg):
        """
        Write message to stdin.
        Return True if successfully flushed
        Return False if we had to carry some over.
        Return None if the process is dead.

        NOTE: call flush() first, and only call this
        method if flush() returns True.
        """

        nm = netstring.encode(msg)
        rc = self.write_or_carry(wfd, nm)
        if rc is None:
            # process died
            return None

        if not rc:
            # carried
            return False

        # success!
        return True

    def proc_stdin(self):
        return self.proc.stdin

    def proc_stdout(self):
        return self.proc.stdout

    def proc_pid(self):
        return self.proc.pid


class WorkpoolCoordinator(threading.Thread):

    def __init__(self, wp):
        super(WorkpoolCoordinator, self).__init__()
        self.wp = wp
        self.tick = time.time()
        self.d = 0

        # to avoid wasting extra CPU waiting for nothing...
        self.prev_num_inp = 0
        self.prev_num_futs = 0
        self.backoff_delay = 0.01

    def run(self):
        """
        Process coordinator: multiplex I/O on processes.
        """

        wp = self.wp
        while wp.is_running():

            to_reap = []

            # who has to give us data?
            rfds = wp.get_stdout_fds()
            wfds = wp.get_stdin_fds()
            ready_rfds, ready_wfds, _ = select.select(rfds, wfds, [], 1.0)

            for buf in wp.get_bufs():

                # get all messages
                if buf.proc_stdout() in ready_rfds:
                    ready_rfds.remove(buf.proc_stdout())
                    msgs = buf.readmsgs(buf.proc_stdout())

                    if msgs is None:
                        # process died
                        to_reap.append(buf.proc)

                    else:
                        # dispatch to futures
                        for msg in msgs:
                            key, payload = Workpool.parse_message(msg)
                            # log.debug("%s: Got %s" % (buf.proc_pid(), key))
                            if key is not None:
                                wp.future_complete(key, payload)
                            else:
                                raise Exception("Worker %s: Unparseable response: '%s'" % (buf.proc_pid(), msg))

            bufs = wp.get_bufs()
            cnt = 0

            for i in xrange(0, len(bufs)):

                # try to round-robin our requests
                buf = bufs[(i + self.d) % len(bufs)]

                # refill this process's input buffer with requests
                if buf.proc_stdin() in ready_wfds:

                    ready_wfds.remove(buf.proc_stdin())

                    rc = buf.flush(buf.proc_stdin())
                    if not rc:
                        if rc is None:
                            # process died
                            to_reap.append(buf.proc)
                        else:
                            # out of buffer space
                            continue

                    # if we're out of outstanding requests, then get the next one
                    if not wp.is_busy(buf.proc_pid()):

                        next_msg = wp.next_pending_input(buf.proc_pid())
                        if next_msg is None:
                            # out of messages
                            continue

                        rc = buf.writemsg(buf.proc_stdin(), next_msg)
                        if not rc:
                            if rc is None:
                                # process died
                                to_reap.append(buf.proc)
                            else:
                                # out of buffer space
                                continue

                        # put a message
                        cnt += 1

            self.d += cnt

            if len(ready_rfds) > 0:
                raise Exception("%s ready read file descriptors unaccounted for" % len(ready_rfds))

            if len(ready_wfds) > 0:
                raise Exception("%s ready write file descriptors unaccounted for" % len(ready_wfds))

            # reap dead processes
            for p in list(set(to_reap)):
                wp.reap_process(p)

            if time.time() > self.tick:
                # throttling
                self.tick = time.time() + 1
                num_inp = wp.num_pending_inputs()
                num_futs = wp.num_pending_outputs()

                if self.prev_num_futs > 0 and self.prev_num_inp == num_inp and self.prev_num_futs == num_futs:
                    # nothing happened.  sleep for a bit
                    time.sleep(self.backoff_delay)
                    self.backoff_delay = min(self.backoff_delay * 2, 1.0)

                else:
                    self.backoff_delay = 0.01

                self.prev_num_futs = num_futs
                self.prev_inp = num_inp

                if num_inp > 0 or num_futs > 0:
                    log.debug("%s requests to send; %s requests to receive" % (num_inp, num_futs))


class Workpool(object):

    def __init__(self, num_workers, worker_bin_path, worker_argv, worker_env=None):

        self.num_workers = num_workers
        self.worker_bin_path = worker_bin_path
        self.worker_argv = worker_argv

        self.procs = []
        self.bufs = []
        self.closed = False
        self.running = True

        self.pending_input_lock = threading.Lock()
        self.pending_inputs = []
        self.in_progress = []   # list of PIDs that are working on messages

        self.pending_output_lock = threading.Lock()
        self.pending_outputs = {}      # map message key to future

        if worker_env is None:
            worker_env = default_worker_env
        else:
            tmp = {}
            tmp.update(default_worker_env)
            tmp.update(worker_env)
            worker_env = tmp

        if 'PYTHONPATH' in worker_env and platform.system().lower() == 'darwin':
            # Mac OS X-specific work-around
            self.worker_bin_path = worker_env['PYTHONPATH'] + "/python"

        # start processes
        for i in xrange(0, num_workers):

            p = subprocess.Popen([self.worker_bin_path] + worker_argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr, env=worker_env, close_fds=True)
            self.procs.append(p)

            # put into non-blocking mode
            for pipe in [p.stdin, p.stdout]:
                fl = fcntl.fcntl(pipe.fileno(), fcntl.F_GETFL)
                fcntl.fcntl(pipe.fileno(), fcntl.F_SETFL, fl | os.O_NONBLOCK)

            # assign work buffer
            buf = WorkIOBuf(p)
            self.bufs.append(buf)

        # start coordinator
        self.coordinator_thread = WorkpoolCoordinator(self)
        self.coordinator_thread.start()

    def close(self):
        """
        Stop sending data: close stdins
        """
        self.closed = True

    def is_closed(self):
        """
        Is the pool closed?
        """
        return self.closed

    def is_running(self):
        """
        Is the pool processing requests?
        """
        return self.running

    def terminate(self):
        """
        Stop the workpool with SIGTERM
        """
        for p in self.procs:
            try:
                p.send_signal( signal.SIGTERM )
            except:
                log.warn("Failed to send SIGTERM to %s" % p.pid)


    def kill(self):
        """
        Stop the workpool with SIGKILL
        """
        for p in self.procs:
            try:
                p.send_signal( signal.SIGKILL )
            except:
                log.warn("Failed to send SIGKILL to %s" % p.pid)


    def join(self, timeout=None):
        """
        Join with the workpool processes.
        If timeout is not None, wait at most @timeout seconds.
        Return True if joined.
        Return False if not.
        """
        joined = True
        self.running = False
        still_running = []
        for p in self.procs:
            log.debug("Wait on %s" % p.pid)

            if timeout is not None:
                # poll every 0.1 seconds 
                deadline = timeout + time.time()
                ret = None
                while time.time() < deadline:
                    time.sleep(0.1)
                    ret = p.poll()
                    if ret is not None:
                        break

                if ret is None:
                    # did not join 
                    joined = False
                    still_running.append(p)

            else:
                # wait indefinitely
                p.wait()

        # join with coordinator
        if joined:
            self.coordinator_thread.join(timeout)
            if self.coordinator_thread.is_alive():
                # not joined 
                joined = False
                log.debug("Workpool not joined (coordinator still alive)")

            else:
                log.debug("Workpool joined")
        else:
            log.debug("Workpool not joined (still alive: %s)" % (",".join([str(p.pid) for p in still_running])))

        # reap dead processes 
        for p in self.procs:
            if p not in still_running:
                self.reap_process(p)
        
        return joined


    def get_bufs(self):
        """
        Return process message buffer set
        """
        return self.bufs

    def get_stdin_fds(self):
        """
        Get list of stdin file descriptors.
        """
        fds = []
        for p in self.procs:
            fds.append(p.stdin)

        return fds

    def get_stdout_fds(self):
        """
        Get list of stdout file descriptors.
        """
        fds = []
        for p in self.procs:
            fds.append(p.stdout)

        return fds

    def next_pending_input(self, pid):
        """
        Get the next pending input message to a process.
        """
        self.pending_input_lock.acquire()

        inp = None
        if len(self.pending_inputs) > 0:
            inp = self.pending_inputs.pop(0)

        self.pending_input_lock.release()

        if inp is not None:
            key, payload = Workpool.parse_message(inp)

            self.pending_output_lock.acquire()
            if self.pending_outputs.has_key(key):
                # record future's PID
                self.pending_outputs[key].pid = pid

            # record that this process has a message
            self.in_progress.append(pid)

            self.pending_output_lock.release()

        return inp

    def num_pending_inputs(self):
        """
        Count the number of outstanding messages to write to stdin
        """
        self.pending_input_lock.acquire()

        count = len(self.pending_inputs)

        self.pending_input_lock.release()

        return count

    def num_pending_outputs(self):
        """
        Count the number of outstanding futures
        """
        self.pending_output_lock.acquire()

        count = len(self.pending_outputs.keys())

        self.pending_output_lock.release()

        return count

    def list_pending_future_keys(self):
        """
        Get the list of future keys that are still pending
        """
        self.pending_output_lock.acquire()

        keys = self.pending_outputs.keys()[:]

        self.pending_output_lock.release()

        return keys

    def is_busy(self, pid):
        """
        Does a process have an outstanding request?
        """
        self.pending_output_lock.acquire()

        ret = (pid in self.in_progress)

        self.pending_output_lock.release()

        return ret

    def reap_process(self, proc):
        """
        Join with a dead process, and clear out any of its futures.
        """

        proc.wait()

        self.pending_output_lock.acquire()

        for key, future in self.pending_outputs.items():
            if future.pid == proc.pid:
                future.put_result(OSError("Child %s died unexpectedly" % proc.pid))
                del self.pending_outputs[key]

        self.pending_output_lock.release()

        if proc in self.procs:
            self.procs.remove(proc)


    @classmethod
    def build_message(cls, key, payload):
        """
        Create a worker message
        """
        if len(key) != 16:
            return None

        return "%s:%s" % (key, payload)

    @classmethod
    def parse_message(cls, line):
        """
        Parse a worker message
        Return key, payload on success
        Return None, None on failure
        """
        if len(line) < 17:
            return (None, None)

        key = line[0:16]
        payload = line[17:]

        return (key, payload)

    @classmethod
    def worker_next_message(cls):
        """
        Get the next message from stdin.
        Called by a worker.
        Return (key, payload)
        Return (None, None) on EOF
        """

        dc = netstring.Decoder()

        # force stdin to be non-blocking
        fl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, fl | os.O_NONBLOCK)

        while True:

            # wait for data
            ready_fds, _, _ = select.select([sys.stdin], [], [], 0.1)

            if len(ready_fds) == 0:
                continue

            # get data
            try:
                buf = sys.stdin.read(4096)
            except (IOError, OSError), e:
                if e.errno == errno.EWOULDBLOCK:
                    continue
                else:
                    raise

            if len(buf) == 0:
                # EOF
                return

            for msg in dc.feed(buf):
                key, payload = cls.parse_message(msg)
                yield (key, payload)

    @classmethod
    def worker_post_message(cls, key, payload):
        """
        Send a message to the workpool on stdout.
        Called by a worker.
        """
        msg = cls.build_message(key, payload)
        ns = netstring.encode(msg)
        sys.stdout.write(ns)
        sys.stdout.flush()

    def apply_async(self, payload):
        """
        Send data to any process, and get back a
        future that can be waited on and will evaluate
        to the result of the work.

        Return a Future on success
        Return None on error (i.e. the pool is closed)
        """

        if self.closed:
            return None

        if len(self.procs) == 0:
            raise Exception("All processes are dead")

        # reserve an output slot
        key = "%016X" % random.randint(0, 2**64)

        self.pending_output_lock.acquire()

        while True:
            if key not in self.pending_outputs.keys():
                break

            # try again
            key = "%016X" % random.randint(0, 2**64)

        fut = WorkFuture(key, self)
        self.pending_outputs[ key ] = fut

        self.pending_output_lock.release()

        # queue input for consumption
        message = Workpool.build_message(key, payload)
        self.pending_input_lock.acquire()

        self.pending_inputs.append(message)

        self.pending_input_lock.release()

        return fut

    def future_complete(self, key, payload):
        """
        Fill in a future, finalizing it.
        Return True if dispatched
        Return False if there was no waiting process.
        """

        rc = None
        fut = None

        self.pending_output_lock.acquire()

        if self.pending_outputs.has_key(key):
            fut = self.pending_outputs[ key ]
            del self.pending_outputs[key]
            rc = True

        else:
            rc = False

        if fut is not None and fut.pid in self.in_progress:
            self.in_progress.remove(fut.pid)

        self.pending_output_lock.release()

        if fut is not None:
            # wake up waiter
            fut.put_result(payload)

        return rc

# bitcoind just for this process
process_local_bitcoind = None
process_local_connect_bitcoind = None


def multiprocess_bitcoind(bitcoind_opts, reset=False):
    """
    Get a per-process bitcoind client.
    """

    global process_local_bitcoind

    if reset:
        process_local_bitcoind = None

    if process_local_bitcoind is None:
        # this proces does not yet have a bitcoind client.
        # make one.
        if bitcoind_opts is None:
            # neither given nor globally set
            raise Exception("No bitcoind options set.")

        connect_bitcoind = multiprocess_connect_bitcoind()
        process_local_bitcoind = connect_bitcoind(bitcoind_opts)

    return process_local_bitcoind


def multiprocess_batch_size(bitcoind_opts):
    """
    How many blocks can we be querying at once?
    """
    num_workers, worker_batch_size = configure_multiprocessing(bitcoind_opts)
    return num_workers * worker_batch_size


def multiprocess_pool(bitcoind_opts, python_filepath):
    """
    Create a multiprocess pool to index the blockchain, given the path to the python file to run to receive commands
    and the blockchain connection options.
    """
    num_workers, worker_batch_size = configure_multiprocessing(bitcoind_opts)

    bitcoind_opts_environ = pickle.dumps(bitcoind_opts)

    worker_env = {
        "VIRTUALCHAIN_BITCOIND_OPTIONS": bitcoind_opts_environ
    }

    if os.environ.get("PYTHONPATH", None) is not None:
        worker_env["PYTHONPATH"] = os.environ["PYTHONPATH"]

    # use full_path to python from sys.executable as default
    # this is used when PYTHONPATH is not set
    return Workpool(num_workers, sys.executable, [python_filepath], worker_env=worker_env)


def multiprocess_bitcoind_opts():
    """
    Get multiprocess bitcoind options
    """
    bitcoind_opts_pickled = os.getenv("VIRTUALCHAIN_BITCOIND_OPTIONS")
    bitcoind_opts = pickle.loads(bitcoind_opts_pickled)
    return bitcoind_opts


def multiprocess_connect_bitcoind():
    """
    Get the connect_bitcoind factory method.
    """
    global process_local_connect_bitcoind
    if process_local_connect_bitcoind is None:

        # override the blockchain connection factory (for testing)
        blockchain_connect_override_module = os.getenv("VIRTUALCHAIN_MOD_CONNECT_BLOCKCHAIN")
        if blockchain_connect_override_module is not None:

            log.debug("Using '%s' to implement blockchain connection factory" % blockchain_connect_override_module)

            # either compiled or source...
            mod_type = None
            if blockchain_connect_override_module.endswith(".pyc"):
                mod_type = imp.PY_COMPILED
            elif blockchain_connect_override_module.endswith(".py"):
                mod_type = imp.PY_SOURCE
            else:
                raise Exception("Unsupported module type: '%s'" % blockchain_connect_override_module)

            # find and load the module with the desired 'connect_bitcoind' method
            mod_fd = open(blockchain_connect_override_module, "r")
            connect_blockchain_mod = imp.load_module("connect_blockchain", mod_fd, blockchain_connect_override_module, ("", 'r', mod_type))

            try:
                process_local_connect_bitcoind = connect_blockchain_mod.connect_bitcoind
                assert hasattr(process_local_connect_bitcoind, "__call__")
            except:
                raise Exception("Module '%s' has no callable 'connect_bitcoind' method" % blockchain_connect_override_module)

        else:
            # default
            process_local_connect_bitcoind = blockchain.session.connect_bitcoind_impl

    return process_local_connect_bitcoind


def multiprocess_rpc_marshal(method_name, method_args):
    """
    Marshal an RPC call into a request to be fed into a worker.
    """
    return pickle.dumps([method_name] + method_args)


def multiprocess_rpc_unmarshal(payload):
    """
    Unmarshal an RPC call and arguments
    Return (method_name, *method_args)
    """
    args = pickle.loads(payload)
    return args[0], args[1:]


def multiprocess_worker_main(mainloop_body):
    """
    Main loop for a worker: dispatch messages to a main-loop body
    """
    for (key, payload) in Workpool.worker_next_message():
        try:
            mainloop_body(key, payload)
        except:
            print >> sys.stderr, "Worker %s exiting on exception" % os.getpid()
            print >> sys.stderr, traceback.format_exc()
            sys.stderr.flush()
            break


def set_default_worker_env(worker_env):
    """
    Set the default environment variables for a worker.
    """
    global default_worker_env
    default_worker_env = worker_env


def set_connect_bitcoind(connect_bitcoind):
    """
    Set default bitcoind connection factory.
    """
    global process_local_connect_bitcoind
    process_local_connect_bitcoind = connect_bitcoind
