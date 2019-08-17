#!/usr/bin/env python2
#
# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Run transperf's orchestrator."""

import calendar
import datetime
import getopt
import logging
import math
import os
import random
import socket
import sys
import time
import xmlrpclib

from transperf import bits
from transperf import cfgutil
from transperf import ip_modes
from transperf import log
from transperf import parse_ip_map
from transperf import path
from transperf import shell

LOG = logging.getLogger('transperf/orchestrator')


def _load_configs():
    """Loads and yields all the config files in the __config directory."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cfg_files = path.list_files(os.path.join(script_dir, '__config'))
    # Load the configuration scripts (eg, cfg0.py, cfg1.py, ...) in order.
    cfg_scripts = [open(f, 'r').read() for f in sorted(cfg_files)]
    for script in cfg_scripts:
        yield cfgutil.config_from_script(script)


def _allocate_rand_portrange(exp, saddrs):
    """Allocates a random port range for the experiment.

    This is a bit complicated because of the policer tc filters. For an
    experiment that needs P ports, we allocate a range with the next higher
    power of two of P. For example, if we need 6 ports, we allocate a port range
    that can accommodate 8 ports. This is because we need to police a group of
    flows using masked ports.

    To do this we first find the size of the port range. Let's say it requires
    B bits. We fill the higher 16-B bits with a random number. Because the port
    numbers must be larger than 1024, we select a random number larger than
    (1024 >> B) and lower than ((65536-1024) >> B).

    Note: we limit the maximum number of ports at 1024. This gives us a 64 bit
          random ranges at the most least.

    Note: When there is no policer we match on exact ports. Thus, the whole
          range is only matched when we have a policer.

    Args:
        exp: The experiment.
        saddrs: The list of sender addresses.

    Returns:
        Tuples of ports to sender addresses.

    Raises:
        RuntimeError: When encountered a critial error.
    """
    cnt = 0
    for s in range(exp.nsenders()):
        sconns, _, _ = exp.sender_info(s)
        # Count the number of connections in all conns.
        cnt += sum([c[1] for c in sconns])
    cnt = bits.next_power_of_two(cnt)
    if cnt >= 1024:
        raise RuntimeError('upto 1024 ports is supported')
    zbits = bits.trailing_zero_bits(cnt)
    start = 1024 >> zbits
    end = 0xFBFF >> zbits
    next_port = random.randint(start, end) << zbits
    port_to_addr = []
    for s in range(exp.nsenders()):
        sconns, _, _ = exp.sender_info(s)
        for c in sconns:
            port_to_addr.append((next_port, saddrs[s]))
            next_port += 1
    return port_to_addr


def _validate_netperf(exp):
    """Validates netperf binary to make sure it has all the options we need.

    Args:
        exp: The experiment object.

    Returns:
        The error message, if netperf cannot run the experiment.
    """
    has_burst = [c for c in exp.conn.conn_list if c.burst_tuple()]
    if not has_burst:
        return None

    out, _, _ = shell.run(path.netperf() + ' -b 1 -w 1 -H 1 -p 1')
    if out.find('not compiled in') == -1:
        return None

    return 'netperf is not compiled with interval support'


def _run_experiment(exp, out_dir, out_dir_rel, rproxy, sproxies,
                    sslog_interval):
    """Runs an experiment.

    Args:
        exp: The experiment object.
        out_dir: The base output directory for all experiments.
        out_dir_rel: The relative output directory for this experiment.
        rproxy: The receiver proxy.
        sproxies: Tuples of sender address and sender proxy.
        sslog_interval: The time interval in seconds to sample ss log.

    Raises:
        RuntimeError: When encountered a critial error.
    """
    LOG.info('Run experiment, log base dir %s relative dir %s',
             out_dir, out_dir_rel)
    nsenders = exp.nsenders()
    if nsenders > len(sproxies):
        # TODO(soheil): Find a better log message for this.
        raise RuntimeError('experiment %s: needs %d senders' % (exp, nsenders))

    np_err = _validate_netperf(exp)
    if np_err:
        raise RuntimeError('experiment %s: %s' % (exp, np_err))

    rproxy.reset(exp.cmd)
    for _, sproxy in sproxies:
        sproxy.reset(exp.cmd)
        sproxy.set_ss(sslog_interval)

    out_dir_exp = os.path.join(out_dir, '__out', out_dir_rel)
    if not os.path.exists(out_dir_exp):
        os.makedirs(out_dir_exp)

    port_to_addr = _allocate_rand_portrange(exp,
                                            [addr.rsplit(':', 1)[0]
                                             for addr, _ in sproxies])
    LOG.debug('receiver machine_cmds:\n%s', exp.cmds_of_receiver())
    rproxy.set_exp_info(exp.bw_infos(), exp.buf, exp.loss, exp.out_loss,
                        exp.slot_info(), exp.policer_info(), port_to_addr,
                        exp.cmds_of_receiver())
    conn_port = port_to_addr[0][0]
    for j, (addr, sproxy) in enumerate(sproxies[:nsenders]):
        sconns, rtts, scmds = exp.sender_info(j)
        # Count the number of connections in all conns.
        LOG.debug('sender(%s), machine_cmds:%s', j, scmds)
        cnt = sum([c[1] for c in sconns])
        err = sproxy.set_cmds(scmds)
        if err:
            raise RuntimeError('error in set_cmds: %s' % err)
        err = sproxy.set_conns(sconns, conn_port)
        if err:
            raise RuntimeError('error in set_conns: %s' % err)
        err = rproxy.set_sender_info(j, (conn_port, conn_port + cnt),
                                     rtts)
        if err:
            raise RuntimeError('error in set_sender_info: %s' % err)
        conn_port += cnt

    try:
        changed = rproxy.setup_ifaces(nsenders)
    except:
        # It is very likely the interface has gone down and we received a
        # timeout here. Let's wait for the interface to come back up again.
        changed = True

    # We need to sleep for 30s here because changing LRO/GRO on some platforms
    # can take cycle the interface (down and up again).
    if changed:
        time.sleep(30)

    # 2s grace period for each machine.
    grace = 2 + int(math.ceil(nsenders * 2))
    utc_start = datetime.datetime.utcnow()
    start_ts = calendar.timegm(utc_start.utctimetuple()) + grace
    end_ts = start_ts + exp.dur

    err = rproxy.run(exp.all_tools(), start_ts, exp.dur, nsenders,
                     os.path.join(out_dir_rel, 'R'))
    if err:
        raise RuntimeError('cannot start receiver: %s' % err)

    for j, (_, sproxy) in enumerate(sproxies[:nsenders]):
        err = sproxy.run(start_ts, exp.dur, os.path.join(out_dir_rel, str(j)))
        if err:
            raise RuntimeError('cannot start sender: %s' % err)

    now = calendar.timegm(datetime.datetime.utcnow().utctimetuple())
    if now < end_ts:
        time.sleep(end_ts - now)

    for _, sproxy in sproxies[:nsenders]:
        sproxy.maybe_join()

    exp_if_path = os.path.join(out_dir_exp, 'exp.info')
    LOG.info('Writing experiment info to %s', exp_if_path)
    expif = open(exp_if_path, 'w')
    expif.write(exp.pretty_str())
    expif.close()


def print_usage():
    """Prints how to use orch.py."""
    print '''./orch.py [options] -r receiver -s sender1,sender2,...

options:
    -v: verbose output.
    --sslog_interval seconds: set the time interval between two ss commands,
                              default 0.1. A value <0 disables ss logging.'''


def _replace_host_with_ip(ipport_str, num_try, ip_mode, ip_map):
    """Replaces hostname part of ipport_str to numeric IP and return.

       Expects a string of format host:port, otherwise return as is.
       Attempts to resolve up to num_try times when a gaierror is encountered.
       Does not work with IPv6.
    Args:
        ipport_str: host:port string.
        num_try: number of attempts to resolve before giving up
        ip_mode: Whether we are using IPv4 or IPv6.
        ip_map: A map from hostname to IP address.
    Returns:
        IP:port string
    """
    ip_port_split = ipport_str.split(':')
    if len(ip_port_split) == 2:
        for i in range(num_try):
            try:
                hostname = ip_port_split[0]
                port = ip_port_split[1]
                if hostname in ip_map:
                    host_ip = ip_map[hostname]
                else:
                    host_ip = socket.getaddrinfo(hostname, 0, ip_mode,
                                                 socket.SOCK_STREAM,
                                                 socket.IPPROTO_TCP)[0][4][0]
                return '%s:%s' % (host_ip, port)
            except (socket.error, socket.herror,
                    socket.gaierror, socket.timeout) as err:
                # Log and retry
                LOG.error('name resolution failed (%d/%d) %s %s',
                          i + 1, num_try, ip_port_split[0], err)
    return ipport_str


def _create_proxy_with_retry(url, num_try):
    """Create xmlrpclib.ServerProxy and verify if online with retry.

       Proxy must have a procedure ping() that returns 0.
       Added to better handle occasional delay in proxy launch.
    Args:
        url: url of proxy.
        num_try: number of attempts to ping before giving up
    Returns:
       xmlrpclib.ServerProxy instance if successful, or None.
    """
    for i in range(num_try):
        try:
            proxy = xmlrpclib.ServerProxy(url, allow_none=True)
            if proxy.ping() == 0:
                return proxy
        except:
            # Log and retry.
            LOG.error('Proxy not ready yet (%d/%d) %s', i + 1, num_try, url)
            time.sleep(1)

    return None


def main():
    ip_mode = socket.AF_INET6
    raddr_val = None
    out_dir = None
    hosts = None
    opts, _ = getopt.getopt(sys.argv[1:], 'vr:s:', ['sslog_interval=',
                                                    'ip_mode=',
                                                    'out_dir=',
                                                    'hosts='])
    for opt, val in opts:
        if opt == '-v':
            continue
        elif opt == '-r':
            raddr_val = val
        elif opt == '-s':
            saddrs = val.split(',')
        elif opt == '--out_dir':
            out_dir = os.path.abspath(os.path.expanduser(val))
        elif opt == '--sslog_interval':
            sslog_interval = float(val)
        elif opt == '--ip_mode':
            key = int(val)
            assert key in ip_modes, 'ip_mode must be in %s' % str(
                ip_modes.keys())
            ip_mode = ip_modes[key]
        elif opt == '--hosts':
            hosts = os.path.abspath(os.path.expanduser(val))
        else:
            print_usage()
            return -1

    log.setup_logging(opts)
    assert out_dir is not None, 'Missing output directory'
    assert raddr_val is not None, 'Missing receiver address.'

    if hosts is not None:
        ip_map = parse_ip_map(hosts)
        LOG.info('IP map: %s', ip_map)
    else:
        ip_map = {}
        LOG.info('No hosts provided to orchestrator.')

    raddr = _replace_host_with_ip(raddr_val, 3, ip_mode, ip_map)
    cfgs = _load_configs()
    rproxy = _create_proxy_with_retry('http://%s/' % (raddr), 10)

    sproxies = []
    for addr in saddrs:
        addr = _replace_host_with_ip(addr, 3, ip_mode, ip_map)
        sproxy = _create_proxy_with_retry('http://%s/' % (addr), 10)
        receiver = ':'.join(raddr.split(':')[:-1])
        sender = ':'.join(addr.split(':')[:-1])
        sproxy.register_receiver(receiver)
        rproxy.register_sender(sender)
        sproxies.append((addr, sproxy))

    for i, cfg in enumerate(cfgs):
        for exp in cfg.experiments():
            out_dir_rel = os.path.join(str(i), exp.get_dir_name())
            _run_experiment(exp, out_dir, out_dir_rel, rproxy, sproxies,
                            sslog_interval)
    return 0


if __name__ == '__main__':
    sys.exit(main())
