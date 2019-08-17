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

"""Run transperf's sender."""

import calendar
import datetime
import getopt
import logging
import os
import re
import shutil
import SimpleXMLRPCServer
import socket
import SocketServer
import sys
import threading
import time

import transperf
from transperf import ip_modes
from transperf import listen_addrs
from transperf import log
from transperf import parse_ip_map
from transperf import path
from transperf import shell

LOG = logging.getLogger('transperf/send')


class Sender(object):
    """Represents a sender.
    """

    def __init__(self, iface_cfg, singlesrv_mode, ip_mode, save_pcap,
                 save_kern_debug, hosts):
        self.__singlesrv_mode = singlesrv_mode
        self.__done = True
        self.__conns = []
        self.__cmds = []
        self.__run_thread = None
        self.__ip_mode = ip_mode
        hostname = socket.gethostname()
        if hosts is not None:
            self.__ip_map = parse_ip_map(hosts)
        else:
            self.__ip_map = {}
            LOG.info('No hosts file provided, skip parsing ip map.')
        if singlesrv_mode:
            assert self.__ip_map
            assert hostname in self.__ip_map
        LOG.info('IP Address map is: %s', str(self.__ip_map))
        self.__ip_addr = (self.__ip_map[hostname]
                          if hostname in self.__ip_map
                          else socket.getaddrinfo(
                              socket.gethostname(), 0, self.__ip_mode,
                              socket.SOCK_STREAM,
                              socket.IPPROTO_TCP)[0][4][0])
        LOG.info('IPAddr: %s', self.__ip_addr)
        self.__first_port = -1
        self.__recv = None
        self.__phys_ifaces = []
        self.__set_ifaces(iface_cfg)
        self.__ss_interval_second = 0.1
        self.__save_pcap = save_pcap
        self.__save_kern_debug = save_kern_debug

        if path.tc():
            shell.run('chmod a+x %s' % path.tc())
        if path.netperf():
            shell.run('chmod a+x %s' % path.netperf())
        if path.netserver():
            shell.run('chmod a+x %s' % path.netserver())

    def __cc_parameters_path(self, cc):
        """Returns /sys/ path for the parameters for the given cc algorithm."""
        return '/sys/module/tcp_%s/parameters' % cc

    def __set_ifaces(self, iface_cfg):
        phys_ifaces = iface_cfg['ifaces']
        LOG.info('Set interfaces for sender: phys: %s', phys_ifaces)
        self.__do_set_ifaces(phys_ifaces)

    def __do_set_ifaces(self, phys_iface_matches):
        """Sets physical interfaces.

        Returns:
            void

        Args:
            phys_iface_matches: A list of match strings describing the
            physical interfaces. Any string prefixed with "match:" specifies a
            regex as the suffix. All other strings are exact matches.
        """
        exact_matches = set([match for match in phys_iface_matches
                             if not match.startswith('regex:')])
        regexes = set([match[len('regex:'):] for match in phys_iface_matches
                       if match.startswith('regex:')])
        regexes = [re.compile(rgx) for rgx in regexes]

        self.__phys_ifaces = []
        all_ifaces = shell.list_ifaces()

        for iface in all_ifaces:
            # Test with every match; if iface has >= 1 hit, accept it.
            # Exact match?
            if iface in exact_matches:
                self.__phys_ifaces.append(iface)
                continue
            # Test with every regex.
            for rgx in regexes:
                if rgx.match(iface) is not None:
                    self.__phys_ifaces.append(iface)
                    continue

        # Sort for ease of debugging/inspection.
        self.__phys_ifaces.sort()
        LOG.info('Got interfaces: %s', self.__phys_ifaces)

    def get_all_ifaces(self):
        """Returns all non-ifb interfaces, physical or bonded, for this node.

        Returns:
            A list of interfaces.
        """
        return self.__phys_ifaces

    def ping(self):
        """Test procedure that returns 0.

           Used by client to check if remote is online.
        Returns:
            Always 0.
        """
        return 0

    def reset(self, cmd):
        """Resets the sender.

        Stops the sender thread, resets all the output directories, and kills
        netperf and tcpdump processes.

        Args:
            cmd: The command to run before starting an experiment.
        """
        self.maybe_join()

        if os.path.exists(path.get_tmp_dir()):
            shutil.rmtree(path.get_tmp_dir())
        os.makedirs(path.get_tmp_dir())

        for tool in transperf.TOOLS.values():
            for binary in tool.binaries:
                shell.run('pkill %s' % binary)
        shell.run('killall -q tcpdump')

        for iface in self.get_all_ifaces():
            shell.run('%s qdisc del dev %s root' % (path.tc(), iface))

        if cmd:
            shell.run(cmd)

    def set_ss(self, interval):
        if interval > 0:
            self.__ss_interval_second = interval
        else:
            self.__ss_interval_second = 0

    def set_cmds(self, cmd_list):
        """Set the command to run on the sender machine.

        This method is called by RPC.

        Args:
            cmd_list: List of sender commands.
        """
        LOG.debug('original machine_cmds_list:\n%s', cmd_list)
        resolved_cmd_list = path.resolve_cmds_path(cmd_list,
                                                   self.__singlesrv_mode)
        LOG.debug('resolved machine_cmds_list:\n%s', resolved_cmd_list)
        self.__cmds = [transperf.machine_cmd(cmd=c[0], start=c[1])
                       for c in resolved_cmd_list]

    def set_conns(self, conn_list, first_port):
        """Sets the connections of this sender.

        This method is called by RPC.

        Args:
            conn_list: List of connections.
            first_port: The first port this sender should use. Next ports
                        are allocated continuously.
        """
        tuple_to_burst = lambda t: transperf.burst(wait=t[0], rounds=t[1],
                                                   repeat=t[2], req=t[3],
                                                   res=t[4]) if t else None
        self.__conns = [transperf.conn(cc=c[0], num=c[1], start=c[2], dur=c[3],
                                       size=c[4], burst=tuple_to_burst(c[5]),
                                       params=c[6], upload=c[7], tool=c[8])
                        for c in conn_list]
        self.__conns.sort(key=lambda c: c.start)
        LOG.debug('sender on %s: connections are: %s',
                  socket.gethostname(),
                  ','.join([str(c) for c in self.__conns]))
        self.__first_port = first_port
        probed = {'cubic': True, 'reno': True}
        for c in self.__conns:
            if probed.get(c.cc):
                continue
            probed[c.cc] = True
            shell.run('rmmod tcp_%s' % c.cc)
            shell.run('modprobe tcp_%s' % c.cc)

            if not c.params:
                continue

            for p in c.params.split(','):
                p = p.strip()
                if not p:
                    continue
                k, v = p.split('=')
                params_dir = self.__cc_parameters_path(c.cc)
                try:
                    f = open('%s/%s' % (params_dir, k), 'w')
                    f.write(v)
                    f.close()
                    LOG.info('set parameter %s:%s to %s', c.cc, k, v)
                except IOError:
                    # Rather than crashing, warn user in log, ignore the
                    # invalid parameter, and continue.
                    LOG.warn('attempting to set invalid parameter %s:%s to %s',
                             c.cc, k, v)

    def register_receiver(self, addr):
        """Registers the receiver address."""
        self.__recv = addr

    def __launch_ss(self, dur, log_path):
        """Run ss command and append log to file.

        Args:
            dur: The duration of the experiment.
            log_path: The path of log file.
        """
        t0 = time.time()
        t = t0
        port_cnt = sum([c.num for c in self.__conns])
        with open(log_path, 'w') as f:
            f.truncate()
        ss_ip = '[%s]' if self.__ip_mode == socket.AF_INET6 else '%s'
        ss_ip %= self.__recv
        ss_cmd = 'ss -tin "dport >= :%d and dport < :%d and dst %s" >> %s' % (
            self.__first_port, self.__first_port + port_cnt, ss_ip,
            log_path,)
        while t < t0 + dur:
            with open(log_path, 'a') as f:
                f.write('# %f\n' % (time.time(),))
            shell.run(ss_cmd)
            t += self.__ss_interval_second
            to_sleep = t - time.time()
            if to_sleep > 0:
                time.sleep(to_sleep)

    def launch_ss(self, dur):
        if self.__ss_interval_second == 0:
            return None, None
        log_path = os.path.join(path.get_tmp_dir(), 'ss.log')
        t = threading.Thread(target=self.__launch_ss,
                             args=(dur, log_path))
        t.start()
        return t, log_path

    def run(self, start_ts, dur, out_dir_rel):
        """Starts the thread that runs the experiment."""
        out_dir = os.path.join(path.get_exp_out_dir(), out_dir_rel)
        self.__run_thread = threading.Thread(target=self.__do_run,
                                             args=(start_ts, dur, out_dir,))
        self.__run_thread.start()

    def __do_run(self, start_ts, dur, out_dir):
        """Runs the experiment.

        Args:
            start_ts: When to start the experiment.
            dur: The duration of the experiment.
            out_dir: The output directory.
        """
        # We wait for 1 second in netperf to establish the control channel.
        dur += 1

        tcpdump_procs, pcap_files = self.__launch_tcpdump()
        self.__truncate_log()

        now = calendar.timegm(datetime.datetime.utcnow().utctimetuple())
        if now < start_ts:
            LOG.debug('sleeping for %s seconds', start_ts - now)
            time.sleep(start_ts - now)

        LOG.info('starting at %s', datetime.datetime.now())
        ss_thread, ss_log_path = self.launch_ss(dur)
        wait = 0
        live_conns = []
        port = self.__first_port

        tasks = self.__conns + self.__cmds
        tasks.sort(key=lambda t: t.start)

        for t in tasks:
            if t.start > wait:
                delta = t.start - wait
                # TODO(soheil): This may drift. Use an absolute TS instead?
                LOG.info('sleeping til the next connection for %s seconds',
                         delta)
                time.sleep(delta)
                wait += delta

            if isinstance(t, transperf.Conn):
                LOG.info('starting connection %s', t)
                n = t.num
                while n:
                    # Make sure the duration of netperf is always 1+ seconds.
                    cmd = t.tool.sender_cmd(t, self.__recv, port,
                                            max(1, dur - wait), self.__ip_addr)
                    LOG.info('running %s', cmd)
                    np_proc = shell.bg(cmd)
                    live_conns.append((t, np_proc, port, t.tool))
                    port += 1
                    n -= 1
            elif isinstance(t, transperf.MachineCommand):
                shell.bg(t.cmd)

        # Wait until the end of the experiment.
        if wait < dur:
            time.sleep(dur - wait)
        ss_thread.join()

        # Collect results.
        LOG.info('saving results in %s', out_dir)
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir)
        os.makedirs(out_dir)

        # Kill all the tool processes and collect their outputs.
        conn_infos = ''
        tool_stats = ''
        for conn, np_proc, port, tool in live_conns:
            out, err, _ = shell.wait(np_proc)
            if err:
                # TODO(soheil): cleanup the output directories.
                LOG.error('error in netperf of %s: %s', conn, err)
            throughput = tool.throughput(out)
            tool_stats += '%s of %s:\n%s\n' % (tool, conn, out)
            conn_infos += '%d=%s,%s,%s,%s,%s,%s,%s\n' % (port,
                                                         self.__ip_addr,
                                                         conn.tool.name(),
                                                         conn.cc,
                                                         conn.start,
                                                         conn.dur,
                                                         throughput,
                                                         conn.params)

        LOG.debug('experiment successfully concluded')

        npf = open(os.path.join(out_dir, 'tool.out'), 'w')
        npf.write(tool_stats)
        npf.close()

        cif = open(os.path.join(out_dir, 'conn.info'), 'w')
        cif.write(conn_infos)
        cif.close()

        if ss_log_path:
            shutil.move(ss_log_path, out_dir)

        # Save tcpdump.
        time.sleep(1)
        for proc in tcpdump_procs:
            shell.terminate(proc)
        for f in pcap_files:
            shutil.move(f, out_dir)

        # Save sysctl.
        mod_params = ''
        for cc in set([c.cc for c in self.__conns]):
            params_dir = self.__cc_parameters_path(cc)
            mod_params += shell.run(
                'grep . %s/*' % params_dir)[0]
            mod_params += '\n'
        modf = open(os.path.join(out_dir, 'mod.out'), 'w')
        modf.write(mod_params)
        modf.close()

        sysctl = shell.run('sysctl -a')[0]
        sysf = open(os.path.join(out_dir, 'sys.out'), 'w')
        sysf.write(sysctl)
        sysf.close()

        # Save kernel debug logs if commanded to do so.
        if self.__save_kern_debug:
            self.__save_kernel_debug_logs(out_dir)
        else:
            LOG.info('Not saving kernel debug log per user request.')


    def __save_kernel_debug_logs(self, out_dir):
        """Save kernel debug log file for this sender.

        Returns:
            void

        Args:
            out_dir: The output directory.
        """
        LOG.info('Saving kernel debug logs to dir for ports: %s: %s',
                 str(self.__ports), out_dir)
        klog_in = open('/var/log/kern.log', 'r')
        lines = []
        for l in klog_in:
            for port in self.__ports():
                if l.find(':%d' % port) != -1:
                    lines.append(l)
                    break
        LOG.info('Total: %d lines for kern-debug.log', len(lines))
        klog_out = open(os.path.join(out_dir, 'kern-debug.log'), 'w')
        klog_out.writelines(lines)
        klog_out.close()

    def maybe_join(self):
        """Joins the receiver if it is running."""
        if not self.__run_thread:
            return
        LOG.info('waiting for sender thread to stop')
        self.__run_thread.join()
        self.__run_thread = None

    def __ports(self):
        """Yeilds all the ports to be used by this sender."""
        cnt = sum([c.num for c in self.__conns])
        for port in xrange(self.__first_port, self.__first_port + cnt):
            yield port

    def __truncate_log(self):
        """Truncates the kern-debug.log file."""
        LOG.info('Truncating kernel debug log!')
        logf = open('/var/log/kern.log', 'w')
        logf.truncate()
        logf.close()

    def __launch_tcpdump(self):
        """Launches the tcpdump process.

        We launch two processes that captures all packets on the sender's
        port range on all ethXX interfaces.

        Returns:
            The list of tcpdump procs and the tcpdump output paths.
        """
        if not self.__save_pcap:
            LOG.info('Not saving pcap info per user request.')
            return ([], [])

        # tcp port 1 or tcp port 2 ...
        ports = ['port %d' % port for port in self.__ports()]
        ports = ' or '.join(ports)

        ifaces = self.get_all_ifaces()

        out_paths = []
        procs = []
        for iface in ifaces:
            out_path = os.path.join(path.get_tmp_dir(), iface + '.pcap')
            tcpdump_cmd = 'tcpdump -s128 -w %s -i %s "host %s and (%s)"' % (
                out_path, iface, self.__recv, ports)
            procs.append(shell.bg(tcpdump_cmd))
            out_paths.append(out_path)
        return (procs, out_paths)

    def listen(self, addr):
        """Runs an XML RPC server listening on the given address."""
        if not self.__done:
            raise RuntimeError('server is already running')

        self.__done = False
        # SimpleXMLRPCServer, by default, is IPv4 only. So we do some surgery.
        SocketServer.TCPServer.address_family = self.__ip_mode
        server = SimpleXMLRPCServer.SimpleXMLRPCServer(addr, allow_none=True)
        server.register_instance(self)
        while not self.__done:
            server.handle_request()


def print_usage():
    """Prints how to use send.py."""
    print """./send.py [options]

options:
    -v: verbose output.
    -p: listening port.
    -n: the (optional) name of the node for singleserver operation.
    -s: invoke in singleserver mode.
    --ifacecfg=: Optional interface config file."""


def main():
    ip_mode = socket.AF_INET6

    opts, _ = getopt.getopt(sys.argv[1:], 'vp:n:s',
                            ['ifacecfg=', 'ip_mode=',
                             'no_pcap', 'no_kern_debug',
                             'hosts='])
    listenport = 6324
    node = None  # Optional; None means we use InterfaceConfig.default_cfg.
    ifacecfg = None
    singlesrv_mode = False
    save_pcap = True
    save_kern_debug = True
    hosts = None

    for opt, val in opts:
        if opt == '-v':
            continue
        elif opt == '-p':
            listenport = int(val)
        elif opt == '--ifacecfg':
            ifacecfg = os.path.abspath(os.path.expanduser(val))
        elif opt == '-n':
            node = val
        elif opt == '-s':
            singlesrv_mode = True
        elif opt == '--ip_mode':
            key = int(val)
            assert key in ip_modes, 'ip_mode must be in %s' % str(
                ip_modes.keys())
            ip_mode = ip_modes[key]
        elif opt == '--no_pcap':
            save_pcap = False
        elif opt == '--no_kern_debug':
            save_kern_debug = False
        elif opt == '--hosts':
            hosts = os.path.abspath(os.path.expanduser(val))
        else:
            print_usage()
            return -1

    log.setup_logging(opts)
    addr = (listen_addrs[ip_mode], listenport)

    LOG.info('starting sender on %s:%d', addr[0], addr[1])
    LOG.info('socket.gethostname() = %s', socket.gethostname())
    ifaces = transperf.InterfaceConfig.default_cfg
    if ifacecfg is not None:
        ifaces = transperf.InterfaceConfig.node_config(ifacecfg, node, LOG)

    sender = Sender(ifaces, singlesrv_mode, ip_mode, save_pcap, save_kern_debug,
                    hosts)
    sender.listen(addr)
    LOG.info('sender stopped')
    return 0

if __name__ == '__main__':
    sys.exit(main())
