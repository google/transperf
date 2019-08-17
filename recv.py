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

"""This module includes the receiver-side functions of transperf."""

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
from transperf import bits
from transperf import ip_modes
from transperf import listen_addrs
from transperf import log
from transperf import parse_ip_map
from transperf import path
from transperf import shell

LOG = logging.getLogger('transperf/receiver')

# Maximum buffer size possible on netem.
INFINITY_BUFFER = 1 << 31


class SenderInfo(object):
    """Represents what a receiver knows about a sender.

    Attributes:
        ip: Sender's ip address.
        ports: Ports for sender.
        bws: Bandwidths for sender.
        rtts: RTT values for sender.
    """

    def __init__(self, ip):
        """Initializes the sender info with sender's ip address."""
        self.ip = ip
        self.ports = []
        self.bws = []
        self.rtts = []


class Receiver(object):
    """Implements the receiver functionalities."""
    tc_protocol_map = {
        socket.AF_INET: 'ip',
        socket.AF_INET6: 'ipv6',
    }
    tc_match_map = {
        socket.AF_INET: 'ip',
        socket.AF_INET6: 'ip6',
    }

    def __init__(self, iface_cfg, singlesrv_mode, ip_mode, hosts):
        self.__singlesrv_mode = singlesrv_mode
        self.__senders = []
        self.__done = True
        self.__run_thread = None
        self.__bws = None
        self.__slot = None
        self.__policer = None
        self.__buf = 0
        self.__loss = 0
        self.__oloss = 0
        self.__port_range = None
        self.__port_to_addr = dict()
        self.__cmds = []
        if hosts is not None:
            self.__ip_map = parse_ip_map(hosts)
        else:
            self.__ip_map = {}
            LOG.info('No hosts file provided, skip parsing ip map.')
        if singlesrv_mode:
            assert self.__ip_map
        self.__ip_mode = ip_mode
        self.__proto = Receiver.tc_protocol_map[ip_mode]
        self.__match = Receiver.tc_match_map[ip_mode]

        self.__prev_lro = None
        self.__prev_gro = None
        self.__bond_iface = None
        self.__phys_ifaces = []
        self.__set_ifaces(iface_cfg)

        self.setup_ifb(not self.__singlesrv_mode)
        if path.tc():
            shell.run('chmod a+x %s' % path.tc())
        if path.netperf():
            shell.run('chmod a+x %s' % path.netperf())
        if path.netserver():
            shell.run('chmod a+x %s' % path.netserver())

    def setup_ifb(self, do_modprobe):
        """Sets up the ifb interfaces.

        Args:
            do_modprobe: Whether we should unload/reload the ifb module. We only
                         do so if we're running in baremetal/normal mode. In
                         singleserver mode, virtsetup.py handles it.
        """
        ifaces = self.get_all_ifaces()
        if do_modprobe:
            shell.run('rmmod ifb')
            shell.run('modprobe ifb numifbs=%s' % len(ifaces))

        for iface in ifaces:
            iface_ifb = self.get_ifb_for_iface(iface)
            shell.run('ip link set dev %s up' % iface_ifb)
            shell.run('ifconfig %s txqueuelen 128000' % iface_ifb)

    def set_receive_offload(self, lro=False, gro=False):
        """Sets LRO and GRO.

        Args:
            lro: Whether to enable LRO.
            gro: Whether to enable GRO.
        """
        lro_str = 'on' if lro else 'off'
        gro_str = 'on' if gro else 'off'
        for iface in self.get_all_ifaces():
            LOG.debug('set_receive_offload: ethtool -K %s gro %s lro %s',
                      iface, gro_str, lro_str)
            shell.run('ethtool -K %s gro %s' % (iface, gro_str))
            shell.run('ethtool -K %s lro %s' % (iface, lro_str))

    def __set_ifaces(self, iface_cfg):
        bond_iface = iface_cfg['bond']
        phys_ifaces = iface_cfg['ifaces']
        LOG.info('Set interfaces for receiver: bond: %s phys: %s',
                 bond_iface, phys_ifaces)
        self.__do_set_ifaces(bond_iface, phys_ifaces)

    def __do_set_ifaces(self, bond_iface, phys_iface_matches):
        """Sets bond and physical interfaces.

        Returns:
            void

        Args:
            bond_iface: The bond interface.
            phys_iface_matches: A list of match strings describing the
            physical interfaces. Any string prefixed with "match:" specifies a
            regex as the suffix. All other strings are exact matches.
        """
        exact_matches = set([match for match in phys_iface_matches
                             if not match.startswith('regex:')])
        regexes = set([match[len('regex:'):] for match in phys_iface_matches
                       if match.startswith('regex:')])
        regexes = [re.compile(rgx) for rgx in regexes]

        self.__bond_iface = bond_iface
        self.__phys_ifaces = []
        all_ifaces = shell.list_ifaces()

        for iface in all_ifaces:
            # Skip bond interface
            if iface == self.__bond_iface:
                continue
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
        LOG.info('Got interfaces: bond: %s physical: %s',
                 self.__bond_iface, self.__phys_ifaces)

    def get_all_ifaces(self):
        """Returns all non-ifb interfaces, physical or bonded, for this node.

        Returns:
            A list of interfaces.
        """
        ifaces = [self.__bond_iface] + self.__phys_ifaces
        LOG.debug('get_all_ifaces: Returning %s', str(ifaces))
        return ifaces

    def get_physical_ifaces(self):
        return self.__phys_ifaces

    def get_bond_iface(self):
        """Returns the bond interface for this node.

        Returns:
            The bond interface.
        """
        return self.__bond_iface

    @staticmethod
    def get_ifb_for_iface(iface):
        """Returns the ifb for this interface.

        Args:
            iface: The interface for which we want the corresponding ifb.

        Returns:
            The ifb interface.
        """
        ifbpfx = 'ifb'
        rgx = re.compile('^%s$' % transperf.InterfaceConfig.ETHX_REGEX)
        # Special case ethX to match existing behaviour
        if rgx.match(iface) is not None:
            return '%s%d' % (ifbpfx, int(iface[len('eth'):]))
        # Else just prefix with ifb. NB: iface name length limits.
        IFNAMSIZ = 16
        ifblen = len(ifbpfx) + len(iface)
        if ifblen > IFNAMSIZ:
            LOG.warning('Getting ifb for dev %s: IFNAMSIZ exceeded (%d > %d)',
                        iface, ifblen, IFNAMSIZ)
        return 'ifb%s' % iface

    def ping(self):
        """Test procedure that returns 0.

           Used by client to check if remote is online.
        Returns:
            Always 0.
        """
        return 0

    def reset(self, cmd):
        """Cleans all the settings and reinitializes the receiver.

        Args:
            cmd: The command to run before starting an experiment.
        """
        for tool in transperf.TOOLS.values():
            for binary in tool.binaries:
                shell.run('pkill %s' % binary)
        shell.run('killall -q tcpdump')
        shell.run(path.tc() + ' qdisc show')

        for iface in self.get_all_ifaces():
            iface_ifb = self.get_ifb_for_iface(iface)
            for dev in [iface, iface_ifb]:
                shell.run(path.tc() + ' filter del dev ' + dev +
                          ' pref 10 parent ffff:')
                shell.run(path.tc() + ' filter del dev ' + dev + ' pref 10')
                shell.run(path.tc() + ' qdisc del dev ' + dev + ' ingress')
                shell.run(path.tc() + ' qdisc del dev ' + dev + ' clsact')
                shell.run(path.tc() + ' qdisc del dev ' + dev + ' root')

        if cmd:
            shell.run(cmd)

        self.__bws = None
        self.__policer = None
        self.__buf = 0
        self.__loss = 0
        self.__oloss = 0
        self.__port_range = None
        self.__port_to_addr = dict()

    def register_sender(self, hostip):
        """Register a sender from ip and allocate a new port.

        Args:
            hostip: The ip of the sender.

        Returns:
            A tuple of the sender's index and its allocated port.
        """
        index = len(self.__senders)
        ip = socket.getaddrinfo(hostip, 0, self.__ip_mode,
                                socket.SOCK_STREAM,
                                socket.IPPROTO_TCP)[0][4][0]
        self.__senders.append(SenderInfo(ip))
        return index

    def set_sender_info(self, sender, ports, rtts):
        """Sets the sender's port and rtt information.

        Args:
            sender: The index of the sender.
            ports: The list of ports of this sender.
            rtts: The time-series of the rtts of this sender.
        """
        LOG.debug('received sender %d info: ports=%s, rtts=%s', sender, ports,
                  rtts)
        info = self.__senders[sender]
        info.ports = ports
        info.rtts = [transperf.RTT.deserialize(t) for t in rtts]

    def setup_ifaces(self, nsenders):
        """Configures the network interfaces.

        Returns:
            True if config changed, or False.

        Args:
            nsenders: Number of senders used in this experiment.
        """
        # TODO(soheil): In some cases, we need to enable either LRO or GRO but
        #               not both. Implement such cases and also add the
        #               appropriate parameters to control it in the
        #               configuration files.
        if self.__qdisc_noop(nsenders):
            lro = gro = True
        else:
            lro = gro = False

        if self.__prev_lro == lro and self.__prev_gro == gro:
            return False

        self.set_receive_offload(lro=lro, gro=gro)
        self.__prev_gro = gro
        self.__prev_lro = lro
        return True

    def bw_policers(self):
        """Returns the combined time-series of bandwidth and policers values.

        To install policer filters we need to know the bandwidth.
        """
        if not self.__policer:
            return None

        bw_policers = []

        bw_idx = 0
        cur_bw = self.__bws[bw_idx]
        bw_dur = cur_bw.dur

        po_idx = 0
        cur_po = self.__policer[po_idx]
        po_dur = cur_po.dur

        while po_idx < len(self.__policer) and bw_idx < len(self.__bws):
            # If the BW is valid for ever, append the remaining policers and
            # break.
            if bw_dur == 0:
                bw_policers.append((cur_bw, cur_po, po_dur))
                for p in self.__policer[po_idx+1:]:
                    bw_policers.append((cur_bw, p, p.dur))
                break

            # If the policer is valid for-ever (which also means it is
            # the last policer) just append the remaining BWs and break.
            if po_dur == 0:
                bw_policers.append((cur_bw, cur_po, bw_dur))
                for w in self.__bws[bw_idx+1:]:
                    bw_policers.append((w, cur_po, w.dur))
                break

            # Append an entry with the minimum duration of the two.
            min_dur = min(po_dur, bw_dur)
            bw_policers.append((cur_bw, cur_po, min_dur))
            po_dur -= min_dur
            bw_dur -= min_dur

            # If expired, use the next policer.
            if po_dur == 0:
                po_idx += 1
                cur_po = self.__policer[po_idx]
                po_dur = cur_po.dur

            # If expired, used the next bandwidth.
            if bw_dur == 0:
                bw_idx += 1
                cur_bw = self.__bws[bw_idx]
                bw_dur = cur_bw.dur

        return bw_policers

    def __qdisc_noop(self, nsenders):
        """Returns whether the experiment needs no Qdiscs.

        Args:
            nsenders: The number of senders valid for this experiment.
        """
        if not self.__bw_qdisc_noop():
            return False

        for s in self.__senders[:nsenders]:
            for rtt in s.rtts:
                if rtt:
                    return False

        return (not self.__policer and not self.__loss and not self.__oloss and
                not self.__buf)

    def __bw_qdisc_noop(self):
        """Returns whether we need no qdisc to emulate the bandwidth."""
        if self.__buf:
            return False

        for bw in self.__bws:
            if bw:
                return False

        return True

    def __bw_cmds(self):
        """Returns the tc commands to enforce BWs.

        Raises:
            RuntimeError: When encountered a critial error.
        """
        cmds = []
        abs_time = 0
        for i, bw in enumerate(self.__bws):
            if not bw and not self.__buf:
                continue

            tc_cmd = 'add' if i == 0 else 'change'
            loss = self.__loss
            oloss = self.__oloss
            in_slot = self.__slot.in_slot if self.__slot else None
            out_slot = self.__slot.out_slot if self.__slot else None

            # Here we install a 100gbps, and then enforce the BW
            # in netem where we also enforce buffer sizes.
            bond_iface = self.get_bond_iface()
            bond_ifb = self.get_ifb_for_iface(bond_iface)
            cmd = ('%s class %s dev %s parent 1: '
                   'classid 1:1 htb rate 100Gbit') % (path.tc(), tc_cmd,
                                                      bond_iface)
            cmds.append((cmd, abs_time))

            cmd = ('%s class %s dev %s parent 1: '
                   'classid 1:1 htb rate 100Gbit') % (path.tc(), tc_cmd,
                                                      bond_ifb)
            cmds.append((cmd, abs_time))

            if not self.__buf:
                raise RuntimeError(
                    'netem with undefined or zero limit. '
                    'Check if buf is misisng or 0 but bw,loss>0 in cfg.')

            cmd = ('%s qdisc %s dev %s parent 1:1 '
                   'handle 11: netem rate %sMbit limit %s %s %s') % (
                       path.tc(), tc_cmd, bond_iface, bw.uplink, self.__buf,
                       'loss %s' % oloss if oloss > 0 else '',
                       out_slot.netem_str() if out_slot else '')
            cmds.append((cmd, abs_time))

            cmd = ('%s qdisc %s dev %s parent 1:1 '
                   'handle 11: netem rate %sMbit limit %s %s %s') % (
                       path.tc(), tc_cmd, bond_ifb, bw.downlink, self.__buf,
                       'loss %s' % loss if loss > 0 else '',
                       in_slot.netem_str() if in_slot else '')
            cmds.append((cmd, abs_time))

            abs_time += bw.dur
        return cmds

    def __rtt_cmds(self, nsenders):
        """Returns the commands to setup RTT qdiscs."""

        # eth0 and ifb0 (the bonding interfaces) are only used for enforcing
        # bandwidth, so we should not use them to install delay qdiscs.
        phy_ifaces = self.get_physical_ifaces()

        cmds = []
        for i, s in enumerate(self.__senders[:nsenders]):
            LOG.debug('generating commands for sender %d', i)
            class_id, handle = self.__sender_class_handle(i)

            for iface in phy_ifaces:
                cmd = ('%s class add dev %s parent 1: '
                       'classid 1:%s htb rate 100Gbit') % (path.tc(), iface,
                                                           class_id)
                cmds.append((cmd, 0))

                iface_ifb = self.get_ifb_for_iface(iface)
                cmd = ('%s class add dev %s parent 1: '
                       'classid 1:%s htb rate 100Gbit') % (path.tc(), iface_ifb,
                                                           class_id)
                cmds.append((cmd, 0))

            abs_time = 0
            for j, rtt in enumerate(s.rtts):
                tc_cmd = 'add' if j == 0 else 'change'

                # Format the delay model descriptions.  If we have
                # distributions for both directions, then use that info
                # exactly.  Otherwise, compute a mean value for any
                # direction without a distribution.  With no distributions,
                # just split rtt between the two directions.
                irtt = rtt.val / 2
                ortt = rtt.val - irtt
                ivar = rtt.var
                ovar = rtt.out_var

                if rtt.in_dist and not rtt.out_dist:
                    ortt = rtt.val - rtt.in_dist.mean
                if rtt.out_dist and not rtt.in_dist:
                    irtt = rtt.val - rtt.out_dist.mean

                def fmt_delay(dist, mean, var):
                    if dist:
                        return '%sms %sms distribution %s' % (
                            dist.mean, dist.var, dist.netem_dist_name())
                    else:
                        var_spec = (' %sms' % var) if var else ''
                        return ('%sms' % mean) + var_spec

                odelay = fmt_delay(rtt.out_dist, ortt, ovar)
                idelay = fmt_delay(rtt.in_dist, irtt, ivar)

                # TODO(soheil): Actually, we don't update the BW when RTT
                #               changes. It's only the other way around and only
                #               because of buffer sizing. Maybe move into its
                #               own loop.
                for iface in phy_ifaces:
                    cmd = ('%s qdisc %s dev %s parent 1:%s '
                           'handle %s: netem limit %s delay %s') % (
                               path.tc(), tc_cmd, iface, class_id, handle,
                               INFINITY_BUFFER, odelay)
                    cmds.append((cmd, abs_time))

                    iface_ifb = self.get_ifb_for_iface(iface)
                    cmd = ('%s qdisc %s dev %s parent 1:%s '
                           'handle %s: netem limit %s delay %s') % (
                               path.tc(), tc_cmd, iface_ifb, class_id, handle,
                               INFINITY_BUFFER, idelay)
                    cmds.append((cmd, abs_time))

                abs_time += rtt.dur
        return cmds

    def __sender_class_handle(self, i):
        """Returns the class and qdisc handle ids for the sender."""
        return ('%s0' % (i+1), '%s1' % (i+1))

    def __filter_cmds(self, nsenders):
        """Returns the commands to setup flow filters using tc."""
        # TODO(arjunroy): There is a regression for IPv6, possibly having to do
        #                 with filter matching for ACK packets. Specifically,
        #                 if we run netperf with a TCP_STREAM test, packets are
        #                 being delayed correctly upon reception via IFB but no
        #                 packets are hitting the outbound delay rule. Thus, we
        #                 see an RTT of X/2 when we configure a link RTT of X.
        #                 On the other hand, for a TCP_RR test, we see hits on
        #                 the outbound delay rule and the measured RTT is X as
        #                 desired. Also, in IPv4, both TCP_STREAM and TCP_RR
        #                 work. Not sure if this is transperf's fault, or an
        #                 issue within linux/tc.
        cmds = []
        bond_iface = self.get_bond_iface()
        bond_ifb = self.get_ifb_for_iface(bond_iface)

        for i, s in enumerate(self.__senders[:nsenders]):
            LOG.debug('generating commands for sender %d', i)
            class_id, _ = self.__sender_class_handle(i)
            # Add filters.
            for port in xrange(s.ports[0], s.ports[1]):
                cmd = ('{tc} filter add dev {dev} parent 1: '
                       'protocol {proto} pref 10 u32 match {match} dst {ip} '
                       'match {match} dport {port} 0xffff flowid 1:1').format(
                           tc=path.tc(), dev=bond_iface, proto=self.__proto,
                           match=self.__match, ip=s.ip, port=port
                       )
                cmds.append((cmd, 0))

                cmd = ('{tc} filter add dev {dev} parent 1: '
                       'protocol {proto} pref 10 u32 match {match} src {ip} '
                       'match {match} sport {port} 0xffff flowid 1:1').format(
                           tc=path.tc(), dev=bond_ifb, proto=self.__proto,
                           match=self.__match, ip=s.ip, port=port
                       )
                cmds.append((cmd, 0))

                for iface in self.get_all_ifaces():
                    iface_ifb = self.get_ifb_for_iface(iface)
                    cmd = ('{tc} filter add dev {dev} parent 1: '
                           'protocol {proto} pref 10 u32 match {match} dst {ip}'
                           ' match {match} dport {port} 0xffff '
                           'flowid 1:{class_id}').format(
                               tc=path.tc(), dev=iface, proto=self.__proto,
                               match=self.__match, ip=s.ip, port=port,
                               class_id=class_id)
                    cmds.append((cmd, 0))

                    cmd = ('{tc} filter add dev {dev} parent 1: '
                           'protocol {proto} pref 10 u32 match {match} src {ip}'
                           ' match {match} sport {port} 0xffff '
                           'flowid 1:{class_id}').format(
                               tc=path.tc(), dev=iface_ifb, proto=self.__proto,
                               match=self.__match, ip=s.ip, port=port,
                               class_id=class_id)
                    cmds.append((cmd, 0))

                    # If there is a policer, do not add the redirect filter
                    # on eth0. Note that eth1+ can should all have the
                    # redirect filter even if there is a policer.
                    if iface != self.get_bond_iface() or not self.__policer:
                        cmd = ('{tc} filter add dev {dev} parent ffff: '
                               'protocol {proto} pref 10 u32 '
                               'match {match} src {ip} '
                               'match {match} sport {port} 0xffff flowid 1:1 '
                               'action mirred egress '
                               'redirect dev {ifb}').format(
                                   tc=path.tc(), dev=iface, proto=self.__proto,
                                   match=self.__match, ip=s.ip, port=port,
                                   ifb=iface_ifb)
                        cmds.append((cmd, 0))

        return cmds

    def __policer_cmds(self):
        """Returns the tc commands to install policer filters.

        Returns:
            [] if there is no policer config and otherwise returns a list of
            commands along with the time they should run.
        """
        if not self.__policer:
            return []

        bond_iface = self.get_bond_iface()
        bond_ifb = self.get_ifb_for_iface(bond_iface)
        bw_policers = self.bw_policers()
        port = self.__port_range[0]
        mask = 0xFFFF - (self.__port_range[1] - 1)
        abs_time = 0
        cmds = []
        for i, (bw, po, dur) in enumerate(bw_policers):
            # Delete the previous policer filter.
            if i > 0:
                cmd = ('%s filter del dev %s '
                       'parent ffff: protocol %s pref 10 u32 ' % (path.tc(),
                                                                  bond_iface,
                                                                  self.__proto))
                cmds.append((cmd, abs_time))

            burst = ('burst %smb' % po.burst) if po.burst else ''
            cmd = ('%s filter add dev %s parent ffff: '
                   'protocol %s pref 10 u32 match %s sport %d 0x%04X '
                   'flowid 1:1 '
                   'action police rate %sMbit peakrate %sMbit %s '
                   'buffer 100K mtu 66000 conform-exceed drop/pipe '
                   'action mirred egress redirect dev %s') % (
                       path.tc(), bond_iface, self.__proto, self.__match,
                       port, mask, po.bw, bw.downlink,
                       burst, bond_ifb)
            cmds.append((cmd, abs_time))
            abs_time += dur
        return cmds

    def run(self, tools, start_ts, dur, nsenders, out_dir_rel):
        """Starts a thread that runs the experiment at start_ts for dur seconds.

        Args:
            tools: The tools to run as server.
            start_ts: The timestamp of the start time.
            dur: The duration of the experiment in seconds.
            nsenders: Number of senders used in this experiment.
            out_dir_rel: The relative output directory of receiver for this
                         experiment.
        """
        out_dir = os.path.join(path.get_exp_out_dir(), out_dir_rel)
        self.__run_thread = threading.Thread(target=self.__do_run,
                                             args=(tools, start_ts, dur,
                                                   nsenders, out_dir,))
        self.__run_thread.start()

    def __do_run(self, tools, start_ts, dur, nsenders, out_dir):
        """Runs the experiment."""
        self.__servers = []
        till_start_sec = start_ts - calendar.timegm(
            datetime.datetime.utcnow().utctimetuple())

        # Build a set of unique tools and their associated ports.
        tool_to_ports = {}
        for tool, port in zip(tools, self.__port_to_addr.keys()):
            existing = tool_to_ports.setdefault(tool, [])
            existing.append((port, self.__port_to_addr[port]))

        # Have each tool add receiver commands to support the senders.
        for tool, ports in tool_to_ports.iteritems():
            toolobj = transperf.TOOLS[tool]
            toolobj.options_dict['ip_mode'] = (
                '-6' if self.__ip_mode == socket.AF_INET6 else '-4')
            for cmd in transperf.TOOLS[tool].receiver_cmds(ports,
                                                           till_start_sec):
                proc = shell.bg(cmd)
                self.__servers.append(proc)
                if proc.poll():
                    raise RuntimeError('cannot run ' + cmd)

        if not self.__servers:
            raise RuntimeError('no server to run')

        LOG.debug('creating commands')
        if self.__qdisc_noop(nsenders):
            # If there is no RTT, BW, nor Policer, don't install any qdisc.
            cmds = []
        else:
            # Setup root qdiscs.
            for iface in self.get_all_ifaces():
                # Skip setting up eth0 and ifb0, if bandwidth is noop.
                if iface == self.get_bond_iface() and self.__bw_qdisc_noop():
                    continue
                iface_ifb = self.get_ifb_for_iface(iface)
                _, err, _ = shell.run('''
                    %(tc)s qdisc replace dev %(iface)s handle 1: root htb
                    %(tc)s qdisc replace dev %(iface)s handle ffff: ingress
                    %(tc)s class replace dev %(iface)s parent 1: classid 1:1 \
                            htb rate 100Gbit
                    ''' % {
                        'tc': path.tc(),
                        'iface': iface,
                    })
                # Some tc versions print 'Success' to stderr.
                if any(l and l != 'RTNETLINK answers: Success'
                       for l in err.split('\n')):
                    raise RuntimeError('Error in setting up %s: %s' % (iface,
                                                                       err))

                _, err, _ = shell.run('''
                    %(tc)s qdisc replace dev %(iface)s handle 1: root htb
                    %(tc)s class replace dev %(iface)s parent 1: classid 1:1 \
                            htb rate 100Gbit
                    ''' % {
                        'tc': path.tc(),
                        'iface': iface_ifb,
                    })
                if any(l and l != 'RTNETLINK answers: Success'
                       for l in err.split('\n')):
                    raise RuntimeError('Error setting up %s: %s' % (iface_ifb,
                                                                    err))

            # We generate commands and their wait time before starting the loop.
            cmds = self.__cmds
            cmds += self.__bw_cmds()
            cmds += self.__rtt_cmds(nsenders)
            cmds += self.__filter_cmds(nsenders)
            cmds += self.__policer_cmds()

        cmds.sort(key=lambda c: c[1])
        for cmd in cmds:
            LOG.debug('at %s will run %s', cmd[1], cmd[0])

        cmds_at_zero = [cmd for cmd in cmds if not cmd[1]]
        cmds_rest = [cmd for cmd in cmds if cmd[1]]

        # Run all the commands that should be run at 0.
        for cmd in cmds_at_zero:
            shell.run(cmd[0])

        now = calendar.timegm(datetime.datetime.utcnow().utctimetuple())
        sdur = start_ts - now
        LOG.debug('sleeping for %s seconds', sdur)
        if start_ts > now:
            time.sleep(start_ts - now)
        now = 0.0
        # Run the commands that has a later deadline.
        for cmd in cmds_rest:
            if cmd[1] < now:
                LOG.warning('command %s is ran after its deadline', cmd)

            if cmd[1] > now:
                LOG.debug('sleeping from %s til %s', now, cmd[1])
                time.sleep(cmd[1] - now)
                now = cmd[1]

            shell.run(cmd[0])

        end_time = datetime.datetime.utcnow().utctimetuple()
        delta = calendar.timegm(end_time) - start_ts
        if delta < dur:
            time.sleep(dur - delta)

        LOG.info('saving qdisc state in %s', out_dir)
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir)
        os.makedirs(out_dir)

        # Save qdisc stats.
        tcs = '\n'.join([shell.run(path.tc() + ' -d -s -p qdisc show')[0],
                         shell.run(path.tc() + ' -d -s -p class show')[0],
                         shell.run(path.tc() + ' -d -s -p class show')[0],
                         shell.run(path.tc() + ' -d -s -p filter show')[0],
                         shell.run(path.tc() + ' -d -s -p filter show')[0]])
        tcf = open(os.path.join(out_dir, 'tc.out'), 'w')
        tcf.write(tcs)
        tcf.close()

        hostname = socket.gethostname()
        if self.__singlesrv_mode:
            assert hostname in self.__ip_map
        if hostname in self.__ip_map:
            rcv_ip = self.__ip_map[hostname]
        else:
            rcv_ip = socket.getaddrinfo(hostname, 0, self.__ip_mode,
                                        socket.SOCK_STREAM,
                                        socket.IPPROTO_TCP)[0][4][0]
        ipf = open(os.path.join(out_dir, 'recv.info'), 'w')
        ipf.write(rcv_ip)
        ipf.close()

    def set_exp_info(self, bws, buf, loss, out_loss,
                     slot, policer, sender_port_ips, cmds):
        """Sets the experiment information that is shared among all senders.

        Args:
            bws: The time-series of bandwidth values.
            buf: The buffer size.
            loss: The input loss ratio.
            out_loss: The output loss ratio.
            slot: The time slot configuration.
            policer: The time-series of policer values.
            sender_port_ips: Tuples of sender port and ip addresses used for
                             this experiment. The list is sorted by port number,
                             and it is guarantee that the ports are consecutive
                             and the range starts from a power of two.
                             For policers, we match the whole power-of-two
                             range starting from the smallest port.
            cmds: The receiver commands.
        """
        self.__buf = buf
        self.__loss = loss
        self.__oloss = out_loss
        self.__port_range = (sender_port_ips[0][0],
                             bits.next_power_of_two(len(sender_port_ips)))
        self.__port_to_addr = dict(sender_port_ips)
        LOG.debug('original machine_cmds:\n%s', cmds)
        self.__cmds = path.resolve_cmds_path(cmds, self.__singlesrv_mode)
        LOG.debug('resolved machine_cmds:\n%s', self.__cmds)
        self.__slot = None
        if slot:
            self.__slot = transperf.SlotConfig.deserialize(slot)

        if bws:
            self.__bws = [transperf.bw(downlink=w[0], uplink=w[1], dur=w[2])
                          for w in bws]

        if policer:
            self.__policer = [transperf.policer(p[0], p[1], p[2])
                              for p in policer]

    def stop(self):
        """Stops the XML RPC server."""
        self.__done = True

    def listen(self, addr):
        """Starts the RPC server on the addrress.

        Args:
            addr: The tuple of listening address and port.

        Raises:
            RuntimeError: If the server is already running.
        """
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
    """Prints how to use rcvr.py."""
    print '''rcvr.py [options]

options:
    -l: listening address in the form of host:port
    -v: verbose output
    -n: the (optional) name of the node for singleserver operation.
    -s: Operate receiver in singleserver mode.
    --ifacecfg=: Optional interface config file.'''


def main():
    ip_mode = socket.AF_INET6
    opts, _ = getopt.getopt(sys.argv[1:], 'vp:n:s',
                            ['ifacecfg=', 'ip_mode=', 'hosts='])
    listenport = 6324
    node = None  # Optional; None means we use InterfaceConfig.default_cfg.
    ifacecfg = None
    singlesrv_mode = False
    hosts = None

    for opt, val in opts:
        if opt == '-v':
            continue
        elif opt == '-p':
            listenport = int(val)
        elif opt == '-n':
            node = val
        elif opt == '--ifacecfg':
            ifacecfg = os.path.abspath(os.path.expanduser(val))
        elif opt == '-s':
            singlesrv_mode = True
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
    addr = (listen_addrs[ip_mode], listenport)

    LOG.info('starting receiver on %s:%d', addr[0], addr[1])

    ifaces = transperf.InterfaceConfig.default_cfg
    if ifacecfg is not None:
        ifaces = transperf.InterfaceConfig.node_config(ifacecfg, node, LOG)

    Receiver(ifaces, singlesrv_mode, ip_mode, hosts).listen(addr)
    LOG.info('receiver stopped')
    return 0


if __name__ == '__main__':
    sys.exit(main())
