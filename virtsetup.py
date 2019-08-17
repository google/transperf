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

"""Transperf singleserver/local container mode test setup."""

from __future__ import print_function

import argparse
import binascii
import datetime
import exceptions
import inspect
import itertools
import logging
import os
import socket
import struct
import subprocess
import sys
import time

import transperf
from transperf import log
from transperf import path
from transperf import shell
from transperf.recv import Receiver

LOG = logging.getLogger('transperf/containermgr')

"""
Lifecycle for containers:

1. transperf launcher is invoked in singleserver mode, specifying a physical
   host that all containers will be run on and a bridge name on that server.

2. If a bridge already exists by the given name, it is removed.

3. If a netns namespace already exists by the given name, it is removed.
   The name of the netns is identical to the container node name.

4. A new bridge and containers are created. The containers are not hooked up to
   the bridge yet (unless running in demo/standalone container creation mode).

5. The transperf orchestrator (orch.py) runs the provided config files (>=1) and
   all experiments within each config file. For each file:

   i.   Assuming a clean slate of zero enabled bond or 'physical' interfaces in
        a container, and no enabled 'physical' interfaces on the bridge
        (*except* the one providing connectivity to/from the root namespace),
        orch.py invokes container.setup_all_container_interfaces() to connect
        each container to the bridge as specified in the config.
   ii.  All experiments for the config are executed.
   iii. orch.py cleans up the interfaces for this config file
        before moving onto the next.

6. After the config files are all done, transperf leaves the bridge and all
   containers in place for manual inspection if needed. Subsequent invocations
   of transperf will clean up the bridge and containers as in step #1.
"""


def traced(func):
    """Decorator to debug-trace function calls."""
    def wrap(*args, **kwargs):
        bound = inspect.getcallargs(func, *args, **kwargs)
        keys = sorted(bound)
        fmt = ' Traced:\t%s:%d:\t%s(' + '%s=%s, '*len(bound) + ')'
        args_arr = list(itertools.chain(*([(kw, bound[kw]) for kw in keys])))
        rewind = 2
        LOG.debug(fmt, *([Utils.__file__(rewind), Utils.__line__(rewind),
                          func.__name__] + list(args_arr)))
        return func(*args, **kwargs)
    return wrap


class Constants(object):
    """Contains constants used by the transperf container-management module."""
    # Filenames and resources.
    HOSTS_PATH = '/etc/hosts'
    BRDEV_LIST_PATH = '/sys/devices/virtual/net/'
    BOND_MASTERS = '/sys/class/net/bonding_masters'
    BOND_PATH_TEMPLATE = '/sys/class/net/{bond}/bonding'
    NET_NS_PFX = '/var/run/netns'
    DEFAULT_OUTDIR_BASE = '/transperf'
    VIRTUALIZED_PATHS = ['/home', '/home/tmp', '/tmp']

    # Network configuration.
    DEFAULT_BRIDGE = 'br-xperf'
    DEFAULT_NODE_CFG = {
        'bond': 'eth0',
        'ifaces': ['eth1', 'regex:%s' % transperf.InterfaceConfig.ETHX_REGEX,],
        'root_nic_offloads_enabled': True,
        'container_nic_offloads_enabled': True,
    }
    # IPv6 addresses.
    TRANSPERF_SUBNET_ADDR = {socket.AF_INET: '10.255.0.0',
                             socket.AF_INET6: 'fd42:7850:5c06:1::'}
    ROOT_TRANSPERF_ADDR = {socket.AF_INET: '10.255.0.1',
                           socket.AF_INET6: 'fd42:7850:5c06:1::1'}
    TRANSPERF_SUBNET = {socket.AF_INET: 24, socket.AF_INET6: 64}
    # IPv6 addresses.
    ROOT_TRANSPERF_IFACE = {'name': 'xperf0',
                            'address': {
                                socket.AF_INET: '%s/%d' % (
                                    ROOT_TRANSPERF_ADDR[socket.AF_INET],
                                    TRANSPERF_SUBNET[socket.AF_INET]),
                                socket.AF_INET6: '%s/%d' % (
                                    ROOT_TRANSPERF_ADDR[socket.AF_INET6],
                                    TRANSPERF_SUBNET[socket.AF_INET6])},
                            'br-pair': 'br-xperf0'}
    # Bond configuration within containers.
    DEFAULT_BOND_MODE = 2  # balance-xor
    DEFAULT_BOND_XMIT_HASH_POLICY = 'layer3+4'
    # Limiting constants.
    IPV4_BITLEN = 32
    IPV6_BITLEN = 128
    MAX_NODES = {
        socket.AF_INET: 2 ** (IPV4_BITLEN - TRANSPERF_SUBNET[socket.AF_INET]),
        socket.AF_INET6: 2 ** (IPV6_BITLEN - TRANSPERF_SUBNET[socket.AF_INET6]),
    }

    # Misc.
    UNSHARE_DELAY_SECONDS = 1


class Utils(object):
    """Contains util functions used by the transperf container module."""

    @staticmethod
    def ip_numeric(ip, ip_mode):
        """Returns numerical value from IP address."""
        if ip_mode == socket.AF_INET:
            # Returns numerical value from IPv4 address (dotted string).
            return struct.unpack('!I', socket.inet_pton(socket.AF_INET, ip))[0]
        elif ip_mode == socket.AF_INET6:
            return int(binascii.hexlify(socket.inet_pton(socket.AF_INET6, ip)),
                       16)
        else:
            raise exceptions.RuntimeError('Invalid IP mode %s' % ip_mode)

    @staticmethod
    def numeric_ip(numeric, ip_mode):
        """Returns IP address from numerical value."""
        if ip_mode == socket.AF_INET:
            # Returns IPv4 address (dotted string) from numerical value.
            return socket.inet_ntop(socket.AF_INET, struct.pack('!I', numeric))
        elif ip_mode == socket.AF_INET6:
            # pad=32 is to 0-pad all 128 bits.
            hex_form = '{value:0{pad}x}'.format(value=numeric, pad=32)
            return socket.inet_ntop(socket.AF_INET6,
                                    binascii.unhexlify(hex_form))
        else:
            raise exceptions.RuntimeError('Invalid IP mode %s' % ip_mode)

    @staticmethod
    def timestamp_dirname():
        """Builds a directory name based on current time."""
        return datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    @staticmethod
    def __func__(rewind=1):
        """Returns function executed by caller for more debug info."""
        frame = inspect.currentframe()
        while rewind > 0:
            upframe = frame.f_back
            if upframe is None:
                break
            frame = upframe
            rewind -= 1
        return frame.f_code.co_name

    @staticmethod
    def __file__(rewind=1):
        """Returns line number executed by caller for more debug info."""
        frame = inspect.currentframe()
        while rewind > 0:
            upframe = frame.f_back
            if upframe is None:
                break
            frame = upframe
            rewind -= 1
        return frame.f_code.co_filename

    @staticmethod
    def __line__(rewind=1):
        """Returns line number executed by caller for more debug info."""
        frame = inspect.currentframe()
        while rewind > 0:
            upframe = frame.f_back
            if upframe is None:
                break
            frame = upframe
            rewind -= 1
        return frame.f_lineno

    @staticmethod
    def debug(fmt, *args):
        """Debug logs with more descriptive debug info."""
        rewind = 2
        fmt = '%s:%d:%s: ' + fmt
        LOG.debug(fmt, *([Utils.__file__(rewind), Utils.__line__(rewind),
                          Utils.__func__(rewind)] + list(args)))

    @staticmethod
    def run(cmd):
        """Wraps transerf::shell::run() with more descriptive debug info."""
        rewind = 2
        fmt = ' Shell:\t%s:%d:\t%s: Executing [%s]'
        LOG.debug(fmt, *([Utils.__file__(rewind), Utils.__line__(rewind),
                          Utils.__func__(rewind), cmd]))
        return shell.run(cmd)


class IfUtils(object):
    """Contains interface management convenience functions."""

    @staticmethod
    def ensure_bonding_available():
        modules = subprocess.check_output('lsmod | awk \'{print $1}\'',
                                          shell=True)
        modules = set(modules.splitlines())
        if 'bonding' not in modules:
            Utils.run('modprobe bonding')

    @staticmethod
    @traced
    def br_exists(brdev):
        """Does this bridge exist?"""
        cmd = '{ctl} show {dev}'.format(ctl=path.brctl(), dev=brdev)
        _, err, _ = Utils.run(cmd)
        errlines = err.splitlines()
        # Format:
        # bridge_name bridge_id STP_enabled interfaces (line 1)
        # ... <per bridge data> on subsequent lines
        if errlines and ('No such device' in errlines[0]
                         or 'can\'t get info' in errlines[0]
                         or 'does not exist' in errlines[0]):
            return False
        return True

    @staticmethod
    @traced
    def create_bridge(brdev):
        """Creates bridge."""
        cmd = '{ctl} addbr {dev}'.format(ctl=path.brctl(), dev=brdev)
        Utils.run(cmd)
        cmd = 'ip link set {dev} up'.format(dev=brdev)
        Utils.run(cmd)

    @staticmethod
    @traced
    def delete_bridge(brdev):
        """Deletes bridge."""
        # Unhook and delete each interface on bridge if it exists.
        br_ifaces = IfUtils.get_bridge_ifaces(brdev, must_exist=False)
        for iface in br_ifaces:
            cmd = 'ip link set {iface} down'.format(iface=iface)
            Utils.run(cmd)
            IfUtils.unhook_br_iface(brdev, iface)
            IfUtils.del_iface(iface)
        # Disable bridge
        cmd = 'ip link set {dev} down'.format(dev=brdev)
        Utils.run(cmd)
        # Delete bridge and verify.
        cmd = '{ctl} delbr {dev}'.format(ctl=path.brctl(), dev=brdev)
        Utils.run(cmd)
        assert not IfUtils.br_exists(brdev), ('Cannot delete '
                                              'bridge %s' % brdev)
        # Delete orphaned root transperf interface.
        IfUtils.del_iface(Constants.ROOT_TRANSPERF_IFACE['name'])
        Utils.debug('Return: Delete bridge %s', brdev)

    @staticmethod
    @traced
    def get_bridge_ifaces(brdev, must_exist=True):
        """Gets bridge interfaces.

        If must_exist is False, return an empty list. If must_exist is True,
        return an error if the bridge does not exist.

        Args:
            brdev: The bridge device.
            must_exist: If true, raise an exception if no bridge found.

        Returns:
            The list of bridge interfaces.
        """

        pathstr = '{br_base}/{dev}/brif'
        pathstr = pathstr.format(br_base=Constants.BRDEV_LIST_PATH, dev=brdev)
        cmd = 'ls {path}'.format(path=pathstr)
        out, err, _ = Utils.run(cmd)
        lines = out.splitlines()
        errlines = err.splitlines()
        assert not errlines or not must_exist, ('Bridge %s '
                                                'does not exist' % brdev)
        return lines

    @staticmethod
    @traced
    def unhook_br_iface(brdev, iface):
        """Removes interface from bridge."""
        cmd = '{ctl} delif {dev} {iface}'.format(ctl=path.brctl(),
                                                 dev=brdev, iface=iface)
        Utils.run(cmd)
        assert iface not in IfUtils.get_bridge_ifaces(brdev), ('Cannot unhook '
                                                               'iface %s from '
                                                               'bridge %s' %
                                                               (iface, brdev))

    @staticmethod
    @traced
    def hook_br_iface(brdev, iface):
        """Adds interface to bridge."""
        cmd = '{ctl} addif {dev} {iface}'.format(ctl=path.brctl(),
                                                 dev=brdev, iface=iface)
        Utils.run(cmd)
        assert iface in IfUtils.get_bridge_ifaces(brdev), ('Unable to add %s '
                                                           'to bridge %s' %
                                                           (iface, brdev))

    @staticmethod
    @traced
    def verify_iface_on_br(brdev, iface):
        """Ensures interface added to bridge."""
        assert iface in IfUtils.get_bridge_ifaces(brdev), ('iface %s not in '
                                                           'bridge %s' %
                                                           (iface, brdev))

    @staticmethod
    @traced
    def verify_iface_cfg(iface_cfg, ip_mode):
        """Verifies interface exists with configured address."""
        iface = iface_cfg['name']
        cmd = 'ip addr show dev {iface}'.format(iface=iface)
        out, err, _ = Utils.run(cmd)
        lines = out.splitlines()
        errlines = err.splitlines()
        # Verify iface exists.
        assert lines, 'No output for %s' % cmd
        assert (not errlines or
                'does not exist' not in errlines[0]), ('Device %s '
                                                       'does not exist.' %
                                                       iface)
        # Verify address.
        matcher = 'inet6' if ip_mode == socket.AF_INET6 else 'inet'
        for line in lines:
            splits = line.split()
            if not splits:
                continue
            if splits[0] != matcher:
                continue
            addr = splits[1]
            if addr == iface_cfg['address'][ip_mode]:
                return
        error = 'Unable to verify interface: %s' % iface_cfg
        LOG.error(error)
        raise RuntimeError(error)

    @staticmethod
    @traced
    def setup_root_veth(brdev, ip_mode):
        """Setup root netns transperf interface with reserved address."""
        # Root veths are reserved constants.
        root_iface_cfg = Constants.ROOT_TRANSPERF_IFACE
        root_iface = root_iface_cfg['name']
        root_addr = root_iface_cfg['address'][ip_mode]
        peer = root_iface_cfg['br-pair']

        IfUtils.setup_iface(brdev, root_iface, peer, ip_mode, addr=root_addr)
        # Give the root interface route a specific route MTU
        # to not break other tests.
        if ip_mode == socket.AF_INET:
            cmd = 'ip route change %s/%d dev %s mtu 1500' % (
                Constants.TRANSPERF_SUBNET_ADDR[ip_mode],
                Constants.TRANSPERF_SUBNET[ip_mode],
                Constants.ROOT_TRANSPERF_IFACE['name'])
            Utils.run(cmd)
        else:
            cmd = 'ip -6 route del %s/%d' % (
                Constants.TRANSPERF_SUBNET_ADDR[ip_mode],
                Constants.TRANSPERF_SUBNET[ip_mode],
            )
            Utils.run(cmd)
            cmd = 'ip -6 route add %s/%d dev %s mtu 1500' % (
                Constants.TRANSPERF_SUBNET_ADDR[ip_mode],
                Constants.TRANSPERF_SUBNET[ip_mode],
                Constants.ROOT_TRANSPERF_IFACE['name'])
            Utils.run(cmd)

    @staticmethod
    @traced
    def setup_iface(brdev, iface, peer, ip_mode, root_offload=True,
                    container_offload=True, netns=None, addr=None):
        """Setup interface with given address.

        If netns is specified, the non-bridge half of the interface is moved
        into the target netns and renamed by stripping "<netns>-" from the name.

        Args:
            brdev: The bridge device the peer is hooked onto.
            iface: The interface we are setting up.
            peer:  The peer interface.
            ip_mode: Whether we are using IPv4 or IPv6.
            root_offload: Whether ethtool offloads are enabled or not for
                          root-facing veth device.
            container_offload: Whether ethtool offloads are enabled or not for
                                container-facing veth device.
            netns: The netns for the interface.
            addr:  The address for the interface.

        Returns:
            Nothing.
        """
        # Ensure old devices gone.
        IfUtils.del_iface(iface)
        IfUtils.del_iface(peer)

        # Create devices.
        cmd = 'ip link add dev {iface} type veth peer name {peer}'
        cmd = cmd.format(iface=iface, peer=peer)
        Utils.run(cmd)

        # Disable offloads.
        if not container_offload:
            cmd = 'ethtool -K {dev} tso off gso off gro off'
            cmd = cmd.format(dev=iface)
            LOG.debug('Container offload disable: executing %s', cmd)
            Utils.run(cmd)

        if not root_offload:
            cmd = 'ethtool -K {dev} tso off gso off gro off'
            cmd = cmd.format(dev=peer)
            Utils.run(cmd)

        # Enable devices.
        cmd = 'ip link set {iface} up'.format(iface=iface)
        Utils.run(cmd)
        cmd = 'ip link set {peer} up'.format(peer=peer)
        Utils.run(cmd)

        # Add peer to bridge.
        IfUtils.hook_br_iface(brdev, peer)

        # Configure addr if netns is None (ie. root device) and addr specified.
        if netns is None:  # Root netns.
            if addr is None:
                return  # Nothing else to do.
            # Set address for root device.
            if ip_mode == socket.AF_INET:
                cmd = 'ifconfig {iface} {addr} up'
                cmd = cmd.format(iface=iface,
                                 addr=addr)
                Utils.run(cmd)
            else:
                cmd = 'ifconfig {iface} up'
                cmd = cmd.format(iface=iface)
                Utils.run(cmd)
                cmd = 'ifconfig {iface} inet6 add {addr}'
                cmd = cmd.format(iface=iface,
                                 addr=addr)
                Utils.run(cmd)
        else:  # Container netns.
            cmd = 'ip link set {iface} netns {netns}'
            cmd = cmd.format(iface=iface,
                             netns=netns)
            Utils.run(cmd)
            # Now rename it within the node netns.
            netns_exec = 'ip netns exec {netns}'.format(netns=netns)
            # Ifdown.
            cmd = '{netexec} ip link set {iface} down'
            cmd = cmd.format(netexec=netns_exec,
                             iface=iface)
            Utils.run(cmd)
            # Strip the node_ prefix from the name to rename.
            newname = iface[len('%s-' % netns):]
            cmd = '{netexec} ip link set {iface} name {new}'
            cmd = cmd.format(netexec=netns_exec, iface=iface, new=newname)
            Utils.run(cmd)
            # Ifup.
            cmd = '{netexec} ip link set {iface} up'
            cmd = cmd.format(netexec=netns_exec, iface=newname)
            Utils.run(cmd)

    @staticmethod
    @traced
    def del_iface(iface):
        """Delete interface."""
        # Delete interface.
        cmd = 'ip link del dev {iface}'.format(iface=iface)
        Utils.run(cmd)
        # Verify it's gone.
        cmd = 'ip addr show dev {iface}'.format(iface=iface)
        out, err, _ = Utils.run(cmd)
        lines = out.splitlines()
        errlines = err.splitlines()
        assert not lines, 'Got output [%s] for %s' % (lines, cmd)
        assert 'does not exist' in errlines[0], ('Device %s '
                                                 'still exists.' % iface)


class ContainerCtx(object):
    """Transperf singleserver container management object.

    Contains methods for setting up, managing and tearing down container
    environments for single server transperf.
    """

    def __init__(self, brdev, nodes, out_dir, ip_mode):
        """Initialize ContainerContext object.

        Args:
            brdev: The name of the bridge used by transperf.
            nodes: A list of node names.
            out_dir: Output directory for transperf.
            ip_mode: Whether we are using IPv4 or IPv6.

        Returns:
            An initialized ContainerCtx.

        Raises:
            Nothing.
        """
        self.brdev = brdev
        self.nodes = nodes
        self.out_dir = out_dir
        self.ip_mode = ip_mode
        self.uts_ns_pfx = ContainerCtx.get_uts_ns_pfx(self.out_dir)
        self.pid_ns_pfx = ContainerCtx.get_pid_ns_pfx(self.out_dir)

    @staticmethod
    def get_pid_ns_pfx(out_dir):
        return os.path.join(out_dir, 'pid')

    @staticmethod
    def get_node_pidfile(out_dir, node):
        return os.path.join(ContainerCtx.get_pid_ns_pfx(out_dir),
                            '%s_init' % node)

    @staticmethod
    def get_uts_ns_pfx(out_dir):
        return os.path.join(out_dir, 'uts')

    @staticmethod
    def get_node_uts_ns_path(out_dir, node):
        return os.path.join(ContainerCtx.get_uts_ns_pfx(out_dir), node)

    @staticmethod
    def get_node_pid_ns_path(out_dir, node):
        return os.path.join(ContainerCtx.get_pid_ns_pfx(out_dir), node)

    @staticmethod
    def get_node_net_ns_path(node):
        return os.path.join(Constants.NET_NS_PFX, node)

    @traced
    def setup_container_environment(self):
        """Setup container environment for experiment.

        Performs the following actions:
        1. Delete existing node containers and bridge device, as well as all
           interfaces connected to bridge device. Unmounts /etc/hosts if needed.
           (We temporarily bind mount per transperf run for node addresses).
        2. Creates virtual bridge and rootns veth pair for contacting nodes in
           namespace (ROOT_TRANSPERF_ADDR/TRANSPERF_SUBNET) with stp off.
        3. Remounts (--make-private, --bind) mount namespace dir.
        4. Creates a container per node with these persistent namespaces:
           uts: <outdir>/uts/<container>
           mount: <outdir>/mntns/<container>
           netns: /var/run/netns/<container>
           with a running 'screen' session as the initial process.
           Creates per-node directories and performs necessary mount ops.

        NB: This method does *not* connect the containers to the bridge
        (see: container.setup_all_container_interfaces() instead).
        It also does not create a custom /etc/hosts file (only orch.py can do
        that since it can vary from config file to config file).
        It also does not handle custom /etc/hosts file bind-mounting
        (see: initialization code in recv.py/send.py/orch.py instead).

        Raises:
            RuntimeError if an operation fails during container setup.

        """
        # Ensures bonding module is loaded.
        IfUtils.ensure_bonding_available()

        # Delete existing bridge.
        IfUtils.delete_bridge(self.brdev)

        # Prepare to create namespaces.
        self.__prepare_ns_dirs()

        # Cleanup existing nodes as necessary.
        for node in self.nodes:
            net_ns = node
            cmd = 'ip netns del {ns}'.format(ns=net_ns)
            Utils.run(cmd)
            # NB: We do not clean up the node processes, however.

        # Create bridge.
        IfUtils.create_bridge(self.brdev)
        assert IfUtils.br_exists(self.brdev), ('Cannot create '
                                               'bridge %s' % self.brdev)

        # Create root veth pair and attach to bridge.
        IfUtils.setup_root_veth(self.brdev, self.ip_mode)
        IfUtils.verify_iface_cfg(Constants.ROOT_TRANSPERF_IFACE, self.ip_mode)
        IfUtils.verify_iface_on_br(self.brdev,
                                   Constants.ROOT_TRANSPERF_IFACE['br-pair'])

        # Create node containers.
        for node in self.nodes:
            self.__create_node_container(node)

    @traced
    def __prepare_ns_dirs(self):
        """Creates and prepares namespace directories."""
        # Ensure UTS namespace directory exists.
        try:
            os.makedirs(self.uts_ns_pfx)
        except OSError:
            assert os.path.isdir(self.uts_ns_pfx), ('UTS path %s '
                                                    'does not exist, '
                                                    'cannot be created.' %
                                                    self.uts_ns_pfx)

        # Ensure PID namespace directory exists.
        try:
            os.makedirs(self.pid_ns_pfx)
        except OSError:
            assert os.path.isdir(self.pid_ns_pfx), ('PID path %s '
                                                    'does not exist, '
                                                    'cannot be created.' %
                                                    self.pid_ns_pfx)

    @traced
    def __create_node_container(self, node):
        """Create a container for a node."""
        # Get persistent namespace paths.
        uts_ns = os.path.join(self.uts_ns_pfx, node)
        pid_ns = os.path.join(self.pid_ns_pfx, node)

        # Create the netns.
        cmd = 'ip netns add {netns}'.format(netns=node)
        Utils.run(cmd)

        # Create the persistent non-net namespaces.
        open(uts_ns, 'a').close()
        open(pid_ns, 'a').close()

        # Start node init process.
        cmd = transperf.path.nodeinit()
        node_pidfile = ContainerCtx.get_node_pidfile(self.out_dir, node)
        unshare(node_pidfile, uts_ns, pid_ns,
                'python2', cmd, node)

        # Make directories and mount.
        node_root = ContainerCtx.get_node_root(self.out_dir, node)
        for dirname in Constants.VIRTUALIZED_PATHS:
            # We can't use os.path.join because it discards paths that occur
            # before any path with a leading slash.
            custom_dir = os.path.normpath(os.path.sep.join([node_root,
                                                            dirname]))
            Utils.debug('Create dir %s for node %s (node_root %s, dirname %s)',
                        custom_dir, node, node_root, dirname)
            os.makedirs(custom_dir)

    @staticmethod
    def get_node_root(out_dir, node):
        """Get the node filesystem root directory."""
        return os.path.join(out_dir, 'fs', node)

    def __get_path_pfxs(self, paths):
        """Gets the subset of paths that aren't prefixed by others."""
        # For each path, False means we think no other path is a prefix.
        pfxs = {os.path.normpath(path): False for path in paths}
        for pfx in pfxs:
            other_pfxs = [other for other in pfxs.keys() if other != pfx]
            for other in other_pfxs:
                # Test if we're contained in other, vice versa, or disjoint.
                common = os.path.commonprefix([pfx, other])
                if pfx == common:
                    pfxs[other] = True  # Other is contained by us
                elif other == common:
                    pfxs[pfx] = True  # We are contained by other
                else:
                    pass  # Neither of us contain the other

        # Every path has been examined by every other path. Get the list of
        # uncontained paths as our mount points.
        return [pathstr for pathstr in pfxs if not pfxs[pathstr]]

    @traced
    def setup_all_container_interfaces(self, node_cfg_dict):
        """Assigns addresses and creates interfaces for all nodes.

        Performs the following actions:
        1. For each node, assign an address, >= 1 + ROOT_TRANSPERF_ADDR.
        2. For each node, setup the container interfaces with the assigned
           address.

        Args:
            node_cfg_dict: A per-node configuration for interfaces.

        Return:
            Nothing.

        Raises:
            RuntimeError: if an operation fails.
        """
        base = Utils.ip_numeric(Constants.ROOT_TRANSPERF_ADDR[self.ip_mode],
                                self.ip_mode)
        nextval = base + 1
        mask = Constants.TRANSPERF_SUBNET[self.ip_mode]
        node_dns = []

        # Check if we have too many nodes.
        max_nodes = Constants.MAX_NODES[self.ip_mode]
        if len(self.nodes) >= max_nodes:
            raise RuntimeError('Too many nodes (%d given, max %d)' %
                               (len(self.nodes), max_nodes))

        # IFB device module is not virtualized by netns. Need to setup IFBs in
        # root namespace and move into the per-node namespaces.
        self.__setup_node_ifbs(node_cfg_dict)

        # Assign subsequent nodes the next available IP address.
        for node in self.nodes:
            val = nextval
            nextval += 1
            node_addr = '{ip}/{mask}'.format(ip=Utils.numeric_ip(val,
                                                                 self.ip_mode),
                                             mask=mask)
            # Get per-node cfg and setup interfaces for node.
            node_cfg = self.__get_node_cfg(node, node_cfg_dict)
            self.__setup_container_interfaces(node, node_addr, node_cfg)
            # DNS entry for augmented /etc/hosts file.
            dns = '{addr} {node}'.format(addr=node_addr.split('/')[0],
                                         node=node)
            node_dns.append(dns)

        # Add nodes to hosts file and bind-mount it on top of regular file.
        new_hosts = os.path.join(self.out_dir, 'hosts')
        with open(new_hosts, 'w') as new_file:
            for dns in node_dns:
                new_file.write('%s\n' % dns)
            new_file.close()

    @traced
    def __setup_container_interfaces(self, node, node_addr, node_cfg):
        """Creates (bond and 'physical') interfaces for the given node.

        Creates interfaces for the given node, connects them to the provided
        bridge, and configures their addresses.

        Precondition: no enabled bond or other interfaces exist in the
        container.

        Performs the following actions:
        1. For each 'physical' interface, creates a veth-pair in the root
           namespace and moves it to the target node netns.
        2. Attaches the root-end of the veth-pair to the transperf bridge.
        3. Renames the node-end of the veth-pair to the config-provided value.
        4. Creates a bond-device within the node netns and assigns all
           node-ends of all veth-pairs to the bond-device.
        5. Assigns the node-end of the veth-pair an IP address (either from the
           config file, or otherwise chosen by transperf from 10/24).
        6. Clears the ARP cache within the node.

        Args:
            node: The current node being configured.
            node_addr: The IP address for the current node.
            node_cfg: A dict with the interface settings for the node.

        Returns:
            Nothing.

        Raises:
            RuntimeError if an operation fails.

        """
        phys_ifaces = [iface for iface in node_cfg['ifaces']
                       if not iface.startswith('regex:')]

        # Create veth pairs, one for each 'physical' interface.
        for iface in phys_ifaces:
            # rootname is used when we first create the interface; it is renamed
            # within the container after it is moved there by setup_iface.
            rootname = '{node}-{iface}'.format(node=node, iface=iface)
            peer = 'br-{node}-{iface}'.format(node=node, iface=iface)
            IfUtils.setup_iface(
                self.brdev, rootname, peer, self.ip_mode,
                root_offload=node_cfg['root_nic_offloads_enabled'],
                container_offload=node_cfg['container_nic_offloads_enabled'],
                netns=node)

        # Get bond device parameters.
        bond_iface = node_cfg['bond']
        bond_path = Constants.BOND_PATH_TEMPLATE.format(bond=bond_iface)
        netns_exec = 'ip netns exec {node}'.format(node=node)
        echo_exec = '{netexec} sh -c'.format(netexec=netns_exec)

        # Create bond device within the node (per config).
        cmd = '{echoexec} \'echo +{bond} > {bondmasters}\''
        cmd = cmd.format(echoexec=echo_exec, bond=bond_iface,
                         bondmasters=Constants.BOND_MASTERS)
        Utils.run(cmd)

        # Set bond mode and hash function within the node.
        bond_mode_path = os.path.join(bond_path, 'mode')
        cmd = '{echoexec} \'echo {mode} > {modepath}\''
        cmd = cmd.format(echoexec=echo_exec, mode=Constants.DEFAULT_BOND_MODE,
                         modepath=bond_mode_path)
        Utils.run(cmd)

        bond_policy_path = os.path.join(bond_path, 'xmit_hash_policy')
        cmd = '{echoexec} \'echo {policy} > {xmitpath}\''
        cmd = cmd.format(echoexec=echo_exec,
                         policy=Constants.DEFAULT_BOND_XMIT_HASH_POLICY,
                         xmitpath=bond_policy_path)
        Utils.run(cmd)

        # Add all 'physical' interfaces to the bond device.
        bond_slaves = os.path.join(bond_path, 'slaves')
        for iface in phys_ifaces:
            # ifdown
            cmd = '{netexec} ip link set {iface} down'
            cmd = cmd.format(netexec=netns_exec,
                             iface=iface)
            Utils.run(cmd)
            # Add to bond
            cmd = '{netexec} sh -c \'echo +{iface} > {slaves}\''
            cmd = cmd.format(netexec=netns_exec,
                             iface=iface,
                             slaves=bond_slaves)
            Utils.run(cmd)
            # ifup
            cmd = '{netexec} ip link set {iface} up'
            cmd = cmd.format(netexec=netns_exec,
                             iface=iface)
            Utils.run(cmd)

        # Assign address to bond device.
        if self.ip_mode == socket.AF_INET:
            cmd = '{netexec} ifconfig {bond} {addr} up'
            cmd = cmd.format(netexec=netns_exec, bond=bond_iface,
                             addr=node_addr)
            Utils.run(cmd)
        else:
            cmd = '{netexec} ifconfig {bond} up'
            cmd = cmd.format(netexec=netns_exec, bond=bond_iface)
            Utils.run(cmd)
            cmd = '{netexec} ifconfig {bond} inet6 add {addr}'
            cmd = cmd.format(netexec=netns_exec, bond=bond_iface,
                             addr=node_addr)
            Utils.run(cmd)

        # Clear node ARP cache.
        cmd = '{netexec} ip -s -s neigh flush all'
        cmd = cmd.format(netexec=netns_exec, node=node)
        Utils.run(cmd)

        # Enable loopback.
        cmd = '{netexec} ifconfig lo up'
        cmd = cmd.format(netexec=netns_exec)
        Utils.run(cmd)

    @traced
    def __setup_node_ifbs(self, node_cfg_dict):
        """Setup node IFBs some basic rules.

           Rules:
           1. No one else on the system is using an IFB.
           2. Every node has 1+N interfaces, where N is the number of 'physical'
              (non-bond) interfaces on the node.

        Args:
            node_cfg_dict: A dictionary of per-node interface configs.

        Returns:
            Nothing.
        """
        # Compute the number of IFBs we need.
        next_ifb_idx = 0
        ifb_node_mappings = []
        for node in self.nodes:
            node_cfg = self.__get_node_cfg(node, node_cfg_dict)
            physical_ifaces = [iface for iface in node_cfg['ifaces']
                               if not iface.startswith('regex:')]
            LOG.debug('Node %s phys ifaces %s', node, physical_ifaces)
            all_ifaces = [node_cfg['bond']] + physical_ifaces
            LOG.debug('Node %s all ifaces %s', node, all_ifaces)

            # Assign mapping from root-ns ifb to the corresponding node iface.
            for iface in all_ifaces:
                LOG.debug('Handle iface %s from %s', iface, all_ifaces)
                ifb_node_mappings.append((node, 'ifb%d' % next_ifb_idx, iface))
                next_ifb_idx += 1

        LOG.debug('Mappings: %s', ifb_node_mappings)
        # Setup the module.
        Utils.run('rmmod ifb')
        Utils.run('modprobe ifb numifbs=%s' % len(ifb_node_mappings))

        # Now we move the ifbs into the destination node namespaces.
        for node, ifb, node_iface in ifb_node_mappings:
            LOG.debug('Handle node %s ifb %s node_iface %s', node, ifb,
                      node_iface)
            # Disable ifb.
            cmd = 'ip link set {ifb} down'.format(ifb=ifb)
            Utils.run(cmd)
            # Move to node.
            cmd = 'ip link set {ifb} netns {node}'
            cmd = cmd.format(ifb=ifb, node=node)
            Utils.run(cmd)
            # Rename.
            newname = Receiver.get_ifb_for_iface(node_iface)
            netns_exec = 'ip netns exec {node}'.format(node=node)

            cmd = '{netexec} ip link set {ifb} name {new}'
            cmd = cmd.format(netexec=netns_exec, ifb=ifb, new=newname)
            Utils.run(cmd)
            # Enable ifb.
            cmd = '{netexec} ip link set {ifb} up'
            cmd = cmd.format(netexec=netns_exec, ifb=newname)
            Utils.run(cmd)

    def __get_node_cfg(self, node, node_cfg_dict):
        """Gets the interface configuration for this node."""
        if node not in node_cfg_dict:
            LOG.debug('Node %s not in cfg dict (%s), '
                      'using default: %s',
                      node,
                      node_cfg_dict,
                      Constants.DEFAULT_NODE_CFG)
            return Constants.DEFAULT_NODE_CFG

        LOG.debug('Node %s using iface cfg %s', node, node_cfg_dict[node])
        return node_cfg_dict[node]

    @traced
    def cleanup_all_container_interfaces(self, node_cfg_dict):
        """Clears (bond and 'physical') interfaces for the given node.

        Clears interfaces for the given node.

        Args:
            node_cfg_dict: A dict with the interface settings for the node.

        Returns:
            Nothing.

        Raises:
            RuntimeError if an operation fails.

        """
        for node in self.nodes:
            self.__cleanup_container_interfaces(node, node_cfg_dict[node])

    @traced
    def __cleanup_container_interfaces(self, node, node_cfg):
        """Cleans up interfaces between subsequent transperf cfgs.

        A single invocation of transperf may run experiments in >1 config file.
        Each config may have its own setup for per-node interfaces. Transperf
        uses freshly created interfaces for each experiment run in singleserver
        mode to provide a clean slate for each experiment.

        Args:
            node: The node being cleaned up.
            node_cfg: A dict with the interface settings for the node.

        Returns:
            Nothing.

        Raises:

        """
        netns_exec = 'ip netns exec {node}'.format(node=node)

        # Disable and remove the bridge interface.
        bond_iface = node_cfg['bond']
        cmd = '{netexec} ip link del dev {bond}'.format(netexec=netns_exec,
                                                        bond=bond_iface)
        Utils.run(cmd)

        # Disable and remove the physical interfaces.
        phys_ifaces = [iface for iface in node_cfg['ifaces']
                       if not iface.startswith('regex:')]
        for iface in phys_ifaces:
            peer = 'br-{node}-{iface}'.format(node=node, iface=iface)
            # Delete iface in netns.
            cmd = '{netexec} ip link del dev {iface}'
            cmd = cmd.format(netexec=netns_exec, iface=iface)
            Utils.run(cmd)
            # Delete bridge side in root ns.
            cmd = 'ip link del dev {iface}'.format(iface=peer)
            Utils.run(cmd)

    def default_node_iface_setup(self, nodes):
        node_cfg = {node: Constants.DEFAULT_NODE_CFG for node in nodes}
        self.setup_all_container_interfaces(node_cfg)
        return node_cfg


def get_init_pid_from_unshare(unshare_pid):
    unshare_pid = str(unshare_pid)
    output = shell.run('pgrep -P %s' % unshare_pid)[0].splitlines()
    return output[0]


def unshare(pidfile, uts, pidns, cmd, *args):
    """Wrapper function for running given command with unshare."""
    # Run unshare, invoking the node init process, and get the pid.
    build = ['setsid',
             'unshare',
             '--fork',
             '--mount-proc',
             '--uts=%s' % uts,
             '--pid=%s' % pidns,
             cmd,]
    build += args
    proc = subprocess.Popen(build)
    unshare_pid = proc.pid
    # Wait for unshare to do its thing.
    time.sleep(Constants.UNSHARE_DELAY_SECONDS)
    # Get pid for node init process - it's the only child of unshare.
    init_pid = get_init_pid_from_unshare(unshare_pid)
    # Write it to the node pidfile.
    with open(pidfile, 'w') as fd:
        fd.write('%s\n' % init_pid)
    LOG.info('Node init pid is: %s:%s\n', pidfile, init_pid)


def main():
    """main() initializes a container environment for singleserver transperf.

    launch.py will call main() over ssh to set up a singleserver
    transperf environment if flagged to do so. main() can also be
    invoked manually to provide a quick flat L2 container based environment to
    play around in.

    Returns:
        0 upon successful exit.
    """
    # Setup CLI args
    parser = argparse.ArgumentParser(description='transperf container setup.')
    parser.add_argument('rcvnode', nargs=1, help='Receiver node (1)')
    parser.add_argument('sndnodes', nargs='+', help='Sender nodes (>=1)')
    parser.add_argument('-b', nargs='?',
                        const=Constants.DEFAULT_BRIDGE,
                        default=Constants.DEFAULT_BRIDGE,
                        dest='brdev', help='Specify bridge device')
    parser.add_argument('-d', nargs='?', const=None, default=None,
                        dest='out_dir', help='Specify out directory')
    parser.add_argument('--demo', action='store_true', default=False,
                        dest='demo', help='Setup basic NICs')
    parser.add_argument('-v', action='store_true', default=False,
                        dest='debug', help='Enabled debug output')
    parser.add_argument('--ifacecfg', nargs='?', dest='ifacecfg',
                        help='Node interfaces config.')
    parser.add_argument('--ip_mode', nargs='?', dest='ip_mode',
                        help='IP mode (4 or 6 (default)).', default=6)

    # Get args
    args = parser.parse_args()

    # Setup logging.
    log.setup_logging([(arg, getattr(args, arg)) for arg in vars(args)])

    ip_mode = transperf.ip_modes[int(args.ip_mode)]
    brdev = args.brdev
    demo_mode = args.demo
    nodes = args.rcvnode + args.sndnodes
    if args.ifacecfg is not None:
        iface_cfgname = args.ifacecfg
        ifacecfg = os.path.abspath(os.path.expanduser(iface_cfgname))
        node_cfg = transperf.InterfaceConfig.validate_config(ifacecfg, LOG)
    else:
        iface_cfgname = 'default'
        node_cfg = {node: dict(Constants.DEFAULT_NODE_CFG) for node in nodes}
    # For receiver node, we need to disable NIC offloads.
    for rcvr in args.rcvnode:
        LOG.debug('Disabling root/container offloads for receiver %s', rcvr)
        node_cfg[rcvr]['root_nic_offloads_enabled'] = False
        node_cfg[rcvr]['container_nic_offloads_enabled'] = False

    # Create output directory.
    out_dir = args.out_dir
    if out_dir is not None:
        out_dir = os.path.abspath(os.path.expanduser(args.out_dir))
    else:
        out_dir = os.path.join(Constants.DEFAULT_OUTDIR_BASE,
                               Utils.timestamp_dirname())
    try:
        os.makedirs(out_dir)
    except OSError:
        assert os.path.isdir(out_dir), ('Output dir %s does not exist '
                                        'and cannot be created.' % out_dir)

    # Setup container environment.
    ctx = ContainerCtx(brdev, nodes, out_dir, ip_mode)
    ctx.setup_container_environment()

    # Setup basic connectivity in demo mode.
    if demo_mode:
        demo_cfg = ctx.default_node_iface_setup(nodes)
        raw_input('Press enter to remove all interfaces for test.')
        ctx.cleanup_all_container_interfaces(demo_cfg)
        raw_input('Press enter to re-add all interfaces for test.')
        ctx.setup_all_container_interfaces(demo_cfg)
        print('\nDemo mode complete; leaving containers running.')
    else:
        # Setup requested connectivity.
        ctx.setup_all_container_interfaces(node_cfg)

    return 0

if __name__ == '__main__':
    sys.exit(main())
