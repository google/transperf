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

"""Transperf singleserver/local container mode test cleanup."""

from __future__ import print_function

import argparse
import logging
import os
import sys

import transperf
import transperf.path
import transperf.virtsetup


LOG = logging.getLogger('transperf/containercleanup')


def _get_nodes_from_fs(out_dir):
    """Get nodes in experiment from the virtualized filesystem directory."""
    fs_dir = os.path.join(out_dir, 'fs')
    if not os.path.isdir(fs_dir):
        return []
    return [node for node in os.listdir(fs_dir)
            if os.path.isdir(os.path.join(fs_dir, node))]


def _get_nodes(out_dir):
    """Get nodes in experiment from the virtualized mntns/pid/uts directory."""
    nodes = _get_nodes_from_fs(out_dir)
    if not nodes:
        # Could mean someone deleted things before we got here.
        backup_dirs = ['pid', 'mntns', 'uts']
        for dname in backup_dirs:
            dname_full = os.path.join(out_dir, dname)
            if not os.path.isdir(dname_full):
                continue
            nodes = [node for node in os.listdir(dname_full)
                     if not os.path.isdir(os.path.join(dname_full, node))]
            # Ignore pid-files in 'pid'.
            nodes = [node for node in nodes if '_init' not in node]
            if nodes:
                break
    return nodes


def _get_log_file(tag):
    log_dir = os.environ.get('GOOGLE_LOG_DIR', None)
    filename = 'virtcleanup{tag}.log'.format(tag='_' + tag if tag else '')
    return None if not log_dir else os.path.join(log_dir, filename)


def main():
    parser = argparse.ArgumentParser(description='transperf container cleanup.')
    parser.add_argument('-d', nargs='?', const=None, default=None,
                        dest='out_dir', help='Specify out directory')
    parser.add_argument('-v', action='store_true', default=False,
                        dest='debug', help='Enabled debug output')
    parser.add_argument('-t', '--tag', const=None, default=None,
                        dest='tag', help='Logfile nametag')
    # Get args
    args = parser.parse_args()
    # Setup logging.
    log_file = _get_log_file(args.tag)
    if log_file:
        logging.basicConfig(filename=log_file, level=logging.INFO)
    else:
        logging.basicConfig(stream=sys.stdout, level=logging.INFO)

    out_dir = os.path.abspath(os.path.expanduser(args.out_dir))

    # Cleanup steps:
    # 1. Clean up all of the mounts we made.
    # 2. Kill the processes via the initfiles.
    # 3. Delete the container directories.

    # First cleanup filesystem mounts:
    # A. For each virtual node, from within the emulated node namespaces,
    #    unmount /etc/hosts, /home, and /tmp.
    # B. For each vnode, from within the emulated node namespaces, unmount
    #    VirtSetup::ContainerCtx::get_mount_ns_pfx(out_dir)
    # C. From the root namespace, unmount /etc/hosts.
    umount_options = '-lf'  # Lazy/force. When we call umount there may still be
                            # users; with -l, we just finish cleanup on exit.
    nodes = _get_nodes(out_dir)

    # Kill init processes.
    pid_dir = os.path.join(out_dir, 'pid')
    initfiles = [fname for fname in transperf.path.list_files(pid_dir)
                 if fname.endswith('_init')]
    init_pids = [int(open(fname, 'r').read().splitlines()[0])
                 for fname in initfiles]
    for pid in init_pids:
        transperf.virtsetup.Utils.run('kill -KILL {pid}'.format(pid=pid))
    for fname in initfiles:
        os.unlink(fname)

    # Remove network namespaces.
    for node in nodes:
        transperf.virtsetup.Utils.run('ip netns del {node}'.format(node=node))

    # Unmount the special namespace files.
    dirs = [os.path.join(out_dir, dname) for dname in ['pid', 'uts']]
    for dname in dirs:
        for fname in transperf.path.list_files(dname):
            transperf.virtsetup.Utils.run(
                'umount {opts} {path}'.format(opts=umount_options, path=fname))

    # Delete the directory.
    transperf.virtsetup.Utils.run('rm -rf {out_dir}'.format(out_dir=out_dir))

    # Delete the root transperf interface.
    root_xperf_if = transperf.virtsetup.Constants.ROOT_TRANSPERF_IFACE['name']
    transperf.virtsetup.IfUtils.del_iface(root_xperf_if)

    return 0

if __name__ == '__main__':
    sys.exit(main())
