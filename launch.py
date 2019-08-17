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

"""Runs BBR experiements and summarizes the results in static HTML files.
"""

from __future__ import print_function

import datetime
import errno
import getopt
import glob
import json
import logging
import os
import pkg_resources
import shutil
import subprocess
import sys
import tempfile
import time

import transperf
from transperf import cfgutil
from transperf import executor
from transperf import gen
from transperf import log
from transperf import shell
from transperf import virtsetup
import transperf.path

LOG = logging.getLogger('transperf/launcher')


def abspath(path):
    return os.path.abspath(os.path.expanduser(path))


def _mkdir_if_not_exists(path):
    """Creates a directory if it does not exist.

    Args:
        path: The directory's path.

    Raises:
        OSError: If there is an IO error or a file already exists on the path.
    """
    try:
        os.makedirs(path)
    except OSError, exc:
        if exc.errno != errno.EEXIST or not os.path.isdir(path):
            raise exc


def _dump_cfgs(cfgs, data_search_path, out_dir):
    """Dumps configuration files and their data files in the output dir.

    Note that some values in each configuration can reference data files
    (e.g., rtt with a probability distribution for delay).  These files
    are gathered into the out/data directory, so they can be copied to
    the appropriate machines for use during execution.

    Args:
        cfgs: The configurations.
        data_search_path: List of directories to search for data files.
        out_dir: The output dir.
    Raises:
        ValueError: A data file is missing or ambiguous.
        RuntimeError: Same data file name is found in multiple directories.
    """
    for f in glob.glob(os.path.join(out_dir, 'cfg*.py')):
        os.remove(f)

    data_dir = os.path.join(out_dir, 'data')
    shutil.rmtree(data_dir, ignore_errors=True)

    data_files = set()
    for i, cfg in enumerate(cfgs):
        cfg_path = os.path.join(out_dir, 'cfg%d.py' % (i))
        f = open(cfg_path, 'w')
        f.write(cfg)
        f.close()

        # Gather any embedded data files required by this configuration.
        c = cfgutil.config_from_script(cfg)
        data_files.update(c.get_data_files())

    # Gather data files needed for all configurations into the out_dir.
    if data_files:
        os.mkdir(data_dir)
        encountered = set()
        for df in data_files:
            # If name is a recognized keyword, then there's nothing to copy.
            if df in transperf.DATA_FILE_KEYWORDS:
                continue

            # Support ~ in data file names.
            df = os.path.expanduser(df)

            # Search for relative path names along the data search path.
            if not os.path.isabs(df):
                found = [os.path.join(dirp, df) for dirp in data_search_path
                         if os.path.isfile(os.path.join(dirp, df))]
                if not found:
                    raise ValueError("data file '%s' not found" % df)
                elif len(found) > 1:
                    raise ValueError(
                        "multiple instances of data file '%s'" % df)
                else:
                    df = found[0]

            # Make sure multiple files don't share the same base name,
            # since we'll gather them all into a single data directory.
            name = os.path.basename(df)
            root = os.path.splitext(name)[0]
            if name in encountered or root in transperf.DATA_FILE_KEYWORDS:
                raise RuntimeError('Conflicting data files named "%s"' % name)

            shutil.copyfile(df, os.path.join(data_dir, name))
            encountered.add(name)


def _read_file(path):
    """Reads the whole file and returns its content.

    Args:
        path: The file path.

    Returns:
        The content of the file.
    """
    f = open(path, 'r')
    return f.read()


def _root_log_dir():
    return transperf.path.get_exp_out_dir()


def print_usage():
    """Prints usage of the launcher."""
    helpstr = '''launch.py [options] HOST1 HOST2 ... HOSTN

options:
    -h/help/unrecognized flags : Print this help message and exit.
    -c config_files: a comma separated list of config file paths. If there is a
                     directory all *.py files in the directory and all its
                     subdirectories will be used.
    -s config_script: a configuration script.
    -o output_dir: the output directory.
    -b binary_dirs: a comma separated list of directories containing binaries.
    -n: do not synchronize the machines.
    -v: verbose output.
    -x: generate xplots.
    -q: not open browser after experiment.
    --rport receiver_port: the port used by the receiver.
    --sport sender_port: the port used by senders.
    --skip_pcap_scan: skip scanning pcap files, but use ss logs to compute
                      metrics.
    --sslog_interval seconds: set the time interval between two ss commands,
                              default 0.1. A value <0 disables ss logging.
    --ifacecfg: specify a file containing an interfaces configuration for nodes
                when running in singleserver/container mode.
    --bridge: specify  a root net namespace bridge name when running in
              singleserver/container mode. (default: {bridge})
    --ssrv: specify a (physical) server to run transperf in
            singleserver/container mode. If '_' is provided, run it on
            the local server where this command is invoked.
    --save: Specify an additional save directory where all output files are
            copied. This can be useful since the normal output directory
            is cleaned up after the test is done.
    --genonly: Instead of running a transperf test, regenerate the output
               processed webpage for an existing test (directory containing
               relevant data specified by -o).
    --gen_from_file: When --genonly specified, --gen_from_file specifies the
                     name of a gzip'd tar archive that contains the trace data
                     that we analyze/create the results dashboard from.
                     Specifying '-' as the file means we read the archive from
                     stdin.
    --virtcleanup: When running in singleserver/container mode, use this
                   flag to specify that the containers created are cleaned up
                   after the test is over. Leave it unset to manually inspect
                   container setup afterwards.
    --ip_mode: Specify IPv4 or IPv6 operation mode, '4' or '6' (default).
    -V: print the version number.
    '''
    helpstr = helpstr.format(bridge=virtsetup.Constants.DEFAULT_BRIDGE)
    print(helpstr)


def _read_file_contents(path):
    with open(path, 'r') as fd:
        return fd.read()


def _stage_transperf_src(tmp=None):
    """Stages transperf src in tmpdir before copy to destination node."""
    listfn = lambda: pkg_resources.resource_listdir('transperf', '')
    readfn = lambda fname: pkg_resources.resource_string('transperf', fname)

    to_sync = []
    if tmp is None:
        tmp = os.path.join(tempfile.gettempdir(), 'transperf')
        if not os.path.exists(tmp):
            os.mkdir(tmp)

    for f in listfn():
        _, ext = os.path.splitext(f)
        if ext != '.py':
            continue
        content = readfn(f)
        path = os.path.join(tmp, f)
        tempf = open(path, 'w')
        tempf.write(content)
        tempf.close()
        to_sync.append(path)
    return tmp, to_sync


def _stage_transperf_binaries(binary_dirs, sync, cleanup_cmds,
                              to_sync, all_targets):
    """Stages transperf binaries before copy to destination node."""
    binary_names = ['tc']
    for tool in transperf.TOOLS.values():
        binary_names += tool.binaries

    for f in binary_names:
        # Check the search directories.
        found = False
        for dname in binary_dirs:
            path = os.path.join(dname, f)
            if os.path.exists(path) and os.path.isfile(path):
                to_sync.append(path)
                found = True
                LOG.info('Adding binary %s (path %s) to stage list.', f, path)
                break
        if found:
            continue
        # Try to find the system binary next.
        path = transperf.path.get_sys_binary(f)
        if path is not None and os.path.exists(path):
            to_sync.append(path)
            found = True
            LOG.info('Using system version of binary %s (path %s)', f, path)
        # We might fail if nothing was found.
        if not found:
            # When the user asked to sync the files, we need to make sure the
            # binaries are actually copied.
            if sync:
                LOG.error('cannot find binary %s in %s', f, binary_dirs)
                sys.exit(-1)

    return to_sync


def _init_servers(r_exec, s_execs, binary_dirs, out_dir, sync,
                  staged_src, singlesrv_cfg):
    """Initializes the receiver and senders.

    Args:
        r_exec: The receiver executor session.
        s_execs: The sender executor sessions.
        binary_dirs: Where to fetch binaries (e.g., tc, netperf, ...). This is a
        list of directories to search in.
        out_dir: Where to put the data.
        sync: Whether to sync the python files on sender and receiver.
        staged_src: Staged transperf source ready for transfer.
        singlesrv_cfg: Single server mode config params.

    Raises:
          RuntimeError: When encountered a critial error.
    """
    # Check if single server mode. If so, we do not use the root namespaces.
    singlesrv_mode = singlesrv_cfg['enabled']
    use_rootns = not singlesrv_mode
    all_targets = [r_exec] + s_execs

    cleanup_cmds = {}
    for target in all_targets:
        cleanup_cmds[target] = ['{sudo} pkill -f transperf']
        tgt_exp_dir = transperf.path.get_exp_out_dir(
            target.get_container_root_dir())
        cleanup_cmds[target].append(
            'rm -rf {exp_dir}'.format(exp_dir=tgt_exp_dir))
        cleanup_cmds[target].append(
            'mkdir -p {exp_dir}'.format(exp_dir=tgt_exp_dir))
        if sync:
            cleanup_cmds[target].append(
                'mkdir -p ' +
                transperf.path.get_transperf_home(
                    target.get_container_root_dir()))

    to_sync = _stage_transperf_binaries(binary_dirs, sync,
                                        cleanup_cmds, staged_src, all_targets)
    LOG.info('Staged files list: %s', to_sync)

    # Background procs are to improve initial launch time. We try to run as much
    # as we can in parallel.
    procs = []
    for target in all_targets:
        for cmd in cleanup_cmds[target]:
            # When in single server mode, trying to run too many commands at
            # the same time intermittently fails.
            target.run(cmd, use_rootns=use_rootns)
        if not singlesrv_mode:
            LOG.debug('disabling containers on %s', target.addr())

    # Create directory for configuration file.
    config_dir = os.path.join(transperf.path.get_transperf_home(), '__config')
    cfg_dir_make_cmd = 'rm -rf %(cfg)s && mkdir -p %(cfg)s && rm -rf %(cfg)s/*'
    cfg_dir_make_cmd %= {'cfg': config_dir}
    cfg_dir_make_cmd = '{sudo} %(cmd)s' % {'cmd': cfg_dir_make_cmd}
    # We push it for the receiver node and orchestrator (if single server mode).
    procs.append(r_exec.bg(cfg_dir_make_cmd, use_rootns=use_rootns))
    if singlesrv_mode:
        procs.append(r_exec.bg(cfg_dir_make_cmd, use_rootns=True))  # for orch

    # Create directory for node interface configuration.
    node_ifacecfg_dir = os.path.join(transperf.path.get_transperf_home(),
                                     transperf.path.IFACE_CFG_DIR)
    scp_node_iface_cmd = '{sudo} mkdir -p %s' % node_ifacecfg_dir
    procs.append(r_exec.bg(scp_node_iface_cmd, use_rootns=use_rootns))
    # NB: orch.py does not need this so no single server special case here.

    # We also push ifacecfg to the sender nodes; prepare directories for them.
    for s_exec in s_execs:
        procs.append(s_exec.bg(scp_node_iface_cmd, use_rootns=use_rootns))

    # Wait for directory creation/cleanup to complete.
    for p in procs:
        shell.wait(p)

    procs = []

    if sync:
        for target in all_targets:
            procs.append(target.push_bg(to_sync,
                                        transperf.path.get_transperf_home(),
                                        use_rootns=use_rootns))

    # Push configs.
    cfg_items = glob.glob(os.path.join(out_dir, '*.py'))
    procs.append(r_exec.push_bg(cfg_items, config_dir, use_rootns=use_rootns))
    if singlesrv_mode:
        procs.append(r_exec.push_bg(cfg_items, config_dir, use_rootns=True))

    # Also push the interface config files if any.
    local_ifacecfg_dir = os.path.join(out_dir, transperf.path.IFACE_CFG_DIR)
    iface_cfgs = glob.glob(os.path.join(local_ifacecfg_dir, '*.py'))
    if iface_cfgs:
        procs.append(r_exec.push_bg(iface_cfgs, node_ifacecfg_dir,
                                    use_rootns=use_rootns))
        # Push ifacecfg to senders too.
        for s_exec in s_execs:
            procs.append(s_exec.push_bg(iface_cfgs, node_ifacecfg_dir,
                                        use_rootns=use_rootns))

    # Install data files needed for tc distributions.
    dist_files = glob.glob(os.path.join(out_dir, 'data', '*.dist'))
    if dist_files:
        # Special case here; tc_lib_dir might or might not be in a
        # node-virtualized directory, and we need to be careful which.
        use_rootns_dist_files = True  # Default behaviour
        tc_lib_dir = transperf.path.tc_lib_dir()
        tc_lib_is_virt = False
        for pfx in virtsetup.Constants.VIRTUALIZED_PATHS:
            if os.path.commonprefix([pfx, tc_lib_dir]) == pfx:
                tc_lib_is_virt = True
                break
        if tc_lib_is_virt and singlesrv_mode:
            use_rootns_dist_files = False
        procs.append(r_exec.push_bg(dist_files, transperf.path.tc_lib_dir(),
                                    use_rootns=use_rootns_dist_files))

    # Wait for transfers to complete.
    for p in procs:
        _, err, returncode = shell.wait(p)
        if err and returncode != 0:
            raise RuntimeError(err)


def _start_servers(r_exec, s_execs,
                   rport, sport, sslog_interval, ifacecfg_rel, singlesrv_cfg,
                   ip_mode, save_pcap, save_kern_debug, out_dir):
    """Starts servers on the receiver and on the sender machines.

    Args:
        r_exec: The receiver executor session.
        s_execs: The sender executor sessions.
        rport: The port used by the receiver.
        sport: The port used by the senders.
        sslog_interval: The time interval in seconds to sample ss log.
        ifacecfg_rel: The name of the staged per-node interface config or None.
        singlesrv_cfg: Single server mode config params.
        ip_mode: Whether we are using ipv4 or ipv6.
        save_pcap: Whether we save pcaps or not.
        save_kern_debug: Whether we scrape/save kernel debug info or not.
        out_dir: Output directory for experiment.

    Raises:
          RuntimeError: When encountered a critical error.
    """
    singlesrv_mode = singlesrv_cfg['enabled']
    singlesrv_local = singlesrv_cfg['local']
    use_rootns = not singlesrv_mode
    ifacecfg_params = []
    if ifacecfg_rel is not None:
        node_ifacecfg_dir = os.path.join(transperf.path.get_transperf_home(),
                                         transperf.path.IFACE_CFG_DIR)
        ifacecfg = os.path.join(node_ifacecfg_dir, ifacecfg_rel)
        ifacecfg_params = ['--ifacecfg', ifacecfg]

    env_vars = ([] if not singlesrv_mode else
                [(transperf.path.TRANSPERF_CONTAINER_ROOT_KEY,
                  r_exec.get_container_root_dir())])
    recv_params = [env_vars]
    recv_params.extend(['recv.py', '-v', '-p', rport, '-n', r_exec.host(),
                        '--ip_mode', str(ip_mode),
                        '-s' if singlesrv_mode else '',])
    if singlesrv_mode:
        recv_params.extend(['--hosts', singlesrv_cfg['hosts']])
    recv_params.extend(ifacecfg_params)
    recv_log = os.path.join(
        transperf.path.get_exp_out_dir(r_exec.get_container_root_dir()),
        'receiver.log')
    recv_params.append('>%s 2>&1' % recv_log)

    rproc = r_exec.bg(shell.py_cmd(*recv_params), use_rootns=use_rootns)

    if rproc.poll():
        _, err, returncode = shell.wait(rproc)
        raise RuntimeError('cannot start receiver: %d: %s' % (returncode, err))

    sprocs = []
    for s_exec in s_execs:
        env_vars = ([] if not singlesrv_mode else
                    [(transperf.path.TRANSPERF_CONTAINER_ROOT_KEY,
                      s_exec.get_container_root_dir())])
        send_params = [env_vars]
        send_params.extend(['send.py', '-v', '-p', sport, '-n', s_exec.host(),
                            '--ip_mode', str(ip_mode),
                            '-s' if singlesrv_mode else '',
                            '' if save_pcap else '--no_pcap',
                            '' if save_kern_debug else '--no_kern_debug',])
        if singlesrv_mode:
            send_params.extend(['--hosts', singlesrv_cfg['hosts']])
        send_params.extend(ifacecfg_params)
        send_log = os.path.join(
            transperf.path.get_exp_out_dir(s_exec.get_container_root_dir()),
            'sender.%s.log' % s_exec.host())
        send_params.append('>%s 2>&1' % send_log)
        sproc = s_exec.bg(shell.py_cmd(*send_params), use_rootns=use_rootns)

        if sproc.poll():
            raise RuntimeError('cannot start sender: %s' % (err))
        sprocs.append(sproc)

    # Sleep for 500ms second for each machine and let the receiver and
    # senders start.
    grace_period = 0.5 * (len(s_execs) + 1)
    LOG.debug('sleeping for %s seconds', grace_period)
    time.sleep(grace_period)
    r_addr = '%s:%d' % (r_exec.host(), rport)
    s_addrs = ['%s:%d' % (s_exec.host(), sport) for s_exec in s_execs]
    env_vars = []
    orch_params = [env_vars]
    orch_out_dir = (singlesrv_cfg['out_dir']
                    if singlesrv_mode and not singlesrv_local else out_dir)
    orch_log_dir = (os.path.join(orch_out_dir, '__out')
                    if singlesrv_mode and not singlesrv_local
                    else _root_log_dir())
    r_exec.run('mkdir -p {orch_dir}'.format(orch_dir=orch_out_dir))
    r_exec.run('mkdir -p {orch_log_dir}'.format(orch_log_dir=orch_log_dir))
    orch_params.extend(['orch.py', '-v', '-r', r_addr, '-s', ','.join(s_addrs),
                        '--ip_mode', str(ip_mode),
                        '--sslog_interval', str(sslog_interval),
                        '--out_dir', orch_out_dir])
    if singlesrv_mode:
        orch_params.extend(['--hosts', singlesrv_cfg['hosts']])
    orch_log = os.path.join(orch_log_dir, 'orch.log')
    orch_params.append('>%s 2>&1' % orch_log)
    orch_stdout, err, returncode = r_exec.run(shell.py_cmd(*orch_params))
    LOG.debug('Orch stdout: [%s]', orch_stdout)
    LOG.debug('Orch err: [%s]', err)
    LOG.debug('Orch code: %s', returncode)
    LOG.debug('terminating recv proc')
    shell.terminate(rproc)
    for sp in sprocs:
        LOG.debug('terminating send proc')
        s_out, s_err, s_ret = shell.terminate(sp)
        LOG.info('Send_ret:[%s]\nSend_out: [%s]\nSend_err: [%s]\n',
                 s_ret, s_out, s_err)

    if err and returncode != 0:
        raise RuntimeError(err)


def _collect_results(r_exec, s_execs, out_dir, singlesrv_cfg):
    """Collects the output on the sender and receiver machines.

    Args:
        r_exec: The receiver executor session.
        s_execs: The sender executor sessions.
        out_dir: Where to put the data.
        singlesrv_cfg: Single server mode config params.
    """
    singlesrv_mode = singlesrv_cfg['enabled']
    singlesrv_local = singlesrv_cfg['local']
    use_rootns = not singlesrv_mode

    # We ignore errors in the pull to make sure we collect any existing
    # results from the experiment. The partial results are useful in
    # debugging transperf and the experiment.
    # Also, since this is the last stage of the experiment, ignoring errors
    # does not have adverse affects.
    procs = []
    for target in [r_exec] + s_execs:
        procs.append(target.pull_bg(transperf.path.get_exp_out_dir(), out_dir,
                                    use_rootns=use_rootns))
    if singlesrv_mode:
        if singlesrv_local:
            orch_log = os.path.join(_root_log_dir(), 'orch.log')
            procs.append(r_exec.pull_bg(orch_log, out_dir))
        else:
            # We'll need orch.log and exp.info for each experiment.
            # Since there are multiple experiments, pull the entire tree.
            procs.append(r_exec.pull_bg(
                os.path.join(singlesrv_cfg['out_dir'], '__out'),
                out_dir))
    for p in procs:
        shell.wait(p)

    procs = []
    if not singlesrv_mode:
        # Only cleanup if not in single server mode. In single server mode, we
        # may want to go back and look at outputs for a specific run.
        for target in [r_exec] + s_execs:
            cleanup_cmd = '{sudo} rm -rf %(out)s/*' % {
                'out': transperf.path.get_exp_out_dir()}
            procs.append(target.bg(cleanup_cmd, use_rootns=use_rootns))
    for p in procs:
        shell.wait(p)


def _timestamp_dirname():
    """Builds a directory name based on current time."""
    return datetime.datetime.now().strftime('%Y%m%d_%H%M%S')


def _validate_and_stage_ifacecfg(ifacecfg, ifacecfg_dir):
    """Validate and stage interface configuration file.

       If ifacecfg is None, we're good - we stage nothing and call processes
       that need the config (recv.py, send.py, etc.) without providing an
       ifacecfg option so they can use transperf.InterfaceConfig.default_cfg.

       Otherwise, ifacecfg must be a valid configuration file (see
       transperf.InterfaceConfig.validate_ifacecfg for details).

    Args:
        ifacecfg: The interface config file.
        ifacecfg_dir: The staging directory.

    Returns:
        The name of the config file, or None.

    Raises:
        RuntimeError if we the config is invalid.

    """
    if ifacecfg is None:
        return None

    parsed = transperf.InterfaceConfig.validate_config(ifacecfg, LOG)
    if parsed is None:
        return None  # Valid but not containing any data.

    LOG.info('Parsed valid interface config: %s', parsed)
    return _stage_ifacecfg(ifacecfg, ifacecfg_dir)


def _stage_ifacecfg(ifacecfg, ifacecfg_dir):
    """Stage validated interface configuration file.

    Args:
        ifacecfg: The interface config file.
        ifacecfg_dir: The staging directory.

    Returns:
        The name of the config file.

    Raises:
        RuntimeError if the config is invalid.
    """
    cmd = 'mkdir -p {stage}'.format(stage=ifacecfg_dir)
    cmd = 'cp {cfg} {stage}'.format(cfg=ifacecfg, stage=ifacecfg_dir)
    shell.run(cmd)
    cfgname = os.path.basename(os.path.normpath(ifacecfg))
    return cfgname


def main():
    invocation_dir = os.getcwd()
    source_dir = os.path.dirname(os.path.realpath(__file__))

    out_dir_rel = _timestamp_dirname()
    out_dir = os.path.join(invocation_dir, out_dir_rel)
    opts, args = getopt.getopt(sys.argv[1:], 'vo:b:c:s:nt:xyhq:V',
                               ['rport=', 'sport=', 'help', 'skip_pcap_scan',
                                'sslog_interval=', 'ifacecfg=', 'bridge=',
                                'ssrv=', 'ssrv_local', 'save=',
                                'genonly', 'gen_from_file=', 'virtcleanup',
                                'ip_mode=', 'no_pcap', 'no_kern_debug',])
    # Setup logging early.
    log.setup_logging(opts)

    # These are arbitrary ports that must be open between test machines.
    ip_mode = 4
    rport, sport = 6200, 6300
    sync = True
    has_xplot = False
    binary_dirs = [invocation_dir]
    if invocation_dir != source_dir:
        binary_dirs.append(source_dir)
    data_search_path = []
    open_page = True
    skip_pcap_scan = False
    sslog_interval = 0.1
    singlesrv_cfg = {'enabled': False,
                     'bridge': virtsetup.Constants.DEFAULT_BRIDGE,
                     'host': None,
                     'local': False,
                     'nodes': [],
                     'cleanup': False}

    ifacecfg = None
    save_dir = None
    gen_only = False
    gen_from_file = None
    save_pcap = True
    save_kern_debug = True
    # cfgs includes all configs both in files and in command line.
    cfgs = []
    for opt, val in opts:
        if opt == '-V':
            print("transperf {}".format(transperf.__version__))
            return
        if opt == '-v':
            continue
        elif opt == '--ip_mode':
            ip_mode = int(val)
            assert ip_mode in [4, 6], '--ip_mode must be in [4 (default), 6]'
        elif opt == '--virtcleanup':
            singlesrv_cfg['cleanup'] = True
        elif opt == '-o':
            out_dir_rel = val
            out_dir = abspath(out_dir_rel)
        elif opt == '-b':
            binary_dirs.extend([abspath(path) for path in val.split(',')])
            data_search_path.extend(binary_dirs)
        elif opt == '-c':
            cfg_paths = [abspath(path) for path in val.split(',')]
            for path in cfg_paths:
                if os.path.isfile(path):
                    data_search_path.append(os.path.dirname(path))
                    cfgs.append(_read_file(path))
                    continue
                data_search_path.append(path)
                cfgs += [_read_file(cfg_file)
                         for cfg_file in transperf.path.list_files(path)]
        elif opt == '-s':
            cfgs.append(val)
        elif opt == '-n':
            sync = False
        elif opt == '--rport':
            rport = int(val)
        elif opt == '--sport':
            sport = int(val)
        elif opt == '-x':
            has_xplot = True
        elif opt == '-q':
            open_page = False
        elif opt == '--skip_pcap_scan':
            skip_pcap_scan = True
        elif opt == '--no_pcap':
            save_pcap = False
            skip_pcap_scan = True  # Since we have no other way to get metrics.
        elif opt == '--no_kern_debug':
            save_kern_debug = False
        elif opt == '--genonly':
            gen_only = True
        elif opt == '--gen_from_file':
            gen_from_file = '-' if val == '-' else (
                os.path.abspath(os.path.expanduser(val)))
        elif opt == '--sslog_interval':
            sslog_interval = float(val)
        elif opt == '--ifacecfg':
            ifacecfg = abspath(val)
        elif opt == '--ssrv':
            if '_' in val:
                assert False, 'Cannot have underscore in hostname for --ssrv.'
            if singlesrv_cfg['local']:
                assert False, 'Cannot set both --ssrv and --ssrv_local at once.'
            singlesrv_cfg['enabled'] = True
            singlesrv_cfg['host'] = val
        elif opt == '--ssrv_local':
            if singlesrv_cfg['host']:
                assert False, 'Cannot set both --ssrv and --ssrv_local at once.'
            singlesrv_cfg['enabled'] = True
            singlesrv_cfg['local'] = True
        elif opt == '--save':
            save_dir = abspath(val)
        elif opt == '--bridge':
            curr_val = singlesrv_cfg['bridge']
            singlesrv_cfg['bridge'] = val if val is not None else curr_val
        elif (opt == '-h' or opt == '--help'):
            print_usage()
            return -1
        else:  # Catch-all for unexpected flags.
            print_usage()
            return -1

    # After processing the input paths, we change directory so we can
    # stage/invoke other source files within transperf. Special case though: we
    # may be invoking from a zip file. In that case, it's hard to know what
    # directory contains the unzipped source, so we just don't bother.
    if os.path.isdir(source_dir):
        os.chdir(source_dir)

    # Short circuit if we're generating an output webpage for previous test run.
    if gen_only:
        _mkdir_if_not_exists(out_dir)
        return _process_output(out_dir, has_xplot, open_page, skip_pcap_scan,
                               gen_from_file)
    else:
        assert gen_from_file is None, ('--gen_from_file only meaningful '
                                       'if --genonly specified.')
    if not args:
        print_usage()
        sys.exit(-1)

    if not cfgs:
        raise RuntimeError('no configuration found')

    LOG.debug('%d config(s) loaded: %s', len(cfgs), cfgs)
    _mkdir_if_not_exists(out_dir)
    _dump_cfgs(cfgs, data_search_path, out_dir)

    ifacecfg_dir = os.path.join(out_dir, transperf.path.IFACE_CFG_DIR)
    _mkdir_if_not_exists(ifacecfg_dir)
    ifacecfg_rel = _validate_and_stage_ifacecfg(ifacecfg, ifacecfg_dir)

    # Grab receiver and sender hostnames.
    recvh, _, recvh_internal = args[0].partition('/')
    sendhs, _, sendhs_internal = [list(t) for t in zip(*[_.partition('/')
                                  for _ in args[1:]])]

    # Check for duplicates.
    nodeset = set([recvh] + sendhs)
    if len(nodeset) != len(sendhs) + 1:
        # There was repetition, which we do not support.
        raise RuntimeError('There are repeated nodes in the arguments!')

    # Are we using ssh or are we local? For debug statements.
    session_type = 'ssh'
    if singlesrv_cfg['enabled']:
        if singlesrv_cfg['local']:
            session_type = 'local'
        else:
            assert singlesrv_cfg['host']

    if singlesrv_cfg['enabled']:
        # Strip usernames for single server mode; we must use root.
        recvh = recvh.split('@')[-1]
        sendhs = [sendh.split('@')[-1] for sendh in sendhs]
        nodes = [recvh] + sendhs
        singlesrv_cfg['nodes'] = nodes
        singlesrv_cfg['scratchd'] = (
            os.path.join(transperf.path.get_transperf_home(), 'containers'))
        singlesrv_cfg['out_dir'] = os.path.join(singlesrv_cfg['scratchd'],
                                                out_dir_rel)
        node_exec_cfgs = get_container_node_exec_cfgs(singlesrv_cfg, nodes)
    else:
        nodes = [recvh] + sendhs
        nodes_internal = [recvh_internal] + sendhs_internal
        node_exec_cfgs = {node: {'ssh': node, 'int_ip': ip, 'cfg': None}
                          for node, ip in zip(nodes, nodes_internal)}

    LOG.info('creating %s session to %s', session_type, recvh)
    r_exec = executor.Executor(node_exec_cfgs[recvh]['ssh'],
                               internal_ip=node_exec_cfgs[recvh]['int_ip'],
                               container_params=node_exec_cfgs[recvh]['cfg'])

    LOG.info('creating %s sessions to %s', session_type, sendhs)
    s_execs = [executor.Executor(node_exec_cfgs[sendh]['ssh'],
                                 internal_ip=node_exec_cfgs[sendh]['int_ip'],
                                 container_params=node_exec_cfgs[sendh]['cfg'])
               for sendh in sendhs]

    _, staged_src = _stage_transperf_src()
    if singlesrv_cfg['enabled']:
        # In this case all executor sessions just point to the same box,
        # so we can just reuse r_exec in use_rootns mode.
        _init_containers(r_exec, singlesrv_cfg, nodes, staged_src,
                         os.path.join(ifacecfg_dir, ifacecfg_rel)
                         if ifacecfg_rel is not None else None, ip_mode)
        # Copy the container hosts file over to the test output directory.
        singlesrv_cfg['hosts'] = os.path.join(singlesrv_cfg['out_dir'], 'hosts')

    if singlesrv_cfg['enabled']:
        if singlesrv_cfg['local']:
            # launch.py and the send/recv/orch processes are all on the same
            # node, and out_dir is accessible from all of them.
            out_dir_for_servers = out_dir
        else:
            # launch.py is local but send/recv/orch are remote; point them to
            # their own directories.
            out_dir_for_servers = os.path.join(
                singlesrv_cfg['out_dir'], 'fs', '{node}',
                transperf.path.EXP_OUT_DIR.lstrip('/'))
    else:
        out_dir_for_servers = os.path.join(transperf.path.TRANSPERF_TMP)
    _init_servers(r_exec, s_execs, binary_dirs, out_dir, sync, staged_src,
                  singlesrv_cfg)

    _start_servers(r_exec, s_execs, rport, sport, sslog_interval, ifacecfg_rel,
                   singlesrv_cfg, ip_mode, save_pcap, save_kern_debug,
                   out_dir_for_servers)
    _collect_results(r_exec, s_execs, out_dir, singlesrv_cfg)

    retcode = _process_output(out_dir, has_xplot, open_page, skip_pcap_scan)

    # Save a copy of the results (e.g. for debugging, wher outdir vanishes).
    if save_dir is not None:
        LOG.info('Saving a copy of results to %s', save_dir)
        _mkdir_if_not_exists(save_dir)
        shell.run('cp -r {out} {save}'.format(out=out_dir,
                                              save=save_dir + os.path.sep))
    else:
        LOG.info('Saving a copy of results not requested, skipping.')

    # Cleanup virtual environment if specified/relevant.
    if singlesrv_cfg['enabled'] and singlesrv_cfg['cleanup']:
        tgt_dir = singlesrv_cfg['out_dir']
        cmd = shell.py_cmd([], 'virtcleanup.py', '-v', '-d', tgt_dir)
        exec_ctx = shell if singlesrv_cfg['local'] else r_exec
        out, err, returncode = exec_ctx.run(cmd)
        LOG.info('Cleanup output: [%d] [%s] stderr: [%s]',
                 returncode, out, err)

    return retcode


def _process_output(out_dir, has_xplot, open_page, skip_pcap_scan,
                    gen_from_file=None):
    """Given an out_dir or archive for completed test, generate results."""
    if gen_from_file is not None:
        cmd = ['tar', '-C', out_dir, '-xvzf', gen_from_file]
        if gen_from_file == '-':
            assert subprocess.call(
                cmd, stdin=sys.stdin, stdout=sys.stdout,
                stderr=sys.stdout) == 0, 'Read(stdin) failed.'
        else:
            assert subprocess.call(cmd) == 0, 'Command failed: %s' % (str(cmd))

    ret = _do_process_output(out_dir, has_xplot, open_page, skip_pcap_scan)
    return ret


def _do_process_output(out_dir, has_xplot, open_page, skip_pcap_scan):
    """Given an out_dir for a completed transperf test, generate results."""
    if has_xplot:
        gen.gen_xplots(out_dir)

    return gen.gen_transperf_pages(out_dir, has_xplot, open_page,
                                   skip_pcap_scan)


def _init_containers(target, singlesrv_cfg, nodes, staged_src, ifacecfg,
                     ip_mode):
    """Initialize node containers on target for transperf single-server mode."""
    LOG.debug('Initialize containers. Sourcefiles: %s', staged_src)
    # Push source to physical node.
    target.run('mkdir -p ' + transperf.path.get_transperf_home())
    target.push(staged_src, transperf.path.get_transperf_home())
    # Will also need virt-setup binaries. If we're running in manual-testing
    # mode we need to provide a working binary in the invocation directory.
    if not os.path.exists('./brctl'):
        LOG.error('No brctl available in current dir %s - failing.',
                  os.getcwd())
        assert False
    if not os.path.exists('./nsenter'):
        LOG.error('No nsenter available in current dir %s - failing.',
                  os.getcwd())
        assert False
    target.push('./brctl', transperf.path.get_transperf_home())
    target.push('./nsenter', transperf.path.get_transperf_home())
    # Push interface config to physical node.
    physhost_ifacecfg_dir = os.path.join(singlesrv_cfg['out_dir'],
                                         transperf.path.IFACE_CFG_DIR)
    target.run('mkdir -p %s' % physhost_ifacecfg_dir)
    if ifacecfg is not None:
        target.push(ifacecfg, physhost_ifacecfg_dir)
        ifacecfg_path = os.path.join(physhost_ifacecfg_dir,
                                     os.path.basename(ifacecfg))

    # Build and execute virtsetup.py command.
    env_vars = []
    virtsetup_params = [env_vars]
    virtsetup_params.extend(['virtsetup.py', '-v',
                             '-d', singlesrv_cfg['out_dir'],
                             '-b', singlesrv_cfg['bridge'],
                             '--ip_mode', str(ip_mode)])
    if ifacecfg is not None:
        virtsetup_params.extend(['--ifacecfg', ifacecfg_path,])
    virtsetup_params.extend(nodes)
    # Execute virtsetup.py with built params list and check for success.
    out, err, returncode = target.run(shell.py_cmd(*virtsetup_params), nohup=True)
    LOG.debug('Container init returned: \nstdout: [%s]\nstderr: [%s]', out, err)
    if err and returncode != 0:
        raise RuntimeError(err)


def get_container_node_exec_cfgs(singlesrv_cfg, nodes):
    """Generate node container exec configurations for single-server mode."""
    target = singlesrv_cfg['host']
    remote_dir = singlesrv_cfg['out_dir']
    exec_cfg = {}
    for node in nodes:
        node_root = virtsetup.ContainerCtx.get_node_root(remote_dir, node)
        uts_ns = virtsetup.ContainerCtx.get_node_uts_ns_path(remote_dir, node)
        net_ns = virtsetup.ContainerCtx.get_node_net_ns_path(node)
        pid_ns = virtsetup.ContainerCtx.get_node_pid_ns_path(remote_dir, node)
        pidfile = virtsetup.ContainerCtx.get_node_pidfile(remote_dir, node)
        container_params = {'node': node, 'root': node_root, 'netns': net_ns,
                            'uts': uts_ns, 'pid': pid_ns,
                            'pidfile': pidfile}
        node_cfg = {'ssh': 'root@%s' % target if target is not None else None,
                    'int_ip': None,
                    'cfg': container_params}
        exec_cfg[node] = node_cfg
    return exec_cfg

if __name__ == '__main__':
    sys.exit(main())
