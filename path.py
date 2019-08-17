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

"""Common utilities for finding the binaries used by transperf."""

import os
import re
import subprocess

# Transperf home directory.
# We do not use /root due to space limitations.
TRANSPERF_HOME = '/home/transperf'

# Python path used by transperf.
TRANSPERF_PYPATH = os.path.normpath(os.path.join(TRANSPERF_HOME, '..'))

# Experiment output directory.
TRANSPERF_TMP = '/home/tmp/transperf'
EXP_OUT_DIR = os.path.join(TRANSPERF_TMP, '__out')

# Temporary output directory.
TMP_DIR = os.path.join(TRANSPERF_TMP, '__tmp_out')

# Directory with per-node interface configs on the machine invoking transperf.
IFACE_CFG_DIR = '__iface_cfg'

_paths = {}

TC_LIB_PATH = '/usr/lib/tc'

_TC = 'tc'
_TC_LIB_FILE = 'paretonormal.dist'
_NPERF = 'netperf'
_NSERV = 'netserver'
_BRCTL = 'brctl'
_NSENTER = 'nsenter'
_NODEINIT = 'nodeinit.py'
_BINS = [_TC, _TC_LIB_FILE, _NPERF, _NSERV, _BRCTL, _NSENTER, _NODEINIT]


TRANSPERF_CONTAINER_ROOT_KEY = 'TRANSPERF_CONTAINER_ROOT'


def _transperf_container_root(container_root):
    return (container_root if container_root is not None
            else (os.environ[TRANSPERF_CONTAINER_ROOT_KEY]
                  if TRANSPERF_CONTAINER_ROOT_KEY in os.environ else ''))


def get_transperf_home(container_root=None):
    return _transperf_container_root(container_root) + TRANSPERF_HOME


def get_transperf_pypath(container_root=None):
    return _transperf_container_root(container_root) + TRANSPERF_PYPATH


def get_exp_out_dir(container_root=None):
    return _transperf_container_root(container_root) + EXP_OUT_DIR


def get_tmp_dir(container_root=None):
    return _transperf_container_root(container_root) + TMP_DIR


def all_files(dir_, name=None, regex=None):
    """List all files with the given extension and name in a directory.

    Args:
        dir_: Is the directory.
        name: Matched against file names if not None or empty.
        regex: Match against file name if not None or empty.

    Yields:
        Tuples of [directory path, filename] for all files that match.
    """
    for dirpath, _, filenames in os.walk(dir_):
        for f in filenames:
            if (name and f == name) or (regex and re.match(regex, f)):
                yield (dirpath, f)


def list_files(files_path):
    """Yields all the files in the path and all its subdirectories."""
    for dpath, _, files in os.walk(files_path):
        for f in files:
            yield os.path.abspath(os.path.join(dpath, f))


def list_dirs(path):
    """Yields all the directories in the path and all its subdirectories."""
    for dpath, dnames, _ in os.walk(path):
        for dname in dnames:
            yield os.path.abspath(os.path.join(dpath, dname))


def get_sys_binary(binary):
    try:
        output = subprocess.check_output(['which', binary]).splitlines()[0]
    except subprocess.CalledProcessError:
        output = None
    return output


def _init(paths):
    """Initializes the tc, netperf and netserver paths.

    Args:
        paths: The dictionary of binary paths.
    """
    cwd = os.getcwd()
    root = TRANSPERF_HOME

    search_path = [root, cwd, TC_LIB_PATH]

    for binary in _BINS:
        for base in search_path:
            path = os.path.join(base, binary)
            if os.path.exists(path):
                paths[binary] = path
                break
        if binary in paths:
            continue
        # If all else fails, check if system provides it; if so, use it.
        paths[binary] = get_sys_binary(binary)


_init(_paths)


def resolve_binary_path_for_cmd(cmd):
    """Resolve binary path for given command, if able."""
    if cmd in _paths:
        return _paths[cmd]
    return None


def _resolve_binary_path_for_timed_cmd(machine_cmd):
    """Resolve single machine command.

    Args:
        machine_cmd: A tuple contains string format command and start time.

    Returns:
        A new command with the same format but resolved binary path.
    """
    # The first element is a string containing commands (separated by ';')
    cmd_lines = [cmd for cmd in machine_cmd[0].split(';') if cmd]
    new_cmds = []
    for cmd in cmd_lines:
        split_cmd = cmd.split()
        if not split_cmd:
            continue
        new_cmd = split_cmd[0]
        para = split_cmd[1:]
        new_bin = os.path.basename(new_cmd)
        new_cmd = _paths[new_bin] if new_bin in _BINS else new_cmd
        para.insert(0, new_cmd)
        new_cmds.append(' '.join(para))
    return (';'.join(new_cmds), machine_cmd[1])


def resolve_cmds_path(cmds, singlesrv_mode):
    """Resolve the cmds path if in single server mode.

    Args:
        cmds: A list of sender/receiver commands.
        singlesrv_mode: A bool on whether running in single server mode.

    Returns:
        The commands that path has been resolved if needed
        (in single server mode).
    """
    if not singlesrv_mode:
        return cmds

    r_cmds = []
    for cmd in cmds:
        r_cmds.append(_resolve_binary_path_for_timed_cmd(cmd))
    return r_cmds


def tc():
    """Returns the path of tc."""
    return _paths[_TC]


def tc_lib_dir():
    """Returns the directory containing library files used by tc."""
    return os.path.dirname(_paths[_TC_LIB_FILE])


def netserver():
    """Returns the path of netserver."""
    return _paths[_NSERV]


def netperf():
    """Returns the path of netperf."""
    return _paths[_NPERF]


def brctl():
    """Returns the path of brctl."""
    return _paths[_BRCTL]


def nsenter():
    """Returns the path of nsenter."""
    return _paths[_NSENTER]


def nodeinit():
    """Returns the path of nodeinit.py."""
    return _paths[_NODEINIT]
