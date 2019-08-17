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

"""Provides simple utilities to run subprocess commands."""

import logging
import os
import re
import subprocess
import tempfile

import transperf


LOG = logging.getLogger('transperf/shell')


RED = '91'
GREEN = '92'


def colorize(text, color=GREEN):
    """Wraps the text with the codes for the given color.

    Args:
        text: The text.
        color: The color.

    Returns:
        The text wrapped with color codes.

    """
    return '\033[%sm%s\033[0m' % (color, text)


def bg(cmd):
    """Runs a command in the background."""
    # Expand {sudo} field in commands as appropriate for this user.
    cmd = cmd.format(sudo='sudo' if os.geteuid() != 0 else '')

    outf = tempfile.NamedTemporaryFile(delete=False)
    errf = tempfile.NamedTemporaryFile(delete=False)
    proc = subprocess.Popen(cmd, shell=True, stdin=open(os.devnull, 'rb'),
                            stdout=outf, stderr=errf)
    proc.outf = outf
    proc.errf = errf
    LOG.debug('run %s in pid %s', cmd, proc.pid)
    return proc


def wait(proc):
    """Waits on a process and returns the tuple of its std out and std err."""
    proc.wait()
    proc.outf.seek(0)
    proc.errf.seek(0)

    out_joined = proc.outf.read()
    if out_joined:
        # The escape codes are to print the stdout in green.
        # Note that we limit the standard output to 2K for two reasons:
        # 1) On some machines, programs with large standard output logs
        #    are mysteriously killed (due to limits).
        # 2) Having large outputs results in slower experiments, due to limits
        #    in ssh throughput.
        LOG.debug(colorize('stdout of %s:\n%s%s', GREEN),
                  proc.pid,
                  '...' if len(out_joined) > 2048 else '',
                  out_joined[-2048:])

    err_joined = proc.errf.read()
    if err_joined:
        LOG.debug(colorize('stderr of %s:\n%s', RED), proc.pid, err_joined)

    return (out_joined, err_joined, proc.returncode)


def terminate(proc):
    """Terminates the process and waits for it.

    Args:
        proc: Process to terminate.

    Returns:
        The standard output and the standard error of the process.
    """
    proc.terminate()
    return wait(proc)


def run(cmd):
    """Runs the command and returns its standard output and error.

    Args:
        cmd: The command.

    Returns:
        A tuple of lines in stdout and stderr.
    """
    proc = bg(cmd)
    return wait(proc)


def py_cmd(env_vars, mod, *args):
    """Returns a command string to run a python module.

    This method prepends the PYTHONPATH along with the appropriate python
    binary to run the command.

    Args:
        env_vars: Environment variables for command.
        mod: The python module.
        *args: The arguments of the command.

    Returns:
        The full shell command to run the python module.
    """
    # Make sure all arguments are string.
    args = [str(arg) for arg in args]
    env_cmd = 'env PYTHONPATH=%s' % transperf.path.get_transperf_pypath()
    for (var, value) in env_vars:
        env_cmd += ' %s=%s' % (var, value)

    return '{sudo} %s python %s/%s %s' % (
        env_cmd, transperf.path.get_transperf_home(), mod,
        ' '.join(args))


def list_ifaces():
    """Lists all the interfaces on the machine.

    Returns:
        The list of all interfaces on this machine.
    """
    # Regex: Match ^<number>: <iface>(@<related): ...$ and return <iface>
    if_rgx = re.compile(r'^\d+:\s+([^@]+)(?:@[^@]+)?:\s+.*$')
    output, _, _ = run('ip link show')
    lines = [line.strip() for line in output.splitlines()]
    matches = [if_rgx.match(line) for line in lines]
    return [match.group(1) for match in matches if match is not None]


def init_ifaces():
    """Initializes all the interfaces on the machine.

    Returns:
        The number of interfaces on this machine.
    """
    i = 0
    while True:
        iface = 'eth%d' % i
        _, err, _ = run('ip link show %s' % iface)
        if err:
            return i

        run('{sudo} ip link set %s up' % iface)
        i += 1
