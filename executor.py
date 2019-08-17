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

"""Executor enables command execution + file transfer for transperf test nodes.

Nodes may either be physical servers or virtual nodes via Linux containers.
This module wraps ssh and scp commands as necessary, providing convenient APIs.
"""

import logging
import os
import socket

import transperf
from transperf import make_iterable
from transperf import path
from transperf import shell

LOG = logging.getLogger('transperf/executor')


class Executor(object):
    """Executor runs commands and copies files to/from nodes.

       A node may be:
       1. A remote physical server.
       2. A container node running on a remote physical server.
       3. The local server.

    Executor wraps the ssh (if needed) and rsync commands and provides
    easy-to-use APIs.

    Attributes:
        conn_string: what is passed to the "ssh" command in the form of
                     [user@]host[:port]. If it is None, we target the local node
                     that we are executing on.
        container_params: A dictionary of parameters for container operation.
    """

    valid_container_params = set(['node', 'netns', 'root', 'uts',
                                  'pid', 'pidfile'])

    def __init__(self, conn_string, internal_ip=None, container_params=None):
        """Inits Executor using the given conn_string.

        Note: a container might be specified for the command, as a parameters
        dict of the following format:
        container_params = {
          'node' : 'some_node_name',
          'netns': '/path/to/persistent/netns',
          'mount': '/path/to/persistent/mount',
          'uts': '/path/to/persistent/uts',
          'root' : '/path/to/root/fs',
        }

        If container_params is None/{}, we execute in the root namespace.
        Else, we use nsenter with the provided parameters.

        Args:
            conn_string: see the conn_string attribute.
            container_params: specifiers for which container to run command in
        """
        LOG.debug('Setup executor with conn_string: %s', conn_string)
        self.conn_string = conn_string
        self.internal_ip = internal_ip
        self.__validate_container_params(container_params)

    def __validate_container_params(self, container_params):
        """Validates provided container parameters.

            Rules:
            1. If no parameters are provided, we accept. This is equivalent to
            executing all commands in the root namespace of the destination
            server. We accept either None or an empty dict.

            2. If parameters are provided, they must be a dict, where the keys
            are in self.valid_container_params. That said, extraneous keys are
            fine, we just strip them.

            3. If we have a non-empty dict passed in, all required keys must be
            there, and have a non-empty string-type value.

        Args:
            container_params: The parameters we are validating.

        Returns:
            Nothing.

        Raises:
            TypeError: When the input is not a dict and not None. Also raised if
            a key type has an invalid value type (not str).
            KeyError: Raised when a mandatory parameter is not found.
            ValueError: When a param value is the empty string.
        """
        self.container_params = None

        # Check empty params case and accept.
        if container_params is None:
            return
        # Ensure it is a dict if not null.
        if not isinstance(container_params, dict):
            raise TypeError('Container parameters is type %s, not dict' %
                            str(type(container_params)))
        # Accept the empty case.
        if not container_params:
            return

        # Now we have a non-empty dict. Cleanup unused keys.
        keys_to_purge = set()
        for key, val in container_params.iteritems():
            if key not in self.valid_container_params:
                keys_to_purge.add(key)
        for key in keys_to_purge:
            del container_params[key]

        # Now ensure our keys are all present/not none.
        for key in self.valid_container_params:
            if key not in container_params:
                raise KeyError('Mandatory container_param %s'
                               ' not found in executor settings.' % key)
            val = container_params[key]
            if not isinstance(val, str):
                raise TypeError('Container key %s: %s is invalid type %s' %
                                key, val, type(val))
            if not val:
                raise ValueError('Container key %s has empty value.' % key)

        # Validation complete.
        self.container_params = container_params

    def addr(self):
        """Returns the host address of the connection string.

        If a internal IP was specified by the user, returns the internal IP.
        """
        if not self.conn_string:
            return socket.gethostname()
        if self.internal_ip:
            return self.internal_ip
        return self.conn_string.split('@')[-1].split(':')[0]

    def host(self):
        """Returns the logical host addressed by this object.

        In the physical server (normal) mode, this is self.addr().
        Else, it is the name of the container this proxy addresses.

        Returns:
            The logical hostname pointed by this instance.
        """
        if self.container_params is not None:
            return self.container_params['node']
        return self.addr()

    def bg(self, cmd, use_rootns=True):
        """Runs a command in background (without blocking)."""
        return shell.bg(self._build_executor_cmd(cmd, use_rootns))

    def run(self, cmd, use_rootns=True, nohup=False):
        """Runs the command, possibly using ssh.

        Args:
            cmd: The command.
            use_rootns: For ssh wrappers normally targeted at a container,
                        specify that we must execute in the root namespace
                        instead.

        Returns:
            A tuple of lines in stdout and stderr.
        """
        return shell.run(self._build_executor_cmd(cmd, use_rootns, nohup))

    def push_bg(self, srcs, dst, dst_is_dir=True, use_rootns=True):
        """Copies a file or a directory to remote using rsync in background.

        Args:
            srcs: The source path(s).
            dst: The (remote) destination path. Note: dst should not include the
                 conn_string.
            dst_is_dir: We are specifying a directory to copy into, not a file.
            use_rootns: Whether we should execute this command in the root
                        namespace of the physical server pointed to by this Ssh
                        object (see self.addr()) or in the context of the
                        optionally specified virtual node (see self.host()).

        Returns:
            The process.

        Raises:
            RuntimeError: if we have multiple sources to copy but are writing
                           to a file and not a directory.
        """
        # Arguments:
        # -r: Recursive copy
        # -L: Follow symlinks and copy underlying files
        # -p: Preserve permissions.
        # -t: Preserve modification time.
        # Note that -u is not present; when copying files over for remote
        # machines to use, we unconditionally copy what we have.
        opts = ['-rLpt']
        assert srcs is not None
        srcs = make_iterable(srcs)
        assert srcs
        if len(srcs) > 1 and not dst_is_dir:
            raise RuntimeError('Destination %s:%s must be dir, >1 srcs!: %s' %
                               (self.conn_string, dst, srcs))
        dst = os.path.normpath(dst)
        if not use_rootns:
            dst = self.__containerize_path(dst)

        # Append rsync+ssh target if appropriate.
        abs_dst = dst
        if self.conn_string:
            abs_dst = '%s:%s' % (self.conn_string, dst)
        # Rsync requires a trailing slash to treat the target as a directory.
        if dst_is_dir:
            abs_dst += os.path.sep
        return shell.bg(' '.join(['rsync'] + opts + srcs + [abs_dst]))

    def push(self, srcs, dst, dst_is_dir=True, ignore_errors=False):
        """Copies a file or a directory to the remote host using rsync.

        Args:
            srcs: The source path(s).
            dst: The destination path. Note: dst should not include the
                 conn_string.
            dst_is_dir: We are specifying a directory to copy into, not a file.
            ignore_errors: do not throw an IOError if there was an error in
                           rsync.

        Raises:
            IOError: if rsync fails to copy the file/directory.
        """
        _, err, returncode = shell.wait(self.push_bg(srcs, dst, dst_is_dir))
        if err and returncode != 0 and not ignore_errors:
            raise IOError(err)

    def pull_bg(self, srcs, dst, dst_is_dir=True, use_rootns=True):
        """Fetches a file or a directory from remote using rsync in background.

        Args:
            srcs: The (remote) source path(s). Note: src should not include the
                  conn_string.
            dst: The destination path.
            dst_is_dir: We are specifying a directory to copy into, not a file.
            use_rootns: Whether we should execute this command in the root
                        namespace of the physical server pointed to by this Ssh
                        object (see self.addr()) or in the context of the
                        optionally specified virtual node (see self.host()).

        Returns:
            The process.

        Raises:
            RuntimeError: if we have multiple sources to copy but are writing
                           to a file and not a directory.

        """
        # Arguments:
        # -r: Recursive copy
        # -L: Follow symlinks and copy underlying files
        # -p: Preserve permissions.
        # -t: Preserve modification time.
        # -u: Only copy over files that are newer than local copies. This fixes
        #     a bug where stale data from a previous run can overwrite fresh
        #     data from a new run.
        args = ['-rLptu']
        srcs = make_iterable(srcs)
        if len(srcs) > 1 and not dst_is_dir:
            raise RuntimeError('Destination %s:%s must be dir, >1 srcs!: %s' %
                               (self.conn_string, dst, srcs))
        if not use_rootns:
            srcs = [self.__containerize_path(src) for src in srcs]
        # Prefix for source node if we're operating remotely.
        src_pfx = self.conn_string + ':' if self.conn_string else ''
        if len(srcs) == 1:
            abs_srcs = src_pfx + srcs[0]
        else:
            abs_srcs = ' '.join(['%s%s' % (src_pfx, src) for src in srcs])
        dst = os.path.normpath(dst)
        if dst_is_dir:
            dst += os.path.sep
        return shell.bg(' '.join(['rsync'] + args + [abs_srcs, dst]))

    def pull(self, srcs, dst, dst_is_dir=True, ignore_errors=False):
        """Fetches a file or a directory from the remote host using rsync.

        Args:
            srcs: The source path(s). Note: src should not include the
                  conn_string.
            dst: The destination path.
            dst_is_dir: We are specifying a directory to copy into, not a file.
            ignore_errors: do not throw an IOError if there was an error in
                           rsync.

        Raises:
            IOError: if rsync fails to copy the file/directory.
        """
        _, err, returncode = shell.wait(self.pull_bg(srcs, dst, dst_is_dir))
        if err and returncode != 0 and not ignore_errors:
            raise IOError(err)

    def __containerize(self, cmd):
        """Wraps command for container-based execution."""
        if not self.container_params:
            raise RuntimeError('Cmd %s (target %s) has no container params!' %
                               cmd, self.conn_string)
        netns = self.container_params['netns']
        pidfile = self.container_params['pidfile']
        initpid = '$(cat {pidfile} | tr -d \'\\n\')'.format(pidfile=pidfile)
        if self.conn_string:  # Escape '$' over ssh
            initpid = '\\' + initpid
        if self.container_params['root']:
            container_root_specifier = 'env {key}=${path}'.format(
                key=path.TRANSPERF_CONTAINER_ROOT_KEY,
                path=self.container_params['root'])
        else:
            container_root_specifier = ''
        template = '{nsenter} -p -u -n{netns} -t {initpid} '
        template += '{rootspec} sh -c \'{cmd}\''
        # The binary must be present in TRANSPERF_HOME.
        nsenter_path = os.path.join(transperf.path.get_transperf_home(),
                                    'nsenter')
        return template.format(nsenter=nsenter_path, netns=netns,
                               initpid=initpid,
                               rootspec=container_root_specifier, cmd=cmd)

    def __containerize_path(self, pathstr):
        """Wraps path for container-based file push/pull."""
        if not self.container_params:
            raise RuntimeError('Executor to %s has no container params.' %
                               self.conn_string)
        return os.path.normpath(os.path.sep.join([self.container_params['root'],
                                                  pathstr]))

    def _build_executor_cmd(self, cmd, use_rootns, nohup=False):
        """Returns the command line for a given command string.

        Args:
            cmd:        The command string to be executed.
                        If not using ssh, or using ssh and the user is
                        not 'root', then any '{sudo}' field in this cmd string
                        is replaced with 'sudo'; otherwise, it is replaced with
                        '' since root can execute things directly.

            use_rootns: Whether we should execute this command in the root
                        namespace of the physical server pointed to by this
                        object (see self.addr()) or in the context of the
                        optionally specified virtual node (see self.host()).

        Returns:
            A list representing the command.
        """
        # Containerize if we need it.
        if not use_rootns:
            cmd = self.__containerize(cmd)
        # Sudo if we need it.
        need_sudo = (not self.conn_string or
                     not self.conn_string.startswith('root@'))
        cmd = cmd.format(sudo='sudo' if need_sudo else '')
        # Are we executing locally?
        if not self.conn_string:
            return cmd
        # If not, run over ssh.
        if nohup:
            return ' '.join(['ssh', self.conn_string, '"nohup {} > /dev/null"'.format(cmd.strip())])

        return ' '.join(['ssh', self.conn_string, '"%s"' % cmd])

    def get_container_root_dir(self):
        return (self.container_params['root']
                if self.container_params is not None else None)

    def __repr__(self):
        """String representation of an Executor."""
        return "Executor: {}".format(self.conn_string)
