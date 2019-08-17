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

"""transperf is a tool to experiment with TCP congestion control.
"""

# Update this version number for each tagged release.
__version__ = "0.1.0"

import collections
import copy
import logging
import math
import md5
import numbers
import os
import socket
import sys
from transperf import path

LOG = logging.getLogger('transperf/init')
_BBR = ['bbr', 'bbr2']

# Static port used to store array into convergence metric.
METRIC_NO_PORT = -1

# The time bucket size in seconds used to check convergence.
CONVERGENCE_BUCKET = 1.0

# TODO(soheil): We should be able to override these in command line arguments.

# Names for built-in NetEm data distributions (no data file needed).
DATA_FILE_KEYWORDS = ['uniform', 'normal', 'pareto', 'paretonormal']


ip_modes = {
    4: socket.AF_INET,
    6: socket.AF_INET6
}


listen_addrs = {
    socket.AF_INET: '0.0.0.0',
    socket.AF_INET6: '::',
}


def parse_ip_map(hosts_file):
    """Read hosts file and return a map from hostname to IP."""
    ip_map = {}
    LOG.info('parse_ip_map: hosts_file=%s', hosts_file)
    try:
        lines = open(hosts_file).readlines()
        for line in lines:
            splits = line.rstrip('\r\n').split()
            if len(splits) == 2:
                ip, host = splits
                ip_map[host] = ip
            else:
                LOG.info('Invalid input line: [%s]', line)
    except IOError:
        LOG.info('Could not open hosts_file [%s]', hosts_file)
    return ip_map


def _type_error(actual, expected):
    """Returns a ValueError that the actual type is not the expected type."""
    msg = 'invalid type: %s is not in %s' % (actual.__name__,
                                             [t.__name__ for t in expected])
    return ValueError(msg)


def assert_type(ins, *args):
    """Asserts that instance is of one of the expected types.

    Args:
        ins: The instance.
        *args: The expected type.

    Raises:
        ValueError: If the ins is not an instance of exp_t.
    """

    for exp_t in args:
        if isinstance(ins, exp_t):
            return

    raise _type_error(type(ins), args)


def make_iterable(val):
    """If val is not an iterable, it puts the val in a list.

    Args:
        val: The value.

    Returns:
        Returns the value if it is iterable, otherwise returns a list that
        contains the value.
    """
    if isinstance(val, collections.Iterable) and not isinstance(val,
                                                                basestring):
        return val

    return [val]


DEFAULT_CC_PARAMS = {
    'bbr': 'flags=0x1,debug_with_printk=1',
    'bbr2': 'flags=0x1,debug_with_printk=1',
}


class Burst(object):
    """Represents a burst from netperf.

    Attributes:
        wait: Inter-burst wait in seconds (can be float) between two rounds.
        rounds: How many rounds of repeated request/response to send.
        repeat: How many requests and responses send back-to-back per round.
        req: Request size.
        res: Response size.
    """

    def __init__(self, wait, rounds, repeat, req, res):
        self.wait = wait
        self.rounds = rounds
        self.repeat = repeat
        self.req = req
        self.res = res

    def __str__(self):
        return 'w%s_r%s_rep%s_req%s_res%s' % (
            self.wait, self.rounds, self.repeat, self.req, self.res)

    def pretty_str(self):
        return 'burst(wait=%s,rounds=%s,repeat=%s,req=%s,res=%s)' % (
            self.wait, self.rounds, self.repeat, self.req, self.res)


def burst(wait=-1, rounds=-1, repeat=-1, req=-1, res=-1):
    """Creates a burst specification.

    Works only when netperf is compiled with --enable-intervals.
    For example, burst(wait=1, rounds=2, repeat=10, req=2000, res=1) will:
        1) send 10 back to back 2KB requests and wait to get all 1B reponses.
        2) send 10 back to back 2KB requests and wait to get all 1B reponses.
        3) sleep for 1sec minus the time spent in 1 and 2.
        4) goto 1.

    Args:
        wait: Inter-burst wait in seconds (can be float) between two rounds.
        rounds: How many rounds of repeated request/response to send.
        repeat: How many requests and responses send back-to-back per round.
        req: Request size.
        res: Response size.

    Returns:
        An object that represents the given burst.
    """
    return Burst(wait, rounds, repeat, req, res)


class Tool(object):
    """Represents a tool to run a connection with.

    Attributes:
        binaries: The name of binaries required to run this tool.
        default_path: Default path to run the binaries if not locally available.
        paths: A dictionary containing the paths for binaries.
        options_dict: Dictionary containing options for tool or None.
    """

    def __init__(self, binaries, default_path='', options=None):
        self.binaries = binaries
        self.default_path = default_path
        self.options_dict = options if isinstance(options, dict) else {}

        self.paths = dict()
        # First look within the binaries resolved by transperf.path. If not
        # present, look in the (possibly-per-container) /home/transperf, $PWD,
        # or otherwise use the system $PATH.
        for binary in binaries:
            # First transperf.path
            self.paths[binary] = path.resolve_binary_path_for_cmd(binary)
            if self.paths[binary] is not None:
                continue
            # Fallback will be the system path.
            self.paths[binary] = binary
            # But before falling back, check the (maybe containerized) transperf
            # home and current working directory.
            for base in [path.get_transperf_home(), os.getcwd()]:
                full_path = os.path.join(base, binary)
                LOG.info('Checking: %s for existence of %s', full_path, binary)
                if os.path.exists(full_path):
                    LOG.info('Found %s for %s', full_path, binary)
                    self.paths[binary] = full_path
                    break
        LOG.info('After resolving binaries: paths=%s', str(self.paths))

    def sender_cmd(self, conn_, host, port, dur, sender_addr):
        """Returns the command to run the sender connection.

        Args:
            conn_: Sender connection object.
            host: Receiver host.
            port: Port to use for this connection.
            dur: Duration of experiment.
            sender_addr: Address of the sender.
        """
        pass

    def receiver_cmds(self, senders_port_to_addr, till_start_sec):
        """Returns the receiver commands for this tool.

        Args:
            senders_port_to_addr: Dict of sender port to address.
            till_start_sec: Time till exp start time in second.
        """
        # TODO(soheil): add control port.
        pass

    def throughput(self, output):
        """Returns the throughput out of the tool output."""
        pass

    def binary_path(self, binary):
        """Returns the binary path depending the system settings."""
        return self.paths.get(binary)

    def name(self):
        """Returns the name of the tool."""
        pass


class Netperf(Tool):
    """Represents netperf (www.netperf.org)."""

    def __init__(self):
        super(Netperf, self).__init__(binaries=['netperf', 'netserver'])
        self.__np_stats = [
            'THROUGHPUT',
            'THROUGHPUT_UNITS',
            'LOCAL_TRANSPORT_RETRANS',
            'LOCAL_BYTES_SENT',
        ]

    def sender_cmd(self, conn_, host, port, dur, sender_addr):
        binary_path = self.binary_path('netperf')

        # connection's duration overrides the experiment duration.
        if conn_.dur:
            dur = conn_.dur

        # If dur is not positive, we cannot run "netperf -l 0/-n" since it will
        # run forever. Instead, we run a simple echo that outputs we cannot run
        # netperf. This ensures that shell.bg returns a process and
        # it outputs useful debug information.
        if dur <= 0 and conn_.size <= 0:
            return 'echo "cannot run netperf with duration of %s"' % (dur)

        # connection's size overrides both connection and experiment durations.
        if conn_.size > 0:
            dur = -conn_.size

        if conn_.upload:
            type_args = '-t TCP_MAERTS'
        elif conn_.burst and conn_.burst.res:
            type_args = '-t TCP_RR'
        else:
            type_args = ''

        burst_args = ''
        if conn_.burst:
            burst_args = '-w %s' % (1000 * conn_.burst.wait)
            if conn_.burst.rounds >= 1:
                burst_args += ' -b %s' % conn_.burst.rounds

        reqres_args = ('-b %s -r "%s,%s"' % (conn_.burst.repeat,
                                             conn_.burst.req,
                                             conn_.burst.res)
                      ) if conn_.burst else ''

        return ('%s %s -H %s -l "%d" %s -- -k "%s" -d send -g -K %s '
                '-P %d %s') % (binary_path, type_args, host, dur, burst_args,
                               ','.join(self.__np_stats), conn_.cc, port,
                               reqres_args)

    def receiver_cmds(self, senders_port_to_addr, till_start_sec):
        binary_path = self.binary_path('netserver')
        ip_mode = self.options_dict.get('ip_mode', '-6')
        assert ip_mode in ['-4', '-6']
        return ['%s %s -- -g' % (binary_path, ip_mode)]

    def throughput(self, output):
        for line in output.split('\n'):
            if line.startswith('THROUGHPUT='):
                return line[len('THROUGHPUT='):]
        return ''

    def name(self):
        return 'netperf'

    def __str__(self):
        return self.name()


# Supported benchmarking tools in transperf.
NETPERF = Netperf()
TOOLS = {
    NETPERF.name(): NETPERF,
}


class Conn(object):
    """Represents a set of connections with one specific congestion control.

    Attributes:
        cc: The name of the congestion control algorithm.
        num: The number of connection of this type.
        start: The initial delay before starting the connection in seconds.
        dur: The duration of the connection in seconds.
        size: The number of bytes to send on the connection.
        burst: The connection burst specification (None means an stream).
        params: The parameters of the CC kernel module.
        sender: The sender machine index.
        upload: Whether the connection sends in the opposite direction.
        tool: The tool to run for tests.
    """

    def __init__(self, cc, num, start, dur, size, burst,
                 params, sender, upload, tool):
        assert_type(cc, basestring)
        assert_type(num, int)
        assert_type(start, int, float)
        assert_type(sender, int)
        assert_type(size, int)
        assert_type(tool, basestring, Tool)
        assert start >= 0, 'connection start time must be positive'
        assert dur >= 0, 'connection duration must be positive'
        self.cc = cc
        self.num = num
        self.start = start
        self.dur = dur
        self.size = size
        self.burst = burst
        if cc in DEFAULT_CC_PARAMS and DEFAULT_CC_PARAMS[cc] not in params:
            self.params = DEFAULT_CC_PARAMS[cc] + ',' + params
        else:
            self.params = params
        self.sender = sender
        self.upload = upload
        if isinstance(tool, basestring):
            self.tool = TOOLS.get(tool)
        else:
            self.tool = tool

    def burst_tuple(self):
        """Returns the tuple representing the burst."""
        return (self.burst.wait, self.burst.rounds, self.burst.repeat,
                self.burst.req, self.burst.res) if self.burst else None

    def __str__(self):
        # TODO(soheil): We can later use this notation in the config files as an
        #               alternative of using conn().
        if self.num > 1:
            s = '%s%ss' % (self.num, self.cc)
        else:
            s = self.cc
        if self.sender:
            s += '@%s' % self.sender
        if self.start:
            s += ':%s' % self.start
        if self.dur:
            s += '-%s' % self.dur
        if self.size:
            s += 's%s' % md5.md5(str(self.size)).hexdigest()[:8]
        if self.burst:
            s += 'b%s' % md5.md5(str(self.burst)).hexdigest()[:8]
        if self.params:
            s += 'p%s' % md5.md5(self.params).hexdigest()[:8]
        if self.upload:
            s += 'up'
        if self.tool:
            s += 't%s' % self.tool
        return s

    def pretty_str(self):
        """Returns a prettified representation of this connection."""
        burst_str = self.burst.pretty_str() if self.burst else 'None'
        return ('conn(cc="%s",num=%s,sender=%s,start=%s,dur=%s,size=%s,'
                'burst=%s,params=%s,upload=%s,tool=%s)') % (
                    self.cc, self.num, self.sender, self.start, self.dur,
                    self.size, burst_str, self.params, self.upload, self.tool)


def conn(cc, num=1, start=0, dur=0, size=0,
         burst=None, params='', sender=0, upload=False, tool=NETPERF):
    """Creates a connection.

    Args:
        cc: The name of the congestion control algorithm.
        num: The number of connection of this type.
        start: The initial delay before starting the connection in seconds.
        dur: The duration of the connection in seconds.
        size: The number of bytes to send on the connection.
        burst: The connection burst specification (None means an stream).
        params: The parameters of the CC kernel module.
        sender: The index of the sender machine.
        upload: Whether the connection sends in the opposite direction.
        tool: The tool to run for tests.

    Returns:
        An object that represents the given connection.
    """
    return Conn(cc, num, start, dur, size, burst, params, sender, upload, tool)


class Conns(object):
    """Represents a set of Conns that are run together in the same experiment.

    Attributes:
        conn_list: The list of connection sets.
        nsenders: The number of sender machines required for conn_list.
        nconns: The number of connections.
    """

    def __init__(self, conn_list):
        if not conn_list:
            raise ValueError('conn_list cannot be empty')

        for i, c in enumerate(conn_list):
            if isinstance(c, basestring):
                conn_list[i] = conn(cc=c)

        senders = dict()
        autoselect = 0
        max_sender = 0
        self.nconns = 0
        for c in conn_list:
            assert_type(c, Conn)
            self.nconns += c.num
            # Count each -1 as one sender.
            if c.sender < 0:
                autoselect += 1
                continue
            senders[c.sender] = True
            max_sender = max(c.sender, max_sender)

        self.conn_list = conn_list
        self.nsenders = len(senders) + autoselect
        if max_sender != self.nsenders - 1:
            raise RuntimeError('There is a gap in the senders used in a conn')

    def __nonzero__(self):
        return len(self.conn_list)

    def __str__(self):
        return '+'.join([str(c) for c in self.conn_list])

    def pretty_str(self):
        """Returns the prettified representation of this connection set."""
        return 'conns(%s)' % (', '.join([c.pretty_str()
                                         for c in self.conn_list]))


def conns(*args):
    """Creates an instance of Conns.

    Args:
        *args: This only accepts instances of Conn and strings.

    Returns:
        An object that represents the given connection.
    """
    for c in args:
        assert_type(c, basestring, Conn)

    return Conns(list(args))


class Bandwidth(object):
    """Represents a temporal bandwidth (a bw valid for a specific duration).

    Attributes:
        downlink: The downlink bandwidth in Mbps.
        uplink: The uplink bandwidth in Mbps. If 0, downlink is used.
        dur: The duration of this bandwidth in seconds. Zero means for
             ever. Note that this value is relative and the exact time that this
             bandwidth is enforced based on the previous bandwidths used in the
             experiment.
    """

    def __init__(self, downlink, uplink, dur):
        assert_type(downlink, int, float)
        assert_type(uplink, int, float)
        assert_type(dur, int)
        self.downlink = downlink
        self.uplink = uplink if uplink else downlink
        self.dur = dur

    def __nonzero__(self):
        return bool(self.downlink or self.uplink or self.dur)

    def __str__(self):
        rate = ('%s' % self.downlink if self.downlink == self.uplink else
                '%s_%s' % (self.downlink, self.uplink))
        if self.dur:
            return '%s@%s' % (rate, self.dur)
        return '%s' % rate

    def pretty_str(self):
        """Returns the pretified representation of this bandwidth."""
        if not self:
            return 'UNLIMITED_BW'
        return 'bw(downlink=%s,uplink=%s,dur=%s)' % (self.downlink, self.uplink,
                                                     self.dur)


class VarBandwidth(object):
    """Represents a variable bandwidth.

    Attributes:
        bws: The sequence of bandwidths.
    """

    def __init__(self, bws):
        for i, w in enumerate(bws):
            if isinstance(w, int) or isinstance(w, float):
                bws[i] = bw(w)
        self.bws = bws

    def __str__(self):
        return '_'.join([str(w) for w in self.bws])

    def pretty_str(self):
        """Represents a prettified representation of the variable BW."""
        return 'var_bw(%s)' % ', '.join(bw.pretty_str() for bw in self.bws)


def bw(downlink, uplink=0, dur=0):
    """Creates a Bandwidth instance with the given rates and duration.

    Args:
        downlink: The rate in Mbps for downlink.
        uplink: The rate in Mbps for uplink. If 0, downlink is used for uplink.
        dur: The duration in seconds.

    Returns:
        The Bandwidth instance.
    """
    return Bandwidth(downlink, uplink, dur)


def var_bw(*args):
    """Returns a variable bandwidth object using args."""
    return VarBandwidth(list(args))


UNLIMITED_BW = bw(0)


class Distribution(object):
    """Represents a probably distribution function.

    Attributes:
        mean: mean value (middle of the distribution)
        var: jitter value.  With no data file, the value is distributed
          uniformly in [mean-var, mean+var].  If the file is present, then
          the value varies between (mean - var * min(norm_table)) and
          (mean + var * max(norm_table)), according to the cumulative
          distribution function in the table.  Here, the "norm_table" value
          is any 16-bit integer from the data file divided by 8096, so
          its maximum range is [-4, 4].  If the data file is a normal
          distribution and "var" is the standard deviation, that means it
          can cover +/- 4 stddev lengths.  However, if values in the data
          file range [0, 8096], then "var" is more like a scaling factor,
          and the distribution will range just [mean, mean+var].
        data_file: data file in the format that NetEm expects (16-bit ints in
          ASCII format).  Usually generated by NetEm maketable.c utility.
    """

    def __init__(self, mean, var, data_file=None):
        if float(var) < 0:
            raise ValueError('var is negative')
        self.mean = float(mean)
        self.var = float(var)
        self.data_file = data_file

    def __str__(self):
        if self.data_file:
            return '%f+/-%f:%s' % (self.mean, self.var, self.data_file)
        else:
            return '[%f,%f]' % (self.mean - self.var, self.mean + self.var)

    def pretty_str(self):
        """Represents a prettified representation of the Distribution."""

        if self.data_file:
            return 'distribution(mean=%f,var=%f,data_file=%s)' % (
                self.mean, self.var, self.data_file)
        else:
            return 'uniform_distribution([%f,%f])' % (
                self.mean - self.var, self.mean + self.var)

    def netem_dist_name(self):
        """Returns the distribution name to pass to netem if available."""
        if not self.data_file:
            return None
        return os.path.splitext(os.path.basename(self.data_file))[0]

    def serialize(self):
        """Returns data that can be sent over XmlRpc for this object."""
        return {'mean': self.mean, 'var': self.var, 'data_file': self.data_file}

    @classmethod
    def deserialize(cls, data):
        """Uses data from serialize() to construct an identical object."""
        return cls(**data)


def uniform_distribution(min_, max_):
    """Creates a uniform Distribution instance in range [min_, max_].

    Args:
        min_: Min value of the uniform range.
        max_: Max value of the uniform range.

    Returns:
        The Distribution instance.

    Raises:
        ValueError: If max_ < min_.
    """
    if max_ < min_:
        raise ValueError('max_ cannot be smaller than min_')
    return Distribution((max_ + min_) / 2.0, (max_ - min_) / 2.0)


def distribution(mean, var, data_file):
    """Creates a non-uniform Distribution instance based on the arguments.

    Distributions are used in NetEm for the delay and slot models, to
    specify something other than a uniform probability.  Values in data_file
    represent a cumulative distribution function scaled according to
    ((x / 8192 * var) + mean).  Values must be in the range +/-32767
    (16-bit integer) and the middle value (0) is typically the mean,
    but it doesn't have to be.  If the values span 0-8192, for example,
    then the mean is just an offset and the var is a scale for the overall
    range.

    The data_file can also be "normal" or other *.dist files in /usr/lib/tc
    that come along with the standard installation for NetEm.

    Args:
        mean: offset for the distribution range.
        var: scale for the distribution range.
        data_file: data file generated by NetEm maketable.c utility.

    Raises:
        ValueError: If var < 0.

    Returns:
        The Distribution instance.
    """
    if var < 0:
        raise ValueError('var is negative')
    return Distribution(mean, var, data_file)


class RTT(object):
    """Represents a round trip time.

    Attributes:
        val: The RTT value in milliseconds.
        dur: The duration of this RTT in seconds.
        var: The inbound variation in RTT in milliseconds.
        out_var: The outbound variation in RTT in milliseconds.
        in_dist: Distribution of values for inbound part of RTT in msec.
        out_dist: Distribution of values for outbound part of RTT in msec.
        sender: The sender which this RTT value applies to.
    """

    def __init__(self, val, dur, var, out_var, in_dist, out_dist, sender):
        self.dur = dur
        self.sender = sender
        self.in_dist = in_dist
        self.out_dist = out_dist

        # Make sure that inputs are not over-specified.
        if in_dist and out_dist:
            total_val = in_dist.mean + out_dist.mean
            if val and total_val != val:
                raise ValueError("RTT value '%s' does not agree with "
                                 "inbound/outbound distributions" % val)
            val = total_val

        if in_dist:
            if var and var != in_dist.var:
                raise ValueError("RTT var '%s' does not agree with "
                                 "in_dist distribution" % var)
            var = in_dist.var

        if out_dist:
            if out_var and out_var != out_dist.var:
                raise ValueError("RTT out_var '%s' does not agree with "
                                 "out_dist distribution" % out_var)
            out_var = out_dist.var

        # Capture overall RTT characteristics.
        self.val = val
        self.var = var
        self.out_var = out_var

    def __nonzero__(self):
        return bool(self.val or self.dur or self.var or
                    self.in_dist or self.out_dist)

    def __str__(self):
        s = '%s' % self.val
        if self.dur:
            s += ':%s' % self.dur

        if self.in_dist:
            s += 'in(%s)' % self.in_dist
        elif self.var:
            s += 'v%s' % self.var

        if self.out_dist:
            s += 'out(%s)' % self.out_dist
        elif self.out_var:
            s += 'o%s' % self.out_var

        if self.sender:
            s += '@%s' % self.sender
        return s

    def pretty_str(self):
        """Represents a prettified representation of the RTT."""
        if not self:
            return 'NO_DELAY'

        return ('rtt(%s,dur=%s,var=%s,out_var=%s,'
                'in_dist=%s,out_dist=%s,sender=%s)' % (
                    self.val, self.dur, self.var, self.out_var,
                    self.in_dist, self.out_dist, self.sender))

    def serialize(self):
        """Returns data that can be sent over XmlRpc for this object."""
        return {
            'val': self.val,
            'dur': self.dur,
            'var': self.var,
            'out_var': self.out_var,
            'in_dist': self.in_dist.serialize() if self.in_dist else None,
            'out_dist': self.out_dist.serialize() if self.out_dist else None,
            'sender': self.sender,
        }

    @classmethod
    def deserialize(cls, data):
        """Uses data from serialize() to construct an identical object."""
        if 'in_dist' in data and data['in_dist']:
            data['in_dist'] = Distribution.deserialize(data['in_dist'])
        if 'out_dist' in data and data['out_dist']:
            data['out_dist'] = Distribution.deserialize(data['out_dist'])
        return cls(**data)

    def rtts_of_sender(self, sender):
        """Returns the RTT seqeuence of the given sender."""
        if self.sender != 0 and self.sender != sender:
            raise ValueError('invalid sender passed to fixed rtt %s' % sender)

        c = copy.deepcopy(self)
        c.sender = sender
        return [c]

    def get_data_files(self):
        """Returns a list of data files embedded in this RTT model."""
        files = []
        for d in [self.in_dist, self.out_dist]:
            if d and d.data_file:
                files.append(d.data_file)
        return files


class MixedRTT(object):
    """Represents round trip times that are different for each sender.

    Attributes:
        rtts: The dictionary of senders to their RTTs. There must be only 1 RTT
              per sender. If no RTT is provided for a specific sender we reuse
              the RTT of sender 0.
        dur: The duration that this mixed RTT is valid in seconds.
    """

    def __init__(self, rtts, dur):
        """Initializes the MixedRTT.

        Args:
            rtts: The list of RTTs. There must be only one RTT per sender.
            dur: The duration that this mixed RTT is valid in seconds.

        Raises:
            ValueError: If any parameter is invalid.
        """
        rtt_dict = dict()
        for t in rtts:
            assert_type(t, RTT, int)
            if isinstance(t, int) or isinstance(t, float):
                t = rtt(t)
            if rtt_dict.get(t.sender):
                raise ValueError('duplicate RTT value for %s' % t.sender)
            rtt_dict[t.sender] = t

        if 0 not in rtt_dict:
            raise ValueError('no RTT provided for sender 0')

        self.rtts = rtt_dict
        self.dur = dur

    def rtts_of_sender(self, sender):
        """Returns the RTT of the sender."""
        srtt = self.rtts.get(sender)
        if srtt:
            srtt = copy.deepcopy(srtt)
        else:
            srtt = copy.deepcopy(self.rtts[0])
        srtt.dur = self.dur
        return [srtt]

    def get_data_files(self):
        """Returns a list of data files embedded in this RTT model."""
        return sum([rtt_.get_data_files() for rtt_ in self.rtts.values()], [])

    def __str__(self):
        senders_str = ':::'.join([str(t) for _, t in self.rtts.iteritems()])
        return '%s:@:%s' % (senders_str, self.dur)

    def pretty_str(self):
        """Returns a pretty representation of the mixed RTT."""
        return 'mixed_rtt(%s, dur=%s)' % (', '.join([t.pretty_str() for _, t in
                                                     self.rtts.iteritems()]),
                                          self.dur)


class VarRTT(object):
    """Represents a round trip time that changes over time.

    Attributes:
        rtts: The list of RTTs. All RTTs except the last one must have a
              duration.
    """

    def __init__(self, rtts):
        for i, t in enumerate(rtts):
            assert_type(t, MixedRTT, RTT, int)
            if isinstance(t, int) or isinstance(t, float):
                rtts[i] = rtt(t)

        for t in rtts[:-1]:
            if not t.dur:
                raise ValueError('in a var RTT, all RTTs except the last'
                                 'one must have a duration')

        self.rtts = rtts

    def rtts_of_sender(self, sender):
        """Returns the sequence of RTTs of the given sender."""
        for t in self.rtts:
            for st in t.rtts_of_sender(sender):
                yield st

    def get_data_files(self):
        """Returns a list of data files embedded in this RTT model."""
        return sum([rtt_.get_data_files() for rtt_ in self.rtts], [])

    def __str__(self):
        return '_'.join([str(rtt_) for rtt_ in self.rtts])

    def pretty_str(self):
        """Returns a pretty representation of the variable RTT."""
        return 'var_rtt(%s)' % ', '.join([rtt_.pretty_str()
                                          for rtt_ in self.rtts])


def rtt(val=None, dur=0, var=0, out_var=0, in_dist=None, out_dist=None,
        sender=0):
    """Creates an RTT instance.

    Args:
        val: Is the round trip time in milliseconds.
        dur: The duration of this RTT in seconds.
        var: The variation in inbound RTT.
        out_var: The variation in outbound RTT.
        in_dist: Distribution of values for inbound part of RTT in msec.
        out_dist: Distribution of values for outbound part of RTT in msec.
        sender: The sender which this RTT applies to.

    Returns:
        An object that represents the given RTT.

    Raises:
        ValueError: No overall RTT or in/out dist values (empty definition).
    """
    if val is None and (in_dist is None or out_dist is None):
        raise ValueError('must specify val or in_dist/out_dist for rtt')
    return RTT(val, dur, var, out_var, in_dist, out_dist, sender)


def mixed_rtt(*args, **kwargs):
    """Creates different rtts for each sender sender.

    For example:
        mixed_rtt(rtt(100, sender=0), rtt(10, sender=1))

    Can be mixed with var_rtt:
        var_rtt(
            mixed_rtt(rtt(100, sender=0), rtt(10, sender=1), dur=100),
            rtt(10)
        )

    Args:
        *args: The list of RTTs.
        **kwargs: only accepts "dur" which is the duration for which this
                mixed_rtt is valid.

    Raises:
        ValueError: If any parameter is invalid.

    Returns:
        An object that represents the given RTT.
    """
    if not kwargs:
        return MixedRTT(args, dur=0)

    if len(kwargs) == 1 and 'dur' in kwargs:
        return MixedRTT(args, dur=kwargs['dur'])

    raise ValueError('invalid named parameters passed to mixed_rtt')


def var_rtt(*args):
    """Creates a variable RTT.

    Args:
        *args: A list of RTTs and MixedRTTs

    Returns:
        An object that represents the given RTTs.
    """
    return VarRTT(list(args))


NO_DELAY = rtt(0)


class Slot(object):
    """Represents a time slot configuration of netem for one direction.

    Attributes:
        dist: Distribution of slot interval in msec. Required.
        max_bytes: Max number of bytes delivered per slot. Ignored when 0.
        max_pkts: Max number of pkts delivered per slot. Ignored when 0.
    """

    def __init__(self, dist, max_bytes, max_pkts):
        assert_type(dist, Distribution)
        assert_type(max_bytes, int)
        assert_type(max_pkts, int)
        if not dist.data_file:
            if dist.mean < 0:
                raise ValueError(
                    'Distribution mean < 0 for uniform. mean:%f' % dist.mean)
            if dist.var < 0:
                raise ValueError(
                    'Distribution var < 0 for uniform. var:%f' % dist.var)
            if dist.mean - dist.var < 0:
                raise ValueError(
                    'Distribution mean - var < 0 for uniform. mean:%f var:%f' %
                    (dist.mean, dist.var))
        if max_bytes < 0:
            raise ValueError('max_bytes < 0: %d' % max_bytes)
        if max_pkts < 0:
            raise ValueError('max_pkts < 0: %d' % max_pkts)
        self.dist = dist
        self.max_bytes = max_bytes
        self.max_pkts = max_pkts

    def __nonzero__(self):
        return bool(self.dist)

    def __str__(self):
        pstr = '%s' % self.dist
        if self.max_bytes > 0:
            pstr += ':%dB' % self.max_bytes
        if self.max_pkts > 0:
            pstr += ':%dP' % self.max_pkts
        return pstr

    def pretty_str(self):
        """Returns a pretty representation of a netem time slot config."""
        pstr = 'slot(dist:%s' % self.dist
        if self.max_bytes > 0:
            pstr += ',max_bytes=%d' % self.max_bytes
        if self.max_pkts > 0:
            pstr += ',max_pkts=%d' % self.max_pkts
        pstr += ')'
        return pstr

    def netem_str(self):
        """Returns a netem slot config string, or an empty string if no-op."""
        if not self.__nonzero__():
            return ''
        pstr = 'slot'

        if self.dist.data_file:
            pstr += ' distribution %s %dus %dus' % (self.dist.netem_dist_name(),
                                                    int(self.dist.mean * 1000),
                                                    int(self.dist.var * 1000))
        else:
            pstr += ' %dus' % int((self.dist.mean - self.dist.var) * 1000.0)
            pstr += ' %dus' % int((self.dist.mean + self.dist.var) * 1000.0)
        if self.max_bytes > 0:
            pstr += ' bytes %d' % self.max_bytes
        if self.max_pkts > 0:
            pstr += ' packets %d' % self.max_pkts
        return pstr

    def get_data_file(self):
        """Returns the distribution data file if defined, or None.
        """
        return self.dist.data_file

    def serialize(self):
        """Returns data that can be sent over XmlRpc for this object."""
        return {'dist': self.dist.serialize(),
                'max_bytes': self.max_bytes,
                'max_pkts': self.max_pkts}

    @classmethod
    def deserialize(cls, data):
        """Uses data from serialize() to construct an identical object."""
        if 'dist' in data and data['dist']:
            data['dist'] = Distribution.deserialize(data['dist'])
        return cls(**data)


class SlotConfig(object):
    """Represents time slot configurations of netem for both directions.

    Attributes:
        in_slot: Slot configuration for inbound. Can be None.
        out_slot: Slot configuration for outbound. Can be None.
    """

    def __init__(self, in_slot, out_slot):
        if in_slot:
            assert_type(in_slot, Slot)
        if out_slot:
            assert_type(out_slot, Slot)
        self.in_slot = in_slot
        self.out_slot = out_slot

    def __nonzero__(self):
        return bool(self.in_slot or self.out_slot)

    def __str__(self):
        pstr = ''
        if self.in_slot:
            pstr += 'i(%s)' % self.in_slot
        if self.out_slot:
            pstr += 'o(%s)' % self.out_slot
        return pstr

    def pretty_str(self):
        """Returns a pretty representation of netem time slot configs."""
        pstr = 'slot_config('
        if self.in_slot:
            pstr += 'in(%s)' % self.in_slot
        if self.out_slot:
            pstr += 'out(%s)' % self.out_slot
        pstr += ')'
        return pstr

    def get_data_files(self):
        """Returns a list of distribution files.
        """
        data_files = []
        if self.in_slot and self.in_slot.get_data_file():
            data_files.append(self.in_slot.get_data_file())
        if self.out_slot and self.out_slot.get_data_file():
            data_files.append(self.out_slot.get_data_file())
        return data_files

    def serialize(self):
        """Returns data that can be sent over XmlRpc for this object."""
        return {
            'in_slot': self.in_slot.serialize() if self.in_slot else None,
            'out_slot': self.out_slot.serialize() if self.out_slot else None
        }

    @classmethod
    def deserialize(cls, data):
        """Uses data from serialize() to construct an identical object."""
        if 'in_slot' in data and data['in_slot']:
            data['in_slot'] = Slot.deserialize(data['in_slot'])
        if 'out_slot' in data and data['out_slot']:
            data['out_slot'] = Slot.deserialize(data['out_slot'])
        return cls(**data)


def slot(**kwargs):
    """Creates a SlotConfig instance based on the arguments.

    Args:
        **kwargs: Expects the following keyed arguments.
            in_dist: Distribution for inbound in msec. Optional
            in_max_bytes: Optional. Ignored when in_dist is missing.
            in_max_pkts: Optional. Ignored when in_dist is missing.
            out_dist: Distribution for outbound in msec. Optional
                      At least one of in_dist and out_dist must be available.
            out_max_bytes: Optional. Ignored when out_dist is missing.
            out_max_pkts: Optional. Ignored when out_dist is missing.

    Returns:
        The SlotConfig instance.

    Raises:
        ValueError: When both in_dist and out_dist are missing.
                    When an unexpected key is passed.
    """
    expected_keys = {'in_dist', 'in_max_bytes', 'in_max_pkts', 'out_dist',
                     'out_max_bytes', 'out_max_pkts'}
    if any(set(kwargs) - expected_keys):
        raise ValueError('unexpected args: %s' %
                         ','.join(set(kwargs) - expected_keys))

    in_slot = None
    out_slot = None

    if 'in_dist' in kwargs:
        in_slot = Slot(
            kwargs['in_dist'],
            kwargs['in_max_bytes'] if 'in_max_bytes' in kwargs else 0,
            kwargs['in_max_pkts'] if 'in_max_pkts' in kwargs else 0)
    if 'out_dist' in kwargs:
        out_slot = Slot(
            kwargs['out_dist'],
            kwargs['out_max_bytes'] if 'out_max_bytes' in kwargs else 0,
            kwargs['out_max_pkts'] if 'out_max_pkts' in kwargs else 0)
    if not bool(in_slot or out_slot):
        raise ValueError('in_dist or out_dist must be defined')
    return SlotConfig(in_slot, out_slot)


class Policer(object):
    """Represents a bandwidth policer.

    Attributes:
        bw: The rate of the policer in Mbps.
        burst: The initial burst that policer allows in MB.
        dur: The duration that this policer is valid for in seconds.
    """

    def __init__(self, bw_, burst, dur):
        assert_type(bw_, int, float)
        assert_type(burst, int, float)
        assert_type(dur, int)
        self.bw = bw_
        self.burst = burst
        self.dur = dur

    def __nonzero__(self):
        return self.bw != 0

    def __str__(self):
        pstr = 'POLICER%s' % self.bw
        if self.burst:
            pstr += ':%s' % self.burst
        if self.dur:
            pstr += '@%s' % self.dur
        return pstr

    def pretty_str(self):
        """Returns a pretty representation of the policer."""
        return 'policer(%s,burst=%s,dur=%s)' % (self.bw, self.burst, self.dur)


class VarPolicer(object):
    """Represents a veriable policer.

    Attributes:
        policers: The sequence of policers.
    """

    def __init__(self, policers):
        for i, p in enumerate(policers):
            if isinstance(p, int) or isinstance(p, float):
                policers[i] = policer(p)
        self.policers = policers

    def __str__(self):
        return '_'.join([str(p) for p in self.policers])

    def pretty_str(self):
        """Returns a pretty representation of the variable policer."""
        return 'var_policer(%s)' % (', '.join([p.pretty_str()
                                               for p in self.policers]))


def policer(bw, burst=0, dur=0):
    """Creates a Policer instance based on the arguments.

    Args:
        bw: The policer rate in Mbps.
        burst: The initial burst that the policer allows in MB.
        dur: The duration that this policer is valid for in seconds.

    Returns:
        The Policer instance.
    """
    return Policer(bw, burst, dur)


def var_policer(*args):
    """Returns a variable policer object built from args."""
    return VarPolicer(args)


def raise_runtime(msg):
    """Raises a runtime error that includes msg."""
    raise RuntimeError(msg)


def has_simple_bw_and_rtt(exp):
    """Returns whether the experiment has only simple BW and RTT."""
    return isinstance(exp.bw, Bandwidth) and isinstance(exp.rtt, RTT)


def bdp(ratio=1):
    """Returns a lambda that returation ratio x the BDP of the experiments.

    If rtt or bw is variable or mixed, then their max value is taken.

    Args:
        ratio: BDP value.
    """
    return lambda exp: calc_bdp(exp, ratio)


def calc_bdp(exp, ratio=1):
    """Returns maximum BDP for an experiment.

    If rtt or bw is constant, then the const value is taken for calc of bdp.
    If rtt or bw is variable or mixed, then their max value is taken.

    Args:
        exp: The experiment object.
        ratio: BDP value.
    """

    if isinstance(exp.bw, Bandwidth):
        bw_ = exp.bw.downlink
    else:
        bw_ = max(b.downlink for b in exp.bw.bws)

    if isinstance(exp.rtt, RTT):
        rtt_ = exp.rtt.val
    elif isinstance(exp.rtt, MixedRTT):
        rtt_ = max(r.val for _, r in exp.rtt.rtts.iteritems())
    else:
        rtt_ = max(r.val for r in exp.rtt.rtts)

    return max(1, int(ratio * bw_ * rtt_ * 1000 / 8. / 1514))


def qdisc(bw, out_bw=-1, qdisc='pfifo', out_qdisc='pfifo'):
    """Returns a machine_cmd to set up qdiscs on the receiver.

    Args:
      bw: Ingress bandwidth.
      out_bw: Egress bandwidth.
      qdisc: Ingress qdisc.
      out_qdisc: Egress qdisc.
    """
    if out_bw < 0:
        out_bw = bw
    return machine_cmd(
        ('%(tc)s qd add dev eth0 handle ffff: ingress;'
         '%(tc)s qd del dev ifb0 root;'
         '%(tc)s qd del dev eth0 root;'
         '%(tc)s qd add dev ifb0 root handle 1: htb default 11;'
         '%(tc)s qd add dev eth0 root handle 1: htb default 11;'
         '%(tc)s cl add dev ifb0 parent 1: classid 1:11 htb rate %(bw)smbit ceil %(bw)smbit;'
         '%(tc)s qd add dev ifb0 parent 1:11 handle 20: %(qdisc)s;'
         '%(tc)s cl add dev eth0 parent 1: classid 1:11 htb rate %(out_bw)smbit ceil %(bw)smbit;'
         '%(tc)s qd add dev eth0 parent 1:11 handle 20: %(out_qdisc)s;') % {
             'tc': path.tc(),
             'bw': bw,
             'out_bw': out_bw,
             'qdisc': qdisc,
             'out_qdisc': out_qdisc,
         },
        sender=NO_SENDERS, receiver=True)

# All sender in a machine command.
ALL_SENDERS = -1
# None of the senders.
NO_SENDERS = -2


class MachineCommand(object):
    """Represents a command ran on all or some of the sender machines.

    Attributes:
        cmd: The command to run.
        start: When to start the command in seconds.
        sender: The index of sender machine to run this machine if any.
                ALL_SENDERS means all of them, None mean none of them.
        receiver: Whether to run the command on the receiver machine.
    """

    def __init__(self, cmd, start, sender, receiver):
        self.cmd = cmd
        self.start = start
        self.sender = sender
        self.receiver = receiver

    def __nonzero__(self):
        return self.cmd

    def __str__(self):
        pstr = 'SNDCMD%s' % self.cmd
        if self.start:
            pstr += ':%s' % self.start
        if self.sender != ALL_SENDERS:
            pstr += '@%s' % self.sender
        if self.receiver:
            pstr += 'R%s' % self.receiver
        return pstr

    def pretty_str(self):
        """Returns a pretty representation of the command."""
        return 'machine_cmd("%s",start=%s,sender=%s,receiver=%s)' % (
            self.cmd, self.start, self.sender, self.receiver)


class MachineCommands(object):
    """Represents multiple commands.

    Attributes:
        cmds: List of sender commands.
    """

    def __init__(self, cmds):
        for i, cmd in enumerate(cmds):
            if isinstance(cmd, basestring):
                cmds[i] = machine_cmd(cmd)
        self.cmds = cmds

    def __nonzero__(self):
        return self.cmds

    def __str__(self):
        return '_'.join([str(cmd_) for cmd_ in self.cmds])

    def pretty_str(self):
        """Returns a pretty representation of the sender commands."""
        return 'machine_cmds(%s)' % (','.join([c.pretty_str()
                                               for c in self.cmds]))


def machine_cmd(cmd, start=0, sender=ALL_SENDERS, receiver=False):
    """Creates a sender command."""
    return MachineCommand(cmd, start, sender, receiver)


def machine_cmds(*args):
    """Creates a list of sender commands."""
    for c in args:
        assert_type(c, basestring, MachineCommand)
    return MachineCommands(list(args))


class Experiment(object):
    """Represents the settings of an experiment.

    Attributes:
        conn: The cnnections.
        rtt: The RTTs.
        bw: The bandwidth.
        buf: The buffer size at the bottleneck where banwdith is emulated.
        loss: The inbound loss ratio.
        out_loss: The outbound loss ratio.
        slot: Time slot configuration for both directions. (SlotConfig)
        policer: The policer.
        machine_cmd: Commands to run on the sender machines.
        cmd: Command to run on all machines before running the experiment.
        dur: The duration of the experiment in seconds.
        machine_cmd: The machine command.
    """

    def __init__(self):
        self.conn = None
        self.rtt = rtt(0)
        self.bw = bw(0)
        self.buf = 0
        self.loss = 0
        self.out_loss = 0
        self.slot = None
        self.policer = None
        self.machine_cmd = machine_cmds()
        self.cmd = None
        self.dur = 0

        self._title = None
        self._dir_name = None

    def conns_of_sender(self, sender):
        """Returns the connections of the sender."""
        return [c for c in self.conn.conn_list if c.sender == sender]

    def cmds_of_sender(self, sender):
        """Returns the commands of the sender."""
        return [c for c in self.machine_cmd.cmds
                if c.sender == sender or c.sender == ALL_SENDERS]

    def rtts_of_sender(self, sender):
        """Returns the RTTs of the sender."""
        return self.rtt.rtts_of_sender(sender)

    def cmds_of_receiver(self):
        """Returns the commands of the receiver as tuple of (command, start).

        This should be used to send data over RPC.
        """
        return [(c.cmd, c.start) for c in self.machine_cmd.cmds if c.receiver]

    def nconns(self):
        """Returns the number of connections in this experiment."""
        return self.conn.nconns

    def nsenders(self):
        """Returns the number of senders required to run this experiment."""
        return self.conn.nsenders

    def all_tools(self):
        """Returns the name of all the tools used in this experiment."""
        return [c.tool.name() for c in self.conn.conn_list]

    def bw_infos(self):
        """Returns the sequence of bandwidths used in this experiment.

        This method is for simpler XML RPC.
        """
        if isinstance(self.bw, Bandwidth):
            return [(self.bw.downlink, self.bw.uplink, self.bw.dur)]
        return [(w.downlink, w.uplink, w.dur)
                for w in self.bw.bws]

    def sender_info(self, sender):
        """Returns the list of connections, RTTs, and commands of the sender.

        Args:
            sender: The sender.

        This method is for simpler XML RPC.
        """
        conn_infos = [(c.cc, c.num, c.start, c.dur, c.size, c.burst_tuple(),
                       c.params, c.upload, c.tool.name())
                      for c in self.conns_of_sender(sender)]
        rtts = [t.serialize() for t in self.rtts_of_sender(sender)]
        cmds = [(c.cmd, c.start) for c in self.cmds_of_sender(sender)]
        return (conn_infos, rtts, cmds)

    def slot_info(self):
        """Returns a serialized representation of SlotConfig or None.

        This method is for simpler XML RPC.
        """
        if self.slot:
            return self.slot.serialize()
        return None

    def policer_info(self):
        """Returns a list of tuples of policer bw, burst and duration.

        This method is for simpler XML RPC.
        """
        if not self.policer:
            return None
        if isinstance(self.policer, Policer):
            return [(self.policer.bw, self.policer.burst, self.policer.dur)]
        return [(p.bw, p.burst, p.dur) for p in self.policer.policers]

    def set_title(self, title):
        """Set a string suitable for a web page title for the experiment."""
        self._title = title

    def get_title(self):
        return self._title

    def set_dir_name(self, dir_name):
        """Set the directory name for this experiment."""
        self._dir_name = dir_name

    def get_dir_name(self):
        return self._dir_name

    def __str__(self):
        policer_str = ('POLICER%s_' % self.policer) if self.policer else ''
        outloss_str = ('OLOSS%s_' % self.out_loss) if self.out_loss else ''
        slot_str = ('SLOT%s_' % self.slot) if self.slot else ''
        extra_str = md5.md5(str(self.cmd) + str(self.machine_cmd)).hexdigest()
        return 'CONNS%s_RTT%s_BW%s_BUF%s_LOSS%s_%s%s%sDUR%s_%s' % (
            self.conn, self.rtt, self.bw, self.buf, self.loss, outloss_str,
            slot_str, policer_str, self.dur, extra_str[:8])

    def pretty_str(self):
        """Returns the prettified representation of this experiment."""
        return '\n'.join([
            'cmd="%s"' % self.cmd,
            'machine_cmd=%s' % self.machine_cmd.pretty_str(),
            'conn=%s' % self.conn.pretty_str(),
            'rtt=%s' % self.rtt.pretty_str(),
            'bw=%s' % self.bw.pretty_str(),
            'policer=%s' % (self.policer.pretty_str() if self.policer else ''),
            'loss=%s' % self.loss,
            'out_loss=%s' % self.out_loss,
            'slot=%s' % (self.slot.pretty_str() if self.slot else ''),
            'buf=%s' % self.buf,
            'dur=%s' % self.dur,
        ])


class InterfaceConfig(object):
    """Represents a per-invocation interface configuration for each node.

    Attributes:
        _ifaces: Per-node interface configurations.
    """
    ETHX_REGEX = r'eth\d+'
    default_cfg = {'bond': 'eth0',
                   'ifaces': ['eth1', 'regex:{rgx}'.format(rgx=ETHX_REGEX)],
                   'root_nic_offloads_enabled': True,
                   'container_nic_offloads_enabled': True,}
    valid_keys = set(default_cfg.keys())

    @staticmethod
    def node_config(ifacecfg, node, logger):
        """Parse interface configuration and return node config.

        Nodes use the following config priority order, depending on scenario:
        1. The explicit node config, if it is specified in a valid ifacecfg.
        2. The optional default (key=None) config specified in a valid ifacecfg.
        3. transperf.InterfaceConfig.default_cfg in all other cases.

        Args:
            ifacecfg: The interface config file.

            node: The node.

            logger: A logger object controlled by the caller.

        Returns:
            The node config.

        """
        parsed = InterfaceConfig.validate_config(ifacecfg, logger)
        if parsed is not None:
            if node in parsed:
                return parsed[node]
            if None in parsed:  # Default in-config
                return parsed[None]
        return InterfaceConfig.default_cfg

    @staticmethod
    def validate_config(ifacecfg, logger):
        r"""Validate interface configuration file.

        ifacecfg must point to a file containing a valid python-language
        configuration of the following format:

        ifaces = {'node': {'bond': 'eth0',
                           'ifaces': ['eth1',
                                      'regex:eth\d+',],},}
        where 'node' is the name of the node that the config corresponds to.

        A valid ifacecfg is any valid python file containing the ifaces
        dict, which can carry 0 or more valid node configs (or, 0 or 1 default
        config with key=None) of the form depicted above. Missing parameters are
        filled in with the default in transperf.InterfaceConfig.default_cfg.

        An invalid ifacecfg means we fail fast.

        Args:
            ifacecfg: The interface config file.

            logger: A logger object controlled by the caller.

        Returns:
            The parsed config.

        Raises:
            RuntimeError if we are unable to parse the provided file.
        """

        with open(ifacecfg, 'r') as fd:
            read = fd.read()

        ns = {}
        parsed = compile(read, ifacecfg, 'exec')
        exec parsed in ns

        if 'ifaces' not in ns:
            logger.warning('Missing "ifaces" key in ifaces cfg file %s - '
                           'nodes will use the global default config',
                           ifacecfg)
            return None

        ifaces = ns['ifaces']
        if None not in ifaces:
            logger.warning('Missing default(None) key in ifaces cfg file %s - '
                           'nodes without explicit cfg will use global default',
                           ifacecfg)

        for node in ifaces:
            if node is not None:
                assert_type(node, str)

            nodecfg = ifaces[node]
            assert_type(nodecfg, dict)

            for key in InterfaceConfig.valid_keys:
                if key not in nodecfg:
                    logger.warning('ifaces[%s] lacks key %s - using default %s',
                                   node, key, InterfaceConfig.default_cfg[key])
                    nodecfg[key] = InterfaceConfig.default_cfg[key]

            for key in nodecfg:
                if key not in InterfaceConfig.valid_keys:
                    logger.warning('ifaces[%s] has extraneous key %s - ignore',
                                   node, key)
                    del nodecfg[key]

            # Extraneous keys removed, valid keys filled in if necessary. Now
            # validate that the data we have is all good.
            assert_type(nodecfg['bond'], str)
            # Ensure that nodecfg.ifaces is for sure a list.
            nodecfg['ifaces'] = list(make_iterable(nodecfg['ifaces']))
            for iface in nodecfg['ifaces']:
                assert_type(iface, str)

        return ifaces


class Config(object):
    """Represents a configuration from which we build experiments.

    Attributes:
        _dur: Duration of the experiments in this config.
        _conn: The connections.
        _rtt: The RTTs.
        _bw: The bandwidths.
        _buf: The buffer sizes.
        _loss: The inbound losses.
        _out_loss: The outbound losses.
        _slot: Time slot configuration for both directions. (SlotConfig)
        _policer: The policers.
        _machine_cmd: The sender commands.
        _cmd: The command to run before running an experiment.
        _check: The function that validates the experiments.
        params: The order that parameters should be evaluated from a config
                file. Note that this list is updated to reflect the order
                of parameters in the user's config file.
                Also note that the names in this list should be the class
                property names (e.g., dur, conn, ...) not (e.g., _dur, _conn,
                ...)
    """

    def __init__(self):
        self._dur = [30]
        self._conn = ['cubic']
        self._bw = [0]
        self._rtt = [0]
        self._buf = [0]
        self._loss = [0]
        self._out_loss = [0]
        self._slot = None
        self._policer = None
        self._machine_cmd = None
        self._cmd = DEFAULT_COMMAND
        self._check = default_check
        # Keep this list in sync with the properties excluding check.
        self.params = ['conn', 'bw', 'rtt', 'buf', 'loss', 'out_loss', 'slot',
                       'policer', 'dur', 'machine_cmd', 'cmd']

    def get_conn(self):
        return self._conn

    def set_conn(self, c):
        conns_list = make_iterable(c)
        for i, conn_set in enumerate(conns_list):
            if isinstance(conn_set, basestring):
                conns_list[i] = conns(conn(cc=conn_set))
            elif isinstance(conn_set, Conn):
                conns_list[i] = conns(conn_set)
        self._conn = conns_list

    def get_bw(self):
        return self._bw

    def set_bw(self, bw_list):
        bw_list = make_iterable(bw_list)
        for i, val in enumerate(bw_list):
            if isinstance(val, int) or isinstance(val, float):
                bw_list[i] = bw(val)
        self._bw = bw_list

    def get_rtt(self):
        return self._rtt

    def set_rtt(self, val):
        val = make_iterable(val)
        for i, t in enumerate(val):
            if isinstance(t, int) or isinstance(t, float):
                val[i] = rtt(t)
        self._rtt = val

    def get_buf(self):
        return self._buf

    def set_buf(self, buf):
        self._buf = make_iterable(buf)

    def get_loss(self):
        return self._loss

    def set_loss(self, loss):
        self._loss = make_iterable(loss)

    def get_out_loss(self):
        return self._out_loss

    def set_out_loss(self, out_loss):
        self._out_loss = make_iterable(out_loss)

    def get_slot(self):
        return self._slot

    def set_slot(self, val):
        self._slot = make_iterable(val)

    def get_policer(self):
        return self._policer

    def set_policer(self, val):
        val = make_iterable(val)
        for i, p in enumerate(val):
            if isinstance(p, int) or isinstance(p, float):
                val[i] = policer(p)
        self._policer = val

    def get_dur(self):
        return self._dur

    def set_dur(self, dur):
        self._dur = make_iterable(dur)
        for dur in self._dur:
            assert dur > 0, 'duration must be positive'

    def get_machine_cmd(self):
        return self._machine_cmd

    def set_machine_cmd(self, cmd):
        cmd = make_iterable(cmd)
        for i, c in enumerate(cmd):
            if isinstance(c, basestring):
                cmd[i] = machine_cmds(machine_cmd(c))
            elif isinstance(c, MachineCommand):
                cmd[i] = machine_cmds(c)
        self._machine_cmd = cmd

    def get_cmd(self):
        return self._cmd

    def set_cmd(self, cmd):
        self._cmd = make_iterable(cmd)

    def get_check(self):
        if not self._check:
            # If there no check in the configuration we return a lambda that
            # always passes.
            return lambda exp, metrics, case: True

        return self._check

    def set_check(self, check):
        self._check = check

    conn = property(get_conn, set_conn)
    bw = property(get_bw, set_bw)
    rtt = property(get_rtt, set_rtt)
    buf = property(get_buf, set_buf)
    loss = property(get_loss, set_loss)
    out_loss = property(get_out_loss, set_out_loss)
    slot = property(get_slot, set_slot)
    policer = property(get_policer, set_policer)
    dur = property(get_dur, set_dur)
    machine_cmd = property(get_machine_cmd, set_machine_cmd)
    cmd = property(get_cmd, set_cmd)
    check = property(get_check, set_check)

    def experiments(self):
        """Generates the experiments from this configuration.

        Returns:
            A list of experiments.
        """
        exps = [Experiment()]
        # First process values to generate the cartesian product of
        # all values for all parameters.
        for name in self.params:
            vals = getattr(self, name)
            # Allow empty commands for an experiment.
            if not vals and name == 'cmd':
                continue
            if vals is None:
                continue
            new_exps = []
            for exp in exps:
                for val in vals:
                    expc = copy.deepcopy(exp)
                    setattr(expc, name, val)
                    new_exps.append(expc)
            exps = new_exps

        # Then process lambda expressions.
        for name in self.params:
            vals = getattr(self, name)
            if vals and hasattr(vals[0], '__call__'):
                for i, exp in enumerate(exps):
                    val = getattr(exps[i], name)
                    setattr(exps[i], name, val(exp))

        # Set the check once all other fields have been set.
        for i, exp in enumerate(exps):
            exp.check = self.check
            exp.set_dir_name(str(i))
            exp.set_title(str(i))

        return exps

    def get_data_files(self):
        """Returns a set of data files embedded within any models.

        Some models (e.g., RTT distributions) may have associated data files.
        Returns a list of all such files in this configuration, so the files
        can be copied to remote machines.
        """
        data_files = set(sum([rtt_.get_data_files() for rtt_ in self.rtt], []))
        if self.slot:
            data_files.update(set(sum(
                [(s.get_data_files() if s else []) for s in self.slot], [])))
        return data_files


class TestCase(object):
    """Represent a test case."""

    def __init__(self):
        self.__errors = []

    def errors(self):
        """Returns the errors stored in the test case.

        Returns:
            The list of errors.
        """
        return self.__errors

    def expect(self, cond, msg, fatal=False):
        """If condition is not met, it adds msg to the list of errors.

        Args:
            cond: The condition.
            msg: The error message to show when the condition is not met.
            fatal: Whether to stop the test.

        Raises:
            RuntimeError: When encountered a critial error.
        """
        if cond:
            return

        if not fatal:
            self.__errors.append(msg)
        else:
            raise RuntimeError(msg)


# Default commands to run to setup machines for experiments.
# Disable ECN
DEFAULT_COMMAND = ['{sudo} sysctl -q -e net.ipv4.tcp_ecn=0']


def _shallow_buf(exp, ratio=0.1):
    """Returns true if buf is shallow for an experiment.

    If buf absolute value is smaller then 3, then it's shallow buffer.
    If buf is not larger than ratio*BDP, then it's shallow buffer.

    Args:
        exp: The experiment object.
        ratio: BDP value.
    """
    if exp.buf < 3 or exp.buf < calc_bdp(exp, ratio):
        return True

    return False


def default_target_score(exp):
    """the function to get default target score dict.

    Note that the default values returned are chosen to make sense for
    BBRv1 and/or v2 (not CUBIC or Reno), so the function should be overridden
    for tests on CUBIC or Reno.

    Args:
        exp: The experiment object.

    Returns:
        The target score dict.
    """
    # Score is a value range from 0 to 100, and 100 means best performance.
    # See README for more details.
    target_score = {
        'tput': 80,
        'rtt_med': 30,
        'lock_on_bw': 80,
        'loss_avoid': 100,
        'fairness': 100,
        'convergence_fairness': 100,
        # convergence_sec is an exception, 10 means 10s.
        'convergence_sec': 4,  # NB: Must be None or in [0, exp.dur].
    }

    if exp.nconns() > 1:
        target_score['loss_avoid'] = 96
        target_score['fairness'] = 96
        target_score['lock_on_bw'] = 35
        target_score['convergence_fairness'] = 90

    if exp.policer is not None:
        target_score['loss_avoid'] = 70
        target_score['convergence_fairness'] = 85

    if _shallow_buf(exp) and exp.nconns() > 1:
        target_score['fairness'] = 80
        target_score['convergence_fairness'] = 70

    return target_score


def _produce_scores(scores, exp):
    """Produces the scores dictionary.

    Args:
        scores: Is either the score dictionary, or a function that produces the
                score dictionary based on an experiment.
        exp: The experiment ojbect.
    Returns:
        The dictionary of scores.
    """
    if isinstance(scores, dict):
        return scores
    return scores(exp)


def default_check_rtt(exp, metrics, case, scores=default_target_score):
    """The default test case for all other metrics unless overridden by the user.

    Args:
        exp: The experiment object.
        metrics: The metrics dictionary.
        case: The TestCase object.
        scores: Is either the score dictionary, or a function that produces the
                score dictionary based on an experiment.
    """
    target_dict = _produce_scores(scores, exp)
    target_score = target_dict['rtt_med']
    LOG.debug('default_check_rtt: target=%s', target_score)
    rtt_ = 0
    if isinstance(exp.rtt, RTT):
        rtt_ = exp.rtt.val

    if isinstance(exp.rtt, RTT) or isinstance(exp.rtt, MixedRTT):
        min_rtts = metrics['min_rtt']
        med_rtts = metrics['med_rtt']
        serial_delays = metrics['serial_delay']
        for cc in _BBR:
            bbr_ports = metrics['tputs'].cc_ports(cc)
            for port in bbr_ports:
                min_rtt = min_rtts.get(port)

                if min_rtt < rtt_:
                    LOG.debug('small raw min_rtt: min_rtt=%s, rtt=%s',
                              min_rtt, rtt_)

                min_rtt += serial_delays.get(port)
                med_rtt = med_rtts.get(port)
                med_rtt += serial_delays.get(port)

                if not min_rtt or not med_rtt:
                    LOG.debug('missing rtt min_rtt=%s, med_rtt=%s',
                              min_rtt, med_rtt)
                    continue

                # For the mixed RTT case, we choose the largest configured.
                max_rtt = (exp.rtt.val if isinstance(exp.rtt, RTT)
                           else max(r.val for _, r in exp.rtt.rtts.iteritems()))

                if isinstance(exp.bw, Bandwidth):
                    bits_per_pkt = 1514 * 8
                    buf_pkts = exp.buf
                    bw_bps = exp.bw.downlink * 1000000
                    if bw_bps > 0:
                        max_qdelay_ms = math.ceil(
                            (1000.0 * buf_pkts * bits_per_pkt) / bw_bps)
                        relaxed_requirement = 1.1  # for false-positives.
                        max_allowed_rtt = relaxed_requirement * (max_rtt +
                                                                 max_qdelay_ms)
                        case.expect(
                            med_rtt < max_allowed_rtt,
                            'medRTT(%s) > %s*(maxRTT(%s) + maxQdelayMs(%s))'
                            % (med_rtt, relaxed_requirement, max_rtt,
                               max_qdelay_ms))

                rtt_score = 100 * min_rtt / med_rtt
                LOG.debug('port=%s, min_rtt=%.3f, med_rtt=%.3f, '
                          'score=%.1f, target=%s',
                          port, min_rtt, med_rtt, rtt_score, target_score)

                case.expect(rtt_score >= target_score,
                            'rtt bloated: port=%s, minRTT=%.3f, '
                            'medRTT=%.3f score=%.1f, rtt_med target=%s' %
                            (port, min_rtt, med_rtt, rtt_score, target_score))


def default_check_loss(exp, metrics, case, scores=default_target_score):
    """The default test case for target loss avoidence score.

    Args:
        exp: The experiment object.
        metrics: The metrics dictionary.
        case: The TestCase object.
        scores: Is either the score dictionary, or a function that produces the
                score dictionary based on an experiment.
    """

    target_dict = _produce_scores(scores, exp)
    target_score = target_dict['loss_avoid']

    LOG.debug('default_check_loss: target=%s', target_score)

    for cc in _BBR:
        bbr_ports = metrics['tputs'].cc_ports(cc)
        loss_rate = metrics['retx']
        for port in bbr_ports:
            loss_rate_port = loss_rate.get(port)
            loss_score = 100 * (1 - loss_rate_port)
            LOG.debug('port=%s, loss_rate=%.3f, score=%.1f, target=%s',
                      port, loss_rate_port, loss_score, target_score)
            case.expect(loss_score >= target_score,
                        'loss: port=%s, loss_rate=%.3f, '
                        'score=%.1f, loss_avoid target=%s' % (
                            port, loss_rate_port, loss_score, target_score))


def default_check_tput(exp, metrics, case, scores=default_target_score,
                       real_bw=0):
    """The default test case for tput metrics unless overridden by the user.

    Scoring semantics: Suppose a test is N seconds long. Not all flows
    necessarily start or end at the same time. However, we assume that during
    any second N, at least one flow is active during that time. Thus, during
    each second, there will be non-zero link utilization. We compute the average
    link utilization across all seconds of the test, from [0, exp.dur]. We
    compare this average to a per-test minimum threshold.

    Args:
        exp: The experiment object.
        metrics: The metrics dictionary.
        case: The TestCase object.
        scores: Is either the score dictionary, or a function that produces the
                score dictionary based on an experiment.
        real_bw: Real bandwidth value (e.g., bw overwritten by qdisc for ECN)
    """
    target_dict = _produce_scores(scores, exp)
    target_score = target_dict['tput']
    tputs = metrics['tputs'].as_array()
    LOG.debug('default_check_tput: target=%s, tputs_array=%s',
              target_score, tputs)
    case.expect(min(tputs) != 0, 'minimal throughput should not be 0')

    # Figure out the expected bottleneck bw (or first one, if several).
    if isinstance(exp.bw, Bandwidth):
        bwlink = exp.bw.downlink
    elif isinstance(exp.bw, VarBandwidth):
        bwlink = exp.bw.bws[0].downlink
    if real_bw:
        bwlink = real_bw
    # Use min as the target bandwidth if there was a policer.
    if exp.policer is not None:
        bwpolicer = exp.policer.bw
        LOG.debug('bwlink=%s, bwpolicer=%s', bwlink, bwpolicer)
        if bwpolicer < bwlink and bwpolicer > 0:
            bwlink = bwpolicer

    LOG.debug('bwlink=%s, rtt=%s, #conn=%s', bwlink, exp.rtt, exp.nconns())
    case.expect(bwlink != 0, 'bw.downlink should not be 0')

    tput_timeline_data = False
    for tput in tputs:
        if not isinstance(tput, float):
            tput_timeline_data = True
            break

    if not tput_timeline_data:
        tput_timeline = {0: tputs}
    else:
        tput_timeline = {}
        # Each (per-port) entry is a list of (timestamp, tput) values.
        for port_timeline in tputs:
            for timestamp, tput_mbps in port_timeline:
                # Don't analyze past the configured end of the experiment.
                if timestamp > exp.dur:
                    break
                if timestamp not in tput_timeline:
                    tput_timeline[timestamp] = []
                tput_timeline[timestamp].append(tput_mbps)

    scores = []
    for timestamp in sorted(tput_timeline.keys()):
        tputs_for_timestamp = tput_timeline[timestamp]
        tputs_sum = sum(tputs_for_timestamp)

        tput_score = 100 * tputs_sum / bwlink
        scores.append(tput_score)
        LOG.debug('bw=%s, timestamp=%s, tputs_sum=%s, score=%.1f, target=%s',
                  bwlink, timestamp, tputs_sum, tput_score, target_score)

    avg_tput_score = sum(scores) / len(scores)
    # Check tput score by comparing with expected threshold.
    case.expect(avg_tput_score >= target_score,
                'low tput: avg score=%.1f, bw=%s, tputs=%s, tput target=%s'
                % (avg_tput_score, bwlink, tputs_sum, target_score))

    for cc in _BBR:
        bbr_ports = metrics['tputs'].cc_ports(cc)
        # Check lock_on_bws, which is the bw when bbr exiting startup
        target_score = target_dict['lock_on_bw']
        lock_on_bws = metrics['lock_on_bw']
        for port in bbr_ports:
            lock_on_bw = lock_on_bws.get(port)
            fair_share = float(bwlink) / float(exp.nconns())
            lock_on_bw_score = 100.0 * lock_on_bw / fair_share
            LOG.debug('port=%s, lock_on_bw=%s, score=%.1f, target=%s',
                      port, lock_on_bw, lock_on_bw_score, target_score)
            case.expect(lock_on_bw_score >= target_score,
                        'premature lock-on port=%s, lock_on_bw=%s, '
                        'score=%.1f, lock_on_bw target=%.1f' % (
                            port, lock_on_bw, lock_on_bw_score,
                            target_score))


def default_check_fairness(exp, metrics, case, scores=default_target_score):
    """The default test case for fairness metrics.

    Scoring semantics: Suppose a test is N seconds long. Not all flows
    necessarily start or end at the same time. However, we assume that during
    any second N, at least one flow is active during that time. Thus, during
    each second, there will be non-zero link utilization, and some fairness
    metric amongst the active flows during that second. We compute the fairness
    for each second *after* a configured minimum convergence period, and then
    take the average fairness across all seconds, from
    [0, exp.dur]. We compare this average to a per-test minimum threshold.

    NB: Note that unlike the throughput computation test (default_check_tput),
    here we only consider fairness values after some initial convergence period.
    For example, when flows are starting up, it's unlikely that the split will
    be fair until some steady state is reached. For tests where we do not care
    about convergency (e.g. forever-dynamic tests) the user can specify None.
    This leads to a passing test as well.

    Regarding the target score: it should either be a numeric value, or a
    callable that takes the experiment as parameter. This is because Jain's
    fairness metric depends on the number of contending entities for the worst
    case (e.g. 2 flows means a worst case fairness of 50; 4 flows means 25 while
    100 is optimal fairness in both cases). Thus, accepting a callable allows
    the experimenter to specify a custom fairness target depending on the
    particulars of the experiment.

    Args:
        exp: The experiment object.
        metrics: The metrics dictionary.
        case: The TestCase object.
        scores: Is either the score dictionary, or a function that produces the
                score dictionary based on an experiment.
    """
    target_dict = _produce_scores(scores, exp)
    target_score = target_dict['fairness']
    if callable(target_score):
        target_score = target_score(exp)
    assert isinstance(target_score, numbers.Number)
    target_convergence_time = target_dict['convergence_sec']
    # If we don't care about convergence, we short-circuit here.
    if target_convergence_time is None:
        return
    case.expect(target_convergence_time >= 0
                and target_convergence_time <= exp.dur,
                'Error: target convergence time %s not in [0, %s]' %
                (target_convergence_time, exp.dur))
    if target_convergence_time < 0 or target_convergence_time > exp.dur:
        return
    nc = exp.nconns()
    tputs = {port: metrics['tputs'].get(port)
             for port in metrics['tputs'].ports()}

    # Marshall data depending on whether we got a flat tput array for the entire
    # test, or a timeline of throughput values.
    tput_timeline_data = False
    for port, tput in tputs.iteritems():
        if not isinstance(tput, float):
            tput_timeline_data = True
            break

    if not tput_timeline_data:
        tput_timeline = {0: metrics['tputs'].as_array()}
    else:
        tput_timeline = {}
        # Each (per-port) entry is a list of (timestamp, tput) values.
        for port in tputs:
            port_timeline = tputs[port]
            for timestamp, tput_mbps in port_timeline:
                if timestamp < target_convergence_time:
                    continue
                # Don't analyze past the configured end of the experiment.
                if timestamp > exp.dur:
                    break
                if timestamp not in tput_timeline:
                    tput_timeline[timestamp] = {}
                tput_timeline[timestamp][port] = tput_mbps
        for timestamp in tput_timeline:
            per_port_bw = tput_timeline[timestamp]
            bw_list = []
            for port in sorted(tputs.keys()):
                bw_list.append(per_port_bw[port])
            tput_timeline[timestamp] = bw_list

    min_tput = min([min(tput_timeline[ts]) for ts in tput_timeline])
    max_tput = max([max(tput_timeline[ts]) for ts in tput_timeline])

    LOG.debug('default_check_fairness: target=%s, #conn=%s', target_score, nc)
    LOG.debug('tputs: min=%.1f, max=%.1f, array=%s',
              min_tput, max_tput, tputs)

    if nc <= 1:
        return

    scores = []
    for timestamp in sorted(tput_timeline.keys()):
        tputs_for_timestamp = tput_timeline[timestamp]
        sum_ = sum(tputs_for_timestamp)

        # Compute Jain's fairness index for throughputs for each flow.
        fairness_score = 100 * sum_ * sum_ / sum(
            [i**2 for i in tputs_for_timestamp]) / nc
        scores.append(fairness_score)

    avg_fairness = sum(scores)/len(scores)
    LOG.debug('fairness scores=%s (avg %f), timestamp=%s, target=%s',
              scores, avg_fairness, timestamp, target_score)
    case.expect(avg_fairness >= target_score,
                'poor avg fairness: score=%.1f, fairness target=%s'
                % (avg_fairness, target_score))


def default_check_convergence(exp, metrics, case, scores=default_target_score):
    """The default test case for convergence metric.

    Args:
        exp: The experiment object.
        metrics: The metrics dictionary.
        case: The TestCase object.
        scores: Is either the score dictionary, or a function that produces the
                score dictionary based on an experiment.
    """
    # If the duration is too short, checking tputs and fairness has been done
    # by other check functions already.
    if exp.dur <= 2 * CONVERGENCE_BUCKET:
        return

    target_dict = _produce_scores(scores, exp)
    target_tput_score = target_dict['tput']
    target_fairness_score = target_dict['convergence_fairness']
    target_convergence_time = target_dict['convergence_sec']
    LOG.debug('default_check_convergence: target=%ds', target_convergence_time)

    LOG.debug('time,\ttputs history (target=%s):', target_tput_score)
    for i, tput in enumerate(metrics['tputs_history'].get(METRIC_NO_PORT)):
        ts = i + CONVERGENCE_BUCKET
        # Don't analyze past the configured end of the experiment.
        if ts > exp.dur:
            break
        LOG.debug('%s,\t%s', ts, tput)
        if ts < target_convergence_time:
            continue
        case.expect(tput >= target_tput_score,
                    'convergence failure: time=%ds, tput=%s, target=%s'
                    % (ts, tput, target_tput_score))

    if exp.nconns() <= 1:
        return

    LOG.debug('time,\tfairness history (target=%s):', target_fairness_score)
    for i, fair in enumerate(metrics['fairness_history'].get(METRIC_NO_PORT)):
        ts = i + CONVERGENCE_BUCKET
        # Don't analyze past the configured end of the experiment.
        if ts > exp.dur:
            break
        LOG.debug('%s,\t%s', ts, fair)
        if ts < target_convergence_time:
            continue
        case.expect(fair >= target_fairness_score,
                    'convergence failure: time=%ds, fairness=%.1f, '
                    'convergence_fairness target=%s'
                    % (ts, fair, target_fairness_score))


def default_check(exp, metrics, case, scores=default_target_score, real_bw=0):
    """The default test case for all experiments unless overridden by the user.

    Args:
        exp: The experiment object.
        metrics: The metrics dictionary.
        case: The TestCase object.
        scores: Is either the score dictionary, or a function that produces the
                score dictionary based on an experiment.
        real_bw: Real bandwidth value (e.g., bw overwritten by qdisc for ECN)
    """
    LOG.debug('\ndefault_check, exp=%s', exp)
    default_check_tput(exp, metrics, case, scores, real_bw)
    default_check_rtt(exp, metrics, case, scores)
    default_check_loss(exp, metrics, case, scores)
    default_check_fairness(exp, metrics, case, scores)
    default_check_convergence(exp, metrics, case, scores)


def check_with_scores(scores, real_bw=0):
    """The function returns the check function with scores as parameter.

    Args:
        scores: Is either the score dictionary, or a function that produces the
                score dictionary based on an experiment.
        real_bw: Real bandwidth value (e.g., bw overwritten by qdisc for ECN)

    Returns:
        The target check function with scores as parameter.
    """
    def _check(exp, metrics, case):
        LOG.debug('\ncheck_with_scores, exp=%s', exp)
        default_check(exp, metrics, case, scores, real_bw)

    return _check
