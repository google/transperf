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

"""metric contains all the aggregate metrics generated for an experiments."""

import logging
import math

from scapy.all import IP
from scapy.all import IPv6
from scapy.all import TCP
from transperf import CONVERGENCE_BUCKET
from transperf import METRIC_NO_PORT
from transperf import outparser
from transperf import tcp
from transperf import VarBandwidth


LOG = logging.getLogger('transperf/metric')


def parse_float(float_str, default=0):
    """Parses the float_str and returns the value if valid.

    Args:
        float_str: String to parse as float.
        default: Value to return if float_str is not valid.

    Returns:
        Parsed float value if valid or default.
    """
    try:
        return float(float_str)
    except ValueError:
        return default


class Metric(object):
    """Represents port-based metics.

    Arg:
        name: The name of this metric.
        vals: The default values.

    Attributes:
        _name: The name of the metric.
        _values: The dictionary of ports to values.
    """

    def __init__(self, name, vals=None, cc=None):
        self._name = name
        self._values = vals if vals is not None else dict()
        self._cc = cc if cc is not None else dict()

    def name(self):
        """Name of the metric."""
        return self._name

    def has(self, port):
        """Returns whether the metric has a value for the port.

        Args:
            port: the port number.

        Returns:
            whether the metrics has a value for the port.
        """
        return int(port) in self._values.keys()

    def set(self, port, value):
        """Sets the metric value for the port.

        Args:
            port: The port.
            value: The value.
        """
        self._values[int(port)] = value

    def set_cc(self, port, cc):
        """Sets the metric cc for the port.

        Args:
            port: The port.
            cc: The cc algorithm.
        """
        self._cc[int(port)] = cc

    def get_cc(self, port):
        """Gets the metric cc for the port.

        Args:
            port: The port.

        Returns:
            The cc algorithm.
        """
        return self._cc[int(port)]

    def as_array(self):
        """Metric values as an array.

        Returns:
            Metric values sorted by port number.
        """
        return [self._values[port] for port in sorted(self._values.keys())]

    def ports(self):
        """Ports that have a value in this metric.

        Returns:
            The port numbers.
        """
        return sorted(self._values.keys())

    def cc_ports(self, cc):
        """Ports that have a specific cc in this metric.

        Args:
            cc: The cc algorithm.

        Returns:
            The port numbers.
        """
        return sorted([k for k, v in self._cc.items() if v == cc])

    def get(self, port):
        """The value assigned for the port.

        Args:
            port: The port number.

        Returns:
            The value
        """
        port = int(port)
        if port not in self._values:
            return 0
        return self._values[port]

    def __str__(self):
        vals = ','.join([('%s:%s' % (port, val))
                         for port, val in self._values.items()])
        ccs = ','.join([('%s:%s' % (port, cc))
                        for port, cc in self._cc.items()])
        return 'Metric(\'%s\',{%s},{%s})' %  (self._name, vals, ccs)


class MetricPublisher(outparser.Visitor):
    """The abstract base class for metrics.

    MetricPublishers are visitors that can publish metrics in a dictionary.
    """

    def publish_metrics(self):
        """Publishes metrics in the metrics dictionary.

        Returns:
            An array of published metrics.
        """
        pass


class TputMetricPublisher(MetricPublisher):
    """Generates throughput metrics.

    Attributes:
        _tputs: Throughput of each port.
    """

    def __init__(self):
        super(TputMetricPublisher, self).__init__()
        self._tputs = Metric('tputs')
        self._tool_tputs = Metric('tool_tputs')  # tput from netperf or similar
        # We want the throughput for each port. Note that not all the flows
        # start at the same time, and they may be configured to run past the
        # duration of the experiment (ie. per conn dur overrides experiment
        # provided dur; suppose a 10-sec experiment where a conn starts at 9
        # seconds in and has a conn-configured dur of 20 seconds.)
        #
        # All we care is that, for each second with a flow active, where that
        # second falls into the lifespan of the experiment as a *whole* (ie.
        # dur= for the experiment itself in the config), that the tput for all
        # such seconds is above the configured threshold for the test. We ignore
        # seconds where no flow was configured to be active (eg. flow from 0-2
        # seconds, then 1 second with now flows, then a flow from 3-10 seconds
        # would ignore t=2 to t=3 seconds). We also ignore cases where a flow
        # continues past the experiment duration as in the case of the 20 second
        # flow above.
        #
        # As metric, we output a timeline of bandwidths for all flows
        # aggregated.
        self._stats = {}
        self._tputs_timeline = {}
        self._prev_time = 0

    def visit_conn(self, ip, port, tool, cc, params, start, dur, tput):
        """Stores connection throughputs.

        See the MetricPublisher interface.
        """
        self._tputs.set(port, parse_float(tput, 0.0))
        self._tputs.set_cc(port, cc)
        self._tool_tputs.set(port, parse_float(tput, 0.0))
        self._tool_tputs.set_cc(port, cc)
        # Prep for when we visit the ss log.
        port = int(port)
        self._stats[port] = (0, 0)
        self._tputs_timeline[port] = []

    def visit_ss_log(self, time, data):
        if 'port' not in data:
            return

        ts = self._prev_time
        while ts + CONVERGENCE_BUCKET <= time:
            ts += CONVERGENCE_BUCKET
            ports = sorted(self._stats.keys())
            for port in ports:
                # The values are cumulative, so use the delta.
                prev, curr = self._stats[port]
                tput_for_port = 8 * (curr - prev) / CONVERGENCE_BUCKET
                # Convert to mbps.
                tput_for_port /= (10**6)
                # Track both the timeline for this port in this bucket and the
                # state for the cumulative delta in the next iteration.
                self._tputs_timeline[port].append((ts, tput_for_port))
                self._stats[port] = (curr, curr)
        self._prev_time = ts

        port = data['port']
        prev, curr = self._stats[port]
        if 'bytes_acked' in data:
            curr = max(curr, data['bytes_acked'])
        self._stats[port] = (prev, curr)

    def publish_metrics(self):
        """Publishes an array of tputs.

        See the MetricPublisher interface.
        """
        for port in self._stats:
            if not self._tputs_timeline[port]:
                # If we did not get data from sslog, we have to rely on what
                # netperf reports - which is definitely wrong if the flows did
                # not coincide in time but it (usually) works for simple tests
                # where they do.
                return [self._tputs, self._tool_tputs]
        # If we do have sslog data: rather than assume all flows have the same
        # lifespan of activity, and setting a single per-flow tput value, we
        # instead will have a list of <timestamp, bandwidth> tuples. It is up to
        # the caller to properly interpret whether the resulting data passes the
        # requirements of whatever test is being run.
        ports = sorted(self._stats.keys())
        for port in ports:
            LOG.debug('port %d: visit_conn tput was %s, sslog is %s\n',
                      port, self._tputs.get(port), self._tputs_timeline[port])
            self._tputs.set(port, self._tputs_timeline[port])
        return [self._tputs, self._tool_tputs]


class KlogMetricsPublisher(MetricPublisher):
    """Generates metrics based on klog entries.

    It publishes lock_on_bw, probing_cnt, compete_cnt,
    policer_cnt, and lock_on_cnt.

    Attributes:
        _port_modes: The count of modes for each port.
        _lock_on_bw: The lock-on BW of each port.
    """

    def __init__(self):
        super(KlogMetricsPublisher, self).__init__()
        self._port_modes = {}
        self._lock_on_bw = Metric('lock_on_bw')

    def visit_conn(self, ip, port, tool, cc, params, start, dur, tput):
        """Stores the experiment port numbers.

        See the MetricPublisher interface.
        """
        port = int(port)
        self._port_modes[port] = {}
        self._lock_on_bw.set(port, 0)

    def visit_klog(self, time, line, match):
        """Updates mode counts and set the lock on bandwidth.

        Args:
            time: Time of the log entry relative to the start time of the
                  experiment.
            line: The raw content of the log file.
            match: The dictionary of all grouped regex matches.
        """
        port = int(match['port'])
        if port not in self._port_modes:
            return

        modes = self._port_modes[port]
        mode = match.get('mode', None)
        if mode not in modes:
            modes[mode] = 1
            if mode == 'W':
                self._lock_on_bw.set(port, int(match.get('bw', 0)) / 1000.)
        else:
            modes[mode] += 1

    def publish_metrics(self):
        """Publishes metrics from the klog entries."""
        probing_cnt = Metric('probing_cnt')
        compete_cnt = Metric('compete_cnt')
        policer_cnt = Metric('policer_cnt')
        lock_on_cnt = Metric('lock_on_cnt')
        for port in self._lock_on_bw.ports():
            port_mode_cnt = self._port_modes[port]
            for mode, metric in [('G', probing_cnt), ('C', compete_cnt),
                                 ('P', policer_cnt), ('W', lock_on_cnt)]:
                if mode not in port_mode_cnt:
                    metric.set(port, 0)
                else:
                    metric.set(port, port_mode_cnt[mode])

        return [probing_cnt, compete_cnt, policer_cnt, lock_on_cnt,
                self._lock_on_bw]


class RetxRateMetricPublisher(MetricPublisher):
    """Publishes the retransmittion rate for each flow.

    Attributes:
        _rcv_ip: The receiver IP address.
        _max_seq: The maximum sequence number sent so far for each port.
        _stats: The number of transmistted and retransmitted packets for each
                port.
    """

    def __init__(self):
        super(RetxRateMetricPublisher, self).__init__()
        self._rcv_ip = None
        self._max_seq = {}
        self._stats = {}

    def begin(self, exp, exp_dir, rcv_ip):
        """Stores the receiver ip address.

        See the outparser.Visitor interface.
        """
        self._rcv_ip = rcv_ip

    def visit_conn(self, ip, port, tool, cc, params, start, dur, tput):
        """Initializes the state for the given port.

        See the outparser.Visitor interface.
        """
        port = int(port)
        self._stats[port] = (0, 0)
        self._max_seq[port] = -1

    def visit_packet(self, time, packet):
        """Generate statistics for each port.

        See the outparser.Visitor interface.
        """
        if (IP not in packet and IPv6 not in packet) or TCP not in packet:
            return

        iph = packet[IP] if IP in packet else packet[IPv6]
        tcph = packet[TCP]

        if iph.src == self._rcv_ip:
            return

        port = tcph.sport
        if port not in self._stats:
            return

        max_seq = self._max_seq[port]
        if IP in packet:
            data_len = iph.len - 4 * iph.ihl - 4 * tcph.dataofs
        else:
            if iph.nh != 6:
                LOG.info('IPv6 pachet has extension headers, skipping.')
                return
            data_len = iph.plen - 4 * tcph.dataofs
        next_seq = tcp.add_seq(tcph.seq, data_len - 1)
        if max_seq == -1 or tcp.after(tcph.seq, max_seq):
            self._max_seq[port] = next_seq
            is_retx = 0
        else:
            is_retx = 1

        tx, retx = self._stats[port]
        self._stats[port] = (tx + data_len, retx + is_retx * data_len)

    def visit_ss_log(self, time, data):
        if 'port' not in data:
            return
        port = data['port']
        tx, retx = self._stats[port]
        if 'data_segs_out' in data:
            tx = data['data_segs_out']
        if 'retrans' in data:
            retx = data['retrans']
        self._stats[port] = (tx, retx)

    def publish_metrics(self):
        ports = sorted(self._stats.keys())
        retxs = Metric('retx')
        for port in ports:
            tx, retx = self._stats[port]
            retxs.set(port, (float(retx) / tx) if tx else 0)
        return [retxs]


class ConvergenceMetricPublisher(MetricPublisher):
    """Publishes the convergence status.

    Attributes:
        _stats: The bytes_acked of previous and current time bucket.
        _tputs: The list containing the throughput per bucket.
        _fairness: The list containing the fairness score per bucket.
        _prev_time: The timestamp in seconds of previous bucket processed.
    """

    def __init__(self):
        super(ConvergenceMetricPublisher, self).__init__()
        self._stats = {}
        self._tputs = []
        self._fairness = []
        self._prev_time = 0

    def visit_conn(self, ip, port, tool, cc, params, start, dur, tput):
        """Initializes the state for the given port.

        See the outparser.Visitor interface.
        """
        port = int(port)
        self._stats[port] = (0, 0)

    def visit_ss_log(self, time, data):
        if 'port' not in data:
            return

        ts = self._prev_time
        while ts + CONVERGENCE_BUCKET <= time:
            ts += CONVERGENCE_BUCKET
            ports = sorted(self._stats.keys())
            tputs = []
            for port in ports:
                # The values are cumulative, so use the delta.
                prev, curr = self._stats[port]
                tputs.append(8*(curr - prev)/CONVERGENCE_BUCKET)
                self._stats[port] = (curr, curr)

            # Compute Jain's fairness index for throughputs for each flow.
            sum_ = sum(tputs)
            self._tputs.append(sum_)
            num_flows = len(ports)
            sum2_ = sum([tput**2 for tput in tputs])
            if sum2_ > 0:
                fairness_score = 100 * sum_ * sum_ / sum2_ / num_flows
            else:
                fairness_score = 0
            self._fairness.append(fairness_score)
        self._prev_time = ts

        port = data['port']
        prev, curr = self._stats[port]
        if 'bytes_acked' in data:
            curr = max(curr, data['bytes_acked'])
        self._stats[port] = (prev, curr)

    def publish_metrics(self):
        tputs_history = Metric('tputs_history')
        tputs_history.set(METRIC_NO_PORT, self._tputs)
        fairness_history = Metric('fairness_history')
        fairness_history.set(METRIC_NO_PORT, self._fairness)
        return [tputs_history, fairness_history]


class RTTMetricPublisher(MetricPublisher):
    """Publishes RTT metrics.

    To be an efficient metric generator with low memory consumption,
    we use the following heuristics to calculate RTT and store the values:

    1) RTT is only calculated when we receive an Ack or SAck after the
       highest previously Ack'ed/SAck'ed data.
    2) We use a multi-resolution histogram to store the measured RTTs.
       In this histogram we store RTTs of less than 10ms in us resolution,
       and RTTs of more than 10ms is ms resolution. Assuming that we almost
       always use a RTT of less 1sec, we will have at most 10,990 buckets.

    Using this histogram we calculate the following metrics:
    1. med_rtt
    2. p95_rtt
    3. p99_rtt

    And we use O(1) memory to calculate the following metrics:
    4. min_rtt
    5. avg_rtt
    6. max_rtt

    Times are kept in pythonic format: a float where its integer part is seconds.

    Attributes:
        _rcv_ip: The receiver IP address.
        _last_acked: The last sequence acked/sacked for each port.
        _unacked: The sequence numbers that higher than the last ack/sack
                  received.
        _samples: Number of RTT samples taken for each port
        _min_rtt: The minimum RTT of each port.
        _max_rtt: The maximum RTT of each port.
        _sum_rtt: The sum of RTTs for each port.
        _hist: The histogram of each port.
    """

    def __init__(self):
        self._rcv_ip = None
        self._last_acked = {}
        self._unacked = {}
        self._samples = {}
        self._min_rtt = {}
        self._max_rtt = {}
        self._sum_rtt = {}
        self._hist = {}

    def begin(self, exp, exp_dir, rcv_ip):
        """Stores the receiver ip address.

        See the outparser.Visitor interface.
        """
        self._rcv_ip = rcv_ip

    def visit_conn(self, ip, port, tool, cc, params, start, dur, tput):
        """Initializes the state for the given port.

        See the outparser.Visitor interface.
        """
        port = int(port)
        self._last_acked[port] = -1
        self._unacked[port] = []
        self._samples[port] = 0
        self._min_rtt[port] = -1
        self._max_rtt[port] = 0
        self._sum_rtt[port] = 0
        self._hist[port] = {}

    def visit_ss_log(self, time, data):
        if ('port' not in data) or ('rtt' not in data):
            return
        self._sample_rtt(data['port'], data['rtt'])

    def visit_packet(self, time, packet):
        if (IP not in packet and IPv6 not in packet) or TCP not in packet:
            return

        iph = packet[IP] if IP in packet else packet[IPv6]
        tcph = packet[TCP]
        if iph.src == self._rcv_ip:
            self._handle_rcv(time, tcph)
        else:
            self._handle_snd(time, tcph)

    def _sample_rtt(self, port, rtt):
        self._max_rtt[port] = max(self._max_rtt[port], rtt)

        min_rtt = self._min_rtt[port]
        if min_rtt == -1:
            min_rtt = rtt
        self._min_rtt[port] = min(rtt, min_rtt)

        samples = self._samples[port]
        self._samples[port] = samples + 1

        self._sum_rtt[port] += rtt

        # RTTs more than 10ms are rounded DOWN to ms resolution.
        # All rtt values in the histogram are in units of usec.
        if rtt > .01:
            rtt = int(rtt * 1000) * 1000
        else:
            rtt = int(rtt * 1000 * 1000)

        if rtt in self._hist[port]:
            self._hist[port][rtt] += 1
        else:
            self._hist[port][rtt] = 1

    def _handle_snd(self, time, tcph):
        port = tcph.sport
        if port not in self._unacked:
            return

        seq = tcph.seq
        unacked = self._unacked[port]
        if not unacked:
            unacked.append((seq, time))
            return

        max_seq = unacked[-1][0]
        if tcp.after(seq, max_seq):
            unacked.append((seq, time))

    def _handle_rcv(self, time, tcph):
        port = tcph.dport
        if port not in self._unacked:
            return

        ack = tcph.ack
        # Ignore packets with ack of 0 or with RST.
        if not ack or tcph.flags & 0x4:
            return

        for _, end in tcp.sacks(tcph):
            ack = max(ack, end)

        i = 0
        max_seq_time = -1
        unacked = self._unacked[port]
        for i, (seq, seq_time) in enumerate(unacked):
            if not tcp.after(ack, seq):
                break

            max_seq_time = max(max_seq_time, seq_time)

        if i >= 1:
            self._unacked[port] = unacked[i-1:]

        if max_seq_time == -1:
            return

        rtt = time - max_seq_time
        self._sample_rtt(port, rtt)

    def publish_metrics(self):
        ports = sorted(self._unacked.keys())

        # min/max/avg_rtt are multiplied by 1000 to convert from sec to msec.
        min_rtt = Metric('min_rtt')
        max_rtt = Metric('max_rtt')
        for port in ports:
            min_rtt.set(port, self._min_rtt[port] * 1000)
            max_rtt.set(port, self._max_rtt[port] * 1000)

        avg_rtts = Metric('avg_rtt')
        for port in ports:
            if self._samples[port]:
                avg_rtts.set(port,
                             self._sum_rtt[port] * 1000. / self._samples[port])
            else:
                avg_rtts.set(port, 0)

        med_rtts = Metric('med_rtt')
        p95_rtts = Metric('p95_rtt')
        p99_rtts = Metric('p99_rtt')

        # med/p95/p99_rtt are divided by 1000 to convert from usec to msec.
        for port in ports:
            samples = self._samples[port]
            hist = self._hist[port]

            med_rtt = p95_rtt = p99_rtt = -1
            total = 0
            for rtt, cnt in sorted(hist.items()):
                total += cnt

                if 0.5 * samples <= total and med_rtt == -1:
                    med_rtt = rtt

                if 0.95 * samples <= total and p95_rtt == -1:
                    p95_rtt = rtt

                if 0.99 * samples <= total and p99_rtt == -1:
                    p99_rtt = rtt

            med_rtts.set(port, med_rtt / 1000.0)
            p95_rtts.set(port, p95_rtt / 1000.0)
            p99_rtts.set(port, p99_rtt / 1000.0)

        # return all metrics in units of msec
        return [min_rtt, avg_rtts, med_rtts, p95_rtts, p99_rtts, max_rtt]


class SerialDelayMetricPublisher(MetricPublisher):
    """Calculates the serialization delay.

    Attributes:
        _rcv_ip: The receiver IP address.
        _packet_size: Counts the size of packets for each port.
    """

    def __init__(self):
        self._rcv_ip = None
        self._packet_size = {}
        self._bw = -1

    def begin(self, exp, exp_dir, rcv_ip):
        self._rcv_ip = rcv_ip

        if isinstance(exp.bw, VarBandwidth):
            self._bw = min([bw.downlink for bw in exp.bw.bws])
        else:
            self._bw = exp.bw.downlink

        # If there is no HTB, set the bandwidth to 10Gbps
        if self._bw == 0:
            self._bw = 10000

    def visit_conn(self, ip, port, tool, cc, params, start, dur, tput):
        self._packet_size[port] = {}

    def visit_packet(self, time, packet):
        if (IP not in packet and IPv6 not in packet) or TCP not in packet:
            return

        iph = packet[IP] if IP in packet else packet[IPv6]
        tcph = packet[TCP]

        if iph.src == self._rcv_ip:
            return

        port = tcph.sport
        if port not in self._packet_size:
            return

        # TODO(arjunroy) IPv4 = total len, IPv6 = payload len. Is it important?
        packet_len = packet.len if IP in packet else packet.plen
        sizes = self._packet_size[port]
        if packet_len in sizes:
            sizes[packet_len] += 1
        else:
            sizes[packet_len] = 1

    def publish_metrics(self):
        ports = sorted(self._packet_size.keys())

        serial_delays = Metric('serial_delay')
        for port in ports:
            samples = sum([v for _, v in self._packet_size[port].items()])

            med_size = 1514
            total = 0
            for size, cnt in sorted(self._packet_size[port].items()):
                total += cnt
                if 0.5 * samples <= total:
                    med_size = size
                    break

            # 3 * median_skb_size_in_bits / configured_link_bw_in_bits
            delay = float(3 * med_size * 8) / (self._bw * 1000 * 1000)
            serial_delays.set(port, delay * 1000)  # in ms.

        return [serial_delays]


class AppLatencyMetricPublisher(MetricPublisher):
    """Estimates the app latency metric.

    Attributes:
        _exp: The experiment.
        _rcv_ip: The receiver IP address.
        _rtt_of_port: The map of port to min RTT (specified in the experiment).
        _bursts_of_ports: The burst of each port.
        _cnt: The number of samples collected for each port.
        _avg: The avg metrics.
        _max: The max metrics.
        _tops: Are the top latency samples maintained for each port, used for
               the p95 metric.
        _chunk_latency: The latency of sending a full chunk for each port.
        _first_ack: The first ack sequence of each port.
        _last_ack: The last relative ack sequence of each port.
        _ports: The ports of this experiment.
    """

    def __init__(self):
        self._exp = None
        self._rcv_ip = None
        self._rtt_of_port = None
        self._bursts_of_ports = {}
        self._cnt = {}
        self._avg = Metric('packet_transfer_avg')
        self._max = Metric('packet_transfer_max')
        self._tops = {}
        self._chunk_latency = {}
        self._first_ack = {}
        self._last_ack = {}
        self._ports = {}

    def begin(self, exp, exp_dir, rcv_ip):
        self._exp = exp
        self._rcv_ip = rcv_ip

    def visit_conn(self, ip, port, tool, cc, params, start, dur, tput):
        self._ports[port] = True
        self._chunk_latency[port] = []

    def _write_time(self, port, byte):
        """Returns the time the application has written "byte" byte of data."""
        if not self._bursts_of_ports:
            # Fill bursts_of_ports.
            bursts = []
            for s in xrange(self._exp.nsenders()):
                for c in self._exp.conns_of_sender(s):
                    for i in range(c.num):
                        bursts.append(c.burst)

            for i, port in enumerate(sorted(self._ports)):
                self._bursts_of_ports[port] = bursts[i]

        if port not in self._bursts_of_ports:
            return 0
        burst = self._bursts_of_ports[port]
        if not burst:
            return 0
        return int(
            byte / (burst.rounds * burst.repeat * burst.req)) * burst.wait

    def _sample(self, port, ack, dur):
        """Collects one latency sample.

        Args:
            port: the connection port.
            ack: relative acknowledged byte.
            dur: latency duration.
        """
        port = int(port)
        if port not in self._cnt.keys():
            self._cnt[port] = 1
            self._avg.set(port, dur)
            self._max.set(port, dur)
            self._tops[port] = [dur]
            return

        cnt = self._cnt[port] + 1
        self._cnt[port] = cnt

        avg = self._avg.get(port)
        avg = (avg * (cnt - 1) + dur) / cnt
        self._avg.set(port, avg)

        max_m = self._max
        max_m.set(port, max(max_m.get(port), dur))

        cnt = self._top_vals_to_keep(cnt)
        tops = self._tops[port]

        # keep tops sorted and keep cnt samples in it.
        i = len(tops) - 1
        while i >= 0:
            if dur <= tops[i]:
                break
            i -= 1
        i += 1
        tops.insert(i, dur)
        if len(tops) > cnt:
            tops.pop()

        burst = self._burst_size(port)
        if not burst:
            return

        c_lats = self._chunk_latency[port]
        # We ignore the first chunk. Thus, if c_lats contains 0 elements, we are
        # looking to receive the ack of the second chunk, and so on...
        if ack >= (len(c_lats) + 2) * burst - 1:
            c_lats.append(dur)

    def _top_vals_to_keep(self, cnt):
        """How much top values we should keep to have a good accuracy for p95.

        Args:
          cnt: Total number of records.

        Returns:
          Number of records to keep.
        """
        if cnt <= 100:
            return 1000
        # Keep at least 10% of the required value, in power of 10 steps:
        #   100 for     101..1000
        #   1000 for    1001..10000
        #   10000 for   10001..100000
        #   ...
        return int(math.pow(10, math.ceil(math.log(cnt, 10)) - 1))

    def _ack(self, time, tcph):
        """Processes an ack and calculates the latency of the acked packets."""
        port = int(tcph.sport)
        if port not in self._first_ack:
            self._first_ack[port] = tcph.ack
            self._last_ack[port] = -1
            return

        ack = tcph.ack
        if ack == 0:
            return
        if ack < self._first_ack[port]:
            ack += 65536
        ack -= self._first_ack[port]
        if ack <= self._last_ack[port]:
            return

        self._last_ack[port] = ack

        ack -= 1
        if ack <= self._burst_size(port):
            return

        wtime = self._write_time(port, ack)
        self._sample(port, ack, time - wtime)

    def visit_packet(self, time, packet):
        if (IP not in packet and IPv6 not in packet) or TCP not in packet:
            return

        iph = packet[IP] if IP in packet else packet[IPv6]
        tcph = packet[TCP]

        if iph.src == self._rcv_ip:
            self._ack(time, tcph)

    def _min_bw(self):
        """Returns the minimum bottleneck bandwidth of the link."""
        bw = self._exp.bw
        if isinstance(bw, VarBandwidth):
            return min([vbw.downlink for vbw in bw.bws])
        else:
            return bw.downlink

    def _burst_size(self, port):
        """Returns the size of the bursts in bytes.

        If the connection is not a burst connection it returns 0.

        Args:
            port: The port number.
        Returns:
            The size of the first burst if any, otherwise 0.
        """
        burst = self._bursts_of_ports.get(port)
        if not burst:
            return 0
        return burst.rounds * burst.repeat * burst.req

    def publish_metrics(self):
        pkt_p95 = Metric('packet_transfer_p95')
        pkt_p99 = Metric('packet_transfer_p99')
        for port, tops in self._tops.items():
            cnt = self._cnt[port]
            top5cnt = int(.05 * cnt)
            top5cnt = min(top5cnt, len(tops) - 1)
            pkt_p95.set(port, tops[top5cnt])
            top1cnt = int(.01 * cnt)
            top1cnt = min(top1cnt, len(tops) - 1)
            pkt_p99.set(port, tops[top1cnt])

        cl_med = Metric('chunk_latency_med')
        cl_avg = Metric('chunk_latency_avg')
        cl_p90 = Metric('chunk_latency_p90')
        cl_p95 = Metric('chunk_latency_p95')
        cl_p99 = Metric('chunk_latency_p99')
        cl_max = Metric('chunk_latency_max')
        for port, lat in self._chunk_latency.items():
            if not lat:
                cl_med.set(port, -1)
                cl_avg.set(port, -1)
                cl_p90.set(port, -1)
                cl_p95.set(port, -1)
                cl_p99.set(port, -1)
                cl_max.set(port, -1)
                continue
            lat = sorted(lat)
            cl_avg.set(port, float(sum(lat)) / len(lat))
            cl_max.set(port, max(lat))
            cl_med.set(port, lat[max(0, int(len(lat) * .50) - 1)])
            cl_p90.set(port, lat[max(0, int(len(lat) * .90) - 1)])
            cl_p95.set(port, lat[max(0, int(len(lat) * .95) - 1)])
            cl_p99.set(port, lat[max(0, int(len(lat) * .99) - 1)])

        # To avoid publishing rubbish on the metrics, make sure each port has
        # 1) sent at least 25% of its data, if it's a stream.
        # 2) sent at least the first chunk, if it's a burst (write-wait).
        bw = self._min_bw()
        for port in self._ports:
            if port not in self._last_ack:
                continue
            lack = self._last_ack[port]
            burst = self._bursts_of_ports.get(port)
            if not burst or burst.wait <= 0:
                thresh = self._exp.dur * bw / 8. / 4
            else:
                thresh = burst.rounds * burst.repeat * burst.req
            if lack < thresh:
                pkt_p95.set(port, -1)
                pkt_p99.set(port, -1)
                self._max.set(port, -1)
                self._avg.set(port, -1)

        return [self._avg, self._max, pkt_p95, pkt_p99,
                cl_med, cl_avg, cl_p90, cl_p95, cl_p99, cl_max]

# TODO(soheil): Maybe later add the following metrics:
#               bloated_rtt, avg_policer_bw, max_policer_bw, fq_bw.
