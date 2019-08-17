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

"""Processes transperf outputs including pcap files and kernel log files.
"""

import csv
import logging
import re

from scapy.all import PcapReader

LOG = logging.getLogger('transperf/outparser')


class Visitor(object):
    """The abstract base class for all the classes that process output files.

    Visitors are added to transperf to process logs and pcap files in one pass,
    *hopefully* with O(1) memory.

    Visitor methods are called in the following sequence:
    1) begin()
    2) visit_conn()
    3) visit_packet()
    4) visit_klog()
    5) end()
    """

    def begin(self, exp, exp_dir, rcv_ip):
        """Called when the visitor should start a new experiment.

        Args:
            exp: The experiment object.
            exp_dir: The experiment output directory.
            rcv_ip: The receiver's IP address.
        """
        pass

    def end(self):
        """Called when all the output entries are passed to the visitor."""
        pass

    def visit_conn(self, ip, port, tool, cc, params, start, dur, tput):
        """Called for each connection.

        Args:
            ip: The ip address of the connection.
            port: The port of the connection.
            tool: The tool used in the experiment.
            cc: The congestion control algorithm.
            params: Parameters used for cc.
            start: The relative start time in seconds.
            dur: The duration of the connection in seconds.
            tput: The throughput reported by the benchmarking
                  application (e.g., netperf).
        """
        pass

    def visit_klog(self, time, line, match):
        """Called for a new klog line.

        The log lines of each connection are sorted by time, but the lines of
        different connections can interleave.

        Args:
            time: Time of the log entry relative to the start time of the
                  experiment.
            line: The raw content of the log file.
            match: The dictionary of all grouped regex matches.
        """
        pass

    def visit_strmr_log(self, time, pline):
        """Called for a new streamer log line.

        The log lines of each connection are sorted by time.

        Args:
            time: Time of the log entry relative to the start time of the
                  experiment.
            pline: The dictionary of all relvant parsed fields of a log line.
        """
        pass

    def visit_ss_log(self, time, data):
        """Called for a new ss log entry.

        The log entries are sorted by time.

        Args:
            time: The time of the log entry when run ss command.
            data: The dictionary of all relvant parsed fields of a log line.
        """
        pass

    def visit_packet(self, time, packet):
        """Called when there is a new packet available to be processed.

        The packets of each connection are sorted by time but packets of
        different connections can interleave..

        Args:
            time: Captured time relative to the start time of the experiment.
            packet: The packet parsed by scapy.
        """
        pass

    def visit_metric(self, metric):
        """Called when a metric is available to be processed.

        Args:
            metric: The metric of type metric.Metric.
        """
        pass


class SsLog(object):
    """Parses ss logs and provides the flows of the experiment.

    Attributes:
        __readers: The ss log file readers.
        __entries: The most recent read entry from each log file. We keep this
                   list to make sure the entries are yielded sorted by time.
    """

    def __init__(self, log_paths):
        self.__readers = [open(path) for path in log_paths]
        self.__times = [0] * len(log_paths)
        self.__entries = [None] * len(log_paths)

    def __read_sslog(self, i):
        """Read the next entry in file.

        Args:
            i: The index of the file reader.

        Returns:
            The next entry in file f. None if there is no entry.
        """
        f = self.__readers[i]
        if not f:
            return None
        time = self.__times[i]
        line = f.readline()
        if not line:
            return None
        while line.startswith('# '):
            self.__times[i] = time = float(line[2:])
            f.readline()
            line = f.readline()
            if not line:
                return None
        data = {}
        port = line.strip()
        port = int(port[port.rfind(':') + 1:])
        data['port'] = port
        line = f.readline()
        if not line:
            return None
        stat = line.strip().split()
        for item in stat:
            if item.startswith('bytes_acked:'):
                data['bytes_acked'] = int(item[item.rfind(':') + 1:])
            elif item.startswith('retrans:'):
                data['retrans'] = int(item[item.rfind('/') + 1:])
            elif item.startswith('data_segs_out:'):
                data['data_segs_out'] = int(item[item.rfind(':') + 1:])
            elif item.startswith('rtt:'):
                data['rtt'] = (
                    float(item[item.find(':') + 1:item.rfind('/')]) / 1000
                )
            elif item.startswith('unacked:'):
                data['unacked'] = int(item[item.find(':') + 1:])
        return time, data

    def __next_entry(self):
        """Returns the next entry ordered by time.

        Returns:
            The next entry. None if there is no entry.
        """
        min_time = -1
        min_index = -1
        for i, entry in enumerate(self.__entries):
            # If the reader has finished reading entries, check the next slot.
            if not self.__readers[i]:
                continue

            # Fill the holes.
            if not entry:
                entry = self.__read_sslog(i)
                self.__entries[i] = entry

            # If entry is not set, it means that there is no entry in the
            # reader. So, we can remove the reader.
            if not entry:
                self.__readers[i] = None
                continue
            entry_time = entry[0]
            if min_index == -1 or entry_time < min_time:
                min_index = i
                min_time = entry_time

        if min_index == -1:
            return None

        entry = self.__entries[min_index]
        self.__entries[min_index] = None
        return entry

    def entries(self):
        """Entries stored in the ss log files.

        Yields:
            A tuple in the form of (relative time in sec, entry).
        """
        min_time = -1
        while True:
            entry = self.__next_entry()
            if not entry:
                break

            if min_time == -1:
                min_time = entry[0]

            yield (entry[0] - min_time, entry[1])


class Pcap(object):
    """Parses pcap files and provides the flows of the experiment.

    Attributes:
        __readers: The pcap readers.
        __packets: The most recent read packet from each pcap file. We keep this
                   list to make sure the packets are yielded sorted by time.
    """

    def __init__(self, pcap_paths):
        self.__readers = [PcapReader(path) for path in pcap_paths]
        self.__packets = [None] * len(pcap_paths)

    def __next_packet(self):
        """Returns the next packet ordered by time.

        Returns:
            The next packet. None if there is no packet.
        """
        min_time = -1
        min_index = -1
        for i, pkt in enumerate(self.__packets):
            # If the reader has finished reading packets, check the next slot.
            if not self.__readers[i]:
                continue

            # Fill the holes.
            if not pkt:
                self.__packets[i] = pkt = self.__readers[i].read_packet()

            # If pkt is not set, it means that there is no packet in the reader.
            # So, we can remove the reader.
            if not pkt:
                self.__readers[i] = None
                continue

            if min_index == -1 or pkt.time < min_time:
                min_index = i
                min_time = pkt.time

        if min_index == -1:
            return None

        pkt = self.__packets[min_index]
        self.__packets[min_index] = None
        return pkt

    def packets(self):
        """Packets stored in the pcap files.

        Yields:
            A tuple in the form of (relative time in sec, raw packet, ip, tcp).
        """
        min_time = -1
        while True:
            pkt = self.__next_packet()
            if not pkt:
                break

            if min_time == -1:
                min_time = pkt.time

            yield (pkt.time - min_time, pkt)


# These are regular expressions to parse congestion control output in
# kern-debug.log.
_LOG_PATTERNS = [
    # BBR:
    re.compile((
        r'\w+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+(\w[\w\d\-]+)\s+kernel:\s+'
        r'\[\s*(?P<ts>[\d\.]+)\] BBR '
        r'(?P<ip>(\d{1,3}\.){3}\d{1,3}):(?P<port>\d{1,6})\s+'
        r'(?P<ack>[\d,]+):(?P<fack>\d+)\s+'
        r'(?P<castate>\S)\s+(?P<mode>\S)\s+'
        r'(?P<snd_cwnd>\d+)\s+'
        r'br\s+(?P<extra_acked>\d+)\s+'
        r'cr\s+(?P<crtt>-?\d+)\s+'
        r'rtt\s+(?P<rtt>-?\d+)\s+'
        r'd\s+(?P<rs_delivered>-?\d+)\s+'
        r'i\s+(?P<interval_us>-?\d+)\s+'
        r'mrtt\s+(?P<mrtt>-?\d+)\s+'
        r'(?P<rs_app_limited>\S)bw\s+(?P<sample_bw>\d+)\s+'
        r'bw\s+(?P<bw>\d+)\s+'
        r'lb\s+(?P<unused1>\d+)\s+'
        r'ib\s+(?P<interval_bw>\d+)\s+'
        r'qb\s+(?P<pacing_bw>\d+)\s+'
        r'a\s+(?P<acked>\d+)\s+'
        r'if\s+(?P<inflight>\d+)\s+'
        r'(?P<unused2>\S)\s+'
        r'(?P<round_start>\S)\s+'
        r'dl\s+(?P<tp_delivered>\d+)\s+'
        r'l\s+(?P<tp_loss>\d+)\s+'
        r'al\s+(?P<tp_app_limited>\d+)\s+'
        r'#\s+(?P<unused3>\d+)\s+'
        r't\s+(?P<targetcw>\d+)\s+'
        r'(?P<reord_seen>r|\.)\s+'
        r'(?P<prev_ca_state>O|D|C|R|L)\s+'
        r'lr\s+(?P<lr_x1000>-?\d+)\s+'
        r'er\s+(?P<ecn_x1000>-?\d+)\s+'
        r'ea\s+(?P<ecn_alpha_x1000>-?\d+)\s+'
        r'bwl\s+(?P<bw_lo>-?\d+)\s+'
        r'il\s+(?P<inflight_lo>-?\d+)\s+'
        r'ih\s+(?P<inflight_hi>-?\d+)\s+'
        r'c\s+(?P<bw_probe_up_cnt>-?\d+)\s+'
        r'v\s+(?P<version>-?\d+)\s+'
        r'(?P<debug_event>[\S])\s+'
        r'(?P<cycle_idx>\d+)\s+'
        r'(?P<ack_phase>I|R|B|F|A)\s+'
        r'(?P<bw_probe_samples>Y|N)'
    )),
]


class KernLog(object):
    """Parses kern-debug.log files.

    Attributes:
        __log_paths: The paths of kernel log files.
    """

    def __init__(self, log_paths):
        self.__log_paths = log_paths

    def lines(self):
        """Yields a tuple for each log entry.

        Yields:
            Tuples in the form of: (timestamp in sec, raw line, parsed line)
        """
        min_ts = {}
        for path in self.__log_paths:
            f = open(path)
            for l in f:
                # All log patterns must have "ts" and "port" fields.
                m = None
                for p in _LOG_PATTERNS:
                    m = p.match(l.strip())
                    if m:
                        break
                if not m:
                    LOG.debug('cannot match log line: %s', l)
                    continue

                mdict = m.groupdict()
                if 'ts' not in mdict or 'port' not in mdict:
                    LOG.debug('no port or timestamp in log line: %s', l)
                    continue

                ts = float(mdict['ts'])

                # Make timestamps relative to the timestamp of the first
                # entry of this port in the log file.
                port = mdict['port']
                if port not in min_ts:
                    min_ts[port] = ts
                    ts = 0
                else:
                    ts -= min_ts[port]

                yield (ts, l, m.groupdict())


class ConnInfo(object):
    """Parses the exp_dir/conn.info file.

    This file is dumped by the sender and includes a line per connection.
    """

    def __init__(self, cinfo_files):
        self.__port_infos = {}
        for f in cinfo_files:
            lines = open(f).readlines()
            for l in lines:
                l = l.strip()
                port, conn_info = l.split('=', 1)
                self.__port_infos[int(port)] = conn_info.split(',', 6)

    def conn_info(self, port):
        """Connection information of the given port."""
        return self.__port_infos[port]

    def ports(self):
        """Ports that exist in the conn.info files."""
        return self.__port_infos.keys()


class RecvInfo(object):
    """Parses the recv.info file that is dumped by receiver.

    This file only contains the IP address of the receiver.
    """

    def __init__(self, rcvinf_file):
        f = open(rcvinf_file)
        self.ip = f.readlines()[0].strip()
        f.close()


class ExpInfo(object):
    """Parses the exp.info file that is dumped by the orchestrator.

    This file contains a readable string representation of the experiment.
    """

    def __init__(self, expinf_file):
        f = open(expinf_file)
        self.__lines = f.readlines()
        f.close()

    def info(self):
        """Returns the lines in the exp.info file."""
        return self.__lines

    def fields(self):
        """Returns a dictionary of experiment parameters and their values."""
        field_dict = {}
        for l in self.__lines:
            p, v = l.strip().split('=', 1)
            field_dict[p] = v
        return field_dict
