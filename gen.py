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

"""gen contains all functionalities to generate transperf's graphs."""

import getopt
import json
import logging
import os
import shutil
import socket
import sys
import threading
import urllib

from scapy.all import IP
from scapy.all import IPv6
from scapy.all import TCP
from scapy.all import UDP
from transperf import cfgutil
from transperf import js
from transperf import log
from transperf import metric
from transperf import outparser
from transperf import shell
from transperf import tcp
from transperf import templates
from transperf import TestCase
from transperf.metric import AppLatencyMetricPublisher
from transperf.metric import ConvergenceMetricPublisher
from transperf.metric import KlogMetricsPublisher
from transperf.metric import parse_float
from transperf.metric import RetxRateMetricPublisher
from transperf.metric import RTTMetricPublisher
from transperf.metric import SerialDelayMetricPublisher
from transperf.metric import TputMetricPublisher
from transperf.path import all_files

LOG = logging.getLogger('transperf/gen')


def _merge_pcaps(exp_dir):
    """Merges all the pcaps in the experiment directory."""
    pcaps = {}
    for d, f in all_files(exp_dir, regex=r'.*\.pcap$'):
        if d == exp_dir:
            continue
        if f not in pcaps:
            pcaps[f] = []
        pcaps[f].append(os.path.join(d, f))
    procs = []
    for f in pcaps:
        procs.append(shell.bg('mergecap -F pcap -w %s %s' % (
            os.path.join(exp_dir, 'all.' + f), ' '.join(pcaps[f]))))
    for p in procs:
        shell.wait(p)


def _merge_sysouts(exp_dir):
    """Merges sys.out (sysctl) files into a single file.

    The format of the new file is:

        Sender 0:
        /sys/...=...

        Sender 1:
        /sys/...=...

    Args:
        exp_dir: The experiment's output directory.
    """
    merged_file = open(os.path.join(exp_dir, 'sys.out'), 'w')
    merged_file.write('Module Params\n')
    merged_file.write('=============\n')
    for d, f in sorted(all_files(exp_dir, name='mod.out')):
        if d == exp_dir:
            continue

        sender_id = d[len(exp_dir) + 1:]
        mod_f = open(os.path.join(d, f))
        lines = mod_f.readlines()
        merged_file.write('Sender %s\n' % sender_id)
        merged_file.write('---------\n')
        merged_file.writelines(lines)
        merged_file.write('\n')
        mod_f.close()

    merged_file.write('Sysctl Params\n')
    merged_file.write('=============\n')
    for d, f in sorted(all_files(exp_dir, name='sys.out')):
        if d == exp_dir:
            continue

        sender_id = d[len(exp_dir) + 1:]
        sys_f = open(os.path.join(d, f))
        lines = sys_f.readlines()
        merged_file.write('Sender %s\n' % sender_id)
        merged_file.write('---------\n')
        merged_file.writelines(lines)
        merged_file.write('\n\n')
        sys_f.close()

    merged_file.close()


def gen_xplots(data_dir):
    """Generates xplots for all the experiments in the data directory."""
    for _, _, _, _, exp_dir in cfgutil.exps(data_dir):
        xpl_paths = []
        conn_info = outparser.ConnInfo(
            [os.path.join(d, f) for d, f in
             all_files(exp_dir, name='conn.info')])
        rcv_ip = outparser.RecvInfo(os.path.join(exp_dir, 'R', 'recv.info')).ip
        ports = conn_info.ports()
        all_lines = []
        procs = []
        for d, f in all_files(exp_dir, regex=r'.*\.pcap$'):
            if d == exp_dir:
                continue
            procs.append(shell.bg('tcptrace -CRSzxy --output_dir="%s" "%s"' % (
                d, os.path.join(d, f))))
        for p in procs:
            shell.wait(p)

        for d, f in all_files(exp_dir, regex=r'.*\.pcap$'):
            for xd, xf in all_files(d, regex=r'.*\.xpl$'):
                # Only process time sequence graphs.
                if xf.find('_tsg') == -1:
                    continue

                xplf = open(os.path.join(xd, xf))
                lines = xplf.readlines()

                # The first 3 lines in the xplot are for the title.
                # The last line is the draw command. The rest (3:-1)
                # is data. We save the rest in all_lines in order to
                # create one xplot that contains the time seqeuence
                # graphs for all flows.
                all_lines += lines[3:-1]

                # Parse the ip and port from the xplot's title. Note that the
                # addresses may be either IPv4 or IPv6.
                parts = lines[2].split('_==>_')[0].split(':')
                ip_base = ':'.join(parts[:-1])
                port = int(parts[-1])
                try:
                    ip = socket.getaddrinfo(ip_base, 0, socket.AF_INET,
                                            socket.SOCK_STREAM,
                                            socket.IPPROTO_TCP)[0][4][0]
                except socket.gaierror:
                    ip = socket.getaddrinfo(ip_base, 0, socket.AF_INET6,
                                            socket.SOCK_STREAM,
                                            socket.IPPROTO_TCP)[0][4][0]

                # If the ip and port are not from this experiment ignore this
                # file.
                if ip == rcv_ip or port not in ports:
                    continue

                # Rewrite the title of the explot as:
                #   ==> CC -- IP:PORT
                addr, _, cc, _, _, _, _ = conn_info.conn_info(port)
                lines[2] = '==>%s -- %s:%s\n' % (cc, addr, port)

                # Save the file.
                xpath = os.path.join(xd, 'out-%s.xpl' % port)
                xpl_paths.append(xpath)
                oxplf = open(xpath, 'w')
                oxplf.writelines(lines)
                oxplf.close()

        # Prepend the title to all_lines and append the draw command (ie, go).
        all_lines = (['dtime signed\n', 'title\n', '===> All flows\n'] +
                     all_lines + ['go'])
        axpath = os.path.join(exp_dir, 'out-all.xpl')
        xpl_paths.append(axpath)
        axplf = open(axpath, 'w')
        axplf.writelines(all_lines)
        axplf.close()

        shell.run('tar -C %s -cvjf %s %s' % (
            exp_dir,
            os.path.join(exp_dir, 'xplots.tbz2'),
            ' '.join([os.path.relpath(p, exp_dir) for p in xpl_paths])))


def gen_transperf_pages(data_dir, has_xplot=False,
                        open_page=True, skip_pcap_scan=False):
    """Generate transperf pages for all the experiements in the data directory.

    Args:
        data_dir: The path to the data directory.
        has_xplot: Whether we have generated xplots.
        open_page: Whether to launch the browser at the end.
        skip_pcap_scan: Whether to skip pcap scan.

    Returns:
        1 if test case errors are present, or 0.
    """
    html = '''
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Connections</th>
                    <th>RTT (ms)</th>
                    <th>BW (Mbps)</th>
                    <th>Buf (pkts)</th>
                    <th>Slot</th>
                    <th>Policer (Mbps)</th>
                    <th>ILoss (%)</th>
                    <th>OLoss (%)</th>
                    <th>Dur (sec)</th>
                    <th>Tputs (Mpbs)</th>
                    <th>Retx</th>
                    <th>p95 RTT (ms)</th>
                    <th>Med RTT (ms)</th>
                    <th>Lock on BW (Mbps)</th>
                    <th>Status</th>
                    <th>Links</th>
                </tr>
            </thead>
            <tbody>'''
    param_cols = [
        ('conn', ''),
        ('rtt', ''),
        ('bw', ''),
        ('buf', 'pkts'),
        ('slot', ''),
        ('policer', ''),
        ('loss', '%'),
        ('out_loss', '%'),
        ('dur', 'sec')
    ]
    metric_cols = [
        ('tool_tputs',  'Mbps', '%s'),   # throughput from netperf or similar
        ('retx',        '',     '%.3f'),
        ('p95_rtt',     'ms',   '%s'),
        ('med_rtt',     'ms',   '%s'),
        ('lock_on_bw',  'Mbps', '%s'),
    ]
    exps = cfgutil.exps(data_dir)
    has_error = 0
    for i, (exp, cfg_dir, cfg_file, exp_name, exp_dir) in enumerate(exps):
        metrics, errs = gen_exp(exp, exp_dir, has_xplot,
                                skip_pcap_scan)
        if errs:
            has_error = 1

        if open_page:
            shell.bg('x-www-browser %s/index.html' % exp_dir)

        exp_info = _exp_info(exp_dir)
        fields = exp_info.fields()
        esc_dir = urllib.quote(os.path.join('__out', cfg_dir, exp_name))

        html += '<tr>'
        html += '<td>%s</td>' % (i + 1)
        for name, unit in param_cols:
            v = fields[name]
            html += '<td>%s %s</td>' % (v, unit)

        for name, unit, fmt in metric_cols:
            v = ', '.join([(fmt % m) for m in metrics[name].as_array()])
            html += '<td>%s %s</td>' % (v, unit)

        html += '<td>'
        if not errs:
            html += '<span class="info">PASSED</span>'
        else:
            html += '<span class="error">FAILED</span><br>'
            html += '<br>'.join(errs)
        html += '</td>'

        html += '<td>'
        html += (''
                 '<a href="%(dir)s/index.html">dashboard</a><br>'
                 '<a href="%(dir)s/timeseq.html">time seq</a><br>'
                 '<a href="%(dir)s/util.html">utilization</a><br>'
                 '<a href="%(dir)s/klog.html">klog graphs</a><br>'
                 '<a href="%(dir)s/all.eth1.pcap">pcap</a><br>'
                 '<a href="%(dir)s/metrics">metrics</a><br>'
                 '<a href="%(dir)s/sys.out">sys params</a><br>'
                 '<a href="%(cfg)s">config file</a><br>'
                ) % {
                    'dir': esc_dir,
                    'cfg': cfg_file,
                }
        if has_xplot:
            html += '<a href="%s/xplots.tbz2">xplots</a><br>' % esc_dir
        html += '</td></tr>'
    html += '</tbody></table>'

    inf = open(os.path.join(data_dir, 'index.html'), 'w')
    inf.write(templates.INDEX % {
        'title': 'experiments',
        'exps': html,
    })
    inf.close()
    return has_error


def _dump_js_files(exp_dir):
    """Dumps the common javascript files in the experiments directory."""
    for name, content in [('jquery.js', js.JQUERY),
                          ('dygraphs.js', js.DYGRAPHS),
                          ('dygraphs.css', js.DYGRAPHS_CSS),
                          ('transperf.js', js.TRANSPERF)]:
        jsf = open(os.path.join(exp_dir, name), 'w')
        jsf.write(content)
        jsf.close()


# Number of buckets used for generating utilization graphs.
BUCKETS = 100


class UtilMetricAndPageGenerator(metric.MetricPublisher):
    """Generates the utilization graphs and publises utilization metrics.

    Attributes:
        __exp_dir: The experiment directory.
        _rcv_ip: The receiver IP address.
        _html_file: The utilization graph html file.
        _columns: The list of column headers.
        _ports: The map of ports to column index.
        _row: Last row of the data that represents the bytes acked in each
              epoch.
        _epoch_dur: The duration of an epoc in sec.
        _end_time: The end of the current epoch.
        _max_bw: The maximum bandwidth.
        _sum_bw: The sum of bandwidths.
    """

    def __init__(self):
        super(UtilMetricAndPageGenerator, self).__init__()
        self._exp_dir = None
        self._rcv_ip = None
        self._html_file = None
        self._columns = []
        self._ports = {}
        self._last_ack = {}
        self._sacked = {}
        self._row = []
        self._epoch_dur = 0.0
        self._end_time = 0.0

        # Metrics.
        self._max_bw = {}
        self._sum_bw = {}
        self._buckets = 0

    def _add_column(self, column_title):
        """Adds a column.

        Args:
            column_title: The title of the column.

        Returns:
            The index of this column.
        """
        self._columns.append(column_title)
        self._row.append(0)
        return len(self._columns) - 1

    def _reset_row(self):
        """Resets the row."""
        self._row = [0] * len(self._columns)

    def _dump_row(self):
        """Write the row in the html file."""
        # Replace bytes with rate.
        for i in xrange(1, len(self._row)):
            self._row[i] *= 8
            self._row[i] /= self._epoch_dur

        self._html_file.write(json.dumps(self._row))
        self._html_file.write(',\n')

        self._buckets += 1
        for port, index in self._ports.items():
            bw = self._row[index]
            if port not in self._max_bw:
                self._max_bw[port] = bw
            else:
                self._max_bw[port] = max(self._max_bw[port], bw)

            if port not in self._sum_bw:
                self._sum_bw[port] = bw
            else:
                self._sum_bw[port] += bw

    def begin(self, exp, exp_dir, rcv_ip):
        # The first column is the timestamp.
        self._add_column('time')
        self._exp_dir = exp_dir
        self._rcv_ip = rcv_ip
        self._epoch_dur = exp.dur / float(BUCKETS)
        self._end_time = self._epoch_dur

        self._html_file = open(os.path.join(exp_dir, 'util.html'), 'w')
        self._html_file.write(templates.UTIL_HEAD % {})
        self._html_file.write('buckets = [')

    def visit_conn(self, ip, port, tool, cc, params, start, dur, tput):
        port_index = self._add_column('%s %s:%s' % (cc, ip, port))
        self._ports[port] = port_index
        self._max_bw[port] = 0
        self._sum_bw[port] = 0
        self._sacked[port] = []

    def visit_ss_log(self, time, data):
        if 'port' not in data:
            return
        port = data['port']
        port_index = self._ports[port]
        acked = 0
        if 'bytes_acked' in data:
            acked = data['bytes_acked']
        if acked < 0:
            return
        while self._end_time <= time+0.001:
            self._dump_row()
            self._reset_row()
            self._end_time += self._epoch_dur
            self._row[0] = self._end_time

        self._row[port_index] += acked - self._last_ack.get(port, 0)
        self._last_ack[port] = acked

    def visit_packet(self, time, packet):
        if (IP not in packet and IPv6 not in packet) or TCP not in packet:
            return

        iph = packet[IP] if IP in packet else packet[IPv6]
        tcph = packet[TCP]

        port = tcph.dport

        # Process only valid ack from receiver
        if (iph.src != self._rcv_ip or
                port not in self._ports or
                not tcph.flags & 0x10):
            return

        # Ignore RST.
        if tcph.flags & 0x4:
            return

        # Set the last acknowledged sequence upon receiving the first packet.
        if port not in self._last_ack:
            self._last_ack[port] = tcph.ack
            return

        # Move the time ahead until we pass this packet's timestamp.
        # Note that it is very important to generate rows of 0 values, and
        # because of that we need to have a loop here and generate 0 value
        # buckets.
        while self._end_time <= time:
            self._dump_row()
            self._reset_row()
            self._end_time += self._epoch_dur
            self._row[0] = self._end_time

        port_index = self._ports[port]
        ack = tcph.ack
        sacks = tcp.sacks(tcph)

        # Fetch the state.
        last_ack = self._last_ack[port]
        sacked = self._sacked[port]
        bucket_bytes = self._row[port_index]

        if tcp.after(ack, last_ack):
            acked = tcp.diff_seq(ack, last_ack)
            for sack in sacked:
                if tcp.after(sack[1], ack):
                    break
                acked -= tcp.sack_block_size(sack)
                sacked = sacked[1:]
            bucket_bytes += acked
            last_ack = ack

        for sack in sacks:
            if tcp.after(sack[1], last_ack):
                sacked, sbytes = tcp.merge_sack_block_into_list(sacked, sack)
                bucket_bytes += sbytes

        # Store the state.
        self._last_ack[port] = last_ack
        self._sacked[port] = sacked
        self._row[port_index] = bucket_bytes

    def end(self):
        """Write the html file.

        See outparser.Visitor interface.
        """
        # Dump the last row.
        self._dump_row()
        self._html_file.write('];\n')
        self._html_file.write('var cols = %s;' % self._columns)
        self._html_file.write(templates.UTIL_FOOT % {})
        self._html_file.close()

    def publish_metrics(self):
        """Publish max_bw and avg_bw in metrics.

        See the metric.MetricPublisher interface.

        Returns:
          A tuple of [max_bw, avg_bw]
        """

        max_bw = metric.Metric('max_bw')
        for port, bw in self._max_bw.items():
            max_bw.set(port, bw / 1000000.)  # Mbps

        avg_bw = metric.Metric('avg_bw')
        for port, bw in self._sum_bw.items():
            if self._buckets:
                avg_bw.set(port, bw / 1000000. / self._buckets)  # Mbps
            else:
                avg_bw.set(port, 0)
        return [max_bw, avg_bw]


def _dump_metrics(exp_dir, metrics):
    """Dump metrics in the metrics file in the experiment's output directory.

    Args:
        exp_dir: The experiment directory.
        metrics: The dictionary of metrics.
    """
    metric_file = open(os.path.join(exp_dir, 'metrics'), 'w')

    for name in sorted(metrics.keys()):
        metric_file.write('%s=%s\n' % (name, metrics[name]))

    metric_file.close()


def _log_metrics(exp, metrics):
    """Log metrics in the metrics file in the experiment's std out.

    Args:
        exp: The experiment object.
        metrics: The dictionary of metrics.
    """
    LOG.debug('metrics of exp=%s', exp)
    for name in sorted(metrics.keys()):
        LOG.debug('%s=%s', name, metrics[name])


def _exp_info(exp_dir):
    """Returns the experiment information stored in exp_dir."""
    return outparser.ExpInfo(os.path.join(exp_dir, 'exp.info'))


class KlogCompressor(outparser.Visitor):
    """Separates klogs of each port in its own file and compress them together.

    Attributes:
        _klog_files: The dictionary ports to klog files.
        _exp_dir: The experiment directory.
    """

    def __init__(self):
        super(KlogCompressor, self).__init__()
        self._klog_files = {}
        self._exp_dir = None

    def begin(self, exp, exp_dir, rcv_ip):
        """Stores the experiment directory.

        See the outparser.Visitor interface.
        """
        self._exp_dir = exp_dir

    def visit_klog(self, time, line, match):
        """Visits a klog entry and append it to the appropriate file.

        See the outparser.Visitor interface.
        """
        port = match['port']
        if port in self._klog_files:
            klogf = self._klog_files[port]
        else:
            klogf = open(os.path.join(self._exp_dir,
                                      'kern-debug-%s.log' % port), 'w')
            self._klog_files[port] = klogf

        klogf.write(line)

    def end(self):
        """Writes the klog compressed file.

        See the outparser.Visitor interface.
        """
        klog_paths = []
        for _, klogf in self._klog_files.iteritems():
            # Should drop the directory prefix to have a flat tarball.
            klog_paths.append(os.path.basename(klogf.name))
            klogf.close()

        shell.run('tar -C %s -cvjf %s %s' % (
            self._exp_dir,
            os.path.join(self._exp_dir, 'kern-debug.tbz2'),
            ' '.join(klog_paths)))


class TimeSeqPageGenerator(outparser.Visitor):
    """Generates the time seqeunce graph.

    The time sequence data consists of rows in the following format:

        [time, seq1, ack1, win1, sack1, seq2, ack2, win2, sack2, ...]

    That is, the length of each row is equal to 1 + (4 * number of flows).

    Attributes:
        _html_file: The html file.
        _rcv_ip: The receiver IP address.
        _ports: The dictionary of ports to legend titles.
        _port_index: The starting index of port in each row.
        _min_seq: The minimum sequence of each port.
        _win_scale: The window scale of each port.
        _row: The current row of data.
        _max_seq: The maximum sequence seen in the data.
    """

    def __init__(self):
        super(TimeSeqPageGenerator, self).__init__()
        self._html_file = None
        self._rcv_ip = None
        self._ports = {}
        self._port_index = {}
        self._min_seq = {}
        self._win_scale = {}
        self._row = [0]
        self._max_seq = -1

    def begin(self, exp, exp_dir, rcv_ip):
        """Stores the experiment directory.

        See the outparser.Visitor interface.
        """
        self._rcv_ip = rcv_ip
        self._html_file = open(os.path.join(exp_dir, 'timeseq.html'), 'w')
        self._html_file.write(templates.TIMESEQ_HEAD % {})
        # Open the data array. This array will be filled in visit_packet().
        self._html_file.write('var data = [')

    def end(self):
        """Write the HTML file.

        See the outparser.Visitor interface.
        """
        # Close the data array.
        self._html_file.write('];')
        self._html_file.write('var ports = %s;' %
                              json.dumps(self._ports.values()))
        self._html_file.write('var max_seq = %s;' % self._max_seq)
        self._html_file.write(templates.TIMESEQ_TAIL % {})
        self._html_file.close()

    def visit_conn(self, ip, port, tool, cc, params, start, dur, tput):
        """Stores the ports.

        See the outparser.Visitor interface.
        """
        port = int(port)
        self._ports[port] = '%s_%s' % (cc, port)
        self._port_index[port] = 4 * (len(self._ports) - 1) + 1
        self._row += [None] * 4
        self._win_scale[port] = 0

    def visit_ss_log(self, time, data):
        if 'port' not in data:
            return
        port = data['port']
        port_index = self._port_index[port]
        prev_time = self._row[0]

        if time - prev_time > 0.001:
            self._dump_row()
            self._row[0] = time

        if 'bytes_acked' in data:
            acked = data['bytes_acked']
            self._row[port_index + 1] = max(self._row[port_index + 1], acked)
            self._max_seq = max(self._max_seq, acked)

    def visit_packet(self, time, packet):
        """Generates the time sequence data.

        See the outparser.Visitor interface.
        """
        if (IP not in packet and IPv6 not in packet) or TCP not in packet:
            return

        iph = packet[IP] if IP in packet else packet[IPv6]
        tcph = packet[TCP]

        port = tcph.dport if iph.src == self._rcv_ip else tcph.sport

        # Ignore unknown ports and reset packets.
        if port not in self._ports or tcph.flags & 0x4:
            return

        # If it has been more than one millisecond since we
        # have created the current row, dump the row.
        prev_time = self._row[0]
        if time - prev_time > 0.001:
            self._dump_row()
            # Store the time with the resolution of 1ms.
            self._row[0] = int(time * 1000) / 1000.0

        if iph.src == self._rcv_ip:
            self._process_rcv(iph, tcph)
        else:
            self._process_snd(iph, tcph)

    def _dump_row(self):
        """Dumps the content of the row in the html file."""
        self._html_file.write(json.dumps(self._row))
        self._html_file.write(',')

    def _process_snd(self, iph, tcph):
        """Handles the send side data and updates the seqeunce number.

        Args:
            iph: The parsed IP header.
            tcph: The parsed TCP header.
        """
        port = tcph.sport
        if port not in self._ports:
            return

        seq = tcph.seq
        if port not in self._min_seq:
            self._min_seq[port] = seq

        seq = tcp.diff_seq(seq, self._min_seq[port])
        self._max_seq = max(self._max_seq, seq)

        port_index = self._port_index[port]
        self._row[port_index] = max(self._row[port_index], seq)

    def _process_rcv(self, iph, tcph):
        """Handles the receive side data and updates the seqeunce number.

        Args:
            iph: The parsed IP header.
            tcph: The parsed TCP header.
        """
        port = tcph.dport
        if port not in self._ports:
            return

        # Make sure we never use the stored win scale on SYNs,
        # since SYNs can be retransmitted.
        if tcph.flags & 0x2:
            win_scale = 0
            opts = tcp.options(tcph)
            if 'WScale' in opts:
                self._win_scale[port] = opts['WScale']
        else:
            win_scale = self._win_scale[port]

        port_index = self._port_index[port]
        min_seq = self._min_seq[port] if port in self._min_seq else 0

        ack = tcp.diff_seq(tcph.ack, min_seq)
        self._row[port_index + 1] = ack

        win = ack + tcph.window << win_scale
        self._row[port_index + 2] = win

        max_sack = -1
        for _, end in tcp.sacks(tcph):
            max_sack = max(max_sack, tcp.diff_seq(end, min_seq))
        self._row[port_index + 3] = max_sack if max_sack != -1 else None


class KlogPageGenerator(outparser.Visitor):
    """Generates the klog grahs.

    We create 3 js files (ie, bw.js, rtt.js, and mode.js) for each port
    and then includes those inside klog.html.

    Attributes:
        _exp_dir: The experiment directory.
        _port_titles: The legend title for the port.
        _js_files: The dictionary from ports to the list of javascript files for
                   that port (bw-port.js, rtt-port.js, mode-port.js).
    """

    def __init__(self):
        super(KlogPageGenerator, self).__init__()
        self._exp_dir = None
        self._port_titles = {}
        self._js_files = {}

    def begin(self, exp, exp_dir, rcv_ip):
        """Stores the experiment directory.

        See the outparser.Visitor interface.
        """
        self._exp_dir = exp_dir

    def end(self):
        """Writes the klog files and includes all the generated javascripts.

        See the outparser.Visitor interface.
        """
        html_file = open(os.path.join(self._exp_dir, 'klog.html'), 'w')
        html_file.write(templates.LOG_HEAD % {'title': 'Klog Graphs'})
        html_file.write(templates.KLOG_VAR % {})

        ports = sorted(self._port_titles.keys())

        labels = []
        for port in ports:
            labels.append(self._port_titles[port])

            if port not in self._js_files:
                continue

            files = self._js_files[port]
            for f in files:
                # All the files are setting an array. So we
                # can simply close the array.
                f.write('];')
                f.close()
                html_file.write(
                    '<script src="%s"></script>' % os.path.basename(f.name))

        html_file.write('<script>ports=%s</script>' % labels)
        html_file.write(templates.LOG_TAIL % {})
        html_file.write(templates.KLOG_TAIL % {})
        html_file.close()

    def visit_conn(self, ip, port, tool, cc, params, start, dur, tput):
        """Stores the port titles.

        See the outparser.Visitor interface.
        """
        if tool == 'netperf':
            self._port_titles[int(port)] = '%s %s:%s' % (cc, ip, port)

    def visit_klog(self, time, line, match):
        port = int(match['port'])

        if port not in self._port_titles:
            return

        if port not in self._js_files:
            port_title = self._port_titles[port]

            # Create the files and write the assignment operator for bws, rtts,
            # and modes.
            bw_js = open(os.path.join(self._exp_dir, 'bws-%s.js' % port), 'w')
            bw_js.write('bws["%s"]=[' % port_title)

            rtt_js = open(os.path.join(self._exp_dir, 'rtts-%s.js' % port), 'w')
            rtt_js.write('rtts["%s"]=[' % port_title)

            mode_js = open(os.path.join(self._exp_dir, 'modes-%s.js' % port),
                           'w')
            mode_js.write('modes["%s"]=[' % port_title)

            self._js_files[port] = (bw_js, rtt_js, mode_js)
        else:
            bw_js, rtt_js, mode_js = self._js_files[port]

        # Bandwidth metrics are multiplied by 1000 to convert from the kbps
        # output by BBR to bps for more intuitive plot labels.
        bw_js.write(json.dumps([time,
                                1000 * int(match.get('bw', 0)),
                                1000 * int(match.get('pacing_bw', 0)),
                                1000 * int(match.get('sample_bw', 0)),
                                1000 * int(match.get('bw_lo', 0)),
                                int(match.get('snd_cwnd', 0)),
                                int(match.get('extra_acked', 0)),
                                int(match.get('inflight', 0)),
                                int(match.get('inflight_lo', 0)),
                                int(match.get('inflight_hi', 0)),
                               ]))
        bw_js.write(',')

        ecn_percent  = int(match.get('ecn_x1000', 0)) / 10.0
        loss_percent = int(match.get('lr_x1000', 0))  / 10.0
        rtt_js.write(json.dumps([time,
                                 ecn_percent,
                                 loss_percent,
                                 int(match.get('rtt', 0)),
                                 int(match.get('mrtt', 0)),
                                 ]))
        rtt_js.write(',')

        mode = match.get('mode', None)
        state = match.get('castate', None)
        cycle = match.get('cycle_idx', None)

        mode_row = [time,
                    1  if mode  == 'G' else None,  # Growing: BBR_MODE_STARTUP
                    2  if mode  == 'D' else None,  # Drain:   BBR_MODE_DRAIN
                    3  if mode  == 'W' else None,  # Window:  BBR_MODE_PROBE_BW
                    4  if mode  == 'M' else None,  # MinRTT:  BBR_MODE_PROBE_RTT
                    5  if mode  == '@' else None,  # Undo
                    6  if state == 'O' else None,  # Open
                    7  if state == 'D' else None,  # Disorder
                    8  if state == 'C' else None,  # Cwnd reduction (ECN)
                    9  if state == 'R' else None,  # Recovery
                    10 if state == 'L' else None,  # Loss
                    11 if cycle == '1' else None,  # BBR_BW_PROBE_DOWN
                    12 if cycle == '2' else None,  # BBR_BW_PROBE_CRUISE
                    13 if cycle == '3' else None,  # BBR_BW_PROBE_REFILL
                    14 if cycle == '0' else None,  # BBR_BW_PROBE_UP
                   ]
        mode_js.write(json.dumps(mode_row))
        mode_js.write(',')


class SummaryPageGenerator(outparser.Visitor):
    """Generates the summary page.

    Attributes:
        _has_xplot: Whether the generator has generated xplots.
        _summary_file: The summary page file.
        _exp: The experiment object.
        _ccs: The dictionary of connection information.
        _rtts: The RTT metrics of each connection.
    """

    def __init__(self, has_xplot):
        super(SummaryPageGenerator, self).__init__()
        self._has_xplot = has_xplot
        self._summary_file = None
        self._exp = None
        self._ccs = {}
        self._metrics = {}

    def begin(self, exp, exp_dir, rcv_ip):
        """Stores the experiment directory.

        See the outparser.Visitor interface.
        """
        self._exp = exp

        links = ''
        if self._has_xplot:
            links += '<a href="xplots.tbz2">xplots</a>'

        self._summary_file = open(os.path.join(exp_dir, 'summary.html'), 'w')
        self._summary_file.write(templates.SUMMARY_HEAD % {'links': links})

    def visit_conn(self, ip, port, tool, cc, params, start, dur, tput):
        """Stores the connection info.

        See the outparser.Visitor interface.
        """
        if cc not in self._ccs:
            infos = []
            self._ccs[cc] = infos
        else:
            infos = self._ccs[cc]
        infos.append((ip, port, start, dur, params, parse_float(tput)))

    def visit_metric(self, metric):
        """Stores the RTT metrics to be used in generating the page.

        See the outparser.Visitor interface.
        """
        if metric.name().endswith('rtt') or metric.name() == 'retx':
            self._metrics[metric.name()] = metric

    def end(self):
        """Writes the content in the summary file and closes the file.

        See the outparser.Visitor interface.
        """
        # Dump the summary of the experiment information.
        self._summary_file.write('<div id="exp_info"><h>Configuration</h>')
        for line in self._exp.pretty_str().split('\n'):
            param, val = line.split('=', 1)
            # Do not include conn in the configuration.
            if param == 'conn':
                continue
            val = val.strip().replace(', ', ',<br/>')
            self._summary_file.write('<b>%s=</b>%s<br/>' % (param, val))
        self._summary_file.write('</div>')

        # Dump the connection information.
        cc_elems = ''
        cc_footers = ''
        for cc, infos in self._ccs.iteritems():
            cc_elem = '<div class="cctitle">%s</div>' % cc
            cc_elem += '''
                <table width="500">
                    <thead>
                        <tr>
                            <th style="width:120px">Address</th>
                            <th style="width:60px">TPut</th>
                            <th style="width:60px">Retx</th>
                            <th style="width:60px">MedRTT</th>
                            <th style="width:60px">P95RTT</th>
                            <th style="width:30px">Start</th>
                            <th style="width:25px">Dur</th>
                            <th style="width:60px">Params</th>
                        </tr>
                    </thead>
                    <tbody>
            '''
            for addr, port, start, dur, params, tput in infos:
                cc_elem += ('<tr><td>%s:%s</td><td>%s Mbps</td>'
                            '<td>%.2f%%</td><td>%sms</td>'
                            '<td>%sms</td><td>%s</td><td>%s</td>'
                            '<td class="params" title="%s">%s</td>'
                            '</tr>') % (addr, port, tput,
                                        self._metrics['retx'].get(port)*100,
                                        self._metrics['med_rtt'].get(port),
                                        self._metrics['p95_rtt'].get(port),
                                        start, dur, params, params)
            cc_elem += '</tbody></table>'
            stputs = sorted([info[-1] for info in infos])
            l = len(stputs)
            if l % 2:
                median = stputs[(l - 1) / 2]
            else:
                median = (stputs[l / 2] + stputs[l/2 - 1]) / 2.0
            avg = sum(stputs) / l
            cc_footers += ('<div class="col">Mdn: %s<br/>Avg: %s'
                           '</div>') % (median, avg)
            cc_elems += '<div class="col">%s</div>' % cc_elem

        self._summary_file.write('<div id="ccs"><h>Results</h>')
        self._summary_file.write('<div class="row">')
        self._summary_file.write(cc_elems)
        self._summary_file.write('</div><div class="row">')
        self._summary_file.write(cc_footers)
        self._summary_file.write('</div></div>')
        self._summary_file.write(templates.SUMMARY_TAIL % {})
        self._summary_file.close()


class DashboardPageGenerator(outparser.Visitor):
    """Generates the experiment's dashboard page."""

    def begin(self, exp, exp_dir, rcv_ip):
        """Generates the dashboard for this experiment.

        See the outparser.Visitor interface.
        """
        dbh = open(os.path.join(exp_dir, 'index.html'), 'w')
        dbh.write(templates.DASHBOARD % {})
        dbh.close()


def gen_exp(exp, exp_dir, has_xplot=False, skip_pcap_scan=False):
    """Generates all the pages for the experiment.

    Args:
        exp: The experiment object.
        exp_dir: The experiment's output directory.
        has_xplot: Whether the xplot is generated for the experiment.
        skip_pcap_scan: Whether to skip pcap scan.

    Returns:
        The tuple of (metrics, test case errors).
    """
    visitors = [
        # Order is important here. Keep MetricPublishers at the head of the list
        # and non-publisher Visitors at the end, so that metrics are published
        # before the visitors are ended.
        KlogMetricsPublisher(),
        RetxRateMetricPublisher(),
        ConvergenceMetricPublisher(),
        RTTMetricPublisher(),
        SerialDelayMetricPublisher(),
        TputMetricPublisher(),
        AppLatencyMetricPublisher(),

        UtilMetricAndPageGenerator(),

        TimeSeqPageGenerator(),
        SummaryPageGenerator(has_xplot),
        KlogPageGenerator(),
        DashboardPageGenerator(),
        KlogCompressor(),
    ]

    _dump_js_files(exp_dir)
    _merge_pcaps(exp_dir)
    _merge_sysouts(exp_dir)

    rcv_ip = outparser.RecvInfo(os.path.join(exp_dir, 'R', 'recv.info')).ip
    conn_info = outparser.ConnInfo([os.path.join(d, f)
                                    for d, f in all_files(exp_dir,
                                                          name='conn.info')])

    pcaps = []
    for i in range(exp.nsenders()):
        snd_dir = os.path.join(exp_dir, str(i))
        snd_pcaps = [os.path.join(d, f)
                     for d, f in all_files(snd_dir, regex=r'.*\.pcap$')]
        # If the machine has eth1 or eth2 interfaces, we have a bonding/slave
        # config. Otherwise, we have one physical interface that are not
        # bonded. In the former case, we use the pcap of the slaves and for the
        # latter we use pcaps from the physical interface eth0.
        is_bonded = len([f for f in snd_pcaps
                         if f.endswith('eth1.pcap') or f.endswith('eth2.pcap')])
        if not is_bonded:
            pcaps += snd_pcaps
        else:
            pcaps += [f for f in snd_pcaps if not f.endswith('eth0.pcap')]
    pcap_parser = outparser.Pcap(pcaps)
    klogs = [os.path.join(d, f) for d, f in all_files(exp_dir,
                                                      name='kern-debug.log')]
    klog_parser = outparser.KernLog(klogs)

    for visitor in visitors:
        visitor.begin(exp, exp_dir, rcv_ip)

    for port in conn_info.ports():
        ip, tool, cc, start, dur, tput, params = conn_info.conn_info(port)
        for visitor in visitors:
            visitor.visit_conn(ip, port, tool, cc, params, start, dur, tput)

    start_times = {}
    if not skip_pcap_scan:
        exp_start = False
        exp_start_time = 0
        for time, packet in pcap_parser.packets():
            if IP not in packet and IPv6 not in packet:
                continue
            if IPv6 not in packet:
                ip = packet[IP]
            else:
                ip = packet[IPv6]

            if TCP in packet:
                l4_hdr = packet[TCP]
            elif UDP in packet:
                l4_hdr = packet[UDP]
            else:
                continue
            port = l4_hdr.dport if ip.src == rcv_ip else l4_hdr.sport

            # Whether this is SYN sent by sender or not
            sender_syn = ip.src != rcv_ip and TCP in packet \
                         and (l4_hdr.flags&0x2)

            # Process pkt only if experiment has started (from sender
            # perspective) i.e. SYN packet sent by atleast one sender
            if not exp_start:
                if not sender_syn:
                    continue
                exp_start_time = time
                exp_start = True

            # Adjust time relative to start of the experiment
            time -= exp_start_time

            # We need to store the port start time for adjusting the klog times.
            if port not in start_times and sender_syn:
                start_times[port] = time

            for visitor in visitors:
                visitor.visit_packet(time, packet)
    else:
        ss_logs = []
        for i in range(exp.nsenders()):
            ss_log = os.path.join(exp_dir, str(i))
            ss_log = os.path.join(ss_log, 'ss.log')
            if os.path.exists(ss_log):
                ss_logs.append(ss_log)
        sslog_parser = outparser.SsLog(ss_logs)
        for time, data in sslog_parser.entries():
            if 'port' in data:
                port = data['port']
                if port not in start_times:
                    start_times[port] = time
            for visitor in visitors:
                visitor.visit_ss_log(time, data)

    for time, line, match in klog_parser.lines():
        # Kernel log times are relative to the kernel log entries. We need
        # to add the start times based on pcap data in order to get a timestamp
        # that is relative to the beginning of the experiment. Thus, we use
        # "time + start_time" instead of time.
        port = int(match['port'])
        start_time = start_times[port] if port in start_times else 0
        for visitor in visitors:
            visitor.visit_klog(time + start_time, line, match)

    metrics = {}
    for visitor in visitors:
        for mt in metrics.values():
            visitor.visit_metric(mt)

        visitor.end()

        if isinstance(visitor, metric.MetricPublisher):
            for mt in visitor.publish_metrics():
                metrics[mt.name()] = mt

    _dump_metrics(exp_dir, metrics)
    _log_metrics(exp, metrics)

    case = TestCase()
    errs = []
    try:
        exp.check(exp, metrics, case)
    except Exception, e:
        errs.append(str(e))
    errs += case.errors()

    if not errs:
        sys.stderr.write(shell.colorize('%s\t[PASSED]\n' % exp, shell.GREEN))
    else:
        sys.stderr.write(shell.colorize('%s\t[FAILED]\n' % exp, shell.RED))
        for err in errs:
            sys.stderr.write(shell.colorize('\terror: %s\n' % err, shell.RED))

    return metrics, errs


def print_usage():
    """Prints the help information."""
    print '''gen.py [options] [DATA_DIR]
    By default we use LATEST as the data directory.

options:
    -v: verbose output
    -x: generate xplots
    -q: not open browser after experiment.'''


def main():
    opts, args = getopt.getopt(sys.argv[1:], 'vt:xq')
    has_xplot = False
    open_page = True
    for opt, val in opts:
        if opt == '-v':
            continue
        elif opt == '-x':
            has_xplot = True
        elif opt == '-q':
            open_page = False
        else:
            print_usage()
            return -1

    log.setup_logging(opts)

    data_dir = 'LATEST' if not args else args[0]

    threads = []
    if has_xplot:
        t = threading.Thread(target=gen_xplots, args=[data_dir])
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return ret


if __name__ == '__main__':
    sys.exit(main())
