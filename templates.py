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

"""Includes all the HTML templates.
"""

import js


INDEX = '''
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <title>%(title)s</title>
        <link href='https://fonts.googleapis.com/css?family=Source+Sans+Pro'
              rel='stylesheet' type='text/css'>
        <style>
            * {
                font-family: 'Source Sans Pro';
                font-size: 10pt;
            }

            body {
                margin: 0;
            }

            h1 {
                font-size: 14pt;
                margin: 10px;
            }

            a {
                white-space: nowrap;
            }

            table, td, th {
                border: 1px #222 solid;
                border-collapse: collapse;
                padding: 10px;
                text-align: left;
            }

            thead {
                background: #222;
                color: #FFF;
                white-space: nowrap;
            }

            tbody tr:nth-child(even) {
                background: #CCC;
            }

            tbody tr:nth-child(odd) {
                background: #FFF;
            }

            thead tr {
                background: #222;
            }

            .error {
                color: #C22;
            }

            .info {
                color: #2C2;
            }
        </style>
    </head>
    <body>
        <h1>Experiments</h1>
        %(exps)s
    </body>
</html>
'''

DASHBOARD = '''
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <title>Dashboard</title>
        <script src="jquery.js"></script>
        <script src="transperf.js"></script>
        <link href='https://fonts.googleapis.com/css?family=Source+Sans+Pro'
              rel='stylesheet' type='text/css'>
        <style>
            * {
                font-family: 'Source Sans Pro';
                font-size: 10pt;
            }

            body {
                margin: 0;
                height: 100%%;
                width: 100%%;
            }

            a {
                display: block;
                margin: 0px 40px 0px 40px;
            }

            h {
                font-size: 16pt;
                width: 100%%;
                margin: 20px;
            }

            iframe {
                border: none;
            }

            #timeseq {
                width: 35%%;
                height: 300px;
                z-index: 100;
                background: white;
            }

            #util {
                background: white;
                width: 100%%;
                position: absolute;
                top: 270px;
                bottom: 0;
                left: 0;
                right: 0;
                min-height: 280px;
                z-index: -1;
                overflow: hidden;
            }

            #klog {
                width: 100%%;
                position: absolute;
                top: 520px;
                bottom: 0;
                left: 0;
                right: 0;
                height: 100%%;
                z-index: -2;
            }

            #summary {
                width: 65%%;
                height: 300px;
                float: right;
                z-index: 100;
                background: white;
            }
        </style>
    </head>
    <body>
        <iframe src="timeseq.html" id="timeseq"></iframe>
        <iframe src="summary.html" id="summary"></iframe>
        <iframe src="util.html" id="util"></iframe>
        <iframe src="klog.html" id="klog"></iframe>
    </body>
</html>
'''


SUMMARY_HEAD = '''
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <title>Summary</title>
        <script src="jquery.js"></script>
        <script src="transperf.js"></script>
        <link href='https://fonts.googleapis.com/css?family=Source+Sans+Pro'
              rel='stylesheet' type='text/css'>
        <style>
            * {
                font-family: 'Source Sans Pro';
                font-size: 10pt;
            }

            body {
                margin: 0;
            }

            a {
                color: white;
                margin-left: 10px;
            }

            #title-container {
                background: rgba(16, 16, 16, 0.8);
                display: inline-flex;
                left: 0px;
                position: fixed;
                height: 30px;
                padding: 0px;
                right: 0px;
                top: 0px;
                width: 100%%;
                z-index: 100;
            }

            h {
                display: block;
                font-size: 14pt;
                font-weight: bold;
            }

            #title-bar {
                color: white;
                margin: auto 5px;
            }

            #title-bar * {
                opacity: 1;
            }

            #exp_info {
                display: inline-block;
                word-break: break-all;
                float: left;
                margin-top: 30px;
                width: 300px;
            }

            #exp_info h {
                margin-bottom: 10px;
            }

            .cctitle {
                font-weight: bold;
                font-size: larger;
            }

            #ccs {
                margin-top: 30px;
                float: left;
            }

            .row {
                display: table-row;
                word-break:break-all;
            }

            .col {
                display: table-cell;
                padding: 5px;
                width: 430px;
            }

            .params {
                max-width: 20px;
                white-space: nowrap;
                overflow: hidden !important;
                text-overflow: ellipsis;
            }

            table, th, td {
                text-align: left;
            }

            th {
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <div id="title-container">
            <div id="title-bar">
                Summary /
                <a href="kern-debug.tbz2">kernel logs</a>
                <a href="all.eth1.pcap">pcap</a>
                <a href="metrics" target="_blank">metrics</a>
                <a href="sys.out" target="_blank">sys params</a>
                %(links)s
                <a href="../../../index.html" target="_blank">
                    other experiments
                </a>
                <a href="#" onclick="document.show_help()">help (?)</a>
            </div>
        </div>
'''


SUMMARY_TAIL = '''
    </body>
</html>
'''


TIMESEQ_HEAD = '''
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <title>TimeSeq Graph</title>
        <link href='https://fonts.googleapis.com/css?family=Source+Sans+Pro'
              rel='stylesheet' type='text/css'>
        <link rel="stylesheet" href="dygraphs.css"/>
        <style>
            * {
                font-family: 'Source Sans Pro';
                font-size: 10pt;
            }

            body {
                margin: 0;
            }

            a {
                color: white;
            }

            #title-container {
                background: rgba(16, 16, 16, 0.8);
                display: inline-flex;
                left: 0px;
                position: fixed;
                height: 30px;
                padding: 0px;
                right: 0px;
                top: 0px;
                width: 100%%;
                z-index: 100;
            }

            #title-bar {
                color: white;
                margin: auto 5px;
            }

            #title-bar * {
                opacity: 1;
            }

            .graph {
                left: 20px;
                right: 20px;
                position: absolute;
            }

            #graph-all {
                bottom: 0px;
                top: 60px;
            }

            .dygraph-legend {
                background: none !important;
                width: 500px,
            }
        </style>
        <script src="jquery.js"></script>
        <script src="dygraphs.js"></script>
        <script src="transperf.js"></script>
        <script>
'''


TIMESEQ_TAIL = '''
            var graphs = [];

            var default_opts = function() {
                var opts = {
                    animatedZooms: true,
                    legend: 'always',
                    drawPoints: true,
                    strokeWidth: 0.5,
                    pointSize: 1,
                    highlightCircleSize: 1,
                    xlabel: 'Time (sec)',
                    axes: {
                        x: {
                            axisLabelFormatter: function(d) {
                                return '' + d;
                            },
                        },
                        y: {
                            axisLabelFormatter: function(d) {
                                return '' + d;
                            },
                        },
                    },
                };
                var labels = ['Time'];
                for (var i in ports) {
                    var name = ports[i];
                    labels[4*i + 1] = name + '_seq';
                    labels[4*i + 2] = name + '_ack';
                    labels[4*i + 3] = name + '_win';
                    labels[4*i + 4] = name + '_sack';
                }
                opts.labels = labels;
                opts.valueRange = [0, max_seq];

                return opts;
            };

            var draw_graph = function() {
                $('#graphs').append(
                        '<div id="graph-all" class="graph"></div>');
                opts = default_opts();
                opts.colors = ['#0266C8', '#00933B', '#F2B50F', '#F90101',
                               '#0216F0', '#00FF3B', '#92B58F', '#FF8101',
                               '#024620', '#107F3B', '#62A98F', '#778101'];
                graphs.push(new Dygraph($('#graph-all')[0], data, opts));
            };

            var get_visibilities = function() {
                var seq = $('#seq').is(':checked');
                var ack = $('#ack').is(':checked');
                var win = $('#win').is(':checked');
                var sack = $('#sack').is(':checked');

                num_flows = Object.keys(ports).length;
                return [];
            };

            var update_visibilities = function() {
                var num_flows = Object.keys(ports).length;

                var seq = $('#seq').is(':checked');
                var ack = $('#ack').is(':checked');
                var win = $('#win').is(':checked');
                var sack = $('#sack').is(':checked');

                var checks = ['#seq', '#ack', '#win', '#sack'];
                for (var c = 0; c < checks.length; c++) {
                    var checked = $(checks[c]).is(':checked');
                    for (var g in graphs) {
                        for (var i = 0; i < num_flows; i++) {
                            graphs[g].setVisibility(4*i + c, checked);
                        }
                    }
                }
            };

            var register_shortcuts = function () {
                $(document).keypress(function(e) {
                    var key = String.fromCharCode(e.charCode);
                    switch (key) {
                        case 'j':
                            var height = $(window).height();
                            var scroll = $(document).scrollTop()
                            var max_h = height *
                                    (Object.keys(ports).length - 1);
                            if (scroll < max_h) {
                                $(document).scrollTop(scroll + height);
                            }
                            break;
                        case 'k':
                            var height = $(window).height();
                            var scroll = $(document).scrollTop()
                            if (scroll > 0) {
                                $(document).scrollTop(
                                        Math.max(0, scroll - height));
                            }
                            break;
                        case 'q':
                            $('#seq').click();
                            break;
                        case 'a':
                            $('#ack').click();
                            break;
                        case 'w':
                            $('#win').click();
                            break;
                        case 's':
                            $('#sack').click();
                            break;
                    }
                });
            };

            $(document).ready(function() {
                draw_graph();
                register_shortcuts();
            })
        </script>
    </head>
    <body>
        <div id="title-container">
            <div id="title-bar">
                <a href="timeseq.html" target="_blank">TimeSeq </a> /
                <input type="checkbox" id="seq" value="combined" checked
                       onclick="update_visibilities()">
                    Se<u>q</u>
                </input>
                <input type="checkbox" id="ack" value="combined" checked
                       onclick="update_visibilities()">
                    <u>A</u>ck
                </input>
                <input type="checkbox" id="win" value="combined" checked
                       onclick="update_visibilities()">
                    R<u>W</u>in
                </input>
                <input type="checkbox" id="sack" value="combined" checked
                       onclick="update_visibilities()">
                    <u>S</u>Ack
                </input>
            </div>
        </div>
        <div id="graphs">
        </div>
    </body>
</html>
'''

LOG_HEAD = '''
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <title>%(title)s</title>
        <link href='https://fonts.googleapis.com/css?family=Source+Sans+Pro'
              rel='stylesheet' type='text/css'>
        <link rel="stylesheet" href="dygraphs.css"/>
        <style>
            * {
                font-family: 'Source Sans Pro';
                font-size: 10pt;
            }

            html, body {
              height: 100%%;
            }

            body {
                margin: 0;
            }

            #title-container {
                background: rgba(16, 16, 16, 0.8);
                display: inline-flex;
                left: 0px;
                position: fixed;
                height: 30px;
                padding: 0px;
                right: 0px;
                top: 0px;
                width: 100%%;
                z-index: 100;
            }

            #title-bar {
                color: white;
                margin: auto 5px;
            }

            #title-bar * {
                opacity: 1;
            }

            .graph {
                height: 100%%;
                margin: 2px;
                width: 100%%;
            }

            .graph-container {
                display: inline-block;
                margin-bottom: 20px;
                height: 240px;
                width: 32%%;
            }

            #graphs {
                margin-top: 30px;
                min-width: 1280px;
                height: 100%%;
            }

            .focus {
                clear: both;
                font-size: 8pt;
                height: 20px;
                margin: 5px;
                z-index: 9999;
            }

            .dygraph-legend {
                background: none !important;
                width: 125px;
            }
        </style>
        <script src="jquery.js"></script>
        <script src="dygraphs.js"></script>
        <script src="transperf.js"></script>
'''

KLOG_VAR = '''
        <script>
            var graphs = [];
            var bws = {};
            var rtts = {};
            var modes = {};
        </script>
'''

LOG_TAIL = '''
        <script>
            var default_opts = function() {
                var opts = {
                    animatedZooms: true,
                    labelsSeparateLines: true,
                    labelsKMB: true,
                    colors: ['#0266C8', '#00933B', '#F2B50F', '#F90101',
                             '#0133BB', '#97009F'],
                    legend: 'always',
                    drawPoints: true,
                    strokeWidth: 1,
                    pointSize: 0,
                    highlightCircleSize: 3,
                    xlabel: 'Time (sec)',
                    axes: {
                        x: {
                            axisLabelFormatter: function(d) {
                                return '' + d;
                            },
                        },
                    },
                };
                return opts;
            };

            var register_shortcuts = function () {
                $(document).keypress(function(e) {
                    var key = String.fromCharCode(e.charCode);
                    switch (key) {
                        case 'j':
                            var height = 500;
                            var scroll = $(document).scrollTop()
                            var max_h = height * (3*ports.length - 1);
                            if (scroll < max_h) {
                                $(document).scrollTop(scroll + height);
                            }
                            break;
                        case 'k':
                            var height = 500;
                            var scroll = $(document).scrollTop()
                            if (scroll > 0) {
                                $(document).scrollTop(
                                        Math.max(0, scroll - height));
                            }
                            break;
                    }
                });
            };

            var toggle_focus = function(graph){
                return function() {
                    this.maximized = !this.maximized;
                    if (this.maximized) {
                        $(this).text('-');
                        $(this).parent().css('width', '100%%');
                        $(this).parent().css('height', '95%%');
                    } else {
                        $(this).text('+');
                        $(this).parent().css('width', '32%%');
                        $(this).parent().css('height', '240px');
                    }
                    graph.resize(0, 0);
                };
            };

            var new_container = function() {
                var container_elem = $('<div class="graph-container" />');
                $('#graphs').append(container_elem);

                var focus_button = $(
                        '<button class="focus">+</button>');
                $(container_elem).append(focus_button);
                return container_elem;
            };
'''

KLOG_TAIL = '''
            var toggle_graph = function(g, name) {
                var idx = g.getLabels().indexOf(name) - 1;
                var vis = g.visibility();
                var num_vis = 0;
                for (var i = 0; i < vis.length; i++) {
                    if (vis[i]) {
                        num_vis++;
                    }
                }
                if (idx < 0 || num_vis <= 1) {
                    for (var i = 0; i < vis.length; i++) {
                        g.setVisibility(i, true);
                    }
                } else {
                    g.setVisibility(idx, false);
                }
            }

            var draw_graphs = function() {
                var max_time = 0;
                for (var name in bws) {
                    var data = bws[name];
                    var time = data[data.length - 1][0];
                    max_time = Math.max(max_time, time);
                }

                ports.sort();
                for (var i in ports) {
                    var row_graphs = []
                    var port = ports[i];

                    var container_elem = new_container();
                    var elem_id = 'graph-' + port.replace(':', '_').replace(
                            ' ', '_');
                    var bw_elem = $('<div id="' + elem_id + '_bw" ' +
                                    'class="graph"></div>');
                    $(container_elem).append(bw_elem);

                    var bw_opts = default_opts();
                    bw_opts.dateWindow = [0, max_time];
                    bw_opts.title = 'BW for ' + port;
                    bw_opts.ylabel = 'Rate (bps)';
                    bw_opts.y2label = 'Packets';
                    bw_opts.labels = ['time',
                                      'bw',
                                      'pacing_bw',
                                      'sample_bw',
                                      'bw_lo',
                                      'cwnd',
                                      'extra_acked',
                                      'inflight',
                                      'inflight_lo',
                                      'inflight_hi']
                    // The following parameters are in units of packets
                    // (not bandwidth) so they use the 2nd y axis:
                    bw_opts.series = {
                        'cwnd': {axis: 'y2'},
                        'extra_acked': {axis: 'y2'},
                        'inflight': {axis: 'y2'},
                        'inflight_lo': {axis: 'y2'},
                        'inflight_hi': {axis: 'y2'},
                    };
                    bw_opts.pointClickCallback = new Function('e', 'p',
                        'toggle_graph(graphs[' + graphs.length + '], p.name)');

                    var g = new Dygraph(bw_elem[0], bws[port], bw_opts);
                    graphs.push(g);
                    row_graphs.push(g);
                    $(container_elem).find('.focus').click(toggle_focus(g));

                    container_elem = new_container();
                    var rtt_elem = $('<div id="' + elem_id + '_rtt" ' +
                                     'class="graph"></div>');
                    $(container_elem).append(rtt_elem);
                    var rtt_opts = default_opts();
                    rtt_opts.dateWindow = [0, max_time];
                    rtt_opts.title = 'RTT for ' + port;
                    rtt_opts.ylabel = 'Time (ms)';
                    rtt_opts.y2label = 'Percent';
                    rtt_opts.labels = ['time',
                                       'ecn_percent',
                                       'loss_percent',
                                       'rtt',
                                       'min_rtt',
                                       ];
                    rtt_opts.series = {
                        'ecn_percent':  {axis: 'y2'},
                        'loss_percent': {axis: 'y2'},
                    };
                    rtt_opts.axes.y = {
                        axisLabelFormatter: function(d) {
                            return '' + d/1000.;
                        }
                    }
                    rtt_opts.colors = ['#F2B50F',   // ecn_percent:  yellow
                                       '#F90101',   // loss_percent: red
                                       '#0266C8',   // rtt:          blue
                                       '#00933B'];  // min_rtt:      green
                    rtt_opts.pointClickCallback = new Function('e', 'p',
                        'toggle_graph(graphs[' + graphs.length + '], p.name)');
                    g = new Dygraph(rtt_elem[0], rtts[port], rtt_opts);
                    graphs.push(g);
                    row_graphs.push(g);
                    $(container_elem).find('.focus').click(toggle_focus(g));

                    container_elem = new_container();
                    var resid_elem = $('<div id="' + elem_id + '_resid" ' +
                                       'class="graph"></div>');
                    $(container_elem).append(resid_elem);
                    var resid_opts = default_opts();
                    resid_opts.dateWindow = [0, max_time];
                    resid_opts.title = 'Mode and CA State for ' + port;
                    resid_opts.labels = [
                        'time',
                        'STARTUP',
                        'DRAIN',
                        'PROBE_BW',
                        'PROBE_RTT',
                        'CA_Undo',
                        'CA_Open',
                        'CA_Disorder',
                        'CA_CWR',
                        'CA_Recovery',
                        'CA_Loss',
                        'BW_DOWN',
                        'BW_CRUISE',
                        'BW_REFILL',
                        'BW_UP'
                    ];
                    resid_opts.series = {
                        'STARTUP':  {axis: 'y2'},
                        'DRAIN':  {axis: 'y2'},
                        'PROBE_BW':  {axis: 'y2'},
                        'PROBE_RTT':  {axis: 'y2'},
                        'CA_Undo':  {axis: 'y2'},
                        'CA_Open': {axis: 'y2'},
                        'CA_Disorder': {axis: 'y2'},
                        'CA_CWR': {axis: 'y2'},
                        'CA_Recovery': {axis: 'y2'},
                        'CA_Loss': {axis: 'y2'},
                        'BW_DOWN': {axis: 'y2'},
                        'BW_CRUISE': {axis: 'y2'},
                        'BW_REFILL': {axis: 'y2'},
                        'BW_UP': {axis: 'y2'}
                    };
                    resid_opts.pointClickCallback = new Function('e', 'p',
                        'toggle_graph(graphs[' + graphs.length + '], p.name)');

                    g = new Dygraph(resid_elem[0], modes[port], resid_opts)
                    graphs.push(g);
                    row_graphs.push(g);
                    $(container_elem).find('.focus').click(toggle_focus(g));

                    // Sync klog graphs per-flow rather than across all flows.
                    //
                    // Range must be false so that each graph can maintain
                    // their own y-axis values.
                    Dygraph.synchronize(row_graphs, {
                        'selection': true,
                        'zoom': true,
                        'range': false
                    });
                }
            };

            $(document).ready(function() {
                register_shortcuts();
                draw_graphs();
            });
        </script>
    </head>
    <body>
        <div id="title-container">
            <div id="title-bar">
                Klog Graphs /
           </div>
        </div>
        <div id="graphs">
        </div>
    </body>
</html>
'''

UTIL_HEAD = '''
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <title>Utilization</title>
        <link href='https://fonts.googleapis.com/css?family=Source+Sans+Pro'
              rel='stylesheet' type='text/css'>
        <link rel="stylesheet" href="dygraphs.css"/>
        <style>
            * {
                font-family: 'Source Sans Pro';
                font-size: 10pt;
            }

            body {
                margin: 0;
            }

            #title-container {
                background: rgba(16, 16, 16, 0.8);
                display: inline-flex;
                left: 0px;
                position: fixed;
                height: 30px;
                padding: 0px;
                right: 0px;
                top: 0px;
                width: 100%%;
                z-index: 100;
            }

            #title-bar {
                color: white;
                margin: auto 5px;
            }

            #title-bar * {
                opacity: 1;
            }

            .graph {
                display: inline-block;
                height: 240px;
                margin: 2px;
                width: 48%%;
            }

            #graphs {
                margin-top: 30px;
                min-width: 1280px;
            }

            .dygraph-legend {
                background: none !important;
                width: 300px,
            }
        </style>
        <script src="jquery.js"></script>
        <script src="dygraphs.js"></script>
        <script src="transperf.js"></script>
        <script>
'''


UTIL_FOOT = '''
            var graphs = [];

            var default_opts = function() {
                var opts = {
                    animatedZooms: true,
                    labelsSeparateLines: true,
                    labelsKMB: true,
                    colors: ['#0266C8', '#00933B', '#F2B50F', '#F90101',
                             '#97009F', '#0133BB'],
                    legend: 'always',
                    drawPoints: true,
                    strokeWidth: 1,
                    pointSize: 0,
                    highlightCircleSize: 3,
                    xlabel: 'Time (sec)',
                    labels: cols,
                    axes: {
                        x: {
                            axisLabelFormatter: function(d) {
                                return '' + d;
                            },
                        },
                    },
                };
                return opts;
            };

            var draw_graphs = function(buckets, title) {
                var indiv_bw = $('<div class="graph"></div>');
                $('#graphs').append(indiv_bw);
                var bw_opts = default_opts();
                bw_opts.title = 'Individual ' + title;
                graphs.push(new Dygraph(indiv_bw[0], buckets, bw_opts));

                var stacked_bw = $('<div class="graph"></div>');
                $('#graphs').append(stacked_bw);
                var bw_opts = default_opts();
                bw_opts.stackedGraph = true;
                bw_opts.title = 'Cumulative ' + title;
                graphs.push(new Dygraph(stacked_bw[0], buckets, bw_opts));
            };


            $(document).ready(function() {
                draw_graphs(buckets, 'Rate');
                Dygraph.synchronize(graphs, {'zoom': true, 'range': false});
            });
        </script>
    </head>
    <body>
        <div id="title-container">
            <div id="title-bar">
                Utilization /
           </div>
        </div>
        <div id="graphs">
        </div>
    </body>
</html>
'''

REGRESS = '''
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <title>%(title)s</title>
        <link href='https://fonts.googleapis.com/css?family=Source+Sans+Pro'
              rel='stylesheet' type='text/css'>
        <style>
            * {
                font-family: 'Source Sans Pro';
                font-size: 10pt;
            }

            body {
                margin: 0;
            }

            #title-container {
                background: rgba(16, 16, 16, 0.8);
                display: inline-flex;
                left: 0px;
                position: fixed;
                height: 30px;
                padding: 0px;
                right: 0px;
                top: 0px;
                width: 100%%;
                z-index: 100;
            }

            #title-bar {
                color: white;
                margin: auto 5px;
            }

            #title-bar * {
                opacity: 1;
            }

            .graph {
                display: inline-block;
                height: 240px;
                margin: 2px;
                width: 25%%;
            }

            pre {
                float: left;
                width: 25%%;
                white-space: pre-wrap;
            }

            .cases {
                display: inline-block;
                padding-top: 10px;
                vertical-align: top;
                width: 10%%;
            }

            .cases span {
                padding: 0px 5px 0px 5px;
            }

            .pass {
                color: #3A3;
            }

            .fail {
                color: #A33;
            }

            #exps {
                margin-top: 30px;
                min-width: 1280px;
            }

            .dygraph-legend {
                background: none !important;
                width: 0px;
            }
        </style>
        <script>''' + js.JQUERY.replace('%', '%%') + '''</script>
        <script>''' + js.DYGRAPHS.replace('%', '%%') + '''</script>
        <script>
            var metrics = %(metrics)s;
            var runs = %(runs)s;
            var exps = %(exps)s;
            var data = %(data)s;
            var cases = %(cases)s;
            var graphs = [];

            var default_opts = function() {
                var opts = {
                    animatedZooms: true,
                    labelsSeparateLines: true,
                    labelsKMB: true,
                    colors: ['#0266C8', '#00933B', '#F2B50F', '#F90101',
                             '#97009F', '#0133BB'],
                    legend: 'always',
                    drawPoints: true,
                    strokeWidth: 1,
                    pointSize: 0,
                    highlightCircleSize: 3,
                    xlabel: 'Runs',
                    axes: {
                        x: {
                            ticker : function() {
                                var ticks = [];
                                for (var r in runs) {
                                    ticks.push({v: Number(r), label: runs[r]});
                                }
                                return ticks;
                            },
                        },
                    },
                    dateWindow: [-0.1, runs.length - 0.9],
                    axisLabelWidth: 100,
                };
                return opts;
            };

            var new_exp_container = function(exp) {
                var container = $('<div class="experiment"></div>');
                $('#exps').append(container);
                container.append($('<pre class="info">' + exp + '</pre>'));
                return container;
            };

            var draw_graph = function(container, metric, cumulative, rows,
                                      max_val) {
                var graph = $('<div class="graph"></div>');
                container.append(graph);
                var opts = default_opts();
                opts.stackedGraph = cumulative;
                opts.title = metric;
                opts.valueRange = [0, 1.1 * max_val];
                graphs.push(new Dygraph(graph[0], rows, opts));
            };

            var draw_exps = function() {
                for (var e in exps) {
                    var exp = exps[e];
                    var container = new_exp_container(exp);

                    var case_container = $('<div class="cases"></div>');
                    for (var r in runs) {
                        var run = runs[r];
                        case_container.append($('<a href="' + run + '">' + run +
                                                '</a>'));
                        if (cases[run][exp]) {
                            case_container.append(
                                    '<span class="pass">PASSED</span>');
                        } else {
                            case_container.append(
                                    '<span class="fail">FAILED</span>');
                        }
                        case_container.append('<br/>');
                    }
                    container.append(case_container);

                    for (var metric in metrics) {
                        var cumulative = metrics[metric];
                        var rows = [];
                        var max_val = 0;
                        for (var r in runs) {
                            var run = runs[r];
                            if (!(exp in data[run])) {
                                continue;
                            }
                            var run_vals = data[run][exp][metric];
                            if (!cumulative) {
                                max_val = Math.max(max_val,
                                                   Math.max.apply(null,
                                                                  run_vals));
                            } else {
                                var sum = run_vals.reduce(function(a, b) {
                                    return a + b;
                                });
                                max_val = Math.max(max_val, sum);
                            }
                            var val = [Number(r)].concat(run_vals);
                            rows.push(val);
                        }
                        draw_graph(container, metric, cumulative, rows,
                                   max_val);
                    }
                }
            };


            $(document).ready(function() {
                draw_exps();
                Dygraph.synchronize(graphs, {'zoom': false});
            });
        </script>
    </head>
    <body>
        <div id="title-container">
            <div id="title-bar">
                %(title)s /
           </div>
        </div>
        <div id="exps">
        </div>
    </body>
</html>
'''
