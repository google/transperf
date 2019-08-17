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

"""Provides the functionalities to compare different experiment results.
"""

import collections
import getopt
import json
import os
import sys

from transperf import cfgutil
from transperf import log
from transperf import templates
from transperf import TestCase


def print_usage():
    """Prints the help information."""
    print '''regress.py [options] DATA_DIR1 DAT_DIR2 ...

options:
    -v: verbose output
    -o: path of output HTML file [default: diff.html]'''


# Metric names and whether they are cumulative or not.
_DIFF_METRICS = collections.OrderedDict([('tputs', True),
                                         ('retx', False),
                                         ('med_rtt', False)])


def _load_metrics(exp, exp_dir):
    """Loads the metrics of an experiment.

    Args:
        exp: The experiment.
        exp_dir: The experiment directory.

    Returns:
        The dictionary of metrics and whether the experiment test case passes.
    """
    metricf = open(os.path.join(exp_dir, 'metrics'))
    ns = {}
    exec 'from transperf import *' in ns
    exec 'from transperf.metric import Metric' in ns
    exec metricf.read() in ns

    case = TestCase()
    passed = True
    try:
        exp.check(exp, ns, case)
        passed = not case.errors()
    except Exception:
        passed = False

    metrics = {}
    for m in _DIFF_METRICS:
        metrics[m] = ns[m]

    return (metrics, passed)


def _gen_diff(runs, output):
    """Generates the diff HTML file.

    Args:
        runs: The list of transperf runs. Each should be a data directory.
        output: The path of the output file.
    """
    exps = collections.OrderedDict()
    data = {}
    cases = {}
    for ddir in runs:
        data[ddir] = {}
        cases[ddir] = {}
        for exp, _, _, _, exp_dir in cfgutil.exps(ddir):
            exp_metrics, err = _load_metrics(exp, exp_dir)
            exp_str = exp.pretty_str()
            data[ddir][exp_str] = exp_metrics
            cases[ddir][exp_str] = err
            if exp_str not in exps:
                exps[exp_str] = True

    page = templates.REGRESS % {
        'title': 'Regression',
        'metrics': json.dumps(_DIFF_METRICS),
        'runs': json.dumps(runs),
        'exps': json.dumps(exps.keys()),
        'cases': json.dumps(cases),
        'data': json.dumps(data),
    }
    rf = open(output, 'w')
    rf.write(page)
    rf.close()
    print 'output in: %s' % output


def main():
    output = 'diff.html'
    opts, args = getopt.getopt(sys.argv[1:], 'vo:')
    for opt, val in opts:
        if opt == '-v':
            continue
        elif opt == '-o':
            output = val
        else:
            print_usage()
            return -1

    if len(args) < 2:
        print_usage()
        return -1

    log.setup_logging(opts)
    _gen_diff(args, output)

if __name__ == '__main__':
    sys.exit(main())
