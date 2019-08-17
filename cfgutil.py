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

"""Utilities to parse configuration files."""

import ast
import os

import transperf


def config_from_script(script):
    """Creates a transperf.Config object from the script.

    Args:
        script: The content of the configuration script.

    Returns:
        A new transperf.Config object.
    """
    ns = {}
    code = compile('from transperf import *', '<string>', 'exec')
    exec code in ns
    # These are the symbols that transperf creates.
    transperf_ns = dict(ns)

    # Find the order in which the parameters are assigned.
    mod = ast.parse(script)
    assign_order = []
    for node in mod.body:
        if not isinstance(node, ast.Assign):
            continue
        for t in node.targets:
            if isinstance(t, ast.Tuple):
                for e in t.elts:
                    if isinstance(e, ast.Name):
                        assign_order.append(node.id)
            elif isinstance(t, ast.Name):
                assign_order.append(t.id)

    code = compile(script, '<script>', 'exec')
    exec code in ns
    if 'cfg' in ns:
        return ns['cfg']

    cfg = transperf.Config()
    for a in assign_order:
        # Ignore a param, if the param is not in the namespace or
        # when it is but it's value is not changed by the config
        # script.
        if a not in cfg.params or (
                a in transperf_ns and transperf_ns[a] == ns[a]):
            continue
        setattr(cfg, a, ns[a])
        # If we remove the parameter from cfg.params and append it to
        # cfg.params again, the order of parameters in cfg.params will
        # reflect the assign order once the loop is finished.
        #
        # We need to ensure that such an order is preserved, so that
        # lambdas are evaluated in the order they occur in the config
        # file.
        cfg.params.remove(a)
        cfg.params.append(a)

    if 'check' in ns:
        cfg.check = ns['check']

    return cfg


def exps(data_dir):
    """Lists the experiments stored in the data directory."""
    out_dir = os.path.join(data_dir, '__out')
    # Configs are stored as cfg0.py, cfg1.py, ... in the output directory.
    cfg_file = lambda i: 'cfg%d.py' % i
    cfg_path = lambda i: os.path.join(data_dir, cfg_file(i))
    i = 0
    while os.path.exists(cfg_path(i)):
        cfg_dir = str(i)
        cfg_abs_dir = os.path.join(out_dir, cfg_dir)
        cfg_script = open(cfg_path(i), 'r').read()
        cfg = config_from_script(cfg_script)
        for exp in cfg.experiments():
            exp_dir = exp.get_dir_name()
            exp_abs_dir = os.path.join(cfg_abs_dir, exp_dir)
            yield (exp, cfg_dir, cfg_file(i), exp_dir, exp_abs_dir)

        i += 1
