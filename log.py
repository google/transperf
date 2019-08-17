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

"""Log utils for transperf."""

import logging
import sys


def setup_logging(opts):
    """Setup logging based on command line arguments.

    If there is -v in the args, it enables debug logging, otherwise uses
    normal logging.

    Args:
        opts: A list of command line tuples.
    """
    for opt, _ in opts:
        if opt == "-v" or opt == "debug":
            logging.basicConfig(
                stream=sys.stdout,
                format="[%(asctime)s][%(levelname)s] %(name)s:%(lineno)s - %(message)s",
                level=logging.DEBUG,
            )

    logging.basicConfig(
        stream=sys.stdout,
        format="[%(asctime)s][%(levelname)s] %(name)s:%(lineno)s - %(message)s",
        level=logging.INFO,
    )
