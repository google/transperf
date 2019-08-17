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

# CUSTOM NODE INTERFACE CONFIG:
ifaces = {
  "host1": {
    "bond": "eth0",
    "ifaces": ["eth1", "regex:eth\d+",],
  },
  "host2": {
    "bond": "eth0",
    "ifaces": ["eth1", "regex:eth\d+",],
  }
}
# DEFAULT NODE INTERFACE CONFIG (hardcoded if unspecified):
# default_node_ifaces = {
#   "bond": "eth0",
#   "ifaces": ["eth1", "regex:eth\d+",]
# }
#
# NB: In singleserver/local mode, "regex:" specifiers for "ifaces" are ignored.
