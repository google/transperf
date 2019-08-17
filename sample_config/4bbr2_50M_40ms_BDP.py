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
#
# Multiple flows: 4x BBR,  50M, 40ms, BDP buf

conn=conns(
    conn('bbr2', num=2, start=0, sender=0),
    conn('bbr2', num=2, start=0, sender=1),
)
bw=50
rtt=40
buf=bdp(1)
dur=60

scores={
    'tput': 80,
    'rtt_med': 40,
    'lock_on_bw': 35,
    'loss_avoid': 99,
    'fairness': 70,
    'convergence_fairness': 50,
    'convergence_sec': 4,
}
check=check_with_scores(scores)
