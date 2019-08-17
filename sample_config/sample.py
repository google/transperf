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

cmd = "sysctl -q -w net.ipv4.tcp_congestion_control=bbr2 net.ipv4.tcp_ecn=0"

# Example set of experiments using multiple flows on two senders
conn = [
    conns(
        conn("bbr2", sender=0, start=0.0),
        conn("bbr2", sender=0, start=0.1),
        conn("bbr2", sender=0, start=0.2),
        conn("bbr2", sender=1, start=0.3),
        conn("bbr2", sender=1, start=0.4),
        conn("bbr2", sender=1, start=0.5),
    ),
    conns(
        conn("cubic", sender=0, start=0.0),
        conn("cubic", sender=0, start=0.1),
        conn("cubic", sender=0, start=0.2),
        conn("cubic", sender=1, start=0.3),
        conn("cubic", sender=1, start=0.4),
        conn("cubic", sender=1, start=0.5),
    ),
]

# X percent loss
loss = 0

# Variable BW:
#   bw=var_bw(bw(1, dur=10), .128)
bw = 10  # Mbps

buf = 1024

# Reordering:
#   rtt=rtt(100, var=10)
#
# Variable RTT:
#   rtt=var_rtt(rtt(10, dur=10), 100)
#
# Different RTTs for different senders:
#   rtt=mixed_rtt(rtt(30, sender=0), rtt(50, sender=1))
#
# A mix and match:
#   rtt=var_rtt(mixed_rtt(rtt(30, sender=0), rtt(50, sender=1), dur=10), 50)
#
# Note that this RTT does NOT include the actual prepagation delay between
# the hosts used to test with.
rtt = 10  # ms

# Lambda paramer:
#   dur=lambda exp: 30 if exp.bw <= .128 else 2
dur = 15  # Chrome sometime cannot handle the number of data points if too large

# policer=.256
# Variable policer:
#   policer=var_policer(policer(.256, dur=10), policer(.128))

# slot=slot(in_dist=distribution(0, 1, 'dist_files/sample.dist'),
#          in_max_bytes=50000,
#          out_dist=uniform_distribution(1, 2),
#          out_max_pkts=50)
# Aggregation with netem time slotting on the receiver. Optional.
# May define for one direction only. Units are in msec.

scores = {
    "tput": 90,  # use X% of total bw as goodput
    "rtt_med": 25,  # 100 * minRTT/rtt_i
    "lock_on_bw": 10,  # should exit STARTUP at bw at least x% of bottleneck
    "loss_avoid": 95,  # non-loss percentage
    "fairness": 75,  # jain fairness index * 100 over lifetime
    "convergence_fairness": 85,  # jain fairness for each second after conv
    "convergence_sec": 1.1,  # how long before asserting convergence
}
check = check_with_scores(scores)
