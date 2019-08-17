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

"""A few bit hacks (from https://graphics.stanford.edu/~seander/bithacks.html).
"""

def next_power_of_two(i):
    """Returns the next highest power of two.

    Args:
        i: Is the number and should be a 32 bit integer.

    Returns:
        The next highest power of two.
    """
    i -= 1
    i |= i >> 1
    i |= i >> 2
    i |= i >> 4
    i |= i >> 8
    i |= i >> 16
    i += 1
    return i


def num_bits(i):
    """Returns the number of bits in an unsigned integer."""
    n = 0
    while i:
        n += 1
        i &= i - 1
    return n


def trailing_zero_bits(i):
    """Returns the number of trailing zero bits."""
    n = 0
    while not i & 0x1:
        i >>= 1
        n += 1
    return n

