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

"""tcp module provides common helpers for TCP."""

# The maximum TCP sequence.
MAX_SEQ = (1 << 32)

# Half of maximum TCP sequence.
HALF_SEQ = (1 << 31)


def diff_seq(seq1, seq0):
    """Returns the difference of two sequences: seq1 - seq0.

    Args:
        seq1: The left operand.
        seq0: The right operand.

    Returns:
        The difference of the two sequences.
    """
    return (seq1 - seq0) % MAX_SEQ


def add_seq(seq, len_bytes):
    """Adds bytes to a seqeuence number.

    Args:
        seq: The sequence number.
        len_bytes: The left in bytes.

    Returns:
        The next seqeunce number properly wrapped.
    """
    return (seq + len_bytes) % MAX_SEQ


def sack_block_size(sack):
    """Calculates the difference between TCP sequences. Supports wrapping.

    Args:
        sack: The sack block.

    Returns:
        The difference of sequence in bytes.
    """
    return diff_seq(sack[1], sack[0])


def is_wrapped(sack):
    """Whether the sack block is wrapped.

    Args:
        sack: The sack block.

    Returns:
        Whether the sack block is wrapped.
    """
    return sack[1] < sack[0]


def after(seq1, seq0):
    """Whether seq1 is after seq0.

    Args:
        seq1: The first sequence.
        seq0: The second sequence.

    Returns:
        Whether seq1 > seq0 considering sequence wrapping.
    """
    diff = seq1 - seq0 if seq0 < seq1 else seq0 - seq1
    if diff > HALF_SEQ:
        return seq1 < seq0
    else:
        return seq0 < seq1


def after_eq(seq1, seq0):
    """Whether seq1 is after or equal to seq0.

    Args:
        seq1: The first seqeunce.
        seq0: The second sequence.

    Returns:
        Whether seq1 >= seq0 considering seqeuence wrapping.
    """
    return after(seq1, seq0) or (seq1 % MAX_SEQ) == (seq0 % MAX_SEQ)


def sacks(tcph):
    """Returns the sacks in the tcp header.

    Args:
        tcph: The parsed TCP header.

    Returns:
        The list of sacks in the form of (start seq, end seq).
    """
    sack_list = []
    for name, val in tcph.options:
        if name != 'SAck':
            continue
        sack_list.append((val[0], val[1]))
    return sack_list


def unwrap(sack):
    """Unwraps a sack.

    In python, we do not have the 32-bit limit. So, if a sack block is
    wrapped, we can simply unwrap it by adding 2^32 to the end sequence.
    Otherwise we add 2^32 to both ends if the function is called.

    Args:
        sack: Sack to unwrap.

    Returns:
        The wrapped sack block.
    """
    if not is_wrapped(sack):
        return (sack[0] + MAX_SEQ, sack[1] + MAX_SEQ)

    return (sack[0], sack[1] + MAX_SEQ)


def overlapping_sack_blocks(sack0, sack1):
    """Whether two sack blocks overlaps.

    Order of arguments does not really matter.

    Args:
        sack0: One block.
        sack1: The other block.

    Returns:
        Whether two sack blocks overlap.
    """
    if is_wrapped(sack0) or is_wrapped(sack1):
        sack0 = unwrap(sack0)
        sack1 = unwrap(sack1)

    return ((after_eq(sack1[0], sack0[0]) and after_eq(sack0[1], sack1[0])) or
            (after_eq(sack1[1], sack0[0]) and after_eq(sack0[1], sack1[1])) or
            (after_eq(sack0[0], sack1[0]) and after_eq(sack1[1], sack0[0])) or
            (after_eq(sack0[1], sack1[0]) and after_eq(sack1[1], sack0[1])))


def diff_sack_blocks(sack1, sack0):
    """Calculates the number of bytes in sack1 not convered by sack0.

    In other words, it calculates (sack1 - sack0).

    Args:
        sack1: The first sack.
        sack0: The second sack.

    Returns:
        The number of bytes in sack1 that is not covered by sack0.
    """
    if not overlapping_sack_blocks(sack1, sack0):
        return sack_block_size(sack1)

    if is_wrapped(sack1) or is_wrapped(sack0):
        sack0 = unwrap(sack0)
        sack1 = unwrap(sack1)

    # If sack0 covers sack1, return 0.
    if sack0[0] <= sack1[0] and sack1[1] <= sack0[1]:
        return 0

    # If sack1 covers sack0, return the size difference.
    if sack1[0] <= sack0[0] and sack0[1] <= sack1[1]:
        return sack_block_size(sack1) - sack_block_size(sack0)

    if sack1[0] <= sack0[0]:
        return sack_block_size((sack1[0], sack0[0]))

    return sack_block_size((sack0[1], sack1[1]))


def merge_sacks(sack0, sack1):
    """Merges two sack blocks if they overlap.

    Args:
        sack0: The first block.
        sack1: The second block.

    Returns:
        The merged sack block.

    Raises:
        RuntimeError: If the blocks do not overlap.
    """
    if not overlapping_sack_blocks(sack0, sack1):
        raise RuntimeError('sack blocks do not overlap')

    # TODO(soheil): I'm almost sure we do not need to unwrap.
    if is_wrapped(sack0) or is_wrapped(sack1):
        sack0 = unwrap(sack0)
        sack1 = unwrap(sack1)

    return (min(sack0[0], sack1[0]) % MAX_SEQ,
            max(sack0[1], sack1[1]) % MAX_SEQ)


def seq_cmp(seq0, seq1):
    """Compares sequences. Used for Python sorting."""
    if after(seq1, seq0):
        return -1

    if (seq0 % MAX_SEQ) == (seq1 % MAX_SEQ):
        return 0

    return 1


def merge_sack_block_into_list(sack_list, sack):
    """Merges the sack block into sacks list and returns the newly acked bytes.

    Args:
        sack_list: The list of sack blocks.
        sack: The sack block.

    Returns:
        A tuple of updated list of sacks sorted by start seq and then by end
        seq and the number of new bytes acknowledged by this sack.

    Raises:
        RuntimeError: When encountered a critial error.
    """
    blen = sack_block_size(sack)
    merged_sack = sack
    processed = []

    for that_sack in sack_list:
        if not overlapping_sack_blocks(merged_sack, that_sack):
            processed.append(that_sack)
            continue

        overlap = sack_block_size(that_sack) - diff_sack_blocks(that_sack, sack)
        blen -= overlap
        if blen < 0:
            raise RuntimeError('overlap is larger than the sack size')

        merged_sack = merge_sacks(merged_sack, that_sack)

    processed.append(merged_sack)
    return (sorted(processed, cmp=lambda s0, s1: seq_cmp(s0[0], s1[0])), blen)


def options(tcph):
    """Returns the dictionary of TCP options.

    Args:
        tcph: the parsed TCP header.

    Returns:
        The dictionary of TCP options.
    """
    return dict(tcph.options)
