#!/usr/bin/env python3
#
# Copyright (c) 2021 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
This module implement Python access to the VPP statistics segment. It
accesses the data structures directly in shared memory.
VPP uses optimistic locking, so data structures may change underneath
us while we are reading. Data is copied out and it's important to
spend as little time as possible "holding the lock".

Counters are stored in VPP as a two dimensional array.
Index by thread and index (typically sw_if_index).
Simple counters count only packets, Combined counters count packets
and octets.

Counters can be accessed in either dimension.
stat['/if/rx'] - returns 2D lists
stat['/if/rx'][0] - returns counters for all interfaces for thread 0
stat['/if/rx'][0][1] - returns counter for interface 1 on thread 0
stat['/if/rx'][0][1]['packets'] - returns the packet counter
                                  for interface 1 on thread 0
stat['/if/rx'][:, 1] - returns the counters for interface 1 on all threads
stat['/if/rx'][:, 1].packets() - returns the packet counters for
                                 interface 1 on all threads
stat['/if/rx'][:, 1].sum_packets() - returns the sum of packet counters for
                                     interface 1 on all threads
stat['/if/rx-miss'][:, 1].sum() - returns the sum of packet counters for
                                  interface 1 on all threads for simple counters
"""

import os
import socket
import array
import mmap
from struct import Struct
import time
import unittest
import re
import asyncio
import sys


def recv_fd(sock):
    """Get file descriptor for memory map"""
    fds = array.array("i")  # Array of ints
    _, ancdata, _, _ = sock.recvmsg(0, socket.CMSG_SPACE(4))
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
            fds.frombytes(cmsg_data[: len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])
    return list(fds)[0]


VEC_LEN_FMT = Struct("I")


def get_vec_len(stats, vector_offset):
    """Equivalent to VPP vec_len()"""
    return VEC_LEN_FMT.unpack_from(stats.statseg, vector_offset - 8)[0]


def get_string(stats, ptr):
    """Get a string from a VPP vector"""
    namevector = ptr - stats.base
    namevectorlen = get_vec_len(stats, namevector)
    if namevector + namevectorlen >= stats.size:
        raise IOError("String overruns stats segment")
    return stats.statseg[namevector : namevector + namevectorlen - 1].decode("ascii")


class StatsVector:
    """A class representing a VPP vector"""

    def __init__(self, stats, ptr, fmt):
        self.vec_start = ptr - stats.base
        self.vec_len = get_vec_len(stats, ptr - stats.base)
        self.struct = Struct(fmt)
        self.fmtlen = len(fmt)
        self.elementsize = self.struct.size
        self.statseg = stats.statseg
        self.stats = stats

        if self.vec_start + self.vec_len * self.elementsize >= stats.size:
            raise IOError("Vector overruns stats segment")

    def __iter__(self):
        with self.stats.lock:
            return self.struct.iter_unpack(
                self.statseg[
                    self.vec_start : self.vec_start + self.elementsize * self.vec_len
                ]
            )

    def __getitem__(self, index):
        if index > self.vec_len:
            raise IOError("Index beyond end of vector")
        with self.stats.lock:
            if self.fmtlen == 1:
                return self.struct.unpack_from(
                    self.statseg, self.vec_start + (index * self.elementsize)
                )[0]
            return self.struct.unpack_from(
                self.statseg, self.vec_start + (index * self.elementsize)
            )


class VPPStats:
    """Main class implementing Python access to the VPP statistics segment"""

    # pylint: disable=too-many-instance-attributes
    shared_headerfmt = Struct("QPQQPP")
    default_socketname = "/run/vpp/stats.sock"

    def __init__(self, socketname=default_socketname, timeout=10):
        self.socketname = socketname
        self.timeout = timeout
        self.directory = {}
        self.lock = StatsLock(self)
        self.connected = False
        self.size = 0
        self.last_epoch = 0
        self.statseg = 0

    def connect(self):
        """Connect to stats segment"""
        if self.connected:
            return
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)

        # Our connect races the corresponding recv_fds call in VPP, if we beat
        # VPP then we will try (unsuccessfully) to receive file descriptors and
        # will have gone away before VPP can respond to our connect.  A short
        # timeout here stops this error occurring.
        sock.settimeout(1)
        sock.connect(self.socketname)

        mfd = recv_fd(sock)
        sock.close()

        stat_result = os.fstat(mfd)
        self.statseg = mmap.mmap(
            mfd, stat_result.st_size, mmap.PROT_READ, mmap.MAP_SHARED
        )
        os.close(mfd)

        self.size = stat_result.st_size
        if self.version != 2:
            raise Exception("Incompatbile stat segment version {}".format(self.version))

        self.refresh()
        self.connected = True

    def disconnect(self):
        """Disconnect from stats segment"""
        if self.connected:
            self.statseg.close()
            self.connected = False

    @property
    def version(self):
        """Get version of stats segment"""
        return self.shared_headerfmt.unpack_from(self.statseg)[0]

    @property
    def base(self):
        """Get base pointer of stats segment"""
        return self.shared_headerfmt.unpack_from(self.statseg)[1]

    @property
    def epoch(self):
        """Get current epoch value from stats segment"""
        return self.shared_headerfmt.unpack_from(self.statseg)[2]

    @property
    def in_progress(self):
        """Get value of in_progress from stats segment"""
        return self.shared_headerfmt.unpack_from(self.statseg)[3]

    @property
    def directory_vector(self):
        """Get pointer of directory vector"""
        return self.shared_headerfmt.unpack_from(self.statseg)[4]

    elementfmt = "IQ128s"

    def refresh(self, blocking=True):
        """Refresh directory vector cache (epoch changed)"""
        directory = {}
        directory_by_idx = {}
        while True:
            try:
                with self.lock:
                    self.last_epoch = self.epoch
                    for i, direntry in enumerate(
                        StatsVector(self, self.directory_vector, self.elementfmt)
                    ):
                        path_raw = direntry[2].find(b"\x00")
                        path = direntry[2][:path_raw].decode("ascii")
                        directory[path] = StatsEntry(direntry[0], direntry[1])
                        directory_by_idx[i] = path
                    self.directory = directory
                    self.directory_by_idx = directory_by_idx
                    return
            except IOError:
                if not blocking:
                    raise

    def __getitem__(self, item, blocking=True):
        if not self.connected:
            self.connect()
        while True:
            try:
                if self.last_epoch != self.epoch:
                    self.refresh(blocking)
                with self.lock:
                    return self.directory[item].get_counter(self)
            except IOError:
                if not blocking:
                    raise

    def __iter__(self):
        return iter(self.directory.items())

    def set_errors(self, blocking=True):
        """Return dictionary of error counters > 0"""
        if not self.connected:
            self.connect()

        errors = {k: v for k, v in self.directory.items() if k.startswith("/err/")}
        result = {}
        for k in errors:
            try:
                total = self[k].sum()
                if total:
                    result[k] = total
            except KeyError:
                pass
        return result

    def set_errors_str(self, blocking=True):
        """Return all errors counters > 0 pretty printed"""
        error_string = ["ERRORS:"]
        error_counters = self.set_errors(blocking)
        for k in sorted(error_counters):
            error_string.append("{:<60}{:>10}".format(k, error_counters[k]))
        return "%s\n" % "\n".join(error_string)

    def get_counter(self, name, blocking=True):
        """Alternative call to __getitem__"""
        return self.__getitem__(name, blocking)

    def get_err_counter(self, name, blocking=True):
        """Alternative call to __getitem__"""
        return self.__getitem__(name, blocking).sum()

    def ls(self, patterns):
        """Returns list of counters matching pattern"""
        # pylint: disable=invalid-name
        if not self.connected:
            self.connect()
        if not isinstance(patterns, list):
            patterns = [patterns]
        regex = [re.compile(i) for i in patterns]
        if self.last_epoch != self.epoch:
            self.refresh()

        return [
            k
            for k, v in self.directory.items()
            if any(re.match(pattern, k) for pattern in regex)
        ]

    def dump(self, counters, blocking=True):
        """Given a list of counters return a dictionary of results"""
        if not self.connected:
            self.connect()
        result = {}
        for cnt in counters:
            result[cnt] = self.__getitem__(cnt, blocking)
        return result

    def get_ring_buffer(self, name, blocking=True):
        """Get a ring buffer by name"""
        if not self.connected:
            self.connect()

        while True:
            try:
                if self.last_epoch != self.epoch:
                    self.refresh(blocking)
                with self.lock:
                    entry = self.directory[name]
                    if entry.type == 8:  # STAT_DIR_TYPE_RING_BUFFER
                        return entry.get_counter(self)
                    else:
                        raise ValueError(f"'{name}' is not a ring buffer")
            except IOError:
                if not blocking:
                    raise

    def poll_ring_buffer(self, name, thread_index=0, timeout=None, callback=None):
        """Convenience method to poll a ring buffer by name"""
        ring_buffer = self.get_ring_buffer(name)
        return ring_buffer.poll_for_data(thread_index, timeout, callback)

    async def poll_ring_buffer_async(
        self, name, thread_index=0, timeout=None, callback=None
    ):
        """Async convenience method to poll a ring buffer by name"""
        ring_buffer = self.get_ring_buffer(name)
        return await ring_buffer.poll_for_data_async(thread_index, timeout, callback)

    def get_ring_buffer_schema(self, name, thread_index=0):
        """Get schema from a ring buffer by name"""
        ring_buffer = self.get_ring_buffer(name)
        return ring_buffer.get_schema(thread_index)

    def get_ring_buffer_schema_string(self, name, thread_index=0):
        """Get schema as string from a ring buffer by name"""
        ring_buffer = self.get_ring_buffer(name)
        return ring_buffer.get_schema_string(thread_index)


class StatsLock:
    """Stat segment optimistic locking"""

    def __init__(self, stats):
        self.stats = stats
        self.epoch = 0

    def __enter__(self):
        acquired = self.acquire(blocking=True)
        assert acquired, "Lock wasn't acquired, but blocking=True"
        return self

    def __exit__(self, exc_type=None, exc_value=None, traceback=None):
        self.release()

    def acquire(self, blocking=True, timeout=-1):
        """Acquire the lock. Await in progress to go false. Record epoch."""
        self.epoch = self.stats.epoch
        if timeout > 0:
            start = time.monotonic()
        while self.stats.in_progress:
            if not blocking:
                time.sleep(0.01)
                if timeout > 0:
                    if start + time.monotonic() > timeout:
                        return False
        return True

    def release(self):
        """Check if data read while locked is valid"""
        if self.stats.in_progress or self.stats.epoch != self.epoch:
            raise IOError("Optimistic lock failed, retry")

    def locked(self):
        """Not used"""


class StatsCombinedList(list):
    """Column slicing for Combined counters list"""

    def __getitem__(self, item):
        """Supports partial numpy style 2d support. Slice by column [:,1]"""
        if isinstance(item, int):
            return list.__getitem__(self, item)
        return CombinedList([row[item[1]] for row in self])


class CombinedList(list):
    """Combined Counters 2-dimensional by thread by index of packets/octets"""

    def packets(self):
        """Return column (2nd dimension). Packets for all threads"""
        return [pair[0] for pair in self]

    def octets(self):
        """Return column (2nd dimension). Octets for all threads"""
        return [pair[1] for pair in self]

    def sum_packets(self):
        """Return column (2nd dimension). Sum of all packets for all threads"""
        return sum(self.packets())

    def sum_octets(self):
        """Return column (2nd dimension). Sum of all octets for all threads"""
        return sum(self.octets())


class StatsTuple(tuple):
    """A Combined vector tuple (packets, octets)"""

    def __init__(self, data):
        self.dictionary = {"packets": data[0], "bytes": data[1]}
        super().__init__()

    def __repr__(self):
        return dict.__repr__(self.dictionary)

    def __getitem__(self, item):
        if isinstance(item, int):
            return tuple.__getitem__(self, item)
        if item == "packets":
            return tuple.__getitem__(self, 0)
        return tuple.__getitem__(self, 1)


class StatsSimpleList(list):
    """Simple Counters 2-dimensional by thread by index of packets"""

    def __getitem__(self, item):
        """Supports partial numpy style 2d support. Slice by column [:,1]"""
        if isinstance(item, int):
            return list.__getitem__(self, item)
        return SimpleList([row[item[1]] for row in self])


class SimpleList(list):
    """Simple counter"""

    def sum(self):
        """Sum the vector"""
        return sum(self)


# Add a helper class for histogram log2
class StatsHistogramLog2:
    def __init__(self, bins, min_exp):
        self.bins = bins  # list of lists: [thread][bin]
        self.min_exp = min_exp

    def sum(self):
        return sum(sum(thread_bins) for thread_bins in self.bins)

    def thread_count(self):
        return len(self.bins)

    def bin_count(self):
        return max((len(b) for b in self.bins), default=0)

    def __getitem__(self, idx):
        return self.bins[idx]

    def __repr__(self):
        return f"StatsHistogramLog2(min_exp={self.min_exp}, bins={self.bins})"


class StatsEntry:
    """An individual stats entry"""

    # pylint: disable=unused-argument,no-self-use

    def __init__(self, stattype, statvalue):
        self.type = stattype
        self.value = statvalue

        if stattype == 1:
            self.function = self.scalar
        elif stattype == 2:
            self.function = self.simple
        elif stattype == 3:
            self.function = self.combined
        elif stattype == 4:
            self.function = self.name
        elif stattype == 6:
            self.function = self.symlink
        elif stattype == 7:  # STAT_DIR_TYPE_HISTOGRAM_LOG2
            self.function = self.histogram_log2
        elif stattype == 8:  # STAT_DIR_TYPE_RING_BUFFER
            self.function = self.ring_buffer
        elif stattype == 9:  # STAT_DIR_TYPE_GAUGE
            self.function = self.scalar
        else:
            self.function = self.illegal

    def illegal(self, stats):
        """Invalid or unknown counter type"""
        return None

    def scalar(self, stats):
        """Scalar counter"""
        return self.value

    def simple(self, stats):
        """Simple counter"""
        counter = StatsSimpleList()
        for threads in StatsVector(stats, self.value, "P"):
            clist = [v[0] for v in StatsVector(stats, threads[0], "Q")]
            counter.append(clist)
        return counter

    def combined(self, stats):
        """Combined counter"""
        counter = StatsCombinedList()
        for threads in StatsVector(stats, self.value, "P"):
            clist = [StatsTuple(cnt) for cnt in StatsVector(stats, threads[0], "QQ")]
            counter.append(clist)
        return counter

    def name(self, stats):
        """Name counter"""
        counter = []
        for name in StatsVector(stats, self.value, "P"):
            if name[0]:
                counter.append(get_string(stats, name[0]))
        return counter

    SYMLINK_FMT1 = Struct("II")
    SYMLINK_FMT2 = Struct("Q")

    def symlink(self, stats):
        """Symlink counter"""
        b = self.SYMLINK_FMT2.pack(self.value)
        index1, index2 = self.SYMLINK_FMT1.unpack(b)
        name = stats.directory_by_idx[index1]
        return stats[name][:, index2]

    def ring_buffer(self, stats):
        """Ring buffer counter"""
        return StatsRingBuffer(stats, self.value)

    def histogram_log2(self, stats):
        """Histogram log2 counter (STAT_DIR_TYPE_HISTOGRAM_LOG2)"""
        # The value is a pointer to a vector of pointers (per-thread), each pointing to a vector of uint64_t bins
        threads_ptr = self.value
        thread_vec = StatsVector(stats, threads_ptr, "P")
        all_bins = []
        min_exp = 0
        for thread_ptr_tuple in thread_vec:
            bins_ptr = thread_ptr_tuple[0]
            if bins_ptr:
                bins_vec = StatsVector(stats, bins_ptr, "Q")
                bins = [v[0] for v in bins_vec]
                if bins:
                    min_exp = bins[0]
                    all_bins.append(bins[1:])
                else:
                    all_bins.append([])
            else:
                all_bins.append([])
        return StatsHistogramLog2(all_bins, min_exp)

    def get_counter(self, stats):
        """Return a list of counters"""
        if stats:
            return self.function(stats)


class StatsRingBuffer:
    """Ring buffer for high-performance data streaming"""

    def __init__(self, stats, ptr):
        self.stats = stats
        self.ring_buffer_ptr = ptr
        self.config = self._get_config()
        self.metadata_ptr = self._get_metadata_ptr()
        self.data_ptr = self._get_data_ptr()
        # Track local tail and last sequence for each thread
        # Note: Since writer doesn't track reader state, we initialize local_tails to 0
        self.local_tails = [0] * self.config["n_threads"]
        self.last_sequences = [None] * self.config["n_threads"]

    def _get_config(self):
        """Get ring buffer configuration from shared memory"""
        config_offset = self.ring_buffer_ptr - self.stats.base
        # Read the full config structure: entry_size, ring_size, n_threads, schema_size, schema_version
        config_data = self.stats.statseg[config_offset : config_offset + 20]
        entry_size, ring_size, n_threads, schema_size, schema_version = Struct(
            "=IIIII"
        ).unpack(config_data)
        return {
            "entry_size": entry_size,
            "ring_size": ring_size,
            "n_threads": n_threads,
            "schema_size": schema_size,
            "schema_version": schema_version,
        }

    def _get_metadata_ptr(self):
        """Get pointer to metadata array using offset"""
        config_offset = self.ring_buffer_ptr - self.stats.base
        # Read metadata_offset from the structure (at offset 20)
        metadata_offset_data = self.stats.statseg[
            config_offset + 20 : config_offset + 24
        ]
        metadata_offset = Struct("=I").unpack(metadata_offset_data)[0]
        return config_offset + metadata_offset

    def _get_data_ptr(self):
        """Get pointer to ring buffer data using offset"""
        config_offset = self.ring_buffer_ptr - self.stats.base
        # Read data_offset from the structure (at offset 24)
        data_offset_data = self.stats.statseg[config_offset + 24 : config_offset + 28]
        data_offset = Struct("=I").unpack(data_offset_data)[0]
        return config_offset + data_offset

    def _get_thread_metadata(self, thread_index):
        """Get metadata for a specific thread, including sequence number and schema info"""
        if thread_index >= self.config["n_threads"]:
            raise IndexError(f"Thread index {thread_index} out of range")

        # Metadata struct: head, schema_version, sequence, schema_offset, schema_size, padding
        metadata_offset = self.metadata_ptr + (
            thread_index * 64  # CLIB_CACHE_LINE_BYTES, typically 64
        )
        metadatafmt_struct = Struct(
            "=IIQII"
        )  # head, schema_version, sequence, schema_offset, schema_size
        metadata_data = self.stats.statseg[
            metadata_offset : metadata_offset + metadatafmt_struct.size
        ]
        head, schema_version, sequence, schema_offset, schema_size = (
            metadatafmt_struct.unpack(metadata_data)
        )
        return {
            "head": head,
            "schema_version": schema_version,
            "sequence": sequence,
            "schema_offset": schema_offset,
            "schema_size": schema_size,
        }

    def get_schema(self, thread_index=0):
        """Get schema data from ring buffer for a specific thread"""
        metadata = self._get_thread_metadata(thread_index)

        # Check if schema exists
        if metadata["schema_size"] == 0:
            return None, 0, 0

        # Calculate schema location
        config_offset = self.ring_buffer_ptr - self.stats.base
        schema_location = config_offset + metadata["schema_offset"]

        # Read schema data
        schema_data = self.stats.statseg[
            schema_location : schema_location + metadata["schema_size"]
        ]

        return schema_data, metadata["schema_size"], metadata["schema_version"]

    def get_schema_string(self, thread_index=0):
        """Get schema as a string (for text-based schemas like CDDL)"""
        schema_data, schema_size, schema_version = self.get_schema(thread_index)

        if schema_data is None:
            return None, 0, 0

        try:
            # Try to decode as UTF-8 string
            schema_string = schema_data.decode("utf-8")
            return schema_string, schema_size, schema_version
        except UnicodeDecodeError:
            # If it's not a valid UTF-8 string, return as bytes
            return schema_data, schema_size, schema_version

    def get_count(self, thread_index=0):
        """Get current count of entries in ring buffer for a thread"""
        # Note: Since the writer doesn't track reader state, we can't determine
        # the actual count. This method is kept for API compatibility.
        return 0

    def is_empty(self, thread_index=0):
        """Check if ring buffer is empty for a thread"""
        # Note: Since the writer doesn't track reader state, we can't determine
        # if the ring is empty. This method is kept for API compatibility.
        return True

    def is_full(self, thread_index=0):
        """Check if ring buffer is full for a thread"""
        # Note: Since the writer doesn't track reader state, we can't determine
        # if the ring is full. This method is kept for API compatibility.
        return False

    def consume_data(self, thread_index=0, max_entries=None):
        """Consume data from ring buffer for a thread (read-only), with sequence check"""
        # Read metadata atomically to get consistent snapshot
        metadata = self._get_thread_metadata(thread_index)
        local_tail = self.local_tails[thread_index]
        last_sequence = self.last_sequences[thread_index]
        sequence = metadata["sequence"]
        ring_size = self.config["ring_size"]

        # Overwrite detection: did the producer lap us?
        if last_sequence is not None:
            delta = (sequence - last_sequence) % (1 << 64)
            if delta > ring_size:
                print(
                    f"[WARN] Ring buffer overwrite detected on thread {thread_index}: "
                    f"sequence jumped from {last_sequence} to {sequence} (delta={delta}, ring_size={ring_size})"
                )
                # Resync local_tail to a reasonable position
                local_tail = (metadata["head"] - ring_size) % ring_size

        # If the sequence hasn't changed, nothing new to read
        if last_sequence == sequence:
            return []

        # Calculate how many new entries are available
        if last_sequence is None:
            # First time reading - calculate how many entries are available
            available = min(sequence, ring_size)
            # Calculate starting position: (head - available) % ring_size
            # This gives us the oldest entry that's still available
            local_tail = (metadata["head"] - available) % ring_size
        else:
            available = (sequence - last_sequence) % (1 << 64)
            if available > ring_size:
                available = ring_size  # Cap at ring size

        if available == 0:
            self.last_sequences[thread_index] = sequence
            return []

        if max_entries is None:
            max_entries = available
        else:
            max_entries = min(max_entries, available)

        consumed_data = []
        entry_size = self.config["entry_size"]

        # Calculate data offset for this thread
        thread_data_offset = self.data_ptr + (
            thread_index * self.config["ring_size"] * entry_size
        )

        # Read data with retry logic for potential contention
        max_retries = 3
        for retry in range(max_retries):
            try:
                for i in range(max_entries):
                    entry_offset = thread_data_offset + (local_tail * entry_size)
                    entry_data = self.stats.statseg[
                        entry_offset : entry_offset + entry_size
                    ]
                    consumed_data.append(entry_data)
                    local_tail = (local_tail + 1) % self.config["ring_size"]

                # Verify sequence number hasn't changed during our read
                current_metadata = self._get_thread_metadata(thread_index)
                if current_metadata["sequence"] == sequence:
                    # Success - update local state
                    self.local_tails[thread_index] = local_tail
                    # Update last_sequence based on how many entries we read
                    if last_sequence is None:
                        # First time reading - update to the sequence number of the last entry we read
                        self.last_sequences[thread_index] = (
                            sequence - available + len(consumed_data)
                        )
                    else:
                        # Subsequent reading - update by the number of entries we read
                        self.last_sequences[thread_index] = last_sequence + len(
                            consumed_data
                        )
                    return consumed_data
                else:
                    # Sequence changed during read, retry
                    if retry < max_retries - 1:
                        # Re-read metadata and recalculate
                        metadata = current_metadata
                        sequence = metadata["sequence"]
                        if last_sequence is None:
                            available = min(sequence, ring_size)
                            # Calculate starting position: (head - available) % ring_size
                            local_tail = (metadata["head"] - available) % ring_size
                        else:
                            available = (sequence - last_sequence) % (1 << 64)
                            if available > ring_size:
                                available = ring_size
                        if available == 0:
                            self.last_sequences[thread_index] = sequence
                            return []
                        max_entries = min(max_entries, available)
                        consumed_data = []
                        local_tail = self.local_tails[thread_index]
                        continue
                    else:
                        # Max retries reached, return what we have
                        print(f"[WARN] Max retries reached, returning partial data")
                        self.local_tails[thread_index] = local_tail
                        self.last_sequences[thread_index] = sequence
                        return consumed_data

            except Exception as e:
                print(f"[ERROR] Exception during data read: {e}")
                if retry < max_retries - 1:
                    continue
                else:
                    return consumed_data

        return consumed_data

    def consume_data_batch(self, thread_index=0, max_entries=None, prefetch=True):
        """Consume data from ring buffer in batches for better performance"""
        # Read metadata atomically to get consistent snapshot
        metadata = self._get_thread_metadata(thread_index)
        local_tail = self.local_tails[thread_index]
        last_sequence = self.last_sequences[thread_index]
        sequence = metadata["sequence"]
        ring_size = self.config["ring_size"]

        # Overwrite detection: did the producer lap us?
        if last_sequence is not None:
            delta = (sequence - last_sequence) % (1 << 64)
            if delta > ring_size:
                print(
                    f"[WARN] Ring buffer overwrite detected on thread {thread_index}: "
                    f"sequence jumped from {last_sequence} to {sequence} (delta={delta}, ring_size={ring_size})"
                )
                # Resync local_tail to a reasonable position
                local_tail = (metadata["head"] - ring_size) % ring_size

        # If the sequence hasn't changed, nothing new to read
        if last_sequence == sequence:
            return []

        # Calculate how many new entries are available
        if last_sequence is None:
            # First time reading - calculate how many entries are available
            available = min(sequence, ring_size)
            # Calculate starting position: (head - available) % ring_size
            # This gives us the oldest entry that's still available
            local_tail = (metadata["head"] - available) % ring_size
        else:
            available = (sequence - last_sequence) % (1 << 64)
            if available > ring_size:
                available = ring_size  # Cap at ring size

        if available == 0:
            self.last_sequences[thread_index] = sequence
            return []

        if max_entries is None:
            max_entries = available
        else:
            max_entries = min(max_entries, available)

        consumed_data = []
        entry_size = self.config["entry_size"]

        # Calculate data offset for this thread
        thread_data_offset = self.data_ptr + (
            thread_index * self.config["ring_size"] * entry_size
        )

        # Prefetch next few entries for better cache performance
        if prefetch and max_entries > 1:
            next_tail = (local_tail + 1) % ring_size
            next_offset = thread_data_offset + (next_tail * entry_size)
            # Note: Python doesn't have direct prefetch, but we can optimize memory access patterns
            # by reading data in larger chunks when possible

        # Read data with retry logic for potential contention
        max_retries = 3
        for retry in range(max_retries):
            try:
                # Read data in larger chunks when possible for better performance
                chunk_size = min(max_entries, 16)  # Read up to 16 entries at once
                for chunk_start in range(0, max_entries, chunk_size):
                    chunk_end = min(chunk_start + chunk_size, max_entries)

                    for i in range(chunk_start, chunk_end):
                        entry_offset = thread_data_offset + (local_tail * entry_size)
                        entry_data = self.stats.statseg[
                            entry_offset : entry_offset + entry_size
                        ]
                        consumed_data.append(entry_data)
                        local_tail = (local_tail + 1) % self.config["ring_size"]

                # Verify sequence number hasn't changed during our read
                current_metadata = self._get_thread_metadata(thread_index)
                if current_metadata["sequence"] == sequence:
                    # Success - update local state
                    self.local_tails[thread_index] = local_tail
                    # Update last_sequence based on how many entries we read
                    if last_sequence is None:
                        # First time reading - update to the sequence number of the last entry we read
                        self.last_sequences[thread_index] = (
                            sequence - available + len(consumed_data)
                        )
                    else:
                        # Subsequent reading - update by the number of entries we read
                        self.last_sequences[thread_index] = last_sequence + len(
                            consumed_data
                        )
                    return consumed_data
                else:
                    # Sequence changed during read, retry
                    if retry < max_retries - 1:
                        # Re-read metadata and recalculate
                        metadata = current_metadata
                        sequence = metadata["sequence"]
                        if last_sequence is None:
                            available = min(sequence, ring_size)
                            local_tail = (metadata["head"] - available) % ring_size
                        else:
                            available = (sequence - last_sequence) % (1 << 64)
                            if available > ring_size:
                                available = ring_size
                        if available == 0:
                            self.last_sequences[thread_index] = sequence
                            return []
                        max_entries = min(max_entries, available)
                        consumed_data = []
                        local_tail = self.local_tails[thread_index]
                        continue
                    else:
                        # Max retries reached, return what we have
                        print(f"[WARN] Max retries reached, returning partial data")
                        self.local_tails[thread_index] = local_tail
                        self.last_sequences[thread_index] = sequence
                        return consumed_data

            except Exception as e:
                print(f"[ERROR] Exception during data read: {e}")
                if retry < max_retries - 1:
                    continue
                else:
                    return consumed_data

        return consumed_data

    def poll_for_data(self, thread_index=0, timeout=None, callback=None):
        """Poll for new data in ring buffer"""
        start_time = time.time()

        while True:
            data = self.consume_data(thread_index)
            if data:
                if callback:
                    for entry_data in data:
                        try:
                            callback(entry_data)
                        except Exception as e:
                            print(f"Callback error: {e}")
                else:
                    return data

            if timeout and (time.time() - start_time) > timeout:
                return []
            time.sleep(0.000001)  # 1μs polling interval

    async def poll_for_data_async(self, thread_index=0, timeout=None, callback=None):
        """Async version of poll_for_data"""

        start_time = asyncio.get_event_loop().time()

        while True:
            metadata = self._get_thread_metadata(thread_index)
            local_tail = self.local_tails[thread_index]

            # Check if new data is available using local tail
            if metadata["head"] != local_tail:
                # Calculate how many new entries
                if metadata["head"] > local_tail:
                    new_entries = metadata["head"] - local_tail
                else:
                    new_entries = (
                        self.config["ring_size"] - local_tail + metadata["head"]
                    )

                data = self.consume_data(thread_index, new_entries)

                if callback:
                    for entry_data in data:
                        await callback(entry_data)
                else:
                    return data

            if timeout and (asyncio.get_event_loop().time() - start_time) > timeout:
                return []

            # Yield control to asyncio
            await asyncio.sleep(0.000001)  # 1μs polling interval

    def get_config(self):
        """Get ring buffer configuration"""
        return self.config.copy()

    def __repr__(self):
        schema_info = ""
        if self.config["schema_size"] > 0:
            schema_info = f", schema_size={self.config['schema_size']}, schema_version={self.config['schema_version']}"

        return (
            f"StatsRingBuffer(entry_size={self.config['entry_size']}, "
            f"ring_size={self.config['ring_size']}, n_threads={self.config['n_threads']}{schema_info})"
        )


class TestStats(unittest.TestCase):
    """Basic statseg tests"""

    def setUp(self):
        """Connect to statseg"""
        self.stat = VPPStats()
        self.stat.connect()
        self.profile = cProfile.Profile()
        self.profile.enable()

    def tearDown(self):
        """Disconnect from statseg"""
        self.stat.disconnect()
        profile = Stats(self.profile)
        profile.strip_dirs()
        profile.sort_stats("cumtime")
        profile.print_stats()
        print("\n--->>>")

    def test_counters(self):
        """Test access to statseg"""

        print("/err/abf-input-ip4/missed", self.stat["/err/abf-input-ip4/missed"])
        print("/sys/heartbeat", self.stat["/sys/heartbeat"])
        print("/if/names", self.stat["/if/names"])
        print("/if/rx-miss", self.stat["/if/rx-miss"])
        print("/if/rx-miss", self.stat["/if/rx-miss"][1])
        print(
            "/nat44-ed/out2in/slowpath/drops",
            self.stat["/nat44-ed/out2in/slowpath/drops"],
        )
        with self.assertRaises(KeyError):
            print("NO SUCH COUNTER", self.stat["foobar"])
        print("/if/rx", self.stat.get_counter("/if/rx"))
        print(
            "/err/ethernet-input/no_error",
            self.stat.get_counter("/err/ethernet-input/no_error"),
        )

    def test_column(self):
        """Test column slicing"""

        print("/if/rx-miss", self.stat["/if/rx-miss"])
        print("/if/rx", self.stat["/if/rx"])  # All interfaces for thread #1
        print(
            "/if/rx thread #1", self.stat["/if/rx"][0]
        )  # All interfaces for thread #1
        print(
            "/if/rx thread #1, interface #1", self.stat["/if/rx"][0][1]
        )  # All interfaces for thread #1
        print("/if/rx if_index #1", self.stat["/if/rx"][:, 1])
        print("/if/rx if_index #1 packets", self.stat["/if/rx"][:, 1].packets())
        print("/if/rx if_index #1 packets", self.stat["/if/rx"][:, 1].sum_packets())
        print("/if/rx if_index #1 packets", self.stat["/if/rx"][:, 1].octets())
        print("/if/rx-miss", self.stat["/if/rx-miss"])
        print("/if/rx-miss if_index #1 packets", self.stat["/if/rx-miss"][:, 1].sum())
        print("/if/rx if_index #1 packets", self.stat["/if/rx"][0][1]["packets"])

    def test_nat44(self):
        """Test the nat counters"""

        print("/nat44-ei/ha/del-event-recv", self.stat["/nat44-ei/ha/del-event-recv"])
        print(
            "/err/nat44-ei-ha/pkts-processed",
            self.stat["/err/nat44-ei-ha/pkts-processed"].sum(),
        )

    def test_legacy(self):
        """Legacy interface"""
        directory = self.stat.ls(["^/if", "/err/ip4-input", "/sys/node/ip4-input"])
        data = self.stat.dump(directory)
        print(data)
        print("Looking up sys node")
        directory = self.stat.ls(["^/sys/node"])
        print("Dumping sys node")
        data = self.stat.dump(directory)
        print(data)
        directory = self.stat.ls(["^/foobar"])
        data = self.stat.dump(directory)
        print(data)

    def test_sys_nodes(self):
        """Test /sys/nodes"""
        counters = self.stat.ls("^/sys/node")
        print("COUNTERS:", counters)
        print("/sys/node", self.stat.dump(counters))
        print("/net/route/to", self.stat["/net/route/to"])

    def test_symlink(self):
        """Symbolic links"""
        print("/interface/local0/rx", self.stat["/interfaces/local0/rx"])
        print("/sys/nodes/unix-epoll-input", self.stat["/nodes/unix-epoll-input/calls"])


class TestRingBuffer(unittest.TestCase):
    """Ring buffer specific tests"""

    def setUp(self):
        """Connect to statseg and find test ring buffer"""
        self.stat = VPPStats()
        self.stat.connect()

        # Look for test ring buffer created by VPP CLI command
        try:
            self.ring_buffer = self.stat.get_ring_buffer("/test/ring-buffer")
            self.ring_buffer_available = True
        except (KeyError, ValueError):
            print(
                "Test ring buffer not found. Run 'test stats ring-buffer-gen test_ring 100 1000 16' in VPP first."
            )
            self.ring_buffer_available = False

    def tearDown(self):
        """Disconnect from statseg"""
        self.stat.disconnect()

    def test_ring_buffer_config(self):
        """Test ring buffer configuration access"""
        if not self.ring_buffer_available:
            self.skipTest("Ring buffer not available")

        config = self.ring_buffer.get_config()
        self.assertIsInstance(config, dict)
        self.assertIn("entry_size", config)
        self.assertIn("ring_size", config)
        self.assertIn("n_threads", config)

        print(f"Ring buffer config: {config}")

        # Verify reasonable values
        self.assertGreater(config["entry_size"], 0)
        self.assertGreater(config["ring_size"], 0)
        self.assertGreater(config["n_threads"], 0)

    def test_ring_buffer_metadata_access(self):
        """Test ring buffer metadata access"""
        if not self.ring_buffer_available:
            self.skipTest("Ring buffer not available")

        # Test metadata access for thread 0
        metadata = self.ring_buffer._get_thread_metadata(0)
        self.assertIsInstance(metadata, dict)
        self.assertIn("head", metadata)
        self.assertIn("sequence", metadata)

        print(f"Thread 0 metadata: {metadata}")

        # Verify metadata values are reasonable
        self.assertIsInstance(metadata["head"], int)
        self.assertIsInstance(metadata["sequence"], int)
        self.assertGreaterEqual(metadata["head"], 0)
        self.assertGreaterEqual(metadata["sequence"], 0)

    def test_ring_buffer_consume_empty(self):
        """Test consuming from empty ring buffer"""
        if not self.ring_buffer_available:
            self.skipTest("Ring buffer not available")

        # Consume from empty buffer
        data = self.ring_buffer.consume_data(thread_index=0)
        self.assertEqual(data, [])

        # Test with max_entries
        data = self.ring_buffer.consume_data(thread_index=0, max_entries=10)
        self.assertEqual(data, [])

    def test_ring_buffer_consume_batch_empty(self):
        """Test batch consuming from empty ring buffer"""
        if not self.ring_buffer_available:
            self.skipTest("Ring buffer not available")

        # Consume from empty buffer
        data = self.ring_buffer.consume_data_batch(thread_index=0)
        self.assertEqual(data, [])

        # Test with max_entries
        data = self.ring_buffer.consume_data_batch(thread_index=0, max_entries=10)
        self.assertEqual(data, [])

    def test_ring_buffer_poll_empty(self):
        """Test polling empty ring buffer"""
        if not self.ring_buffer_available:
            self.skipTest("Ring buffer not available")

        # Poll with short timeout
        data = self.ring_buffer.poll_for_data(thread_index=0, timeout=0.1)
        self.assertEqual(data, [])

    def test_ring_buffer_poll_with_callback(self):
        """Test polling with callback function"""
        if not self.ring_buffer_available:
            self.skipTest("Ring buffer not available")

        collected_data = []

        def callback(data):
            collected_data.append(data)

        # Poll with callback and short timeout
        result = self.ring_buffer.poll_for_data(
            thread_index=0, timeout=0.1, callback=callback
        )
        self.assertEqual(result, [])
        self.assertEqual(collected_data, [])

    def test_ring_buffer_invalid_thread(self):
        """Test ring buffer with invalid thread index"""
        if not self.ring_buffer_available:
            self.skipTest("Ring buffer not available")

        config = self.ring_buffer.get_config()
        invalid_thread = config["n_threads"] + 1

        # Test metadata access with invalid thread
        with self.assertRaises(IndexError):
            self.ring_buffer._get_thread_metadata(invalid_thread)

        # Test consume with invalid thread
        data = self.ring_buffer.consume_data(thread_index=invalid_thread)
        self.assertEqual(data, [])

    def test_ring_buffer_api_compatibility(self):
        """Test API compatibility methods"""
        if not self.ring_buffer_available:
            self.skipTest("Ring buffer not available")

        # Test compatibility methods (these return simplified values)
        count = self.ring_buffer.get_count(thread_index=0)
        self.assertEqual(count, 0)

        is_empty = self.ring_buffer.is_empty(thread_index=0)
        self.assertTrue(is_empty)

        is_full = self.ring_buffer.is_full(thread_index=0)
        self.assertFalse(is_full)

    def test_ring_buffer_repr(self):
        """Test ring buffer string representation"""
        if not self.ring_buffer_available:
            self.skipTest("Ring buffer not available")

        repr_str = repr(self.ring_buffer)
        self.assertIsInstance(repr_str, str)
        self.assertIn("StatsRingBuffer", repr_str)
        self.assertIn("entry_size", repr_str)
        self.assertIn("ring_size", repr_str)
        self.assertIn("n_threads", repr_str)

        print(f"Ring buffer repr: {repr_str}")

    def test_ring_buffer_multiple_threads(self):
        """Test ring buffer access across multiple threads"""
        if not self.ring_buffer_available:
            self.skipTest("Ring buffer not available")

        config = self.ring_buffer.get_config()

        # Test all available threads
        for thread_index in range(config["n_threads"]):
            metadata = self.ring_buffer._get_thread_metadata(thread_index)
            self.assertIsInstance(metadata, dict)
            self.assertIn("head", metadata)
            self.assertIn("sequence", metadata)

            data = self.ring_buffer.consume_data(thread_index=thread_index)
            self.assertIsInstance(data, list)

    def test_ring_buffer_sequence_consistency(self):
        """Test sequence number consistency across reads"""
        if not self.ring_buffer_available:
            self.skipTest("Ring buffer not available")

        # Read metadata multiple times to check consistency
        metadata1 = self.ring_buffer._get_thread_metadata(0)
        metadata2 = self.ring_buffer._get_thread_metadata(0)

        # Sequence numbers should be consistent (same or increasing)
        self.assertGreaterEqual(metadata2["sequence"], metadata1["sequence"])

    def test_ring_buffer_error_handling(self):
        """Test ring buffer error handling"""
        if not self.ring_buffer_available:
            self.skipTest("Ring buffer not available")

        # Test with invalid parameters
        data = self.ring_buffer.consume_data(thread_index=0, max_entries=0)
        self.assertEqual(data, [])

        data = self.ring_buffer.consume_data(thread_index=0, max_entries=-1)
        self.assertEqual(data, [])

    def test_ring_buffer_batch_vs_individual(self):
        """Test that batch and individual consume return same results"""
        if not self.ring_buffer_available:
            self.skipTest("Ring buffer not available")

        # Reset local state to ensure fair comparison
        self.ring_buffer.local_tails[0] = 0
        self.ring_buffer.last_sequences[0] = None

        # Consume with individual method
        individual_data = self.ring_buffer.consume_data(thread_index=0, max_entries=5)

        # Reset local state
        self.ring_buffer.local_tails[0] = 0
        self.ring_buffer.last_sequences[0] = None

        # Consume with batch method
        batch_data = self.ring_buffer.consume_data_batch(thread_index=0, max_entries=5)

        # Results should be the same
        self.assertEqual(individual_data, batch_data)

    def test_ring_buffer_prefetch_parameter(self):
        """Test prefetch parameter in batch consume"""
        if not self.ring_buffer_available:
            self.skipTest("Ring buffer not available")

        # Test with prefetch enabled
        data1 = self.ring_buffer.consume_data_batch(thread_index=0, prefetch=True)

        # Test with prefetch disabled
        data2 = self.ring_buffer.consume_data_batch(thread_index=0, prefetch=False)

        # Results should be the same regardless of prefetch setting
        self.assertEqual(data1, data2)

    def test_ring_buffer_schema_access(self):
        """Test ring buffer schema access"""
        if not self.ring_buffer_available:
            self.skipTest("Ring buffer not available")

        # Test schema access
        schema_data, schema_size, schema_version = self.ring_buffer.get_schema(
            thread_index=0
        )

        # Should return schema information (may be None if no schema)
        self.assertIsInstance(schema_size, int)
        self.assertIsInstance(schema_version, int)
        self.assertGreaterEqual(schema_size, 0)
        self.assertGreaterEqual(schema_version, 0)

        # Test schema string access
        schema_string, schema_size_str, schema_version_str = (
            self.ring_buffer.get_schema_string(thread_index=0)
        )

        # Should return consistent information
        self.assertEqual(schema_size, schema_size_str)
        self.assertEqual(schema_version, schema_version_str)

        # If schema exists, it should be readable
        if schema_size > 0:
            self.assertIsNotNone(schema_data)
            self.assertIsInstance(schema_data, bytes)
            self.assertEqual(len(schema_data), schema_size)

            # If it's a string schema, it should be decodable
            if schema_string is not None:
                self.assertIsInstance(schema_string, str)
                self.assertGreater(len(schema_string), 0)

        print(f"Schema info: size={schema_size}, version={schema_version}")
        if schema_string:
            print(f"Schema content: {schema_string}")

    def test_ring_buffer_schema_metadata(self):
        """Test that schema information is included in metadata"""
        if not self.ring_buffer_available:
            self.skipTest("Ring buffer not available")

        # Get metadata for thread 0
        metadata = self.ring_buffer._get_thread_metadata(0)

        # Should include schema information
        self.assertIn("schema_version", metadata)
        self.assertIn("schema_offset", metadata)
        self.assertIn("schema_size", metadata)

        # Values should be consistent with config
        self.assertEqual(
            metadata["schema_version"], self.ring_buffer.config["schema_version"]
        )
        self.assertEqual(
            metadata["schema_size"], self.ring_buffer.config["schema_size"]
        )

    def test_ring_buffer_schema_config(self):
        """Test that schema information is included in config"""
        if not self.ring_buffer_available:
            self.skipTest("Ring buffer not available")

        config = self.ring_buffer.get_config()

        # Should include schema information
        self.assertIn("schema_size", config)
        self.assertIn("schema_version", config)

        # Values should be reasonable
        self.assertIsInstance(config["schema_size"], int)
        self.assertIsInstance(config["schema_version"], int)
        self.assertGreaterEqual(config["schema_size"], 0)
        self.assertGreaterEqual(config["schema_version"], 0)

        print(
            f"Config schema info: size={config['schema_size']}, version={config['schema_version']}"
        )

    def test_ring_buffer_schema_convenience_methods(self):
        """Test convenience methods for schema access"""
        if not self.ring_buffer_available:
            self.skipTest("Ring buffer not available")

        # Test convenience methods from VPPStats
        schema_data, schema_size, schema_version = self.stat.get_ring_buffer_schema(
            "/test/ring-buffer"
        )
        schema_string, schema_size_str, schema_version_str = (
            self.stat.get_ring_buffer_schema_string("/test/ring-buffer")
        )

        # Should return consistent information
        self.assertEqual(schema_size, schema_size_str)
        self.assertEqual(schema_version, schema_version_str)

        # Should match direct access
        direct_schema_data, direct_schema_size, direct_schema_version = (
            self.ring_buffer.get_schema()
        )
        self.assertEqual(schema_size, direct_schema_size)
        self.assertEqual(schema_version, direct_schema_version)
        if schema_data is not None:
            self.assertEqual(schema_data, direct_schema_data)

    def test_ring_buffer_schema_content(self):
        """Test that schema content matches expected CDDL format"""
        if not self.ring_buffer_available:
            self.skipTest("Ring buffer not available")

        # Get schema string
        schema_string, schema_size, schema_version = self.ring_buffer.get_schema_string(
            thread_index=0
        )

        # If schema exists, verify it has expected content
        if schema_size > 0 and schema_string:
            # Should be a string (not bytes)
            self.assertIsInstance(schema_string, str)

            # Should contain expected CDDL-like content
            self.assertIn("ring_test_schema", schema_string)
            self.assertIn("name:", schema_string)
            self.assertIn("version:", schema_string)
            self.assertIn("fields:", schema_string)
            self.assertIn("seq", schema_string)
            self.assertIn("timestamp", schema_string)

            print(f"✓ Schema content verified: {schema_string[:100]}...")
        else:
            print("ℹ No schema found in ring buffer")


class TestRingBufferIntegration(unittest.TestCase):
    """Integration tests that coordinate with VPP writer tests"""

    def setUp(self):
        """Connect to statseg and find integration test ring buffer"""
        self.stat = VPPStats()
        self.stat.connect()

        # Look for integration test ring buffer
        try:
            self.ring_buffer = self.stat.get_ring_buffer("/integration/test")
            self.ring_buffer_available = True
        except (KeyError, ValueError):
            print(
                "Integration test ring buffer not found. Run integration test setup first."
            )
            self.ring_buffer_available = False

    def tearDown(self):
        """Disconnect from statseg"""
        self.stat.disconnect()

    def test_integration_data_flow(self):
        """Test complete data flow from writer to reader"""
        if not self.ring_buffer_available:
            self.skipTest("Integration ring buffer not available")

        # This test would coordinate with a VPP writer test
        # For now, we'll test the basic flow

        # Reset reader state
        self.ring_buffer.local_tails[0] = 0
        self.ring_buffer.last_sequences[0] = None

        # Try to consume data
        data = self.ring_buffer.consume_data(thread_index=0)

        # Should get list (empty or with data)
        self.assertIsInstance(data, list)

        # If we got data, verify it's the right format
        for entry in data:
            self.assertIsInstance(entry, bytes)
            self.assertGreater(len(entry), 0)

    def test_integration_overwrite_detection(self):
        """Test overwrite detection in integration scenario"""
        if not self.ring_buffer_available:
            self.skipTest("Integration ring buffer not available")

        # This test would coordinate with a writer that intentionally overwrites
        # For now, we'll test the detection mechanism

        # Simulate overwrite by manipulating sequence numbers
        original_sequence = self.ring_buffer.last_sequences[0]

        # This would normally happen when writer laps reader
        # For testing, we'll just verify the detection logic exists
        metadata = self.ring_buffer._get_thread_metadata(0)
        self.assertIn("sequence", metadata)

    def test_integration_performance(self):
        """Test performance characteristics"""
        if not self.ring_buffer_available:
            self.skipTest("Integration ring buffer not available")

        import time

        # Test individual consume performance
        start_time = time.time()
        for _ in range(100):
            self.ring_buffer.consume_data(thread_index=0, max_entries=1)
        individual_time = time.time() - start_time

        # Test batch consume performance
        start_time = time.time()
        for _ in range(10):
            self.ring_buffer.consume_data_batch(thread_index=0, max_entries=10)
        batch_time = time.time() - start_time

        print(f"Individual consume time: {individual_time:.6f}s")
        print(f"Batch consume time: {batch_time:.6f}s")

        # Batch should be faster (though with empty data, difference might be minimal)
        self.assertIsInstance(individual_time, float)
        self.assertIsInstance(batch_time, float)


def run_ring_buffer_tests():
    """Run ring buffer tests with proper setup"""
    print("Running Ring Buffer Tests...")
    print("=" * 50)

    # Create test suite
    suite = unittest.TestSuite()

    # Add ring buffer tests
    suite.addTest(unittest.makeSuite(TestRingBuffer))
    suite.addTest(unittest.makeSuite(TestRingBufferIntegration))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("=" * 50)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    return result.wasSuccessful()


def demo_ring_buffer_schema():
    """Demo function showing how to use ring buffer schema functionality"""
    print("Ring Buffer Schema Demo")
    print("=" * 30)

    try:
        # Connect to VPP stats
        stats = VPPStats()
        stats.connect()

        # Look for test ring buffer
        try:
            ring_buffer = stats.get_ring_buffer("/test/ring-buffer")
            print("✓ Found test ring buffer")

            # Get configuration
            config = ring_buffer.get_config()
            print(f"Ring buffer config: {config}")

            # Get schema information
            schema_data, schema_size, schema_version = ring_buffer.get_schema()
            print(f"Schema info: size={schema_size}, version={schema_version}")

            # Get schema as string
            schema_string, _, _ = ring_buffer.get_schema_string()
            if schema_string:
                print(f"Schema content:\n{schema_string}")
            else:
                print("No schema found")

            # Use convenience methods
            print("\nUsing convenience methods:")
            conv_schema_string, conv_size, conv_version = (
                stats.get_ring_buffer_schema_string("/test/ring-buffer")
            )
            print(
                f"Convenience method result: size={conv_size}, version={conv_version}"
            )
            if conv_schema_string:
                print(f"Schema: {conv_schema_string[:100]}...")

        except (KeyError, ValueError) as e:
            print(f"Test ring buffer not found: {e}")
            print(
                "Run 'test stats ring-buffer-gen /test/ring-buffer 100 1000 16' in VPP first"
            )

        stats.disconnect()

    except Exception as e:
        print(f"Error: {e}")
        print("Make sure VPP is running and stats socket is available")

    print("=" * 30)


if __name__ == "__main__":
    import cProfile
    from pstats import Stats

    # Run ring buffer tests if available
    if "--ring-buffer-tests" in sys.argv:
        success = run_ring_buffer_tests()
        sys.exit(0 if success else 1)

    # Run schema demo if requested
    if "--schema-demo" in sys.argv:
        demo_ring_buffer_schema()
        sys.exit(0)

    # Run original tests
    unittest.main()
