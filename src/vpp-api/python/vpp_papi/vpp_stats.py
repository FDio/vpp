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


def recv_fd(sock):
    """Get file descriptor for memory map"""
    fds = array.array("i")  # Array of ints
    _, ancdata, _, _ = sock.recvmsg(0, socket.CMSG_LEN(4))
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

    def get_counter(self, stats):
        """Return a list of counters"""
        if stats:
            return self.function(stats)


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


if __name__ == "__main__":
    import cProfile
    from pstats import Stats

    unittest.main()
