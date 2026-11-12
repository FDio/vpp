# SPDX-License-Identifier: Apache-2.0

"""Unprivileged regression tests for namespace helper synchronization."""

import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from asfframework import CPUInterface, VppTestRunner
import vpp_qemu_utils as utils


def _hold_namespace_lock(connection):
    with utils._namespace_lock(timeout=5):
        connection.send("locked")
        connection.recv()


def _acquire_namespace_lock(connection):
    connection.send("waiting")
    with utils._namespace_lock(timeout=5):
        connection.send("acquired")


def _stop_process(process):
    if process.is_alive():
        process.terminate()
    process.join(timeout=5)
    if process.is_alive():
        process.kill()
        process.join(timeout=5)
    process.close()


class TestQemuUtils(CPUInterface, unittest.TestCase):
    """Namespace helper locking and command deadlines"""

    @classmethod
    def is_tagged_run_solo(cls):
        return False

    @classmethod
    def has_tag(cls, tag):
        return False

    @classmethod
    def get_cores_required(cls):
        return 0

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="vpp-qemu-lock-test-")
        self.addCleanup(directory.cleanup)
        self.lock_path = str(Path(directory.name) / "helpers.lock")
        Path(self.lock_path).touch()
        lock_path = patch.object(utils, "_lock_path", self.lock_path)
        lock_path.start()
        self.addCleanup(lock_path.stop)
        # Match the test runner's fork semantics, including the shared path.
        self.context = multiprocessing.get_context("fork")

    def _start_worker(self, target):
        parent, child = self.context.Pipe()
        process = self.context.Process(target=target, args=(child,))
        process.start()
        child.close()
        self.addCleanup(parent.close)
        self.addCleanup(_stop_process, process)
        self.assertTrue(parent.poll(5), "Lock worker did not start")
        return process, parent

    def _start_holder(self):
        process, connection = self._start_worker(_hold_namespace_lock)
        self.assertEqual(connection.recv(), "locked")
        return process, connection

    def test_workers_are_serialized(self):
        """Independent workers cannot enter the critical section together."""
        holder, release = self._start_holder()
        waiter, acquired = self._start_worker(_acquire_namespace_lock)
        self.assertEqual(acquired.recv(), "waiting")
        self.assertFalse(acquired.poll(0.1), "Waiter bypassed the held lock")
        release.send("release")
        self.assertTrue(acquired.poll(5), "Waiter did not acquire the released lock")
        self.assertEqual(acquired.recv(), "acquired")
        for process in (holder, waiter):
            process.join(timeout=5)
            self.assertEqual(process.exitcode, 0)

    def test_owner_death_releases_lock(self):
        """A killed worker cannot poison subsequent suites or retries."""
        holder, _ = self._start_holder()
        holder.kill()
        holder.join(timeout=5)
        self.assertIsNotNone(holder.exitcode)
        waiter, acquired = self._start_worker(_acquire_namespace_lock)
        self.assertEqual(acquired.recv(), "waiting")
        self.assertTrue(acquired.poll(5), "Dead owner left the lock held")
        self.assertEqual(acquired.recv(), "acquired")
        waiter.join(timeout=5)
        self.assertEqual(waiter.exitcode, 0)

    def test_lock_acquisition_has_deadline(self):
        """A live but stuck owner produces a diagnostic instead of a hang."""
        self._start_holder()
        with self.assertRaisesRegex(TimeoutError, "waiting for namespace helper lock"):
            with utils._namespace_lock(timeout=0.05):
                self.fail("Acquired an already-held lock")

    def test_acquisitions_use_independent_descriptors(self):
        """Repeated acquisitions in one process do not share a flock owner."""
        with utils._namespace_lock():
            with self.assertRaises(TimeoutError):
                with utils._namespace_lock(timeout=0):
                    self.fail("Acquisitions shared an open file description")

    def test_exception_releases_lock_and_preserves_file(self):
        """Normal release keeps the same inode for existing waiters."""
        inode = os.stat(self.lock_path).st_ino
        with self.assertRaisesRegex(ValueError, "test exception"):
            with utils._namespace_lock():
                raise ValueError("test exception")
        with utils._namespace_lock(timeout=0):
            self.assertEqual(os.stat(self.lock_path).st_ino, inode)

    def test_exec_does_not_inherit_lock_descriptor(self):
        """Even a child launched without close_fds cannot retain the lock."""
        script = (
            "import os, sys; "
            "print(any(os.path.realpath('/proc/self/fd/' + fd) == sys.argv[1] "
            "for fd in os.listdir('/proc/self/fd')))"
        )
        with utils._namespace_lock():
            result = subprocess.run(
                [sys.executable, "-c", script, self.lock_path],
                close_fds=False,
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )
        self.assertEqual(result.stdout.strip(), "False")

    def test_network_commands_have_timeout(self):
        """Network operations retain their options and gain a command deadline."""
        with patch.object(utils.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0)
            self.assertTrue(utils.interface_exists("test-ns", "test-if"))
        run.assert_called_once_with(
            ["ip", "netns", "exec", "test-ns", "ip", "link", "show", "dev", "test-if"],
            timeout=utils.NETWORK_COMMAND_TIMEOUT,
            capture_output=True,
        )

    def test_command_timeout_releases_lock(self):
        """A real timed-out child does not prevent the next acquisition."""
        with patch.object(utils, "NETWORK_COMMAND_TIMEOUT", 0.05):
            with self.assertRaisesRegex(
                TimeoutError, "Network helper command timed out"
            ):
                with utils._namespace_lock():
                    utils._run_network_command(
                        [sys.executable, "-c", "import time; time.sleep(30)"],
                        capture_output=True,
                    )
        with utils._namespace_lock(timeout=0):
            pass

    def test_namespace_probe_does_not_hide_timeout(self):
        """A stuck capability probe is an error, not a reason to skip tests."""
        with patch.object(utils.subprocess, "run") as run:
            run.side_effect = subprocess.TimeoutExpired(
                ["ip", "netns", "add", "probe-ns"], utils.NETWORK_COMMAND_TIMEOUT
            )
            with self.assertRaisesRegex(TimeoutError, "ip netns add probe-ns"):
                utils.can_create_namespaces("probe-ns")
        with utils._namespace_lock(timeout=0):
            pass

    def test_namespace_probe_permission_denied(self):
        """An ordinary namespace permission failure still disables netns tests."""
        with patch.object(utils.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 1, b"", b"not permitted")
            self.assertFalse(utils.can_create_namespaces())


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
