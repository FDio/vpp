#!/usr/bin/env python3
"""Test framework utility functions tests"""

import unittest
from multiprocessing import get_context
from multiprocessing.synchronize import Event
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from asfframework import VppTestRunner, CPUInterface
from config import config
from filelock import Timeout
from vpp_papi import mac_pton, mac_ntop
from vpp_qemu_utils import net_helper_lock


def _hold_net_helper_lock(ready: Event) -> None:
    """Hold the configured lock until this worker is terminated."""
    with net_helper_lock():
        ready.set()
        get_context("fork").Event().wait()


class TestUtil(CPUInterface, unittest.TestCase):
    """Test framework utility tests"""

    @classmethod
    def is_tagged_run_solo(cls):
        """if the test case class is timing-sensitive - return true"""
        return False

    @classmethod
    def has_tag(cls, tag):
        """if the test case has a given tag - return true"""
        try:
            return tag in cls.test_tags
        except AttributeError:
            pass
        return False

    @classmethod
    def get_cores_required(cls):
        return 0

    def test_mac_to_binary(self):
        """MAC to binary and back"""
        mac = "aa:bb:cc:dd:ee:ff"
        b = mac_pton(mac)
        mac2 = mac_ntop(b)
        self.assertEqual(type(mac), type(mac2))
        self.assertEqual(mac2, mac)

    def test_net_helper_lock_owner_exit(self) -> None:
        """Verify lock recovery after terminating its owning worker."""
        context = get_context("fork")
        with (
            TemporaryDirectory() as directory,
            patch.object(
                config, "net_helper_lock_path", str(Path(directory) / "helper.lock")
            ),
            patch.object(config, "net_helper_lock_timeout", 0.1),
        ):
            ready = context.Event()
            child = context.Process(target=_hold_net_helper_lock, args=(ready,))
            child.start()
            try:
                self.assertTrue(ready.wait(3))
                with self.assertRaises(Timeout):
                    with net_helper_lock():
                        pass
                child.kill()
                child.join(3)
                self.assertFalse(child.is_alive())
                with net_helper_lock():
                    pass
            finally:
                if child.is_alive():
                    child.kill()
                child.join(3)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
