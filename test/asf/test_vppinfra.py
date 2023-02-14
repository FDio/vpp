#!/usr/bin/env python3

import unittest

from asfframework import VppTestCase, VppTestRunner


class TestVppinfra(VppTestCase):
    """Vppinfra Unit Test Cases"""

    @classmethod
    def setUpClass(cls):
        super(TestVppinfra, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestVppinfra, cls).tearDownClass()

    def setUp(self):
        super(TestVppinfra, self).setUp()

    def tearDown(self):
        super(TestVppinfra, self).tearDown()

    def test_bitmap_unittest(self):
        """Bitmap unit tests"""

        cmds = ["test bitmap"]

        for cmd in cmds:
            error = self.vapi.cli(cmd)
            if error:
                self.logger.critical(error)
                self.assertNotIn("failed", error)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
