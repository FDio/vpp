#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner


class TestVppinfra(VppTestCase):
    """ Vppinfra Unit Test Cases """
    vpp_worker_count = 1

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
        """ Bitmap Code Coverage Test """
        cmds = ["test bitmap"]

        for cmd in cmds:
            r = self.vapi.cli_return_response(cmd)
            if r.retval != 0:
                if hasattr(r, 'reply'):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
