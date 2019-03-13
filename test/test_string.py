#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class TestString(VppTestCase):
    """ String Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestString, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestString, cls).tearDownClass()

    def setUp(self):
        super(TestString, self).setUp()

    def tearDown(self):
        super(TestString, self).tearDown()

    def test_string_unittest(self):
        """ String unit tests """
        names = ["memcpy_s",
                 "clib_memcmp", "clib_memcpy", "clib_memset",
                 "clib_strcat", "clib_strcmp", "clib_strcpy",
                 "clib_strncat", "clib_strncmp", "clib_strncpy",
                 "clib_strnlen", "clib_strstr", "clib_strtok",
                 "memcmp_s", "memcpy_s", "memset_s ",
                 "strcat_s", "strcmp_s", "strcpy_s",
                 "strncat_s", "strncmp_s", "strncpy_s",
                 "strnlen_s", "strstr_s", "strtok_s"]

        for name in names:
            error = self.vapi.cli("test string " + name)
            if error.find("failed") != -1:
                self.logger.critical("FAILURE in the " + name + " test")
                self.assertNotIn("failed", error)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
