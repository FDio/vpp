#!/usr/bin/env python

from __future__ import print_function
from multiprocessing import Pipe
from sys import exit
from hook import VppDiedError
from framework import VppTestCase, KeepAliveReporter


class SanityTestCase(VppTestCase):
    """ Dummy test case used to check if VPP is able to start """
    extra_vpp_config = []

if __name__ == '__main__':
    rc = 0
    tc = SanityTestCase
    x, y = Pipe()
    reporter = KeepAliveReporter()
    reporter.pipe = y
    try:
        tc.setUpClass()
    except VppDiedError:
        rc = -1
    else:
        try:
            tc.tearDownClass()
        except:
            pass
    x.close()
    y.close()

    exit(rc)
