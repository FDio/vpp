#!/usr/bin/env python

from __future__ import print_function
from multiprocessing import Pipe
from sys import exit
from hook import VppDiedError
from framework import VppTestCase, KeepAliveReporter


class SanityTestCase(VppTestCase):
    """ Sanity test case - verify if VPP is able to start """
    pass

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
