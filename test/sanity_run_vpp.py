#!/usr/bin/env python3

from __future__ import print_function
from multiprocessing import Pipe
import sys
import os
from framework import VppDiedError, VppTestCase, KeepAliveReporter


class SanityTestCase(VppTestCase):
    """ Sanity test case - verify whether VPP is able to start """
    pass

    # don't ask to debug SanityTestCase
    @classmethod
    def wait_for_enter(cls, pid=0):
        pass

    @classmethod
    def _debug_quit(cls):
        try:
            cls.vpp.poll()
        except AttributeError:
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
        except Exception:
            rc = -1
    x.close()
    y.close()

    if rc == 0:
        print('Sanity test case passed.\n')
    else:
        print('Sanity test case failed.\n')

    sys.exit(rc)
