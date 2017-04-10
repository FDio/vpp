#!/usr/bin/env python

from __future__ import print_function
from framework import VppTestCase
from hook import VppDiedError
from sys import exit


class SanityTestCase(VppTestCase):
    """ Dummy test case used to check if VPP is able to start """
    pass

if __name__ == '__main__':
    rc = 0
    tc = SanityTestCase
    try:
        tc.setUpClass()
    except VppDiedError:
        rc = -1
    else:
        try:
            tc.tearDownClass()
        except:
            pass

    exit(rc)
