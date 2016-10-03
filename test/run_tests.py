#!/usr/bin/env python

import os
import unittest
from framework import VppTestRunner

if __name__ == '__main__':
    try:
        verbose = int(os.getenv("V", 0))
    except:
        verbose = 0
    unittest.main(testRunner=VppTestRunner, module=None, verbosity=verbose)
