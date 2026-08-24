#!/usr/bin/env python3

from __future__ import print_function
from multiprocessing import Pipe
import sys
from asfframework import (
    KeepAliveReporter,
    VppAsfTestCase,
    VppDiedError,
    VppTestResult,
)


class SanityTestCase(VppAsfTestCase):
    """Sanity test case - verify whether VPP is able to start"""

    cpus = [0]

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


def main():
    rc = 0
    tc = SanityTestCase
    x, y = Pipe()
    reporter = KeepAliveReporter()
    reporter.pipe = y
    try:
        try:
            tc.setUpClass()
        except VppDiedError:
            rc = -1
        else:
            try:
                tc.tearDownClass()
            except Exception:
                rc = -1
    finally:
        # The normal test run starts after this preflight.  setUpClass()
        # populates this class-level result context, which is inherited by
        # subsequently forked workers.  A skipped class, or a class whose
        # setup fails before VppAsfTestCase.setUpClass(), cannot replace it;
        # leaving it set would attribute that class's result to SanityTestCase.
        VppTestResult.current_test_case_info = None
    x.close()
    y.close()

    if rc == 0:
        print("Sanity test case passed.")
    else:
        print("Sanity test case failed.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
