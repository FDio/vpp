import gc
import pprint

import objgraph
from pympler import tracker

import framework
import vpp_papi
from vpp_papi_provider import VppPapiProvider


tr = tracker.SummaryTracker()

"""
  Internal debug Test Case

  TestCase for debugging the test framework.
  (VppTestCases are converted in run_tests.py by setting TEST_DEBUG.) 
"""


class DebugInternalVppTestCase(framework.VppTestCase):

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        gc.collect()
        tr.print_diff()
        objects = gc.get_objects()
        counter = 0
        with open(cls.tempdir + '/python_objects.txt', 'w') as f:
            interesting = [
                o for o in objects
                if isinstance(o, (VppPapiProvider, vpp_papi.VPP))]
            del objects
            gc.collect()
            for o in interesting:
                objgraph.show_backrefs([o], max_depth=5,
                                       filename="%s/%s.png" %
                                       (cls.tempdir, counter))
                counter += 1
                refs = gc.get_referrers(o)
                pp = pprint.PrettyPrinter(indent=2)
                f.write("%s\n" % pp.pformat(o))
                for r in refs:
                    try:
                        f.write("%s\n" % pp.pformat(r))
                    except (ValueError, AttributeError):
                        f.write("%s\n" % type(r))
