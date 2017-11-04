from __future__ import print_function

import os
from vpp_papi_unserialize import VPPUnserializeBuffer
from vpp_papi_graph import VPPNodeThreads

""" TestPAPIGraph is a subclass of VPPTestCase classes.

Basic test for the VPP node graph unserializer.

"""

if __name__ == "__main__":
    # if we're running this directly, to get a 'repr'
    # dump, then to avoid the need to setup various paths,
    # fake this class. this is a bit kludgy
    class VppTestCase(object):
        pass
else:
    from framework import VppTestCase


def getpath(name):
    """Work out the full path to a file relative to the test dir"""
    return os.path.sep.join((os.path.dirname(os.path.realpath(__file__)),
                             name))


graphdump = getpath("papi_unserialize/vppgraph.bin")
graphrepr = getpath("papi_unserialize/vppgraph.repr")


class TestPAPIGraph(VppTestCase):
    """ PAPI VPP Node Graph Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestPAPIGraph, cls).setUpClass()
        cls.v = cls.vapi.papi

    def test_parse_api_reply_in_shmem(self):
        rc = self.v.get_node_graph()
        # check the reply is the right type of thing
        # if this is an integer then we didn't go fetch the
        # data; it should be 'bytes'
        self.assertIsInstance(rc.reply_in_shmem, bytes)

        # now parse it
        b = VPPUnserializeBuffer(rc.reply_in_shmem)
        t = VPPNodeThreads(b)

        # check all the bytes were consumed and some other
        # obvious values
        self.assertEqual(b.offset, len(b.data),
                         "buffer offset should equal its length")
        self.assertEqual(len(t.threads), 1,
                         "There should be one thread")
        self.assertEqual(t.threads[0].nodes[0].name, 'null-node',
                         "Node 0 should be named 'null-node'")

    def test_parse_from_file(self):
        with open(graphdump) as fp:
            blob = bytes(fp.read())

        b = VPPUnserializeBuffer(blob)
        t = VPPNodeThreads(b)

        # check all the bytes were consumed and some other
        # obvious values
        self.assertEqual(b.offset, len(b.data),
                         "buffer offset should equal its length")
        self.assertEqual(len(t.threads), 1,
                         "There should be one thread")
        self.assertEqual(t.threads[0].nodes[0].name, 'null-node',
                         "Node 0 should be named 'null-node'")

        # crude - compare the repr output with one we prepared earlier
        # since there's nothing dynamic like a dict in here, this is
        # safe to do.
        with open(graphrepr) as fp:
            text = fp.read()

        self.assertEqual(repr(t), text,
                         "repr text of the decoded structure "
                         "should be the same")


if __name__ == "__main__":
    # TODO add some way to store a fresh blob from a running VPP
    # should that change in future
    with open(graphdump) as fp:
        blob = bytes(fp.read())

    # The obvious flaw here is that we're comparing with something
    # we previously decoded using the same code; the idea is to catch
    # regressions in the decoder, not necessarily prove the decoder since
    # we do that elsewhere.
    b = VPPUnserializeBuffer(blob)
    t = VPPNodeThreads(b)

    with open(graphrepr, "w") as fp:
        fp.write(repr(t))

    print("done")
