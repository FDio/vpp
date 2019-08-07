#! /usr/bin/env python3

#import framework2
from framework import unittest

from parameterized import parameterized

from vpp_fixture import VppFixture


class TestPlugins(unittest.TestCase):
    @parameterized.expand([('ioam_plugin.so',),
                           ('memif_plugin.so',),
                           ('perfmon_plugin.so',)
                           ])
    def test_vpp_starts_without_plugin(self, plugin_name):
        self.vpp = VppFixture()
        self.vpp.run()
        print('PID: %s' % self.vpp.pid)
        print('out: %s' % self.vpp.stdout)
        print('err: %s' % self.vpp.stderr)
        self.vpp.quit()


if __name__ == '__main__':
    unittest.main()
