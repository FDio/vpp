#! /usr/bin/env python3

import framework

from framework import VppTestCase, VppTestRunner
from framework import unittest


class PluginPerfmonTestcase(VppTestCase):
    """PluginPerfmonTestcase"""

    PLUGIN_NAME = 'perfmon'

    @classmethod
    def setUpClass(cls):
        super(PluginPerfmonTestcase, cls).setUpClass()

    @property
    def plugin_shared_lib(self):
        return "%s_plugin.so" % self.PLUGIN_NAME

    @classmethod
    def tearDownClass(cls):
        super(PluginPerfmonTestcase, cls).tearDownClass()

    def test_plugin_enabled(self):
        command = self.vapi.cli("show plugin")
        self.assertIn(self.plugin_shared_lib, command,
                      "Plugin '%s' not found in 'show plugin'."
                      % self.plugin_shared_lib)

    def test_errors_in_logs(self):
        command = self.vapi.cli('show logging')
        filter_ = self.PLUGIN_NAME
        errors = [x for x in command.splitlines() if filter_ in x]
        self.assertIn('err', errors,
                      'Plugin logged errors:\n%s' % '\n'.join(errors))

    def test_PerfmonTables_installed(self):
        file = 'PerfmonTables.tar.xz'
        command = self.vapi.cli('show logging')
        filter_ = self.PLUGIN_NAME
        errors = [x for x in command.splitlines() if filter_ in x]
        self.assertNotIn(file, errors,
                         "%s Not installed." % file)

    def test_perfmon_has_cpiud_info(self):
        command = self.vapi.cli('show logging')
        filter_ = self.PLUGIN_NAME
        errors = [x for x in command.splitlines() if filter_ in x]
        if 'No table for cpuid' in errors:
            command = self.vapi.cli('show cpu')





if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
