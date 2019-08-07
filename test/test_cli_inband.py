import framework

from framework import VppTestCase, VppTestRunner


class TestCliInband(VppTestCase):
    """TestCliInband"""

    def test_cli_foo(self):
        """test_cli_foo"""
        with self.assertRaises(self.vapi.vpp.VPPApiClientUnexpectedReturnValueError) as ctx:
            print(self.vapi.cli_inband(cmd='foo\n'))
        print(vars(ctx))

    def test_cli_show_log(self):
        """test_cli_show_log"""
        rv = self.vapi.cli_inband(cmd='show log\n')
        print(rv.reply)


if __name__ == '__main__':
    framework.main(testRunner=VppTestRunner, verbosity=2)
