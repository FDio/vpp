#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner
from util import ppp
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP
from custom_exceptions import CaptureUnexpectedPacketError
from vpp_papi_provider import SYSLOG_SEVERITY
from syslog_rfc5424_parser import SyslogMessage, ParseError
from syslog_rfc5424_parser.constants import SyslogFacility, SyslogSeverity


class TestSyslog(VppTestCase):
    """ Syslog Protocol Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestSyslog, cls).setUpClass()

        try:
            cls.pg_interfaces = cls.pg0, = cls.create_pg_interfaces(
                range(1), idempotent=True)
            cls.pg0.admin_up()
            cls.pg0.config_ip4()
            cls.pg0.resolve_arp()

        except Exception:
            super(TestSyslog, cls).tearDownClass()
            raise

    def syslog_generate(self, facility, severity, appname, msgid, sd=None,
                        msg=None):
        """
        Generate syslog message

        :param facility: facility value
        :type  syslog_rfc5424_parser.constants SyslogFacility
        :param severity: severity level
        :type  syslog_rfc5424_parser.constants SyslogSeverity
        :param appname: application name that originate message
        :param msgid: message identifier
        :param sd: structured data (optional)
        :param msg: free-form message (optional)
        """
        facility_str = ['kernel', 'user-level', 'mail-system',
                        'system-daemons', 'security-authorization', 'syslogd',
                        'line-printer', 'network-news', 'uucp', 'clock-daemon',
                        '', 'ftp-daemon', 'ntp-subsystem', 'log-audit',
                        'log-alert', '', 'local0', 'local1', 'local2',
                        'local3', 'local4', 'local5', 'local6', 'local7']

        severity_str = ['emergency', 'alert', 'critical', 'error', 'warning',
                        'notice', 'informational', 'debug']

        cli_str = "test syslog %s %s %s %s" % (facility_str[facility],
                                               severity_str[severity],
                                               appname,
                                               msgid)
        if sd is not None:
            for sd_id, sd_params in sd.items():
                cli_str += " sd-id %s" % (sd_id)
                for name, value in sd_params.items():
                    cli_str += " sd-param %s %s" % (name, value)
        if msg is not None:
            cli_str += " %s" % (msg)
        self.vapi.cli(cli_str)

    def syslog_verify(self, data, facility, severity, appname, msgid, sd=None,
                      msg=None):
        """
        Verify syslog message

        :param data: syslog message
        :param facility: facility value
        :param severity: severity level
        :param appname: application name that originate message
        :param msgid: message identifier
        :param sd: structured data (optional)
        :param msg: free-form message (optional)
        """
        message = data.decode('utf-8')
        if sd is None:
            sd = {}
        try:
            message = SyslogMessage.parse(message)
            self.assertEqual(message.facility, facility)
            self.assertEqual(message.severity, severity)
            self.assertEqual(message.appname, appname)
            self.assertEqual(message.msgid, msgid)
            self.assertEqual(message.msg, msg)
            self.assertEqual(message.sd, sd)
            self.assertEqual(message.version, 1)
            self.assertEqual(message.hostname, self.pg0.local_ip4)
        except ParseError as e:
            self.logger.error(e)

    def test_syslog(self):
        """ Syslog Protocol test """
        self.vapi.syslog_set_sender(self.pg0.remote_ip4n, self.pg0.local_ip4n)
        config = self.vapi.syslog_get_sender()
        self.assertEqual(str(config.collector_address),
                         self.pg0.remote_ip4)
        self.assertEqual(config.collector_port, 514)
        self.assertEqual(str(config.src_address), self.pg0.local_ip4)
        self.assertEqual(config.vrf_id, 0)
        self.assertEqual(config.max_msg_size, 480)

        appname = 'test'
        msgid = 'testMsg'
        msg = 'this is message'
        sd1 = {'exampleSDID@32473': {'iut': '3',
                                     'eventSource': 'App',
                                     'eventID': '1011'}}
        sd2 = {'exampleSDID@32473': {'iut': '3',
                                     'eventSource': 'App',
                                     'eventID': '1011'},
               'examplePriority@32473': {'class': 'high'}}

        self.pg_enable_capture(self.pg_interfaces)
        self.syslog_generate(SyslogFacility.local7,
                             SyslogSeverity.info,
                             appname,
                             msgid,
                             None,
                             msg)
        capture = self.pg0.get_capture(1)
        try:
            self.assertEqual(capture[0][IP].src, self.pg0.local_ip4)
            self.assertEqual(capture[0][IP].dst, self.pg0.remote_ip4)
            self.assertEqual(capture[0][UDP].dport, 514)
            self.assert_packet_checksums_valid(capture[0], False)
        except(IndexError,):
                self.logger.error(ppp("invalid packet:", capture[0]))
                raise CaptureUnexpectedPacketError(packet=capture[0],
                                                   interface=self.pg0)
        self.syslog_verify(capture[0][Raw].load,
                           SyslogFacility.local7,
                           SyslogSeverity.info,
                           appname,
                           msgid,
                           None,
                           msg)

        self.pg_enable_capture(self.pg_interfaces)
        self.vapi.syslog_set_filter(SYSLOG_SEVERITY.WARN)
        filter_ = self.vapi.syslog_get_filter()
        self.assertEqual(filter_.severity, SYSLOG_SEVERITY.WARN)
        self.syslog_generate(SyslogFacility.local7,
                             SyslogSeverity.info,
                             appname,
                             msgid,
                             None,
                             msg)
        self.pg0.assert_nothing_captured()

        self.pg_enable_capture(self.pg_interfaces)
        self.syslog_generate(SyslogFacility.local6,
                             SyslogSeverity.warning,
                             appname,
                             msgid,
                             sd1,
                             msg)
        capture = self.pg0.get_capture(1)
        self.syslog_verify(capture[0][Raw].load,
                           SyslogFacility.local6,
                           SyslogSeverity.warning,
                           appname,
                           msgid,
                           sd1,
                           msg)

        self.vapi.syslog_set_sender(self.pg0.remote_ip4n,
                                    self.pg0.local_ip4n,
                                    collector_port=12345)
        config = self.vapi.syslog_get_sender()
        self.assertEqual(config.collector_port, 12345)

        self.pg_enable_capture(self.pg_interfaces)
        self.syslog_generate(SyslogFacility.local5,
                             SyslogSeverity.err,
                             appname,
                             msgid,
                             sd2,
                             None)
        capture = self.pg0.get_capture(1)
        try:
            self.assertEqual(capture[0][UDP].dport, 12345)
        except (KeyError,):
                self.logger.error(ppp("invalid packet:", capture[0]))
                raise CaptureUnexpectedPacketError(packet=capture[0],
                                                   interface=self.pg0)
        self.syslog_verify(capture[0][Raw].load,
                           SyslogFacility.local5,
                           SyslogSeverity.err,
                           appname,
                           msgid,
                           sd2,
                           None)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
