#!/usr/bin/env python

from framework import VppTestCase
from scapy.contrib.gtp import *
from scapy.all import *


class TestSRv6EndMGTP4E(VppTestCase):
    """ SRv6 End.M.GTP4.E (SRv6 -> GTP-U) """

    @classmethod
    def setUpClass(cls):
        super(TestSRv6EndMGTP4E, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.pg_if_i = cls.pg_interfaces[0]
            cls.pg_if_o = cls.pg_interfaces[1]

            cls.pg_if_i.config_ip4()
            cls.pg_if_o.config_ip6()

            for pg_if in cls.pg_interfaces:
                pg_if.admin_up()
                pg_if.resolve_arp()

        except Exception:
            super(TestSRv6EndMGTP4E, cls).tearDownClass()
            raise


class TestSRv6TMTmap(VppTestCase):
    """ SRv6 T.M.Tmap (GTP-U -> SRv6) """

    @classmethod
    def setUpClass(cls):
        super(TestSRv6TMTmap, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.pg_if_i = cls.pg_interfaces[0]
            cls.pg_if_o = cls.pg_interfaces[1]

            cls.pg_if_i.config_ip4()
            cls.pg_if_o.config_ip6()

            for pg_if in cls.pg_interfaces:
                pg_if.admin_up()
                pg_if.resolve_arp()

        except Exception:
            super(TestSRv6TMTmap, cls).tearDownClass()
            raise


class TestSRv6EndMGTP6E(VppTestCase):
    """ SRv6 End.M.GTP6.E """

    @classmethod
    def setUpClass(cls):
        super(TestSRv6EndMGTP6E, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.pg_if_i = cls.pg_interfaces[0]
            cls.pg_if_o = cls.pg_interfaces[1]

            cls.pg_if_i.config_ip4()
            cls.pg_if_o.config_ip6()

            for pg_if in cls.pg_interfaces:
                pg_if.admin_up()
                pg_if.resolve_arp()

        except Exception:
            super(TestSRv6EndMGTP6E, cls).tearDownClass()
            raise


class TestSRv6EndMGTP6D(VppTestCase):
    """ SRv6 End.M.GTP6.D """

    @classmethod
    def setUpClass(cls):
        super(TestSRv6EndMGTP6D, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.pg_if_i = cls.pg_interfaces[0]
            cls.pg_if_o = cls.pg_interfaces[1]

            cls.pg_if_i.config_ip4()
            cls.pg_if_o.config_ip6()

            for pg_if in cls.pg_interfaces:
                pg_if.admin_up()
                pg_if.resolve_arp()

        except Exception:
            super(TestSRv6EndMGTP6D, cls).tearDownClass()
            raise
