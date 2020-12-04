#!/usr/bin/env python3

from os.path import dirname, realpath, split,\
    join, isdir, exists
from os import remove, system, mkdir
from logging import getLogger, basicConfig,\
    DEBUG, INFO, ERROR
from argparse import ArgumentParser
from atexit import register
from shutil import rmtree

from jinja2 import Environment, FileSystemLoader

from docker.errors import NotFound, APIError
from docker import from_env

from scapy.contrib.gtp import *
from scapy.all import *


verbose_levels = {
    'error': ERROR,
    'debug': DEBUG,
    'info': INFO}


class ContainerStartupError(Exception):
    pass


class Container(object):

    tmp = "/tmp"
    cmd = "vppctl -s 0:5002"
    cmd_bash = "/bin/bash"

    def __init__(self, ref, name):
        self._name = name
        self._ref = ref

    @property
    def name(self):
        return self._name

    @property
    def temp(self):
        return join(self.tmp, self.name)

    @property
    def pg_input_file(self):
        return join(self.temp, "pgi.pcap")

    @property
    def pg_output_file(self):
        return join(self.temp, "pgo.pcap")

    @property
    def pg_input_file_in(self):
        return join("/mnt", "pgi.pcap")

    @property
    def pg_output_file_in(self):
        return join("/mnt", "pgo.pcap")

    def disconnect_all(self):
        status = False
        for net in self._ref.client.networks.list():
            try:
                net.disconnect(self._ref)
            except APIError:
                continue
            status = True
        return status

    @classmethod
    def new(cls, client, image, name):

        temp = join(cls.tmp, name)
        if isdir(temp):
            rmtree(temp)
        mkdir(temp)

        ref = client.containers.run(
            detach=True,
            remove=True,
            auto_remove=True,
            image=image,
            name=name,
            privileged=True,
            volumes={
                temp: {
                    'bind': '/mnt',
                    'mode': 'rw'}})

        obj = cls.get(client, name)
        if not obj:
            raise ContainerStartupError()

        obj.disconnect_all()
        return obj

    @classmethod
    def get(cls, client, name):
        try:
            ref = client.containers.get(name)
        except NotFound:
            pass
        else:
            return cls(ref, name)

    def rem(self):
        self._ref.kill()

    def vppctl(self):
        system("docker exec -it {} {}".format(self.name, self.cmd))

    def bash(self):
        system("docker exec -it {} {}".format(self.name, self.cmd_bash))

    def vppctl_exec(self, cmd):
        ec, resp = self._ref.exec_run(cmd="{} {}".format(self.cmd, cmd))
        assert(ec == 0)
        return resp

    def setup_host_interface(self, name, ip):
        self.vppctl_exec("create host-interface name {}".format(name))
        self.vppctl_exec("set int ip addr host-{} {}".format(name, ip))
        self.vppctl_exec("set int state host-{} up".format(name))

    def pg_create_interface(self, local_ip, remote_ip, local_mac, remote_mac):
        # remote_ip can't have subnet mask

        time.sleep(2)
        self.vppctl_exec("create packet-generator interface pg0")
        self.vppctl_exec("set int mac address pg0 {}".format(local_mac))
        self.vppctl_exec("set int ip addr pg0 {}".format(local_ip))
        self.vppctl_exec(
            "set ip neighbor pg0 {} {}".format(remote_ip, remote_mac))
        self.vppctl_exec("set int state pg0 up")

    def pg_create_interface4(self, local_ip, remote_ip, local_mac, remote_mac):
        # remote_ip can't have subnet mask

        time.sleep(2)
        self.vppctl_exec("create packet-generator interface pg0")
        self.vppctl_exec("set int mac address pg0 {}".format(local_mac))
        self.vppctl_exec("set int ip addr pg0 {}".format(local_ip))
        self.vppctl_exec("set ip neighbor pg0 {} {}".format(remote_ip, remote_mac))
        self.vppctl_exec("set int state pg0 up")

    def pg_create_interface6(self, local_ip, remote_ip, local_mac, remote_mac):
        # remote_ip can't have subnet mask

        time.sleep(2)
        self.vppctl_exec("create packet-generator interface pg0")
        self.vppctl_exec("set int mac address pg0 {}".format(local_mac))
        self.vppctl_exec("set int ip addr pg0 {}".format(local_ip))
        self.vppctl_exec("set ip neighbor pg0 {} {}".format(remote_ip, remote_mac))
        self.vppctl_exec("set int state pg0 up")

    def pg_create_interface4_name(self, ifname, local_ip, remote_ip, local_mac, remote_mac):
        # remote_ip can't have subnet mask

        time.sleep(2)
        self.vppctl_exec("create packet-generator interface {}".format(ifname))
        self.vppctl_exec("set int mac address {} {}".format(ifname, local_mac))
        self.vppctl_exec("set int ip addr {} {}".format(ifname, local_ip))
        self.vppctl_exec("set ip neighbor {} {} {}".format(ifname, remote_ip, remote_mac))
        self.vppctl_exec("set int state {} up".format(ifname))

    def pg_create_interface6_name(self, ifname, local_ip, remote_ip, local_mac, remote_mac):
        # remote_ip can't have subnet mask

        time.sleep(2)
        self.vppctl_exec("create packet-generator interface {}".format(ifname))
        self.vppctl_exec("set int mac address {} {}".format(ifname, local_mac))
        self.vppctl_exec("set int ip addr {} {}".format(ifname, local_ip))
        self.vppctl_exec("set ip neighbor {} {} {}".format(ifname, remote_ip, remote_mac))
        self.vppctl_exec("set int state {} up".format(ifname))

    def pg_enable(self):
        # start packet generator
        self.vppctl_exec("packet-generator enable")

    def pg_create_stream(self, stream):
        wrpcap(self.pg_input_file, stream)
        self.vppctl_exec(
            "packet-generator new name pg-stream "
            "node ethernet-input pcap {}".format(
                self.pg_input_file_in))

    def pg_start_capture(self):
        if exists(self.pg_output_file):
            remove(self.pg_output_file)
        self.vppctl_exec(
            "packet-generator capture pg0 pcap {}".format(
                self.pg_output_file_in))

    def pg_start_capture_name(self, ifname):
        if exists(self.pg_output_file):
            remove(self.pg_output_file)
        self.vppctl_exec(
            "packet-generator capture {} pcap {}".format(
                ifname, self.pg_output_file_in))

    def pg_read_packets(self):
        return rdpcap(self.pg_output_file)

    def set_ipv6_route(self, out_if_name, next_hop_ip, subnet):
        self.vppctl_exec(
            "ip route add {} via host-{} {}".format(
                subnet, out_if_name, next_hop_ip))

    def set_ipv6_route2(self, out_if_name, next_hop_ip, subnet):
        self.vppctl_exec(
            "ip route add {} via {} {}".format(
                subnet, out_if_name, next_hop_ip))

    def set_ip_pgroute(self, out_if_name, next_hop_ip, subnet):
        self.vppctl_exec("ip route add {} via {} {}".format(
            subnet, out_if_name, next_hop_ip))

    def set_ipv6_pgroute(self, out_if_name, next_hop_ip, subnet):
        self.vppctl_exec("ip route add {} via {} {}".format(
            subnet, out_if_name, next_hop_ip))

    def set_ipv6_default_route(self, out_if_name, next_hop_ip):
        self.vppctl_exec(
            "ip route add ::/0 via host-{} {}".format(
                out_if_name, next_hop_ip))

    def enable_trace(self, count):
        self.vppctl_exec("trace add af-packet-input {}".format(count))


class Containers(object):

    def __init__(self, client, image):
        self.client = client
        self.image = image

    def tmp_render(self, path, template, kwargs):

        with open(path, "w") as fo:
            fo.write(template.render(**kwargs))

        register(lambda: remove(path))

    def build(self, path, vpp_path):
        env = Environment(loader=FileSystemLoader(path),
                          autoescape=True,
                          trim_blocks=True)

        self.tmp_render(join(vpp_path, "Dockerfile"),
                        env.get_template("Dockerfile.j2"),
                        {'vpp_path': vpp_path})

        self.tmp_render(join(vpp_path, "startup.conf"),
                        env.get_template("startup.conf.j2"),
                        {'vpp_path': vpp_path})

        ref, _ = self.client.images.build(path=vpp_path,
                                          tag=self.image, rm=True)
        return ref

    def release(self, path, vpp_path):
        env = Environment(loader=FileSystemLoader(path),
                          autoescape=True,
                          trim_blocks=True)

        self.tmp_render(join(vpp_path, "Dockerfile"),
                        env.get_template("Dockerfile.j2.release"),
                        {'vpp_path': vpp_path})

        self.tmp_render(join(vpp_path, "startup.conf"),
                        env.get_template("startup.conf.j2"),
                        {'vpp_path': vpp_path})

        ref, _ = self.client.images.build(path=vpp_path,
                                          tag="srv6m-release-image", rm=True)
        return ref

    def new(self, name):
        return Container.new(self.client, self.image, name)

    def get(self, name):
        return Container.get(self.client, name)

    def vppctl(self, name, command=None):
        container = self.get(name)
        if not command:
            container.vppctl()
        else:
            print(container.vppctl_exec(command).decode())

    def bash(self, name):
        container = self.get(name)
        container.bash()


class Network(object):

    def __init__(self, ref, name):
        self._name = name
        self._ref = ref

    @property
    def name(self):
        return self._name

    @classmethod
    def new(cls, client, name):
        ref = client.networks.create(name, driver="bridge",
                                     check_duplicate=True)
        return cls(ref, name)

    @classmethod
    def get(cls, client, name):
        try:
            ref = client.networks.get(name)
        except NotFound:
            pass
        else:
            return cls(ref, name)

    def rem(self):
        self._ref.remove()

    def connect(self, c):
        self._ref.connect(c.name)


class Networks(object):

    def __init__(self, client):
        self.client = client

    def new(self, name):
        return Network.new(self.client, name)

    def get(self, name):
        return Network.get(self.client, name)


class Program(object):

    image = "srv6m-image"

    name_prefix = "hck"

    # TODO: add description to these instances
    # for exmaple what the vpp is supposed to be
    # in our topoloty overview

    instance_names = ["vpp-1",
                      "vpp-2",
                      "vpp-3",
                      "vpp-4"]

    network_names = ["net-1",
                     "net-2",
                     "net-3"]

    def __init__(self, image=None, prefix=None):
        self.path = dirname(realpath(__file__))

        if image:
            self.image = image
        if prefix is not None:
            self.name_prefix = prefix

        client = from_env()
        self.containers = Containers(client, self.image)
        self.networks = Networks(client)

        self.logger = getLogger(__name__)

    @property
    def vpp_path(self):
        return self.path.rsplit("/", 4)[0]

    def get_name(self, name):
        if not self.name_prefix:
            return name
        return "{}-{}".format(self.name_prefix, name)

    def stop_containers(self):

        for name in self.instance_names:
            instance = self.containers.get(self.get_name(name))
            if instance:
                instance.rem()

        for name in self.network_names:
            network = self.networks.get(self.get_name(name))
            if network:
                network.rem()

    def start_containers(self):

        self.stop_containers()

        networks = list()

        for name in self.network_names:
            networks.append(self.networks.new(self.get_name(name)))

        n1, n2, n3 = networks

        instances = list()

        for name in self.instance_names:
            instances.append(self.containers.new(self.get_name(name)))

        c1, c2, c3, c4 = instances

        # setup packet generator interfaces
        # c1.pg_create_interface(local_ip="C::1/120", remote_ip="C::2",
        # local_mac="aa:bb:cc:dd:ee:01", remote_mac="aa:bb:cc:dd:ee:02")

        # setup network between instances
        n1.connect(c1)
        n1.connect(c2)

        n2.connect(c2)
        n2.connect(c3)

        n3.connect(c3)
        n3.connect(c4)

        # c1 & c2 link
        c1.setup_host_interface("eth1", "A1::1/120")
        c2.setup_host_interface("eth1", "A1::2/120")

        # c2 & c3 link
        c2.setup_host_interface("eth2", "A2::1/120")
        c3.setup_host_interface("eth1", "A2::2/120")

        # c3 & c4 link
        c3.setup_host_interface("eth2", "A3::1/120")
        c4.setup_host_interface("eth1", "A3::2/120")

        # c1 > c2 default route

        c1.set_ipv6_default_route("eth1", "A1::2")
        # c2 > c3 default route
        c2.set_ipv6_default_route("eth2", "A2::2")
        # c3 > c2 default route
        c3.set_ipv6_default_route("eth1", "A2::1")
        # c4 > c3 default route
        c4.set_ipv6_default_route("eth1", "A3::1")

        # c3 > c4 static route for address B::1/128
        c3.set_ipv6_route("eth2", "A3::2", "B::1/128")
        c3.set_ipv6_route("eth2", "A3::2", "B::2/128")

    def test_ping(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface(
            local_ip="C::1/120",
            remote_ip="C::2",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface(
            local_ip="B::1/120",
            remote_ip="B::2",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IPv6(src="C::2", dst="B::2") / ICMPv6EchoRequest())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_srv6(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 C::1/120
        # pg interface on c4 B::1/120

        self.start_containers()

        print("Sleeping")
        time.sleep(30)

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface(
            local_ip="C::1/120",
            remote_ip="C::2",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface(
            local_ip="B::1/120",
            remote_ip="B::2",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr D1::")
        c1.vppctl_exec(
            "sr policy add bsid D1::999:1 next D2:: next D3:: next D4::")
        c1.vppctl_exec("sr steer l3 B::/120 via bsid D1::999:1")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec("sr localsid address D4:: behavior end.dx6 pg0 B::2")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/128")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IPv6(src="C::2", dst="B::2") / ICMPv6EchoRequest())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c2.enable_trace(10)
        c3.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    ''' T.Map is obsolete
    def test_tmap(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface4(
            local_ip="172.16.0.1/30",
            remote_ip="172.16.0.2/30",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface4(
            local_ip="1.0.0.2/30",
            remote_ip="1.0.0.1",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec(
            "sr policy add bsid D1:: next D2:: next D3:: "
            "gtp4_removal sr_prefix D4::/32 v6src_prefix C1::/64")
        c1.vppctl_exec("sr steer l3 172.20.0.1/32 via bsid D1::")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec(
            "sr localsid prefix D4::/32 "
            "behavior end.m.gtp4.e v4src_position 64")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "1.0.0.1", "172.20.0.1/32")

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IP(src="172.20.0.2", dst="172.20.0.1") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="g_pdu", teid=200) /
             IP(src="172.99.0.1", dst="172.99.0.2") /
             ICMP())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_tmap_5g(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface4(
            local_ip="172.16.0.1/30",
            remote_ip="172.16.0.2/30",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface4(
            local_ip="1.0.0.2/30",
            remote_ip="1.0.0.1",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec(
            "sr policy add bsid D1:: next D2:: next D3:: "
            "gtp4_removal sr_prefix D4::/32 v6src_prefix C1::/64")
        c1.vppctl_exec("sr steer l3 172.20.0.1/32 via bsid D1::")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec(
            "sr localsid prefix D4::/32 "
            "behavior end.m.gtp4.e v4src_position 64")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "1.0.0.1", "172.20.0.1/32")

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IP(src="172.20.0.2", dst="172.20.0.1") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="g_pdu", teid=200) /
             GTPPDUSessionContainer(R=1, QFI=3) /
             IP(src="172.99.0.1", dst="172.99.0.2") /
             ICMP())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_tmap_ipv6(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface4(
            local_ip="172.16.0.1/30",
            remote_ip="172.16.0.2/30",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface4(
            local_ip="1.0.0.2/30",
            remote_ip="1.0.0.1",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec(
            "sr policy add bsid D1:: next D2:: next D3:: "
            "gtp4_removal sr_prefix D4::/32 v6src_prefix C1::/64")
        c1.vppctl_exec("sr steer l3 172.20.0.1/32 via bsid D1::")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec(
            "sr localsid prefix D4::/32 "
            "behavior end.m.gtp4.e v4src_position 64")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "1.0.0.1", "172.20.0.1/32")

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IP(src="172.20.0.2", dst="172.20.0.1") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="g_pdu", teid=200) /
             IPv6(src="2001::1", dst="2002::1") /
             ICMPv6EchoRequest())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_tmap_ipv6_5g(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface4(
            local_ip="172.16.0.1/30",
            remote_ip="172.16.0.2/30",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface4(
            local_ip="1.0.0.2/30",
            remote_ip="1.0.0.1",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec(
            "sr policy add bsid D1:: next D2:: next D3:: "
            "gtp4_removal sr_prefix D4::/32 v6src_prefix C1::/64")
        c1.vppctl_exec("sr steer l3 172.20.0.1/32 via bsid D1::")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec(
            "sr localsid prefix D4::/32 "
            "behavior end.m.gtp4.e v4src_position 64")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "1.0.0.1", "172.20.0.1/32")

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IP(src="172.20.0.2", dst="172.20.0.1") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="g_pdu", teid=200) /
             GTPPDUSessionContainer(R=1, QFI=3) /
             IPv6(src="2001::1", dst="2002::1") /
             ICMPv6EchoRequest())

        print("Sending packet on {}:".format(c1.name))
        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()
    '''

    def test_gtp4(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface4(
            local_ip="172.16.0.1/30",
            remote_ip="172.16.0.2/30",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface4(
            local_ip="1.0.0.2/30",
            remote_ip="1.0.0.1",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D4:: next D2:: next D3::")
        c1.vppctl_exec("sr policy add bsid D5:: behavior t.m.gtp4.d D4::/32 v6src_prefix C1::/64 nhtype ipv4")
        c1.vppctl_exec("sr steer l3 172.20.0.1/32 via bsid D5::")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec(
            "sr localsid prefix D4::/32 "
            "behavior end.m.gtp4.e v4src_position 64")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "1.0.0.1", "172.20.0.1/32")

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IP(src="172.20.0.2", dst="172.20.0.1") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="g_pdu", teid=200) /
             IP(src="172.99.0.1", dst="172.99.0.2") /
             ICMP())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        time.sleep(10) 
        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_gtp4_usid(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface4(
            local_ip="172.16.0.1/30",
            remote_ip="172.16.0.2/30",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface4(
            local_ip="1.0.0.2/30",
            remote_ip="1.0.0.1",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D4:: next D2:1111:aaaa:bbbb::")
        c1.vppctl_exec("sr policy add bsid D5:: behavior t.m.gtp4.d D4::/32 v6src_prefix C1::/64 nhtype ipv4")
        c1.vppctl_exec("sr steer l3 172.20.0.1/32 via bsid D5::")

        c2.vppctl_exec("sr localsid prefix D2:1111:aaaa::/48 behavior end usid 16")

        c3.vppctl_exec("sr localsid prefix D2:1111:bbbb::/48 behavior end usid 16")

        c4.vppctl_exec(
            "sr localsid prefix D4::/32 "
            "behavior end.m.gtp4.e v4src_position 64")

        c2.set_ipv6_route("eth2", "A2::2", "D2:1111:bbbb::/48")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "1.0.0.1", "172.20.0.1/32")

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IP(src="172.20.0.2", dst="172.20.0.1") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="g_pdu", teid=200) /
             IP(src="172.99.0.1", dst="172.99.0.2") /
             ICMP())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        time.sleep(10) 
        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_gtp4_5g(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface4(
            local_ip="172.16.0.1/30",
            remote_ip="172.16.0.2/30",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface4(
            local_ip="1.0.0.2/30",
            remote_ip="1.0.0.1",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D4:: next D2:: next D3::")
        c1.vppctl_exec("sr policy add bsid D5:: behavior t.m.gtp4.d D4::/32 v6src_prefix C1::/64 nhtype ipv4")
        c1.vppctl_exec("sr steer l3 172.20.0.1/32 via bsid D5::")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec(
            "sr localsid prefix D4::/32 "
            "behavior end.m.gtp4.e v4src_position 64")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "1.0.0.1", "172.20.0.1/32")

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IP(src="172.20.0.2", dst="172.20.0.1") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="g_pdu", teid=200) /
             GTPPDUSessionContainer(type=1, R=1, QFI=3) /
             IP(src="172.99.0.1", dst="172.99.0.2") /
             ICMP())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_gtp4_echo(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface4(
            local_ip="172.16.0.1/30",
            remote_ip="172.16.0.2/30",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface4(
            local_ip="1.0.0.2/30",
            remote_ip="1.0.0.1",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D4:: next D2:: next D3::")
        c1.vppctl_exec("sr policy add bsid D5:: behavior t.m.gtp4.d D4::/32 v6src_prefix C1::/64 nhtype ipv4")
        c1.vppctl_exec("sr steer l3 172.20.0.1/32 via bsid D5::")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec(
            "sr localsid prefix D4::/32 "
            "behavior end.m.gtp4.e v4src_position 64")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "1.0.0.1", "172.20.0.1/32")

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IP(src="172.20.0.2", dst="172.20.0.1") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="echo_request", S=1, teid=200, seq=200))

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_gtp4_reply(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface4(
            local_ip="172.16.0.1/30",
            remote_ip="172.16.0.2/30",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface4(
            local_ip="1.0.0.2/30",
            remote_ip="1.0.0.1",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D4:: next D2:: next D3::")
        c1.vppctl_exec("sr policy add bsid D5:: behavior t.m.gtp4.d D4::/32 v6src_prefix C1::/64 nhtype ipv4")
        c1.vppctl_exec("sr steer l3 172.20.0.1/32 via bsid D5::")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec(
            "sr localsid prefix D4::/32 "
            "behavior end.m.gtp4.e v4src_position 64")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "1.0.0.1", "172.20.0.1/32")

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IP(src="172.20.0.2", dst="172.20.0.1") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="echo_response", S=1, teid=200, seq=200))

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_gtp4_error(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface4(
            local_ip="172.16.0.1/30",
            remote_ip="172.16.0.2/30",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface4(
            local_ip="1.0.0.2/30",
            remote_ip="1.0.0.1",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D4:: next D2:: next D3::")
        c1.vppctl_exec("sr policy add bsid D5:: behavior t.m.gtp4.d D4::/32 v6src_prefix C1::/64 nhtype ipv4")
        c1.vppctl_exec("sr steer l3 172.20.0.1/32 via bsid D5::")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec(
            "sr localsid prefix D4::/32 "
            "behavior end.m.gtp4.e v4src_position 64")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "1.0.0.1", "172.20.0.1/32")

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IP(src="172.20.0.2", dst="172.20.0.1") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="error_indication", S=1, teid=200, seq=200)/
             IE_TEIDI(TEIDI=65535)/IE_GSNAddress(address="1.1.1.1")/
             IE_PrivateExtension(extention_value="z"))

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_gtp4_ipv6(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface4(
            local_ip="172.16.0.1/30",
            remote_ip="172.16.0.2/30",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface4(
            local_ip="1.0.0.2/30",
            remote_ip="1.0.0.1",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D4:: next D2:: next D3::")
        c1.vppctl_exec("sr policy add bsid D5:: behavior t.m.gtp4.d D4::/32 v6src_prefix C1::/64")
        c1.vppctl_exec("sr steer l3 172.20.0.1/32 via bsid D5::")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec(
            "sr localsid prefix D4::/32 "
            "behavior end.m.gtp4.e v4src_position 64")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "1.0.0.1", "172.20.0.1/32")

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IP(src="172.20.0.2", dst="172.20.0.1") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="g_pdu", teid=200) /
             IPv6(src="2001::1", dst="2002::1") /
             ICMPv6EchoRequest())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_gtp4_ipv6_5g(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface4(
            local_ip="172.16.0.1/30",
            remote_ip="172.16.0.2/30",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface4(
            local_ip="1.0.0.2/30",
            remote_ip="1.0.0.1",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D4:: next D2:: next D3::")
        c1.vppctl_exec("sr policy add bsid D5:: behavior t.m.gtp4.d D4::/32 v6src_prefix C1::/64")
        c1.vppctl_exec("sr steer l3 172.20.0.1/32 via bsid D5::")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec(
            "sr localsid prefix D4::/32 "
            "behavior end.m.gtp4.e v4src_position 64")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "1.0.0.1", "172.20.0.1/32")

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IP(src="172.20.0.2", dst="172.20.0.1") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="g_pdu", teid=200) /
             GTPPDUSessionContainer(R=1, QFI=3) /
             IPv6(src="2001::1", dst="2002::1") /
             ICMPv6EchoRequest())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_gtp6_drop_in(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        print("Deleting the old containers...")
        time.sleep(30)
        print("Starting the new containers...")

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface(
            local_ip="C::1/120",
            remote_ip="C::2",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface(
            local_ip="B::1/120",
            remote_ip="B::2",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D4:: next D2:: next D3::")

        c1.vppctl_exec(
            "sr localsid prefix D::/64 behavior end.m.gtp6.d.di D4::/64")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec("sr localsid prefix D4::/64 behavior end.m.gtp6.e")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "B::2", "D::2/128")

        print("Waiting...")
        time.sleep(30)

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IPv6(src="C::2", dst="D::2") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="g_pdu", teid=200) /
             IP(src="172.99.0.1", dst="172.99.0.2") /
             ICMP())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_gtp6_drop_in_5g(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        print("Deleting the old containers...")
        time.sleep(30)
        print("Starting the new containers...")

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface(
            local_ip="C::1/120",
            remote_ip="C::2",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface(
            local_ip="B::1/120",
            remote_ip="B::2",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D4:: next D2:: next D3::")

        c1.vppctl_exec(
            "sr localsid prefix D::/64 behavior end.m.gtp6.d.di D4::/64")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec("sr localsid prefix D4::/64 behavior end.m.gtp6.e")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "B::2", "D::2/128")

        print("Waiting...")
        time.sleep(30)

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IPv6(src="C::2", dst="D::2") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="g_pdu", teid=200) /
             GTPPDUSessionContainer(type=1, R=1, QFI=3) /
             IP(src="172.99.0.1", dst="172.99.0.2") /
             ICMP())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_gtp6_drop_in_echo(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        print("Deleting the old containers...")
        time.sleep(30)
        print("Starting the new containers...")

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface(
            local_ip="C::1/120",
            remote_ip="C::2",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface(
            local_ip="B::1/120",
            remote_ip="B::2",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D4:: next D2:: next D3::")

        c1.vppctl_exec(
            "sr localsid prefix D::/64 behavior end.m.gtp6.d.di D4::/64")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec("sr localsid prefix D4::/64 behavior end.m.gtp6.e")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "B::2", "D::2/128")

        print("Waiting...")
        time.sleep(30)

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IPv6(src="C::2", dst="D::2") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="echo_request", S=1, teid=200, seq=300))

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_gtp6_drop_in_reply(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        print("Deleting the old containers...")
        time.sleep(30)
        print("Starting the new containers...")

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface(
            local_ip="C::1/120",
            remote_ip="C::2",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface(
            local_ip="B::1/120",
            remote_ip="B::2",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D4:: next D2:: next D3::")

        c1.vppctl_exec(
            "sr localsid prefix D::/64 behavior end.m.gtp6.d.di D4::/64")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec("sr localsid prefix D4::/64 behavior end.m.gtp6.e")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "B::2", "D::2/128")

        print("Waiting...")
        time.sleep(30)

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IPv6(src="C::2", dst="D::2") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="echo_response", S=1, teid=200, seq=300))

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_gtp6_drop_in_error(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        print("Deleting the old containers...")
        time.sleep(30)
        print("Starting the new containers...")

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface(
            local_ip="C::1/120",
            remote_ip="C::2",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface(
            local_ip="B::1/120",
            remote_ip="B::2",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D4:: next D2:: next D3::")

        c1.vppctl_exec(
            "sr localsid prefix D::/64 behavior end.m.gtp6.d.di D4::/64")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec("sr localsid prefix D4::/64 behavior end.m.gtp6.e")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "B::2", "D::2/128")

        print("Waiting...")
        time.sleep(30)

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IPv6(src="C::2", dst="D::2") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="error_indication", S=1, teid=200, seq=300)/
             IE_TEIDI(TEIDI=65535)/IE_GSNAddress(address="1.1.1.1")/
             IE_PrivateExtension(extention_value="z"))

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_gtp6_drop_in_ipv6(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        print("Deleting the old containers...")
        time.sleep(30)
        print("Starting the new containers...")

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface(
            local_ip="C::1/120",
            remote_ip="C::2",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface(
            local_ip="B::1/120",
            remote_ip="B::2",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D4:: next D2:: next D3::")

        c1.vppctl_exec(
            "sr localsid prefix D::/64 behavior end.m.gtp6.d.di D4::/64")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec("sr localsid prefix D4::/64 behavior end.m.gtp6.e")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "B::2", "D::2/128")

        print("Waiting...")
        time.sleep(30)

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IPv6(src="C::2", dst="D::2") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="g_pdu", teid=200) /
             IPv6(src="2001::1", dst="2002::1") /
             ICMPv6EchoRequest())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_gtp6_drop_in_ipv6_5g(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        print("Deleting the old containers...")
        time.sleep(30)
        print("Starting the new containers...")

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface(
            local_ip="C::1/120",
            remote_ip="C::2",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface(
            local_ip="B::1/120",
            remote_ip="B::2",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D4:: next D2:: next D3::")

        c1.vppctl_exec(
            "sr localsid prefix D::/64 behavior end.m.gtp6.d.di D4::/64")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec("sr localsid prefix D4::/64 behavior end.m.gtp6.e")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "B::2", "D::2/128")

        print("Waiting...")
        time.sleep(30)

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IPv6(src="C::2", dst="D::2") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="g_pdu", teid=200) /
             GTPPDUSessionContainer(R=1, QFI=3) /
             IPv6(src="2001::1", dst="2002::1") /
             ICMPv6EchoRequest())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_gtp6(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        print("Deleting the old containers...")
        time.sleep(30)
        print("Starting the new containers...")

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface(
            local_ip="C::1/120",
            remote_ip="C::2",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface4(
            local_ip="1.0.0.2/30",
            remote_ip="1.0.0.1",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D4:: next D2:: next D3::")

        c1.vppctl_exec(
            "sr localsid prefix D::/64 behavior end.m.gtp6.d D4::/64")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec("set ip neighbor pg0 1.0.0.1 aa:bb:cc:dd:ee:22")
        c4.vppctl_exec("sr localsid prefix D4::/64 behavior end.dt4 2")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "1.0.0.1", "172.200.0.1/32")

        print("Waiting...")
        time.sleep(30)

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IPv6(src="C::2", dst="D::2") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="g_pdu", teid=200) /
             IP(src="172.100.0.1", dst="172.200.0.1") /
             ICMP())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_gtp6_5g(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        print("Deleting the old containers...")
        time.sleep(30)
        print("Starting the new containers...")

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface(
            local_ip="C::1/120",
            remote_ip="C::2",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface4(
            local_ip="1.0.0.2/30",
            remote_ip="1.0.0.1",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D4:: next D2:: next D3::")

        c1.vppctl_exec(
            "sr localsid prefix D::/64 behavior end.m.gtp6.d D4::/64")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec("set ip neighbor pg0 1.0.0.1 aa:bb:cc:dd:ee:22")
        c4.vppctl_exec("sr localsid prefix D4::/64 behavior end.dt4 2")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ip_pgroute("pg0", "1.0.0.1", "172.200.0.1/32")

        print("Waiting...")
        time.sleep(30)

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IPv6(src="C::2", dst="D::2") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="g_pdu", teid=200) /
             GTPPDUSessionContainer(R=1, QFI=3) /
             IP(src="172.100.0.1", dst="172.200.0.1") /
             ICMP())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_gtp6_ipv6(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        print("Deleting the old containers...")
        time.sleep(30)
        print("Starting the new containers...")

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface(
            local_ip="C::1/120",
            remote_ip="C::2",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface(
            local_ip="B::1/120",
            remote_ip="B::2",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D4:: next D2:: next D3::")

        c1.vppctl_exec(
            "sr localsid prefix D::/64 behavior end.m.gtp6.d D4::/64")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec("set ip neighbor pg0 B::2 aa:bb:cc:dd:ee:22")
        c4.vppctl_exec("sr localsid prefix D4::/64 behavior end.dt6 2")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ipv6_pgroute("pg0", "B::2", "2002::1/128")

        print("Waiting...")
        time.sleep(30)

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IPv6(src="C::2", dst="D::2") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="g_pdu", teid=200) /
             IPv6(src="2001::1", dst="2002::1") /
             ICMPv6EchoRequest())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_gtp6_ipv6_5g(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        print("Deleting the old containers...")
        time.sleep(30)
        print("Starting the new containers...")

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c2 = self.containers.get(self.get_name(self.instance_names[1]))
        c3 = self.containers.get(self.get_name(self.instance_names[2]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        c1.pg_create_interface(
            local_ip="C::1/120",
            remote_ip="C::2",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")
        c4.pg_create_interface(
            local_ip="B::1/120",
            remote_ip="B::2",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D4:: next D2:: next D3::")

        c1.vppctl_exec(
            "sr localsid prefix D::/64 behavior end.m.gtp6.d D4::/64")

        c2.vppctl_exec("sr localsid address D2:: behavior end")

        c3.vppctl_exec("sr localsid address D3:: behavior end")

        c4.vppctl_exec("set ip neighbor pg0 B::2 aa:bb:cc:dd:ee:22")
        c4.vppctl_exec("sr localsid prefix D4::/64 behavior end.dt6 2")

        c2.set_ipv6_route("eth2", "A2::2", "D3::/128")
        c2.set_ipv6_route("eth1", "A1::1", "C::/120")
        c3.set_ipv6_route("eth2", "A3::2", "D4::/32")
        c3.set_ipv6_route("eth1", "A2::1", "C::/120")
        c4.set_ipv6_pgroute("pg0", "B::2", "2002::1/128")

        print("Waiting...")
        time.sleep(30)

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IPv6(src="C::2", dst="D::2") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="g_pdu", teid=200) /
             GTPPDUSessionContainer(R=1, QFI=3) /
             IPv6(src="2001::1", dst="2002::1") /
             ICMPv6EchoRequest())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)
        c4.enable_trace(10)

        c4.pg_start_capture()

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c4.name))
        for p in c4.pg_read_packets():
            p.show2()

    def test_gtp6_dt(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        print("Deleting the old containers...")
        time.sleep(30)
        print("Starting the new containers...")

        c1 = self.containers.get(self.get_name(self.instance_names[0]))

        c1.pg_create_interface6_name(
            ifname="pg0",
            local_ip="C::1/120",
            remote_ip="C::2",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")

        c1.pg_create_interface4_name(
            ifname="pg1",
            local_ip="1.0.0.2/30",
            remote_ip="1.0.0.1",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")

        c1.vppctl_exec(
            "sr localsid prefix D::/64 behavior end.m.gtp6.dt46 fib-table 0 local-fib-table 0")

        c1.vppctl_exec("set ip neighbor pg1 1.0.0.1 aa:bb:cc:dd:ee:22")
        c1.set_ip_pgroute("pg1", "1.0.0.1", "172.200.0.1/32")

        print("Waiting...")
        time.sleep(30)

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IPv6(src="C::2", dst="D::2") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="g_pdu", teid=200) /
             IP(src="172.100.0.1", dst="172.200.0.1") /
             ICMP())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)

        c1.pg_start_capture_name(ifname="pg1")

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c1.name))
        for p in c1.pg_read_packets():
            p.show2()

    def test_gtp4_dt(self):
        # TESTS:
        # trace add af-packet-input 10
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        self.start_containers()

        print("Deleting the old containers...")
        time.sleep(30)
        print("Starting the new containers...")

        c1 = self.containers.get(self.get_name(self.instance_names[0]))

        c1.pg_create_interface4_name(
            ifname="pg0",
            local_ip="172.16.0.1/30",
            remote_ip="172.16.0.2",
            local_mac="aa:bb:cc:dd:ee:01",
            remote_mac="aa:bb:cc:dd:ee:02")

        c1.pg_create_interface4_name(
            ifname="pg1",
            local_ip="1.0.0.2/30",
            remote_ip="1.0.0.1",
            local_mac="aa:bb:cc:dd:ee:11",
            remote_mac="aa:bb:cc:dd:ee:22")

        c1.vppctl_exec("set sr encaps source addr A1::1")
        c1.vppctl_exec("sr policy add bsid D5:: behavior t.m.gtp4.dt4 fib-table 0")
        c1.vppctl_exec("sr steer l3 172.20.0.1/32 via bsid D5::")

        c1.vppctl_exec("set ip neighbor pg1 1.0.0.1 aa:bb:cc:dd:ee:22")
        c1.set_ip_pgroute("pg1", "1.0.0.1", "172.200.0.1/32")

        print("Waiting...")
        time.sleep(30)

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") /
             IP(src="172.20.0.2", dst="172.20.0.1") /
             UDP(sport=2152, dport=2152) /
             GTP_U_Header(gtp_type="g_pdu", teid=200) /
             IP(src="172.100.0.1", dst="172.200.0.1") /
             ICMP())

        print("Sending packet on {}:".format(c1.name))
        p.show2()

        c1.enable_trace(10)

        c1.pg_start_capture_name(ifname="pg1")

        c1.pg_create_stream(p)
        c1.pg_enable()

        # timeout (sleep) if needed
        print("Sleeping")
        time.sleep(5)

        print("Receiving packet on {}:".format(c1.name))
        for p in c1.pg_read_packets():
            p.show2()

    def status_containers(self):

        print("Instances:")

        for i, name in enumerate(self.instance_names):
            name = self.get_name(name)
            print("\t[{}] {} - {}".format(
                i, name,
                "running" if self.containers.get(name) else "missing"))

        print("Networks:")

        for i, name in enumerate(self.network_names):
            name = self.get_name(name)
            print("\t[{}] {} - {}".format(
                i, name,
                "running" if self.networks.get(name) else "missing"))

    def build_image(self):
        print("VPP Path (build): {}".format(self.vpp_path))
        self.containers.build(self.path, self.vpp_path)

    def release_image(self):
        print("VPP Path (release): {}".format(self.vpp_path))
        instance = self.containers.new("release-build")

        system(
            "docker cp release-build:{}/vpp-package.tgz {}/".format(
                self.vpp_path, self.vpp_path))

        instance.rem()

        self.containers.release(self.path, self.vpp_path)

        system("rm -rf {}/vpp-package.tgz".format(self.vpp_path))

    def vppctl(self, index, command=None):
        if index >= len(self.instance_names):
            return
        name = self.get_name(self.instance_names[index])
        self.logger.error("connecting to: {}".format(name))
        self.containers.vppctl(name, command)

    def bash(self, index):
        if index >= len(self.instance_names):
            return
        name = self.get_name(self.instance_names[index])
        self.logger.error("connecting to: {}".format(name))
        self.containers.bash(name)


def get_args():
    parser = ArgumentParser()

    parser.add_argument("--verbose", choices=['error', 'debug', 'info'])

    parser.add_argument('--image', choices=['debug', 'release'])

    subparsers = parser.add_subparsers()

    p1 = subparsers.add_parser(
        "infra", help="Infrastructure related commands.")

    p1.add_argument(
        "op",
        choices=[
            'stop',
            'start',
            'status',
            'restart',
            'build',
            'release'])

    p1.add_argument("--prefix")
    p1.add_argument("--image")

    p2 = subparsers.add_parser("cmd", help="Instance related commands.")

    p2.add_argument("op", choices=['vppctl', 'bash'])

    p2.add_argument(
        "index",
        type=int,
        help="Container instance index. (./runner.py infra status)")

    p2.add_argument(
        "--command", help="Only vppctl supports this optional argument.")

    p3 = subparsers.add_parser("test", help="Test related commands.")

    p3.add_argument(
        "op",
        choices=[
            "ping",
            "srv6",
            # "tmap",
            # "tmap_5g",
            # "tmap_ipv6",
            # "tmap_ipv6_5g",
            "gtp4",
            "gtp4_usid",
            "gtp4_5g",
            "gtp4_echo",
            "gtp4_reply",
            "gtp4_error",
            "gtp4_ipv6",
            "gtp4_ipv6_5g",
            "gtp6_drop_in",
            "gtp6_drop_in_5g",
            "gtp6_drop_in_echo",
            "gtp6_drop_in_reply",
            "gtp6_drop_in_error",
            "gtp6_drop_in_ipv6",
            "gtp6_drop_in_ipv6_5g",
            "gtp6",
            "gtp6_5g",
            "gtp6_ipv6",
            "gtp6_ipv6_5g",
            "gtp6_dt",
            "gtp4_dt"])

    args = parser.parse_args()
    if not hasattr(args, "op") or not args.op:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return vars(args)


def main(op=None, prefix=None, verbose=None,
         image=None, index=None, command=None):

    if verbose:
        basicConfig(level=verbose_levels[verbose])

    if image == 'release':
        image = "srv6m-release-image"
    elif image == 'debug':
        image = "srv6m-image"
    else:
        image = "srv6m-image"

    print("Target image: {}".format(image))

    program = Program(image, prefix)

    try:
        if op == 'build':
            program.build_image()
        elif op == 'release':
            program.release_image()
        elif op == 'stop':
            program.stop_containers()
        elif op == 'start':
            program.start_containers()
        elif op == 'status':
            program.status_containers()
        elif op == 'vppctl':
            program.vppctl(index, command)
        elif op == 'bash':
            program.bash(index)
        elif op == 'ping':
            program.test_ping()
        elif op == 'srv6':
            program.test_srv6()
        # elif op == 'tmap':
        #    program.test_tmap()
        # elif op == 'tmap_5g':
        #    program.test_tmap_5g()
        # elif op == 'tmap_ipv6':
        #    program.test_tmap_ipv6()
        # elif op == 'tmap_ipv6_5g':
        #    program.test_tmap_ipv6_5g()
        elif op == 'gtp4':
            program.test_gtp4()
        elif op == 'gtp4_usid':
            program.test_gtp4_usid()
        elif op == 'gtp4_5g':
            program.test_gtp4_5g()
        elif op == 'gtp4_echo':
            program.test_gtp4_echo()
        elif op == 'gtp4_reply':
            program.test_gtp4_reply()
        elif op == 'gtp4_error':
            program.test_gtp4_error()
        elif op == 'gtp4_ipv6':
            program.test_gtp4_ipv6()
        elif op == 'gtp4_ipv6_5g':
            program.test_gtp4_ipv6_5g()
        elif op == 'gtp6_drop_in':
            program.test_gtp6_drop_in()
        elif op == 'gtp6_drop_in_5g':
            program.test_gtp6_drop_in_5g()
        elif op == 'gtp6_drop_in_echo':
            program.test_gtp6_drop_in_echo()
        elif op == 'gtp6_drop_in_reply':
            program.test_gtp6_drop_in_reply()
        elif op == 'gtp6_drop_in_error':
            program.test_gtp6_drop_in_error()
        elif op == 'gtp6_drop_in_ipv6':
            program.test_gtp6_drop_in_ipv6()
        elif op == 'gtp6_drop_in_ipv6_5g':
            program.test_gtp6_drop_in_ipv6_5g()
        elif op == 'gtp6':
            program.test_gtp6()
        elif op == 'gtp6_5g':
            program.test_gtp6_5g()
        elif op == 'gtp6_ipv6':
            program.test_gtp6_ipv6()
        elif op == 'gtp6_ipv6_5g':
            program.test_gtp6_ipv6_5g()
        elif op == 'gtp6_dt':
            program.test_gtp6_dt()
        elif op == 'gtp4_dt':
            program.test_gtp4_dt()

    except Exception:
        program.logger.exception("")
        rc = 1
    else:
        rc = 0

    return rc


if __name__ == "__ma