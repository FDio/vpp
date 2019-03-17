#!/usr/bin/env python3

from os.path import dirname, realpath, split, join, \
        isdir
from os import remove, system, mkdir
from logging import getLogger, basicConfig, DEBUG, \
        INFO, ERROR
from argparse import ArgumentParser
from subprocess import Popen, run
from atexit import register
import sys

from jinja2 import Environment, FileSystemLoader
from docker.errors import NotFound, APIError
from docker import from_env
from scapy.all import *


verbose_levels = {
    'error': ERROR,
    'debug': DEBUG,
    'info': INFO}


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
        if not isdir(temp):
            mkdir(temp)

        ref = client.containers.run(detach=True,
                remove=True, auto_remove=True,
                image=image, name=name,
                privileged=True,
                volumes={ temp: {
                    'bind': '/mnt',
                    'mode': 'rw'
                    }})

        # TODO: bug if container exits, we don't know about it
        #       we should test if it is still running
        # hack disconnect all default networks
        obj = cls(ref, name)
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

    def bash_exec(self, cmd):
        pass

    def setup_host_interface(self, name, ip):
        self.vppctl_exec("create host-interface name {}".format(name))
        self.vppctl_exec("set int ip addr host-{} {}".format(name, ip))
        self.vppctl_exec("set int state host-{} up".format(name))


    def pg_create_interface(self, mac, ip):
        self.vppctl_exec("create packet-generator interface pg0")
        self.vppctl_exec("set int mac address pg0 {}".format(mac))
        self.vppctl_exec("set int ip addr pg0 {}".format(ip))

    def pg_enable(self):
        # start packet generator
        self.vppctl_exec("packet-generator enable")

    def pg_create_stream(self, stream):

        #if not type(stream) == list:
        #    stream = list(stream)

        wrpcap(self.pg_input_file, stream) 
        self.vppctl_exec("packet-generator new name pg-stream node ethernet-input pcap {}".format(
            self.pg_input_file_in))

    def pg_capture_packets(self):
        self.vppctl_exec("packet-generator capture pg0 pcap {}".format(
            self.pg_output_file_in))
        # sleep ? or read until you get the desired number of packets ?
        return rdpcap(self.pg_output_file)

    def set_ipv6_route(self, out_if_name, next_hop_ip, subnet):
        self.vppctl_exec("ip route add {} via host-{} {}".format(
            subnet, out_if_name, next_hop_ip))

    def set_ipv6_default_route(self, out_if_name, next_hop_ip):
        self.vppctl_exec("ip route add ::/0 via host-{} {}".format(
            out_if_name, next_hop_ip))


class Containers(object):

    def __init__(self, client, image):
        self.client = client
        self.image = image

    def tmp_render(self, path, template, kwargs):

        with open(path, "w") as fo:
            fo.write(template.render(**kwargs))

        register(lambda : remove(path))

    def build(self, path, vpp_path):
        env = Environment(
                loader=FileSystemLoader(path),
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

    def bash(self, name, command=None):
        container = self.get(name)
        if not command:
            container.bash()
        else:
            print(container.bash_exec(command).decode())



class Network(object):

    def __init__(self, ref, name):
        self._name = name
        self._ref = ref

    @property
    def name(self):
        return self._name

    @classmethod
    def new(cls, client, name):
        ref = client.networks.create(
                name, driver="bridge",
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

    image = "ietf104-image"

    name_prefix = "hck"

    # TODO: add description to these instances
    # for exmaple what the vpp is supposed to be
    # in our topoloty overview

    instance_names = [
        "vpp-1",
        "vpp-2",
        "vpp-3",
        "vpp-4"
        ]

    network_names = [
        "net-1", 
        "net-2",
        "net-3",
        ]

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
        return split(split(self.path)[0])[0]

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

        networks = list()

        for name in self.network_names:
            networks.append(self.networks.new(self.get_name(name)))

        n1, n2, n3 = networks

        instances = list()

        for name in self.instance_names:
            instances.append(self.containers.new(self.get_name(name)))

        c1, c2, c3, c4 = instances

        # setup packet generator interfaces
        c1.pg_create_interface(ip="C::1/120", mac="aa:bb:cc:dd:ee:01")
        c4.pg_create_interface(ip="B::1/120", mac="aa:bb:cc:dd:ee:04")

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

    def test_ping(self):
        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        c1 = self.containers.get(self.get_name(self.instance_names[0]))
        c4 = self.containers.get(self.get_name(self.instance_names[-1]))

        p = (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01")/
             IPv6(src="C::1", dst="B::1")/ICMPv6EchoRequest())

        p.show2()

        c1.pg_create_stream(p)
        c4.pg_enable()
        c1.pg_enable()

        for p in c4.pg_capture_packets():
            p.show2()

    def status_containers(self):

        print("Instances:")

        for i, name in enumerate(self.instance_names):
            name = self.get_name(name)
            print("\t[{}] {} - {}".format(i, name,
                "running" if self.containers.get(name) else "missing"))

        print("Networks:")

        for i, name in enumerate(self.network_names):
            name = self.get_name(name)
            print("\t[{}] {} - {}".format(i, name,
                "running" if self.networks.get(name) else "missing"))

    def restart_containers(self):
        self.stop_containers()
        self.start_containers()

    def build_image(self):
        # TODO: build process should be optimized (speed and size)
        self.containers.build(self.path, self.vpp_path)

    def vppctl(self, index, command=None):
        if index >= len(self.instance_names):
            return
        name = self.get_name(
            self.instance_names[index])
        self.logger.error("connecting to: {}".format(name))
        self.containers.vppctl(name, command)

    def bash(self, index, command=None):
        if index >= len(self.instance_names):
            return
        name = self.get_name(
            self.instance_names[index])
        self.logger.error("connecting to: {}".format(name))
        self.containers.bash(name, command)


def get_args():
    parser = ArgumentParser()

    parser.add_argument("--verbose", choices=[
        'error', 'debug', 'info'])

    subparsers = parser.add_subparsers()

    p1 = subparsers.add_parser("infra",
            help="Infrastructure related commands.")

    p1.add_argument("op", choices=[
        'stop', 'start', 'status', 'restart', 'build'])
    
    p1.add_argument("--prefix")
    p1.add_argument("--image")

    p2 = subparsers.add_parser("cmd",
            help="Instance related commands.")

    p2.add_argument("op", choices=[
        'vppctl', 'bash'])

    p2.add_argument("index", type=int,
            help="Container instance index. (./runner.py infra status)")

    p2.add_argument("--command")

    p3 = subparsers.add_parser("test",
            help="Test related commands.")

    p3.add_argument("op", choices=[
        "ping"])

    return vars(parser.parse_args())


def main(op=None, image=None, prefix=None, verbose=None, index=None, command=None):

    if verbose:
        basicConfig(level=verbose_levels[verbose])

    program = Program(image, prefix)

    # TODO: return help msg
    if op is None:
        return 1

    try:
        if op == 'build':
            program.build_image()
        elif op == 'stop':
            program.stop_containers()
        elif op == 'start':
            program.start_containers()
        elif op == 'status':
            program.status_containers()
        elif op == 'restart':
            program.restart_containers()
        elif op == 'vppctl':
            program.vppctl(index, command)
        elif op == 'bash':
            program.bash(index, command)
        elif op == 'ping':
            program.test_ping()

    except Exception:
        program.logger.exception("")
        rc = 1
    else:
        rc = 0

    return rc


if __name__ == "__main__":
    sys.exit(main(**get_args()))

