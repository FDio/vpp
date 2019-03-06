#!/usr/bin/env python3

from os.path import dirname, realpath, split, join
from os import remove, system
from logging import getLogger, basicConfig, DEBUG, \
        INFO, ERROR
from argparse import ArgumentParser
from subprocess import Popen, run
from atexit import register
import sys

from jinja2 import Environment, FileSystemLoader
from docker.errors import NotFound, APIError
from docker import from_env


verbose_levels = {
    'error': ERROR,
    'debug': DEBUG,
    'info': INFO}


class Container(object):

    cmd = "vppctl -s 0:5002"

    def __init__(self, ref, name):
        self._name = name
        self._ref = ref

    @property
    def name(self):
        return self._name

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
        ref = client.containers.run(detach=True,
                remove=True, auto_remove=True,
                image=image, name=name,
                privileged=True)
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

    def vppctl_exec(self, cmd):
        ec, resp = self._ref.exec_run(cmd="{} {}".format(self.cmd, cmd))
        assert(ec == 0)

    def setup_host_interface(self, name, ip):
        self.vppctl_exec("create host-interface name {}".format(name))
        self.vppctl_exec("set int ip addr host-{} {}".format(name, ip))
        self.vppctl_exec("set int state host-{} up".format(name))

    # TODO:
    def setup_pg_interface(self):
        pass

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

    def vppctl(self, name):
        container = self.get(name)
        container.vppctl()


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

        n1.connect(c1)
        n1.connect(c2)

        n2.connect(c2)
        n2.connect(c3)

        n3.connect(c3)
        n3.connect(c4)

        c1.setup_host_interface("eth1", "A1::1/120")
        c2.setup_host_interface("eth1", "A1::2/120")

        c2.setup_host_interface("eth2", "A2::1/120")
        c3.setup_host_interface("eth1", "A2::2/120")

        c3.setup_host_interface("eth2", "A3::1/120")
        c4.setup_host_interface("eth1", "A3::2/120")

        c1.set_ipv6_default_route("eth1", "A1::2")
        c2.set_ipv6_default_route("eth2", "A2::2")
        c3.set_ipv6_default_route("eth1", "A2::1")
        c4.set_ipv6_default_route("eth1", "A3::1")

        c2.set_ipv6_route("eth1", "A1::1", "172.20.0.1/32")
        c3.set_ipv6_route("eth2", "A3::2", "B::1/128")

        # TODO:

        # pg interface on c1 172.20.0.1
        # pg interface on c4 B::1/120

        c4.vppctl_exec("create loopback interface")
        c4.vppctl_exec("set int ip addr loop0 B::1/120")

    def status_containers(self):

        print("containers:")

        for name in self.instance_names:
            name = self.get_name(name)
            print("\t{} - {}".format(name,
                "running" if self.containers.get(name) else "missing"))

        print("networks:")

        for name in self.network_names:
            name = self.get_name(name)
            print("\t{} - {}".format(name,
                "running" if self.networks.get(name) else "missing"))

    def restart_containers(self):
        self.stop_containers()
        self.start_containers()

    def build_image(self):
        # TODO: run make wipe & other commands on the repo
        # before calling docker build
        self.containers.build(self.path, self.vpp_path)

    def vppctl(self, name):
        self.containers.vppctl(name)


def get_args():
    parser = ArgumentParser()

    parser.add_argument("--verbose", choices=[
        'error', 'debug', 'info'])

    subparsers = parser.add_subparsers()

    p1 = subparsers.add_parser("infra")

    p1.add_argument("op", choices=[
        'stop', 'start', 'status', 'restart', 'build'])
    
    p1.add_argument("--prefix")
    p1.add_argument("--image")

    p2 = subparsers.add_parser("ct")

    p2.add_argument("op", choices=[
        'vppctl'])
    p2.add_argument("name")
    
    return vars(parser.parse_args())


def main(op, image=None, prefix=None, verbose=None, name=None):

    if verbose:
        basicConfig(level=verbose_levels[verbose])

    program = Program(image, prefix)

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
            program.vppctl(name)

    except Exception:
        program.logger.exception("")
        rc = 1
    else:
        program.logger.info("operation {} done".format(op))
        rc = 0

    return rc


if __name__ == "__main__":
    sys.exit(main(**get_args()))

