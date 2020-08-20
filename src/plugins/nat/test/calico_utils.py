
from vpp_object import VppObject


class VppCalicoEndpoint(object):
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def encode(self):
        return {'addr': self.ip,
                'port': self.port}

    def __str__(self):
        return ("%s:%d" % (self.ip, self.port))


class VppCalicoEndpointTuple(object):
    def __init__(self, src, dst):
        self.src = src
        self.dst = dst

    def encode(self):
        return {'src_ep': self.src.encode(),
                'dst_ep': self.dst.encode()}

    def __str__(self):
        return ("%s->%s" % (self.src, self.dst))


def find_calico_translation(test, id):
    ts = test.vapi.calico_translation_dump()
    for t in ts:
        if id == t.translation.id:
            return True
    return False


class VppCalicoTranslation(VppObject):

    def __init__(self, test, vip, iproto, paths, flags):
        self._test = test
        self.vip = vip
        self.iproto = iproto,
        self.paths = paths
        self.flags = flags
        self.encoded_paths = []
        for path in self.paths:
            self.encoded_paths.append(path.encode())

    def add_vpp_config(self):
        r = self._test.vapi.calico_translation_update(
            {'vip': self.vip.encode(),
             'ip_proto': self.iproto[0],
             'n_paths': len(self.paths),
             'paths': self.encoded_paths,
             'flags': self.flags})
        self._test.registry.register(self, self._test.logger)
        self.id = r.id

    def modify_vpp_config(self, paths):
        self.paths = paths
        self.encoded_paths = []
        for path in self.paths:
            self.encoded_paths.append(path.encode())

        r = self._test.vapi.calico_translation_update(
            {'vip': self.vip.encode(),
             'ip_proto': self.iproto[0],
             'n_paths': len(self.paths),
             'paths': self.encoded_paths})
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.calico_translation_del(self.id)

    def query_vpp_config(self):
        return find_calico_translation(self._test, self.id)

    def object_id(self):
        return ("calico-translation-%s" % (self.vip))

    def get_stats(self):
        c = self._test.statistics.get_counter("/net/calico-translation")
        return c[0][self.id]
