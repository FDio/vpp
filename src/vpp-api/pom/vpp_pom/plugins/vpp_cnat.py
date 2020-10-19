from scapy.layers.inet import UDP, TCP

from vpp_pom.vpp_object import VppObject
from vpp_papi import VppEnum


class VppCNatTranslation(VppObject):

    def __init__(self, vclient, iproto, vip, paths):
        self._vclient = vclient
        self.vip = vip
        self.iproto = iproto
        self.paths = paths
        self.encoded_paths = []
        for path in self.paths:
            self.encoded_paths.append(path.encode())

    def __str__(self):
        return ("%s %s %s" % (self.vip, self.iproto, self.paths))

    @property
    def vl4_proto(self):
        ip_proto = VppEnum.vl_api_ip_proto_t
        return {
            UDP: ip_proto.IP_API_PROTO_UDP,
            TCP: ip_proto.IP_API_PROTO_TCP,
        }[self.iproto]

    def add_vpp_config(self):
        r = self._vclient.cnat_translation_update(
            {'vip': self.vip.encode(),
             'ip_proto': self.vl4_proto,
             'n_paths': len(self.paths),
             'paths': self.encoded_paths})
        self._vclient.registry.register(self, self._vclient.logger)
        self.id = r.id

    def modify_vpp_config(self, paths):
        self.paths = paths
        self.encoded_paths = []
        for path in self.paths:
            self.encoded_paths.append(path.encode())

        r = self._vclient.cnat_translation_update(
            {'vip': self.vip.encode(),
             'ip_proto': self.vl4_proto,
             'n_paths': len(self.paths),
             'paths': self.encoded_paths})
        self._vclient.registry.register(self, self._vclient.logger)

    def remove_vpp_config(self):
        self._vclient.cnat_translation_del(id=self.id)

    def query_vpp_config(self):
        for t in self._vclient.cnat_translation_dump():
            if self.id == t.translation.id:
                return t.translation
        return None

    def object_id(self):
        return ("cnat-translation-%s" % (self.vip))

    def get_stats(self):
        c = self._vclient.statistics.get_counter("/net/cnat-translation")
        return c[0][self.id]