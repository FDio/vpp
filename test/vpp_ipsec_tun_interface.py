from vpp_tunnel_interface import VppTunnelInterface


class VppIpsecTunInterface(VppTunnelInterface):
    """
    VPP IPsec Tunnel interface
    """

    def __init__(self, test, parent_if, local_spi,
                 remote_spi, crypto_alg, local_crypto_key, remote_crypto_key,
                 integ_alg, local_integ_key, remote_integ_key, salt=0,
                 udp_encap=False,
                 is_ip6=False,
                 dst=None):
        super(VppIpsecTunInterface, self).__init__(test, parent_if)
        self.local_spi = local_spi
        self.remote_spi = remote_spi
        self.crypto_alg = crypto_alg
        self.local_crypto_key = local_crypto_key
        self.remote_crypto_key = remote_crypto_key
        self.integ_alg = integ_alg
        self.local_integ_key = local_integ_key
        self.remote_integ_key = remote_integ_key
        self.salt = salt
        if is_ip6:
            self.local_ip = self.parent_if.local_ip6
            self.remote_ip = self.parent_if.remote_ip6
        else:
            self.local_ip = self.parent_if.local_ip4
            self.remote_ip = self.parent_if.remote_ip4
        if dst:
            self.remote_ip = dst
        self.udp_encap = udp_encap

    def add_vpp_config(self):
        r = self.test.vapi.ipsec_tunnel_if_add_del(
            self.local_ip, self.remote_ip,
            self.remote_spi, self.local_spi,
            self.crypto_alg, self.local_crypto_key, self.remote_crypto_key,
            self.integ_alg, self.local_integ_key, self.remote_integ_key,
            salt=self.salt,
            udp_encap=self.udp_encap)
        self.set_sw_if_index(r.sw_if_index)
        self.generate_remote_hosts()
        self.test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self.test.vapi.ipsec_tunnel_if_add_del(
            self.local_ip, self.remote_ip,
            self.remote_spi, self.local_spi,
            self.crypto_alg, self.local_crypto_key, self.remote_crypto_key,
            self.integ_alg, self.local_integ_key, self.remote_integ_key,
            is_add=0)

    def object_id(self):
        return "ipsec-tun-if-%d" % self._sw_if_index
