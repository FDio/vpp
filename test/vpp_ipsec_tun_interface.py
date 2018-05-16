from vpp_tunnel_interface import VppTunnelInterface


class VppIpsecTunInterface(VppTunnelInterface):
    """
    VPP IPsec Tunnel interface
    """

    def __init__(self, test, parent_if, local_spi,
                 remote_spi, crypto_alg, local_crypto_key, remote_crypto_key,
                 integ_alg, local_integ_key, remote_integ_key):
        super(VppIpsecTunInterface, self).__init__(test, parent_if)
        self.local_spi = local_spi
        self.remote_spi = remote_spi
        self.crypto_alg = crypto_alg
        self.local_crypto_key = local_crypto_key
        self.remote_crypto_key = remote_crypto_key
        self.integ_alg = integ_alg
        self.local_integ_key = local_integ_key
        self.remote_integ_key = remote_integ_key

    def add_vpp_config(self):
        r = self.test.vapi.ipsec_tunnel_if_add_del(
            self.parent_if.local_ip4n, self.parent_if.remote_ip4n,
            self.remote_spi, self.local_spi, self.crypto_alg,
            self.local_crypto_key, self.remote_crypto_key, self.integ_alg,
            self.local_integ_key, self.remote_integ_key)
        self.set_sw_if_index(r.sw_if_index)
        self.generate_remote_hosts()
        self.test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self.test.vapi.ipsec_tunnel_if_add_del(
            self.parent_if.local_ip4n, self.parent_if.remote_ip4n,
            self.remote_spi, self.local_spi, self.crypto_alg,
            self.local_crypto_key, self.remote_crypto_key, self.integ_alg,
            self.local_integ_key, self.remote_integ_key, is_add=0)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "ipsec-tun-if-%d" % self._sw_if_index
