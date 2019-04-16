from vpp_tunnel_interface import VppTunnelInterface


class VppIpsecTunInterface(VppTunnelInterface):
    """
    VPP IPsec Tunnel interface
    """

    def __init__(self, test, parent_if, local_spi,
                 remote_spi, crypto_alg, local_crypto_key, remote_crypto_key,
                 integ_alg, local_integ_key, remote_integ_key, salt=0,
                 is_ip6=False):
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

    def add_vpp_config(self):
        r = self.test.vapi.ipsec_tunnel_if_add_del(
            self.local_ip, self.remote_ip,
            self.remote_spi, self.local_spi,
            self.crypto_alg, self.local_crypto_key, self.remote_crypto_key,
            self.integ_alg, self.local_integ_key, self.remote_integ_key,
            salt=self.salt)
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


class VppIpsecGRETunInterface(VppTunnelInterface):
    """
    VPP IPsec GRE Tunnel interface
     this creates headers
       IP / ESP / IP / GRE / payload
     i.e. it's GRE over IPSEC, rather than IPSEC over GRE.
    """

    def __init__(self, test, parent_if, sa_out, sa_in):
        super(VppIpsecGRETunInterface, self).__init__(test, parent_if)
        self.sa_in = sa_in
        self.sa_out = sa_out

    def add_vpp_config(self):
        r = self.test.vapi.ipsec_gre_tunnel_add_del(
            self.parent_if.local_ip4n,
            self.parent_if.remote_ip4n,
            self.sa_out,
            self.sa_in)
        self.set_sw_if_index(r.sw_if_index)
        self.generate_remote_hosts()
        self.test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self.test.vapi.ipsec_gre_tunnel_add_del(
            self.parent_if.local_ip4n,
            self.parent_if.remote_ip4n,
            self.sa_out,
            self.sa_in,
            is_add=0)

    def query_vpp_config(self):
        ts = self.test.vapi.ipsec_gre_tunnel_dump(sw_if_index=0xffffffff)
        for t in ts:
            if t.tunnel.sw_if_index == self._sw_if_index:
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "ipsec-gre-tun-if-%d" % self._sw_if_index
