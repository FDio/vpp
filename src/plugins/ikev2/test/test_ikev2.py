import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
from scapy.layers.ipsec import ESP
from scapy.layers.inet import IP, UDP, Ether
from scapy.packet import raw, Raw
from scapy.utils import long_converter
from framework import VppTestCase, VppTestRunner
from vpp_ikev2 import Profile, IDType, AuthMethod
from vpp_papi import VppEnum


KEY_PAD = b"Key Pad for IKEv2"


# defined in rfc3526
# tuple structure is (p, g, key_len)
DH = {
    '2048MODPgr': (long_converter("""
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
    15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"""), 2, 256),

    '3072MODPgr': (long_converter("""
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
    15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
    ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
    ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
    F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
    BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
    43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF"""), 2, 384)
}


class CryptoAlgo(object):
    def __init__(self, name, cipher, mode):
        self.name = name
        self.cipher = cipher
        self.mode = mode
        if self.cipher is not None:
            self.bs = self.cipher.block_size // 8

    def encrypt(self, data, key):
        iv = os.urandom(self.bs)
        encryptor = Cipher(self.cipher(key), self.mode(iv),
                           default_backend()).encryptor()
        return iv + encryptor.update(data) + encryptor.finalize()

    def decrypt(self, data, key, icv=None):
        iv = data[:self.bs]
        ct = data[self.bs:]
        decryptor = Cipher(algorithms.AES(key),
                           modes.CBC(iv),
                           default_backend()).decryptor()
        return decryptor.update(ct) + decryptor.finalize()

    def pad(self, data):
        pad_len = (len(data) // self.bs + 1) * self.bs - len(data)
        data = data + b'\x00' * (pad_len - 1)
        return data + bytes([pad_len])


class AuthAlgo(object):
    def __init__(self, name, mac, mod, key_len, trunc_len=None):
        self.name = name
        self.mac = mac
        self.mod = mod
        self.key_len = key_len
        self.trunc_len = trunc_len or key_len


CRYPTO_ALGOS = {
    'NULL': CryptoAlgo('NULL', cipher=None, mode=None),
    'AES-CBC': CryptoAlgo('AES-CBC', cipher=algorithms.AES, mode=modes.CBC),
    'AES-GCM-16ICV': CryptoAlgo('AES-GCM-16ICV', cipher=algorithms.AES,
                                mode=modes.GCM),
}

AUTH_ALGOS = {
    'NULL': AuthAlgo('NULL', mac=None, mod=None, key_len=0, trunc_len=0),
    'HMAC-SHA1-96': AuthAlgo('HMAC-SHA1-96', hmac.HMAC, hashes.SHA1, 20, 12),
    'SHA2-256-128': AuthAlgo('SHA2-256-128', hmac.HMAC, hashes.SHA256, 32, 16),
    'SHA2-384-192': AuthAlgo('SHA2-384-192', hmac.HMAC, hashes.SHA256, 48, 24),
    'SHA2-512-256': AuthAlgo('SHA2-512-256', hmac.HMAC, hashes.SHA256, 64, 32),
}

PRF_ALGOS = {
    'NULL': AuthAlgo('NULL', mac=None, mod=None, key_len=0, trunc_len=0),
    'PRF_HMAC_SHA2_256': AuthAlgo('PRF_HMAC_SHA2_256', hmac.HMAC,
                                  hashes.SHA256, 32),
}


class IKEv2ChildSA(object):
    def __init__(self, local_ts, remote_ts, spi=None):
        self.spi = spi or os.urandom(4)
        self.local_ts = local_ts
        self.remote_ts = remote_ts


class IKEv2SA(object):
    def __init__(self, test, is_initiator=True, spi=b'\x04' * 8,
                 i_id=None, r_id=None, id_type='fqdn', nonce=None,
                 auth_data=None, local_ts=None, remote_ts=None,
                 auth_method='shared-key', priv_key=None, natt=False):
        self.natt = natt
        if natt:
            self.sport = 4500
            self.dport = 4500
        else:
            self.sport = 500
            self.dport = 500
        self.dh_params = None
        self.test = test
        self.priv_key = priv_key
        self.is_initiator = is_initiator
        nonce = nonce or os.urandom(32)
        self.auth_data = auth_data
        self.i_id = i_id
        self.r_id = r_id
        if isinstance(id_type, str):
            self.id_type = IDType.value(id_type)
        else:
            self.id_type = id_type
        self.auth_method = auth_method
        if self.is_initiator:
            self.rspi = None
            self.ispi = spi
            self.i_nonce = nonce
        else:
            self.rspi = spi
            self.ispi = None
            self.r_nonce = None
        self.child_sas = [IKEv2ChildSA(local_ts, remote_ts)]

    def dh_pub_key(self):
        return self.i_dh_data

    def compute_secret(self):
        priv = self.dh_private_key
        peer = self.r_dh_data
        p, g, l = self.ike_group
        return pow(int.from_bytes(peer, 'big'),
                   int.from_bytes(priv, 'big'), p).to_bytes(l, 'big')

    def generate_dh_data(self):
        # generate DH keys
        if self.is_initiator:
            if self.ike_dh not in DH:
                raise NotImplementedError('%s not in DH group' % self.ike_dh)
            if self.dh_params is None:
                dhg = DH[self.ike_dh]
                pn = dh.DHParameterNumbers(dhg[0], dhg[1])
                self.dh_params = pn.parameters(default_backend())
            priv = self.dh_params.generate_private_key()
            pub = priv.public_key()
            x = priv.private_numbers().x
            self.dh_private_key = x.to_bytes(priv.key_size // 8, 'big')
            y = pub.public_numbers().y
            self.i_dh_data = y.to_bytes(pub.key_size // 8, 'big')

    def complete_dh_data(self):
        self.dh_shared_secret = self.compute_secret()

    def calc_child_keys(self):
        prf = self.ike_prf_alg.mod()
        s = self.i_nonce + self.r_nonce
        c = self.child_sas[0]

        encr_key_len = self.esp_crypto_key_len
        integ_key_len = self.esp_integ_alg.key_len
        salt_len = 0 if integ_key_len else 4

        l = (integ_key_len * 2 +
             encr_key_len * 2 +
             salt_len * 2)
        keymat = self.calc_prfplus(prf, self.sk_d, s, l)

        pos = 0
        c.sk_ei = keymat[pos:pos+encr_key_len]
        pos += encr_key_len

        if integ_key_len:
            c.sk_ai = keymat[pos:pos+integ_key_len]
            pos += integ_key_len
        else:
            c.salt_ei = keymat[pos:pos+salt_len]
            pos += salt_len

        c.sk_er = keymat[pos:pos+encr_key_len]
        pos += encr_key_len

        if integ_key_len:
            c.sk_ar = keymat[pos:pos+integ_key_len]
            pos += integ_key_len
        else:
            c.salt_er = keymat[pos:pos+salt_len]
            pos += salt_len

    def calc_prfplus(self, prf, key, seed, length):
        r = b''
        t = None
        x = 1
        while len(r) < length and x < 255:
            if t is not None:
                s = t
            else:
                s = b''
            s = s + seed + bytes([x])
            t = self.calc_prf(prf, key, s)
            r = r + t
            x = x + 1

        if x == 255:
            return None
        return r

    def calc_prf(self, prf, key, data):
        h = self.ike_integ_alg.mac(key, prf, backend=default_backend())
        h.update(data)
        return h.finalize()

    def calc_keys(self):
        prf = self.ike_prf_alg.mod()
        # SKEYSEED = prf(Ni | Nr, g^ir)
        s = self.i_nonce + self.r_nonce
        self.skeyseed = self.calc_prf(prf, s, self.dh_shared_secret)

        # calculate S = Ni | Nr | SPIi SPIr
        s = s + self.ispi + self.rspi

        prf_key_trunc = self.ike_prf_alg.trunc_len
        encr_key_len = self.ike_crypto_key_len
        tr_prf_key_len = self.ike_prf_alg.key_len
        integ_key_len = self.ike_integ_alg.key_len
        l = (prf_key_trunc +
             integ_key_len * 2 +
             encr_key_len * 2 +
             tr_prf_key_len * 2)
        keymat = self.calc_prfplus(prf, self.skeyseed, s, l)

        pos = 0
        self.sk_d = keymat[:pos+prf_key_trunc]
        pos += prf_key_trunc

        self.sk_ai = keymat[pos:pos+integ_key_len]
        pos += integ_key_len
        self.sk_ar = keymat[pos:pos+integ_key_len]
        pos += integ_key_len

        self.sk_ei = keymat[pos:pos+encr_key_len]
        pos += encr_key_len
        self.sk_er = keymat[pos:pos+encr_key_len]
        pos += encr_key_len

        self.sk_pi = keymat[pos:pos+tr_prf_key_len]
        pos += tr_prf_key_len
        self.sk_pr = keymat[pos:pos+tr_prf_key_len]

    def generate_authmsg(self, prf, packet):
        if self.is_initiator:
            id = self.i_id
            nonce = self.r_nonce
            key = self.sk_pi
        data = bytes([self.id_type, 0, 0, 0]) + id
        id_hash = self.calc_prf(prf, key, data)
        return packet + nonce + id_hash

    def auth_init(self):
        prf = self.ike_prf_alg.mod()
        authmsg = self.generate_authmsg(prf, raw(self.init_req_packet))
        if self.auth_method == 'shared-key':
            psk = self.calc_prf(prf, self.auth_data, KEY_PAD)
            self.auth_data = self.calc_prf(prf, psk, authmsg)
        elif self.auth_method == 'rsa-sig':
            self.auth_data = self.priv_key.sign(authmsg, padding.PKCS1v15(),
                                                hashes.SHA1())
        else:
            raise TypeError('unknown auth method type!')

    def encrypt(self, data):
        data = self.ike_crypto_alg.pad(data)
        return self.ike_crypto_alg.encrypt(data, self.my_cryptokey)

    @property
    def peer_authkey(self):
        if self.is_initiator:
            return self.sk_ar
        return self.sk_ai

    @property
    def my_authkey(self):
        if self.is_initiator:
            return self.sk_ai
        return self.sk_ar

    @property
    def my_cryptokey(self):
        if self.is_initiator:
            return self.sk_ei
        return self.sk_er

    @property
    def peer_cryptokey(self):
        if self.is_initiator:
            return self.sk_er
        return self.sk_ei

    def concat(self, alg, key_len):
        return alg + '-' + str(key_len * 8)

    @property
    def vpp_ike_cypto_alg(self):
        return self.concat(self.ike_crypto, self.ike_crypto_key_len)

    @property
    def vpp_esp_cypto_alg(self):
        return self.concat(self.esp_crypto, self.esp_crypto_key_len)

    def verify_hmac(self, ikemsg):
        integ_trunc = self.ike_integ_alg.trunc_len
        exp_hmac = ikemsg[-integ_trunc:]
        data = ikemsg[:-integ_trunc]
        computed_hmac = self.compute_hmac(self.ike_integ_alg.mod(),
                                          self.peer_authkey, data)
        self.test.assertEqual(computed_hmac[:integ_trunc], exp_hmac)

    def compute_hmac(self, integ, key, data):
        h = self.ike_integ_alg.mac(key, integ, backend=default_backend())
        h.update(data)
        return h.finalize()

    def decrypt(self, data):
        return self.ike_crypto_alg.decrypt(data, self.peer_cryptokey)

    def hmac_and_decrypt(self, ike):
        ep = ike[ikev2.IKEv2_payload_Encrypted]
        self.verify_hmac(raw(ike))
        integ_trunc = self.ike_integ_alg.trunc_len

        # remove ICV and decrypt payload
        ct = ep.load[:-integ_trunc]
        return self.decrypt(ct)

    def generate_ts(self):
        c = self.child_sas[0]
        ts1 = ikev2.IPv4TrafficSelector(
                IP_protocol_ID=0,
                starting_address_v4=c.local_ts['start_addr'],
                ending_address_v4=c.local_ts['end_addr'])
        ts2 = ikev2.IPv4TrafficSelector(
                IP_protocol_ID=0,
                starting_address_v4=c.remote_ts['start_addr'],
                ending_address_v4=c.remote_ts['end_addr'])
        return ([ts1], [ts2])

    def set_ike_props(self, crypto, crypto_key_len, integ, prf, dh):
        if crypto not in CRYPTO_ALGOS:
            raise TypeError('unsupported encryption algo %r' % crypto)
        self.ike_crypto = crypto
        self.ike_crypto_alg = CRYPTO_ALGOS[crypto]
        self.ike_crypto_key_len = crypto_key_len

        if integ not in AUTH_ALGOS:
            raise TypeError('unsupported auth algo %r' % integ)
        self.ike_integ = integ
        self.ike_integ_alg = AUTH_ALGOS[integ]

        if prf not in PRF_ALGOS:
            raise TypeError('unsupported prf algo %r' % prf)
        self.ike_prf = prf
        self.ike_prf_alg = PRF_ALGOS[prf]
        self.ike_dh = dh
        self.ike_group = DH[self.ike_dh]

    def set_esp_props(self, crypto, crypto_key_len, integ):
        self.esp_crypto_key_len = crypto_key_len
        if crypto not in CRYPTO_ALGOS:
            raise TypeError('unsupported encryption algo %r' % crypto)
        self.esp_crypto = crypto
        self.esp_crypto_alg = CRYPTO_ALGOS[crypto]

        if integ not in AUTH_ALGOS:
            raise TypeError('unsupported auth algo %r' % integ)
        self.esp_integ = None if integ == 'NULL' else integ
        self.esp_integ_alg = AUTH_ALGOS[integ]

    def crypto_attr(self, key_len):
        if self.ike_crypto in ['AES-CBC', 'AES-GCM']:
            return (0x800e << 16 | key_len << 3, 12)
        else:
            raise Exception('unsupported attribute type')

    def ike_crypto_attr(self):
        return self.crypto_attr(self.ike_crypto_key_len)

    def esp_crypto_attr(self):
        return self.crypto_attr(self.esp_crypto_key_len)

    def compute_nat_sha1(self, ip, port):
        data = self.ispi + b'\x00' * 8 + ip + (port).to_bytes(2, 'big')
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
        digest.update(data)
        return digest.finalize()


class TemplateResponder(VppTestCase):
    """ responder test template """

    @classmethod
    def setUpClass(cls):
        import scapy.contrib.ikev2 as _ikev2
        globals()['ikev2'] = _ikev2
        super(TemplateResponder, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    @classmethod
    def tearDownClass(cls):
        super(TemplateResponder, cls).tearDownClass()

    def setUp(self):
        super(TemplateResponder, self).setUp()
        self.config_tc()
        self.p.add_vpp_config()
        self.sa.generate_dh_data()

    def create_ike_msg(self, src_if, msg, sport=500, dport=500, natt=False):
        res = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
               IP(src=src_if.remote_ip4, dst=src_if.local_ip4) /
               UDP(sport=sport, dport=dport))
        if natt:
            # insert non ESP marker
            res = res / Raw(b'\x00' * 4)
        return res / msg

    def send_sa_init(self, behind_nat=False):
        tr_attr = self.sa.ike_crypto_attr()
        trans = (ikev2.IKEv2_payload_Transform(transform_type='Encryption',
                 transform_id=self.sa.ike_crypto, length=tr_attr[1],
                 key_length=tr_attr[0]) /
                 ikev2.IKEv2_payload_Transform(transform_type='Integrity',
                 transform_id=self.sa.ike_integ) /
                 ikev2.IKEv2_payload_Transform(transform_type='PRF',
                 transform_id=self.sa.ike_prf_alg.name) /
                 ikev2.IKEv2_payload_Transform(transform_type='GroupDesc',
                 transform_id=self.sa.ike_dh))

        props = (ikev2.IKEv2_payload_Proposal(proposal=1, proto='IKEv2',
                 trans_nb=4, trans=trans))

        if behind_nat:
            next_payload = 'Notify'
        else:
            next_payload = None

        self.sa.init_req_packet = (
                ikev2.IKEv2(init_SPI=self.sa.ispi,
                            flags='Initiator', exch_type='IKE_SA_INIT') /
                ikev2.IKEv2_payload_SA(next_payload='KE', prop=props) /
                ikev2.IKEv2_payload_KE(next_payload='Nonce',
                                       group=self.sa.ike_dh,
                                       load=self.sa.dh_pub_key()) /
                ikev2.IKEv2_payload_Nonce(next_payload=next_payload,
                                          load=self.sa.i_nonce))

        if behind_nat:
            src_nat = self.sa.compute_nat_sha1(b'\x0a\x0a\x0a\x01',
                                               self.sa.sport)
            nat_detection = ikev2.IKEv2_payload_Notify(
                    type='NAT_DETECTION_SOURCE_IP',
                    load=src_nat)
            self.sa.init_req_packet = self.sa.init_req_packet / nat_detection

        ike_msg = self.create_ike_msg(self.pg0, self.sa.init_req_packet,
                                      self.sa.sport, self.sa.dport,
                                      self.sa.natt)
        self.pg0.add_stream(ike_msg)
        self.pg0.enable_capture()
        self.pg_start()
        capture = self.pg0.get_capture(1)
        self.verify_sa_init(capture[0])

    def send_sa_auth(self):
        tr_attr = self.sa.esp_crypto_attr()
        trans = (ikev2.IKEv2_payload_Transform(transform_type='Encryption',
                 transform_id=self.sa.esp_crypto, length=tr_attr[1],
                 key_length=tr_attr[0]) /
                 ikev2.IKEv2_payload_Transform(transform_type='Integrity',
                 transform_id=self.sa.esp_integ) /
                 ikev2.IKEv2_payload_Transform(
                 transform_type='Extended Sequence Number',
                 transform_id='No ESN') /
                 ikev2.IKEv2_payload_Transform(
                 transform_type='Extended Sequence Number',
                 transform_id='ESN'))

        props = (ikev2.IKEv2_payload_Proposal(proposal=1, proto='ESP',
                 SPIsize=4, SPI=os.urandom(4), trans_nb=4, trans=trans))

        tsi, tsr = self.sa.generate_ts()
        plain = (ikev2.IKEv2_payload_IDi(next_payload='IDr',
                 IDtype=self.sa.id_type, load=self.sa.i_id) /
                 ikev2.IKEv2_payload_IDr(next_payload='AUTH',
                 IDtype=self.sa.id_type, load=self.sa.r_id) /
                 ikev2.IKEv2_payload_AUTH(next_payload='SA',
                 auth_type=AuthMethod.value(self.sa.auth_method),
                 load=self.sa.auth_data) /
                 ikev2.IKEv2_payload_SA(next_payload='TSi', prop=props) /
                 ikev2.IKEv2_payload_TSi(next_payload='TSr',
                 number_of_TSs=len(tsi),
                 traffic_selector=tsi) /
                 ikev2.IKEv2_payload_TSr(next_payload='Notify',
                 number_of_TSs=len(tsr),
                 traffic_selector=tsr) /
                 ikev2.IKEv2_payload_Notify(type='INITIAL_CONTACT'))
        encr = self.sa.encrypt(raw(plain))

        trunc_len = self.sa.ike_integ_alg.trunc_len
        plen = len(encr) + len(ikev2.IKEv2_payload_Encrypted()) + trunc_len
        tlen = plen + len(ikev2.IKEv2())

        sk_p = ikev2.IKEv2_payload_Encrypted(next_payload='IDi',
                                             length=plen, load=encr)
        sa_auth = (ikev2.IKEv2(init_SPI=self.sa.ispi, resp_SPI=self.sa.rspi,
                   length=tlen, flags='Initiator', exch_type='IKE_AUTH', id=1))
        sa_auth /= sk_p

        integ_data = raw(sa_auth)
        hmac_data = self.sa.compute_hmac(self.sa.ike_integ_alg.mod(),
                                         self.sa.my_authkey, integ_data)
        sa_auth = sa_auth / Raw(hmac_data[:trunc_len])
        assert(len(sa_auth) == tlen)

        packet = self.create_ike_msg(self.pg0, sa_auth, self.sa.sport,
                                     self.sa.dport, self.sa.natt)
        self.pg0.add_stream(packet)
        self.pg0.enable_capture()
        self.pg_start()
        capture = self.pg0.get_capture(1)
        self.verify_sa_auth(capture[0])

    def get_ike_header(self, packet):
        try:
            ih = packet[ikev2.IKEv2]
        except IndexError as e:
            # this is a workaround for getting IKEv2 layer as both ikev2 and
            # ipsec register for port 4500
            esp = packet[ESP]
            ih = self.verify_and_remove_non_esp_marker(esp)
        return ih

    def verify_sa_init(self, packet):
        ih = self.get_ike_header(packet)

        self.assertEqual(ih.exch_type, 34)
        self.assertTrue('Response' in ih.flags)
        self.assertEqual(ih.init_SPI, self.sa.ispi)
        self.assertNotEqual(ih.resp_SPI, 0)
        self.sa.rspi = ih.resp_SPI
        try:
            sa = ih[ikev2.IKEv2_payload_SA]
            self.sa.r_nonce = ih[ikev2.IKEv2_payload_Nonce].load
            self.sa.r_dh_data = ih[ikev2.IKEv2_payload_KE].load
        except AttributeError as e:
            self.logger.error("unexpected reply: SA/Nonce/KE payload found!")
            raise
        self.sa.complete_dh_data()
        self.sa.calc_keys()
        self.sa.auth_init()

    def verify_and_remove_non_esp_marker(self, packet):
        if self.sa.natt:
            # if we are in nat traversal mode check for non esp marker
            # and remove it
            data = raw(packet)
            self.assertEqual(data[:4], b'\x00' * 4)
            return ikev2.IKEv2(data[4:])
        else:
            return packet

    def verify_udp(self, udp):
        self.assertEqual(udp.sport, self.sa.sport)
        self.assertEqual(udp.dport, self.sa.dport)

    def verify_sa_auth(self, packet):
        ike = self.get_ike_header(packet)
        udp = packet[UDP]
        self.verify_udp(udp)
        plain = self.sa.hmac_and_decrypt(ike)
        self.sa.calc_child_keys()

    def verify_child_sas(self):
        sas = self.vapi.ipsec_sa_dump()
        self.assertEqual(len(sas), 2)
        sa0 = sas[0].entry
        sa1 = sas[1].entry
        c = self.sa.child_sas[0]

        vpp_crypto_alg = self.vpp_enums[self.sa.vpp_esp_cypto_alg]
        self.assertEqual(sa0.crypto_algorithm, vpp_crypto_alg)
        self.assertEqual(sa1.crypto_algorithm, vpp_crypto_alg)

        if self.sa.esp_integ is None:
            vpp_integ_alg = 0
        else:
            vpp_integ_alg = self.vpp_enums[self.sa.esp_integ]
        self.assertEqual(sa0.integrity_algorithm, vpp_integ_alg)
        self.assertEqual(sa1.integrity_algorithm, vpp_integ_alg)

        # verify crypto keys
        self.assertEqual(sa0.crypto_key.length, len(c.sk_er))
        self.assertEqual(sa1.crypto_key.length, len(c.sk_ei))
        self.assertEqual(sa0.crypto_key.data[:len(c.sk_er)], c.sk_er)
        self.assertEqual(sa1.crypto_key.data[:len(c.sk_ei)], c.sk_ei)

        # verify integ keys
        if vpp_integ_alg:
            self.assertEqual(sa0.integrity_key.length, len(c.sk_ar))
            self.assertEqual(sa1.integrity_key.length, len(c.sk_ai))
            self.assertEqual(sa0.integrity_key.data[:len(c.sk_ar)], c.sk_ar)
            self.assertEqual(sa1.integrity_key.data[:len(c.sk_ai)], c.sk_ai)
        else:
            self.assertEqual(sa0.salt.to_bytes(4, 'little'), c.salt_er)
            self.assertEqual(sa1.salt.to_bytes(4, 'little'), c.salt_ei)

    def test_responder(self):
        self.send_sa_init(self.sa.natt)
        self.send_sa_auth()
        self.verify_child_sas()


class Ikev2Params(object):
    def config_params(self, params={}):
        ec = VppEnum.vl_api_ipsec_crypto_alg_t
        ei = VppEnum.vl_api_ipsec_integ_alg_t
        self.vpp_enums = {
                'AES-CBC-128': ec.IPSEC_API_CRYPTO_ALG_AES_CBC_128,
                'AES-CBC-192': ec.IPSEC_API_CRYPTO_ALG_AES_CBC_192,
                'AES-CBC-256': ec.IPSEC_API_CRYPTO_ALG_AES_CBC_256,
                'AES-GCM-16ICV-128':  ec.IPSEC_API_CRYPTO_ALG_AES_GCM_128,
                'AES-GCM-16ICV-192':  ec.IPSEC_API_CRYPTO_ALG_AES_GCM_192,
                'AES-GCM-16ICV-256':  ec.IPSEC_API_CRYPTO_ALG_AES_GCM_256,

                'HMAC-SHA1-96': ei.IPSEC_API_INTEG_ALG_SHA1_96,
                'SHA2-256-128': ei.IPSEC_API_INTEG_ALG_SHA_256_128,
                'SHA2-384-192': ei.IPSEC_API_INTEG_ALG_SHA_384_192,
                'SHA2-512-256': ei.IPSEC_API_INTEG_ALG_SHA_512_256}

        is_natt = 'natt' in params and params['natt'] or False
        self.p = Profile(self, 'pr1')

        if 'auth' in params and params['auth'] == 'rsa-sig':
            auth_method = 'rsa-sig'
            work_dir = os.getenv('BR') + '/../src/plugins/ikev2/test/certs/'
            self.vapi.ikev2_set_local_key(
                    key_file=work_dir + params['server-key'])

            client_file = work_dir + params['client-cert']
            server_pem = open(work_dir + params['server-cert']).read()
            client_priv = open(work_dir + params['client-key']).read()
            client_priv = load_pem_private_key(str.encode(client_priv), None,
                                               default_backend())
            self.peer_cert = x509.load_pem_x509_certificate(
                    str.encode(server_pem),
                    default_backend())
            self.p.add_auth(method='rsa-sig', data=str.encode(client_file))
            auth_data = None
        else:
            auth_data = b'$3cr3tpa$$w0rd'
            self.p.add_auth(method='shared-key', data=auth_data)
            auth_method = 'shared-key'
            client_priv = None

        self.p.add_local_id(id_type='fqdn', data=b'vpp.home')
        self.p.add_remote_id(id_type='fqdn', data=b'roadwarrior.example.com')
        self.p.add_local_ts(start_addr=0x0a0a0a0, end_addr=0x0a0a0aff)
        self.p.add_remote_ts(start_addr=0xa000000, end_addr=0xa0000ff)

        self.sa = IKEv2SA(self, i_id=self.p.remote_id['data'],
                          r_id=self.p.local_id['data'],
                          id_type=self.p.local_id['id_type'], natt=is_natt,
                          priv_key=client_priv, auth_method=auth_method,
                          auth_data=auth_data,
                          local_ts=self.p.remote_ts, remote_ts=self.p.local_ts)

        ike_crypto = ('AES-CBC', 32) if 'ike-crypto' not in params else\
            params['ike-crypto']
        ike_integ = 'HMAC-SHA1-96' if 'ike-integ' not in params else\
            params['ike-integ']
        ike_dh = '2048MODPgr' if 'ike-dh' not in params else params['ike-dh']

        esp_crypto = ('AES-CBC', 32) if 'esp-crypto' not in params else\
            params['esp-crypto']
        esp_integ = 'HMAC-SHA1-96' if 'esp-integ' not in params else\
            params['esp-integ']

        self.sa.set_ike_props(
                crypto=ike_crypto[0], crypto_key_len=ike_crypto[1],
                integ=ike_integ, prf='PRF_HMAC_SHA2_256', dh=ike_dh)
        self.sa.set_esp_props(
                crypto=esp_crypto[0], crypto_key_len=esp_crypto[1],
                integ=esp_integ)


class TestResponderNATT(TemplateResponder, Ikev2Params):
    """ test ikev2 responder - nat traversal """
    def config_tc(self):
        self.config_params(
                {'natt': True})


class TestResponderPsk(TemplateResponder, Ikev2Params):
    """ test ikev2 responder - pre shared key auth """
    def config_tc(self):
        self.config_params()


class TestResponderRsaSign(TemplateResponder, Ikev2Params):
    """ test ikev2 responder - cert based auth """
    def config_tc(self):
        self.config_params({
            'auth': 'rsa-sig',
            'server-key': 'server-key.pem',
            'client-key': 'client-key.pem',
            'client-cert': 'client-cert.pem',
            'server-cert': 'server-cert.pem'})


class Test_IKE_AES_CBC_128_SHA256_128_MODP2048_ESP_AES_CBC_192_SHA_384_192\
        (TemplateResponder, Ikev2Params):
    """
    IKE:AES_CBC_128_SHA256_128,DH=modp2048 ESP:AES_CBC_192_SHA_384_192
    """
    def config_tc(self):
        self.config_params({
            'ike-crypto': ('AES-CBC', 16),
            'ike-integ': 'SHA2-256-128',
            'esp-crypto': ('AES-CBC', 24),
            'esp-integ': 'SHA2-384-192',
            'ike-dh': '2048MODPgr'})


class TestAES_CBC_128_SHA256_128_MODP3072_ESP_AES_GCM_16\
        (TemplateResponder, Ikev2Params):
    """
    IKE:AES_CBC_128_SHA256_128,DH=modp3072 ESP:AES_GCM_16
    """
    def config_tc(self):
        self.config_params({
            'ike-crypto': ('AES-CBC', 32),
            'ike-integ': 'SHA2-256-128',
            'esp-crypto': ('AES-GCM-16ICV', 32),
            'esp-integ': 'NULL',
            'ike-dh': '3072MODPgr'})


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
