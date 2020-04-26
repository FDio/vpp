from vpp_object import VppObject
from vpp_papi import VppEnum


class AuthMethod:
    v = {'rsa-sig': 1,
         'shared-key': 2}

    @staticmethod
    def value(key): return AuthMethod.v[key]


class IDType:
    v = {'ip4-addr': 1,
         'fqdn': 2}

    @staticmethod
    def value(key): return IDType.v[key]


class Profile(VppObject):
    """ IKEv2 profile """
    def __init__(self, test, profile_name):
        self.test = test
        self.vapi = test.vapi
        self.profile_name = profile_name

    def add_auth(self, method, data, is_hex=False):
        if isinstance(method, int):
            m = method
        elif isinstance(method, str):
            m = AuthMethod.value(method)
        else:
            raise Exception('unsupported type {}'.format(method))
        self.auth = {'auth_method': m,
                     'data': data,
                     'is_hex': is_hex}

    def add_local_id(self, id_type, data):
        if isinstance(id_type, str):
            t = IDType.value(id_type)
        self.local_id = {'id_type': t,
                         'data': data,
                         'is_local': True}

    def add_remote_id(self, id_type, data):
        if isinstance(id_type, str):
            t = IDType.value(id_type)
        self.remote_id = {'id_type': t,
                          'data': data,
                          'is_local': False}

    def add_local_ts(self, start_addr, end_addr, start_port=0, end_port=0xffff,
                     proto=0):
        self.local_ts = {'is_local': True,
                         'proto': proto,
                         'start_port': start_port,
                         'end_port': end_port,
                         'start_addr': start_addr,
                         'end_addr': end_addr}

    def add_remote_ts(self, start_addr, end_addr, start_port=0,
                      end_port=0xffff, proto=0):
        self.remote_ts = {'is_local': False,
                          'proto': proto,
                          'start_port': start_port,
                          'end_port': end_port,
                          'start_addr': start_addr,
                          'end_addr': end_addr}

    def object_id(self):
        return 'ikev2-profile-%s' % self.profile_name

    def remove_vpp_config(self):
        self.vapi.ikev2_profile_add_del(name=self.profile_name, is_add=False)

    def add_vpp_config(self):
        self.vapi.ikev2_profile_add_del(name=self.profile_name, is_add=True)
        if hasattr(self, 'auth'):
            self.vapi.ikev2_profile_set_auth(name=self.profile_name,
                                             data_len=len(self.auth['data']),
                                             **self.auth)
        if hasattr(self, 'local_id'):
            self.vapi.ikev2_profile_set_id(name=self.profile_name,
                                           data_len=len(self.local_id
                                                        ['data']),
                                           **self.local_id)
        if hasattr(self, 'remote_id'):
            self.vapi.ikev2_profile_set_id(name=self.profile_name,
                                           data_len=len(self.remote_id
                                                        ['data']),
                                           **self.remote_id)
        if hasattr(self, 'local_ts'):
            self.vapi.ikev2_profile_set_ts(name=self.profile_name,
                                           **self.local_ts)
        if hasattr(self, 'remote_ts'):
            self.vapi.ikev2_profile_set_ts(name=self.profile_name,
                                           **self.remote_ts)

    def query_vpp_config(self):
        raise NotImplementedError()
