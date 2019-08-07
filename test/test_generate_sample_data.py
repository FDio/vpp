import binascii
import json
import framework
from framework import VppTestCase, VppTestRunner

# class SwInterfaceDetails(sw_interface_details):
#     pass

def format_mac(mac):
    return ':'.join(['{:02x}'.format(int(mac[x:x+2], 16)) for x in range(0, len(mac), 2)])

class TestGenerateSampleData(VppTestCase):
    """TestGenerateSampleData"""

    @classmethod
    def setUpClass(cls):
        super(TestGenerateSampleData, cls).setUpClass()


    def test_generate_interface_details(self):
        """test_generate_interface_details"""

        # Create lo0, ifindex 1
        self.vapi.create_loopback()
        # Create bvi ifindex 2
        self.vapi.bvi_create(user_instance= 4294967295)
        self.vapi.pg_create_interface(interface_id=10)
        self.vapi.pg_create_interface(interface_id=0)


        rv = self.vapi.sw_interface_dump()
        swiddump = []
        for nt in rv:
            obj = nt._asdict()
            l2_len = obj['l2_address_length']
            obj['l2_address'] = format_mac(binascii.hexlify(obj['l2_address'][:l2_len]))
            obj['interface_name'] = obj['interface_name'].replace('\0','')
            obj['tag'] = obj['tag'].replace('\0', '')
            obj['b_dmac'] = format_mac(binascii.hexlify(obj['b_dmac']))
            obj['b_smac'] = format_mac(binascii.hexlify(obj['b_smac']))
            swiddump.append(obj)

        print(json.dumps(swiddump, indent=4, separators=(',', ': ')))


if __name__ == '__main__':
    framework.main(testRunner=VppTestRunner)
