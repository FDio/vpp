//
// VPP C++ API example
//
// The uplink is the 1st interface (sw_if_index is 1) and is set
// to 10.10.10.10/24 The uplink gateway is 10.10.10.1 The IPsec tunnel is set
// between 10.10.10.10 and 10.20.20.20 The protected subnet is 192.168.0.0/24
// VRF 1 is for uplink ingress
// VRF 2 is IPsec egress (clear -> cipher)
// VRF 3 is IPsec ingress (cipher -> clear)
//
// The following examples must be run with VPP in the following state:
//   ip table add 1             # VRF 1
//   ip table add 2             # VRF 2
//   ip table add 3             # VRF 3
//   loop create                # loop0 is used as uplink with sw_if_index=1
//   set int ip table loop0 1   # VRF 1 is ingress
//   set int state loop0 up
//
// Then the API will configure VPP similar to this:
//   # configure uplink address
//   set int addr loop0 10.10.10.10/24
//   # create the IP-IP tunnel
//   create ipip tunnel src 10.10.10.1 dst 10.20.20.20 outer-table-id 2
//   # use VRF-3 as IPsec ingress VRF (cipher -> clear)
//   set int ip table ipip0 3
//   set int unnum ipip0 use loop0
//   set int state ipip0 up
//   ipsec sa add 20 spi 200 crypto-key 01234567890123456789012345678901
//     crypto-alg aes-cbc-128 integ-key 01234567890123456789 integ-alg sha1-96
//     use-anti-replay udp-encap
//   ipsec sa add 30 spi 300 crypto-key 01234567890123456789012345678901
//     crypto-alg aes-cbc-128 integ-key 01234567890123456789 integ-alg sha1-96
//     use-anti-replay udp-encap
//   # protect IP-IP with IPsec
//   ipsec tunnel protect ipip0 sa-in 30 sa-out 20
//   # subnet to route through IPsec (clear -> cipher)
//   ip route add table 1 192.168.0.0/24 via ipip0
//   # default route for IPsec packets after encapsulation (clear -> cipher)
//   ip route add table 20.0.0.0/0 via 10.10.10.1 loop0
//   # default route for clear-text packets after decapsulation
//   # (cipher -> clear)
//   ip route add table 30.0.0.0/0 via 10.10.10.1 loop0
//
#include <iostream>
#include <algorithm>
#include <vapi/vapi.hpp>
#include <vapi/vpe.api.vapi.hpp>
DEFINE_VAPI_MSG_IDS_VPE_API_JSON
#include <vapi/interface.api.vapi.hpp>
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON
#include <vapi/ip.api.vapi.hpp>
DEFINE_VAPI_MSG_IDS_IP_API_JSON
#include <vapi/ipip.api.vapi.hpp>
DEFINE_VAPI_MSG_IDS_IPIP_API_JSON
#include <vapi/ipsec.api.vapi.hpp>
DEFINE_VAPI_MSG_IDS_IPSEC_API_JSON

template <typename MyRequest>
static auto &
execute (vapi::Connection &con, MyRequest &req)
{
  // send the command to VPP
  auto err = req.execute ();
  if (VAPI_OK != err)
    throw std::runtime_error ("execute()");
  // active-wait for command result
  do
    {
      err = con.wait_for_response (req);
    }
  while (VAPI_EAGAIN == err);
  if (VAPI_OK != err)
    throw std::runtime_error ("wait_for_response()");
  // verify the reply error code
  auto &rmp = req.get_response ().get_payload ();
  if (0 != rmp.retval)
    throw std::runtime_error ("wrong return code");
  return rmp;
}

static void
route_add (vapi::Connection &con, const int vrf, const unsigned char prefix[4],
	   const int plen, const int sw_if_index, const unsigned char nh[4])
{
  std::cout << "Adding route..." << std::endl;
  // ip route add table <vrf> <prefix>/<plen> via <nh> <sw_if_index>
  vapi::Ip_route_add_del route (con,
				1); // cf. src/vnet/ip/ip.api:ip_route_add_del
				    // - we allocate space for 1 path (nh)
  auto &mp = route.get_request ().get_payload ();
  mp.is_add = true;
  mp.is_multipath = false;
  mp.route.table_id = vrf;
  mp.route.prefix.address.af = ADDRESS_IP4;
  std::copy (prefix, prefix + 4, mp.route.prefix.address.un.ip4);
  mp.route.prefix.len = plen;
  mp.route.n_paths =
    1; // 1 path, must match allocation in route declaration above
  // cf. src/vnet/fib/fib_types.api:fib_path
  mp.route.paths[0].sw_if_index = sw_if_index;
  mp.route.paths[0].proto = FIB_API_PATH_NH_PROTO_IP4;
  std::copy (nh, nh + 4, mp.route.paths[0].nh.address.ip4);
  execute (con, route);
}

static void
ipsec_sa_add (vapi::Connection &con, const int id, const int spi)
{
  std::cout << "Adding SA " << id << "..." << std::endl;
  // ipsec sa add <id> spi <spi> crypto-key 01234567890123456789012345678901
  // crypto-alg aes-cbc-128 integ-key 01234567890123456789 integ-alg sha1-96
  // use-anti-replay udp-encap
  vapi::Ipsec_sad_entry_add_del_v2 ipsec (
    con); // cf. src/vnet/ipsec/ipsec.api:ipsec_sad_entry_add_del_v2
  auto &mp = ipsec.get_request ().get_payload ();
  mp.is_add = true;
  // cf. src/vnet/ipsec/ipsec_types.api:ipsec_sad_entry_v2
  mp.entry.sad_id = id; // user-defined SA id
  mp.entry.spi = spi;
  mp.entry.protocol = IPSEC_API_PROTO_ESP;
  mp.entry.crypto_algorithm = IPSEC_API_CRYPTO_ALG_AES_CBC_128;
  const char key[] =
    "\x01\x23\x45\x67\x89\x01\x23\x45\x67\x89\x01\x23\x45\x67\x89\x01";
  // cf. src/vnet/ipsec/ipsec_types.api:key
  mp.entry.crypto_key.length = sizeof (key) - 1;
  std::copy (key, key + sizeof (key) - 1, mp.entry.crypto_key.data);
  mp.entry.integrity_algorithm = IPSEC_API_INTEG_ALG_SHA1_96;
  mp.entry.integrity_key.length = sizeof (key) - 1;
  std::copy (key, key + sizeof (key) - 1, mp.entry.integrity_key.data);
  mp.entry.flags = (vapi_enum_ipsec_sad_flags) (
    IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY | IPSEC_API_SAD_FLAG_UDP_ENCAP);
  mp.entry.udp_src_port = 4500;
  mp.entry.udp_dst_port = 4500;
  execute (con, ipsec);
}

int
main ()
{
  // Connect to VPP: client name, API prefix, max outstanding request, response
  // queue size
  std::cout << "Connecting to VPP..." << std::endl;
  vapi::Connection con;
  auto err = con.connect ("example_client", nullptr, 32, 32);
  if (VAPI_OK != err)
    throw std::runtime_error ("connection to VPP failed");

  try
    {

      std::cout << "Configuring address..." << std::endl;
      {
	// set int addr <uplink> 10.10.10.10/24
	vapi::Sw_interface_add_del_address addr (
	  con); // cf. src/vnet/interface.api:sw_interface_add_del_address
	auto &mp = addr.get_request ().get_payload ();
	mp.sw_if_index = 1; // uplink
	mp.is_add = true;
	mp.prefix.address.af = ADDRESS_IP4;
	const char ip[] = { 0x0a, 0x0a, 0x0a, 0x0a }; // 10.10.10.10
	std::copy (ip, ip + 4, mp.prefix.address.un.ip4);
	mp.prefix.len = 24;
	execute (con, addr);
      }

      std::cout << "Creating IP-IP tunnel..." << std::endl;
      unsigned ipip_sw_if_index;
      {
	// create ipip tunnel src 10.10.10.1 dst 10.20.20.20 outer-table-id 2
	vapi::Ipip_add_tunnel ipip (
	  con); // cf. src/vnet/ipip/ipip.api:ipip_add_tunnel
	auto &mp = ipip.get_request ().get_payload ();
	mp.tunnel.instance = ~0;
	mp.tunnel.src.af = ADDRESS_IP4;
	const char src[] = { 0x0a, 0x0a, 0x0a, 0x0a }; // 10.10.10.10
	std::copy (src, src + 4, mp.tunnel.src.un.ip4);
	mp.tunnel.dst.af = ADDRESS_IP4;
	const char dst[] = { 0x0a, 0x14, 0x14, 0x14 }; // 10.20.20.20
	std::copy (dst, dst + 4, mp.tunnel.dst.un.ip4);
	mp.tunnel.table_id =
	  2; // VRF 2 - encapsulated (ciphered) packets should be lookup'ed in
	     // VRF 2 to determine path
	auto &rmp = execute (con, ipip);
	ipip_sw_if_index =
	  rmp.sw_if_index; // save ipip tunnel index for later use
      }

      std::cout << "Moving IP-IP tunnel to VRF 3..." << std::endl;
      {
	// set int ip table ipip0 3
	vapi::Sw_interface_set_table table (
	  con); // cf. src/vnet/interface.api:sw_interface_set_table
	auto &mp = table.get_request ().get_payload ();
	mp.sw_if_index = ipip_sw_if_index;
	mp.vrf_id = 3; // VRF 3 - decapsulated (deciphered) packets should be
		       // lookup'ed in VRF 3 to determine path
	execute (con, table);
      }

      std::cout << "Configuring IP-IP tunnel as unnumbered..." << std::endl;
      {
	// set int unnum ipip0 use <uplink>
	vapi::Sw_interface_set_unnumbered unnum (
	  con); // cf. src/vnet/interface.api:sw_interface_set_unnumbered
	auto &mp = unnum.get_request ().get_payload ();
	mp.sw_if_index = 1; // uplink
	mp.unnumbered_sw_if_index = ipip_sw_if_index;
	execute (con, unnum);
      }

      std::cout << "Setting IP-IP tunnel up..." << std::endl;
      {
	// set int state ipip0 up
	vapi::Sw_interface_set_flags flags (
	  con); // cf. src/vnet/interface.api:sw_interface_set_flags
	auto &mp = flags.get_request ().get_payload ();
	mp.sw_if_index = ipip_sw_if_index;
	mp.flags = IF_STATUS_API_FLAG_ADMIN_UP;
	execute (con, flags);
      }

      // ipsec sa add 20 spi 200 crypto-key 01234567890123456789012345678901
      // crypto-alg aes-cbc-128 integ-key 01234567890123456789 integ-alg
      // sha1-96 use-anti-replay udp-encap
      ipsec_sa_add (con, 20, 200);

      // ipsec sa add 30 spi 300 crypto-key 01234567890123456789012345678901
      // crypto-alg aes-cbc-128 integ-key 01234567890123456789 integ-alg
      // sha1-96 use-anti-replay udp-encap
      ipsec_sa_add (con, 30, 300);

      std::cout << "Protecting IP-IP tunnel..." << std::endl;
      {
	// ipsec tunnel protect ipip0 sa-in 30 sa-out 20
	vapi::Ipsec_tunnel_protect_update tun (
	  con, 1); // cf. src/vnet/ipsec/ipsec.api:ipsec_tunnel_protect_update
		   // - we allocate space for 1 sa_in
	auto &mp = tun.get_request ().get_payload ();
	// cf. src/vnet/ipsec/ipsec.api:ipsec_tunnel_protect
	mp.tunnel.sw_if_index = ipip_sw_if_index;
	mp.tunnel.sa_out = 20;
	mp.tunnel.n_sa_in =
	  1; // 1 SA, must match allocation in declaration above
	mp.tunnel.sa_in[0] = 30;
	execute (con, tun);
      }

      // add route for clear-text packets to be encrypted
      // ip route add table 1 192.168.0.0/24 via ipip0
      route_add (con,
		 1, // VRF 1
		 (const unsigned char[]){ 192, 168, 0, 0 },
		 24,			     // 192.168.0.0/24
		 ipip_sw_if_index,	     // ipip0
		 (const unsigned char[]){}); // 0

      // add default route for encrypted packets (clear -> ciphered)
      // ip route add table 2 0.0.0.0/0 via 10.10.10.1 <uplink>
      route_add (con,
		 2,					    // VRF 2
		 (const unsigned char[]){}, 0,		    // 0.0.0.0/0
		 1,					    // <uplink>
		 (const unsigned char[]){ 10, 10, 10, 1 }); // 10.0.0.1

      // add default route for decrypted packets (ciphered -> clear)
      // ip route add table 3 0.0.0.0/0 via 10.10.10.1 <uplink>
      route_add (con,
		 3,					    // VRF 3
		 (const unsigned char[]){}, 0,		    // 0.0.0.0/0
		 1,					    // <uplink>
		 (const unsigned char[]){ 10, 10, 10, 1 }); // 10.0.0.1
    }
  catch (...)
    {
      std::cerr << "Failure" << std::endl;
      con.disconnect ();
      return 1;
    }

  con.disconnect ();
  std::cerr << "Success" << std::endl;
  return 0;
}
