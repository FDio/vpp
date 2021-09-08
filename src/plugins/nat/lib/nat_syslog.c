/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * @file
 * @brief NAT syslog logging
 */
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip.h>
#include <vnet/syslog/syslog.h>

#include <nat/lib/nat_syslog.h>
#include <nat/lib/inlines.h>

#include <nat/lib/nat_syslog_constants.h>

static inline void
nat_syslog_nat44_apmap (u32 ssubix, u32 sfibix, ip4_address_t * isaddr,
			u16 isport, ip4_address_t * xsaddr, u16 xsport,
			nat_protocol_t proto, u8 is_add,
			ip6_address_t * sv6enc)
{
  syslog_msg_t syslog_msg;
  fib_table_t *fib;

  if (!syslog_is_enabled ())
    return;

  if (syslog_severity_filter_block (APMADD_APMDEL_SEVERITY))
    return;

  syslog_msg_init (&syslog_msg, NAT_FACILITY, APMADD_APMDEL_SEVERITY,
		   NAT_APPNAME, is_add ? APMADD_MSGID : APMDEL_MSGID);

  syslog_msg_sd_init (&syslog_msg, NAPMAP_SDID);
  syslog_msg_add_sd_param (&syslog_msg, SSUBIX_SDPARAM_NAME, "%d", ssubix);
  if (sv6enc)
    {
      syslog_msg_add_sd_param (&syslog_msg, SV6ENC_SDPARAM_NAME, "%U",
			       format_ip6_address, sv6enc);
    }
  else
    {
      fib = fib_table_get (sfibix, FIB_PROTOCOL_IP4);
      syslog_msg_add_sd_param (&syslog_msg, SVLAN_SDPARAM_NAME, "%d",
			       fib->ft_table_id);
    }
  syslog_msg_add_sd_param (&syslog_msg, IATYP_SDPARAM_NAME, IATYP_IPV4);
  syslog_msg_add_sd_param (&syslog_msg, ISADDR_SDPARAM_NAME, "%U",
			   format_ip4_address, isaddr);
  syslog_msg_add_sd_param (&syslog_msg, ISPORT_SDPARAM_NAME, "%d",
			   clib_net_to_host_u16 (isport));
  syslog_msg_add_sd_param (&syslog_msg, XATYP_SDPARAM_NAME, IATYP_IPV4);
  syslog_msg_add_sd_param (&syslog_msg, XSADDR_SDPARAM_NAME, "%U",
			   format_ip4_address, xsaddr);
  syslog_msg_add_sd_param (&syslog_msg, XSPORT_SDPARAM_NAME, "%d",
			   clib_net_to_host_u16 (xsport));
  syslog_msg_add_sd_param (&syslog_msg, PROTO_SDPARAM_NAME, "%d",
			   nat_proto_to_ip_proto (proto));

  syslog_msg_send (&syslog_msg);
}

void
nat_syslog_nat44_apmadd (u32 ssubix, u32 sfibix, ip4_address_t * isaddr,
			 u16 isport, ip4_address_t * xsaddr, u16 xsport,
			 nat_protocol_t proto)
{
  nat_syslog_nat44_apmap (ssubix, sfibix, isaddr, isport, xsaddr, xsport,
			  proto, 1, 0);
}

void
nat_syslog_nat44_apmdel (u32 ssubix, u32 sfibix, ip4_address_t * isaddr,
			 u16 isport, ip4_address_t * xsaddr, u16 xsport,
			 nat_protocol_t proto)
{
  nat_syslog_nat44_apmap (ssubix, sfibix, isaddr, isport, xsaddr, xsport,
			  proto, 0, 0);
}

void
nat_syslog_dslite_apmadd (u32 ssubix, ip6_address_t * sv6enc,
			  ip4_address_t * isaddr, u16 isport,
			  ip4_address_t * xsaddr, u16 xsport,
			  nat_protocol_t proto)
{
  nat_syslog_nat44_apmap (ssubix, 0, isaddr, isport, xsaddr, xsport,
			  proto, 1, sv6enc);
}

void
nat_syslog_dslite_apmdel (u32 ssubix, ip6_address_t * sv6enc,
			  ip4_address_t * isaddr, u16 isport,
			  ip4_address_t * xsaddr, u16 xsport,
			  nat_protocol_t proto)
{
  nat_syslog_nat44_apmap (ssubix, 0, isaddr, isport, xsaddr, xsport,
			  proto, 0, sv6enc);
}

static inline void
nat_syslog_nat64_sess (u32 sfibix, ip6_address_t * isaddr, u16 isport,
		       ip4_address_t * xsaddr, u16 xsport,
		       ip4_address_t * xdaddr, u16 xdport,
		       nat_protocol_t proto, u8 is_add)
{
  syslog_msg_t syslog_msg;
  fib_table_t *fib;

  if (!syslog_is_enabled ())
    return;

  if (syslog_severity_filter_block (SADD_SDEL_SEVERITY))
    return;

  fib = fib_table_get (sfibix, FIB_PROTOCOL_IP6);

  syslog_msg_init (&syslog_msg, NAT_FACILITY, SADD_SDEL_SEVERITY, NAT_APPNAME,
		   is_add ? SADD_MSGID : SDEL_MSGID);

  syslog_msg_sd_init (&syslog_msg, NSESS_SDID);
  syslog_msg_add_sd_param (&syslog_msg, SVLAN_SDPARAM_NAME, "%d",
			   fib->ft_table_id);
  syslog_msg_add_sd_param (&syslog_msg, IATYP_SDPARAM_NAME, IATYP_IPV6);
  syslog_msg_add_sd_param (&syslog_msg, ISADDR_SDPARAM_NAME, "%U",
			   format_ip6_address, isaddr);
  syslog_msg_add_sd_param (&syslog_msg, ISPORT_SDPARAM_NAME, "%d",
			   clib_net_to_host_u16 (isport));
  syslog_msg_add_sd_param (&syslog_msg, XATYP_SDPARAM_NAME, IATYP_IPV4);
  syslog_msg_add_sd_param (&syslog_msg, XSADDR_SDPARAM_NAME, "%U",
			   format_ip4_address, xsaddr);
  syslog_msg_add_sd_param (&syslog_msg, XSPORT_SDPARAM_NAME, "%d",
			   clib_net_to_host_u16 (xsport));
  syslog_msg_add_sd_param (&syslog_msg, PROTO_SDPARAM_NAME, "%d", proto);
  syslog_msg_add_sd_param (&syslog_msg, XDADDR_SDPARAM_NAME, "%U",
			   format_ip4_address, xdaddr);
  syslog_msg_add_sd_param (&syslog_msg, XDPORT_SDPARAM_NAME, "%d",
			   clib_net_to_host_u16 (xdport));

  syslog_msg_send (&syslog_msg);
}

void
nat_syslog_nat64_sadd (u32 sfibix, ip6_address_t * isaddr, u16 isport,
		       ip4_address_t * xsaddr, u16 xsport,
		       ip4_address_t * xdaddr, u16 xdport,
		       nat_protocol_t proto)
{
  nat_syslog_nat64_sess (sfibix, isaddr, isport, xsaddr, xsport, xdaddr,
			 xdport, proto, 1);
}

void
nat_syslog_nat64_sdel (u32 sfibix, ip6_address_t * isaddr, u16 isport,
		       ip4_address_t * xsaddr, u16 xsport,
		       ip4_address_t * xdaddr, u16 xdport,
		       nat_protocol_t proto)
{
  nat_syslog_nat64_sess (sfibix, isaddr, isport, xsaddr, xsport, xdaddr,
			 xdport, proto, 0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
