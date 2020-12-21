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
 * @file nat44_ei.h
 * NAT44 endpoint independent plugin declarations
 */
#ifndef __included_nat44_ei_h__
#define __included_nat44_ei_h__

typedef struct
{
  /* maximum number of users */
  u32 users;
  /* maximum number of sessions */
  u32 sessions;
  /* maximum number of ssessions per user */
  u32 user_sessions;

  /* plugin features */
  u8 static_mapping_only;
  u8 connection_tracking;
  u8 out2in_dpo;

  u32 inside_vrf;
  u32 outside_vrf;

} nat44_ei_config_t;

typedef struct
{
  u32 translations;
  u32 translation_buckets;
  u32 user_buckets;

  nat44_ei_config_t rconfig;

} nat44_ei_main_t;

int nat44_ei_plugin_enable (nat44_ei_config_t c);

int nat44_ei_plugin_disable ();

/**
 * @brief Delete specific NAT44 EI user and his sessions
 *
 * @param addr         IPv4 address
 * @param fib_index    FIB table index
 */
int nat44_ei_user_del (ip4_address_t *addr, u32 fib_index);

/**
 * @brief Delete session for static mapping
 *
 * @param addr         IPv4 address
 * @param fib_index    FIB table index
 */
void nat44_ei_static_mapping_del_sessions (snat_main_t *sm,
					   snat_main_per_thread_data_t *tsm,
					   snat_user_key_t u_key,
					   int addr_only, ip4_address_t e_addr,
					   u16 e_port);

u32 nat44_ei_get_in2out_worker_index (ip4_header_t *ip0, u32 rx_fib_index0,
				      u8 is_output);

u32 nat44_ei_get_out2in_worker_index (vlib_buffer_t *b, ip4_header_t *ip0,
				      u32 rx_fib_index0, u8 is_output);

/**
 * @brief Set address and port assignment algorithm to default/standard
 */
void nat44_ei_set_alloc_default (void);

/**
 * @brief Set address and port assignment algorithm for MAP-E CE
 *
 * @param psid        Port Set Identifier value
 * @param psid_offset number of offset bits
 * @param psid_length length of PSID
 */
void nat44_ei_set_alloc_mape (u16 psid, u16 psid_offset, u16 psid_length);

/**
 * @brief Set address and port assignment algorithm for port range
 *
 * @param start_port beginning of the port range
 * @param end_port   end of the port range
 */
void nat44_ei_set_alloc_range (u16 start_port, u16 end_port);

/**
 * @brief Add/delete NAT44-EI static mapping
 *
 * @param l_addr       local IPv4 address
 * @param e_addr       external IPv4 address
 * @param l_port       local port number
 * @param e_port       external port number
 * @param proto        L4 protocol
 * @param sw_if_index  use interface address as external IPv4 address
 * @param vrf_id       local VRF ID
 * @param addr_only    1 = 1:1NAT, 0 = 1:1NAPT
 * @param identity_nat identity NAT
 * @param tag opaque   string tag
 * @param is_add       1 = add, 0 = delete
 *
 * @return 0 on success, non-zero value otherwise

 */
int nat44_ei_add_del_static_mapping (ip4_address_t l_addr,
				     ip4_address_t e_addr, u16 l_port,
				     u16 e_port, nat_protocol_t proto,
				     u32 sw_if_index, u32 vrf_id, u8 addr_only,
				     u8 identity_nat, u8 *tag, u8 is_add);

/**
 * @brief Delete NAT44-EI session
 *
 * @param addr   IPv4 address
 * @param port   L4 port number
 * @param proto  L4 protocol
 * @param vrf_id VRF ID
 * @param is_in  1 = inside network address and port pair, 0 = outside
 *
 * @return 0 on success, non-zero value otherwise
 */
int nat44_ei_del_session (snat_main_t *sm, ip4_address_t *addr, u16 port,
			  nat_protocol_t proto, u32 vrf_id, int is_in);

/**
 * @brief Match NAT44-EI static mapping.
 *
 * @param key             address and port to match
 * @param addr            external/local address of the matched mapping
 * @param port            port of the matched mapping
 * @param fib_index       fib index of the matched mapping
 * @param by_external     if 0 match by local address otherwise match by
 * external address
 * @param is_addr_only    1 if matched mapping is address only
 * @param is_identity_nat 1 if indentity mapping
 *
 * @returns 0 if match found otherwise 1.
 */
int nat44_ei_static_mapping_match (ip4_address_t match_addr, u16 match_port,
				   u32 match_fib_index,
				   nat_protocol_t match_protocol,
				   ip4_address_t *mapping_addr,
				   u16 *mapping_port, u32 *mapping_fib_index,
				   u8 by_external, u8 *is_addr_only,
				   u8 *is_identity_nat);

/**
 * @brief Clear all active NAT44-EI sessions.
 */
void nat44_ei_sessions_clear ();

#endif /* __included_nat44_ei_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
