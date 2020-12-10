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

int nat44_ei_plugin_enable ();

void nat44_ei_plugin_disable ();

/**
 * @brief Delete specific NAT44 EI user and his sessions
 *
 * @param addr         IPv4 address
 * @param fib_index    FIB table index
 */
int nat44_ei_user_del (ip4_address_t * addr, u32 fib_index);

/**
 * @brief Delete session for static mapping
 *
 * @param addr         IPv4 address
 * @param fib_index    FIB table index
 */
void
nat44_ei_static_mapping_del_sessions (snat_main_t * sm,
				      snat_main_per_thread_data_t * tsm,
				      snat_user_key_t u_key, int addr_only,
				      ip4_address_t e_addr, u16 e_port);

u32
nat44_ei_get_in2out_worker_index (ip4_header_t * ip0, u32 rx_fib_index0,
				  u8 is_output);

u32
nat44_ei_get_out2in_worker_index (vlib_buffer_t * b, ip4_header_t * ip0,
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

#endif /* __included_nat44_ei_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
