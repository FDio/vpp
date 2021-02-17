/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
#ifndef __included_ikev2_ipsec_wrapper_h__
#define __included_ikev2_ipsec_wrapper_h__

#include <vlib/vlib.h>
#include <vnet/ip/ip_types.h>
#include <ipsec/ipsec_sa.h>
#include <ipsec/ipsec_punt.h>

clib_error_t *ikev2_ipsec_wrapper_init ();
void ikev2_ipsec_get_combined_counters (u32 index, vlib_counter_t *result);
void ikev2_ipsec_punt_register (vlib_punt_hdl_t, ipsec_punt_reason_type_t,
				const char *);
int ikev2_ipsec_tun_protect_del (u32 sw_if_index, const ip_address_t *nh);

int ikev2_ipsec_sa_unlock_id (u32 id);

int ikev2_ipsec_sa_add_and_lock (u32 id, u32 spi, ipsec_protocol_t proto,
				 ipsec_crypto_alg_t crypto_alg,
				 const ipsec_key_t *ck,
				 ipsec_integ_alg_t integ_alg,
				 const ipsec_key_t *ik, ipsec_sa_flags_t flags,
				 u32 salt, u16 src_port, u16 dst_port,
				 const tunnel_t *tun, u32 *sa_out_index);

int ikev2_ipsec_tun_protect_update (u32 sw_if_index, const ip_address_t *nh,
				    u32 sa_out, u32 *sa_ins);

void ikev2_ipsec_sa_walk (ipsec_sa_walk_cb_t cd, void *ctx);

void ikev2_ipsec_mk_key (ipsec_key_t *key, const u8 *data, u8 len);

#endif /* __included_ikev2_ipsec_wrapper_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */