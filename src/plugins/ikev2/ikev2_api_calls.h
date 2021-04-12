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
#ifndef __IKEV2_API_CALLS_H__
#define __IKEV2_API_CALLS_H__

#include <vlibmemory/api.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_types_api.h>
#include <vnet/tunnel/tunnel_types_api.h>
#include <vnet/ip/ip_types_api.h>

u32 ikev2_api_register_client ();
int ikev2_api_ipsec_sa_add_and_lock (
  u32 id, u32 spi, ipsec_protocol_t proto, ipsec_crypto_alg_t crypto_alg,
  const ipsec_key_t *ck, ipsec_integ_alg_t integ_alg, const ipsec_key_t *ik,
  ipsec_sa_flags_t flags, u32 salt, u16 src_port, u16 dst_port,
  const tunnel_t *tun, u32 *sa_out_index);
int ikev2_api_ipsec_tun_protect_del (u32 sw_if_index, const ip_address_t *nh);
int ikev2_api_ipsec_tun_protect_update (u32 sw_if_index,
					const ip_address_t *nh, u32 sa_out,
					u32 *sas_in);
int ikev2_api_ipsec_sa_unlock_id (u32 id);
int ikev2_api_ipsec_register_udp_port (u16 port);
int ikev2_api_ipsec_unregister_udp_port (u16 port);

#endif /* __IKEV2_API_CALLS_H__ */