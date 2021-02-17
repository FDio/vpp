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

#include <ikev2/ikev2_ipsec_wrapper.h>
#include <vlib/unix/plugin.h>

#define IPSEC_PLUGIN_NAME "ipsec_plugin.so"

typedef int (*ipsec_tun_protect_del_fun_t) (u32, const ip_address_t *);
typedef int (*ipsec_sa_unlock_id_fun_t) (u32 id);
typedef int (*ipsec_sa_add_and_lock_fun_t) (
  u32 id, u32 spi, ipsec_protocol_t proto, ipsec_crypto_alg_t crypto_alg,
  const ipsec_key_t *ck, ipsec_integ_alg_t integ_alg, const ipsec_key_t *ik,
  ipsec_sa_flags_t flags, u32 salt, u16 src_port, u16 dst_port,
  const tunnel_t *tun, u32 *sa_out_index);
typedef int (*ipsec_tun_protect_update_fun_t) (u32 sw_if_index,
					       const ip_address_t *nh,
					       u32 sa_out, u32 *sa_ins);
typedef void (*ipsec_sa_walk_fun_t) (ipsec_sa_walk_cb_t cd, void *ctx);

typedef void (*ipsec_mk_key_fun_t) (ipsec_key_t *key, const u8 *data, u8 len);

static vlib_combined_counter_main_t *ikev2_ipsec_sa_counters;
static vlib_punt_reason_t *ikev2_ipsec_punt_reason;

static ipsec_tun_protect_del_fun_t ipsec_tun_protect_del_fun;
static ipsec_sa_unlock_id_fun_t ipsec_sa_unlock_id_fun;
static ipsec_sa_add_and_lock_fun_t ipsec_sa_add_and_lock_fun;
static ipsec_tun_protect_update_fun_t ipsec_tun_protect_update_fun;
static ipsec_sa_walk_fun_t ipsec_sa_walk_fun;
static ipsec_mk_key_fun_t ipsec_mk_key_fun;

clib_error_t *
ikev2_ipsec_wrapper_init ()
{
  ikev2_ipsec_sa_counters =
    vlib_get_plugin_symbol (IPSEC_PLUGIN_NAME, "ipsec_sa_counters");
  ikev2_ipsec_punt_reason =
    vlib_get_plugin_symbol (IPSEC_PLUGIN_NAME, "ipsec_punt_reason");
  ipsec_tun_protect_del_fun =
    vlib_get_plugin_symbol (IPSEC_PLUGIN_NAME, "ipsec_tun_protect_del");
  ipsec_sa_unlock_id_fun =
    vlib_get_plugin_symbol (IPSEC_PLUGIN_NAME, "ipsec_sa_unlock_id");
  ipsec_sa_add_and_lock_fun =
    vlib_get_plugin_symbol (IPSEC_PLUGIN_NAME, "ipsec_sa_add_and_lock");
  ipsec_tun_protect_update_fun =
    vlib_get_plugin_symbol (IPSEC_PLUGIN_NAME, "ipsec_tun_protect_update");
  ipsec_sa_walk_fun =
    vlib_get_plugin_symbol (IPSEC_PLUGIN_NAME, "ipsec_sa_walk");
  ipsec_mk_key_fun =
    vlib_get_plugin_symbol (IPSEC_PLUGIN_NAME, "ipsec_mk_key");

  if (ikev2_ipsec_sa_counters == NULL || ikev2_ipsec_punt_reason == NULL ||
      ipsec_tun_protect_del_fun == NULL || ipsec_sa_unlock_id_fun == NULL ||
      ipsec_sa_add_and_lock_fun == NULL ||
      ipsec_tun_protect_update_fun == NULL || ipsec_sa_walk_fun == NULL ||
      ipsec_mk_key_fun == NULL)
    return clib_error_return (0,
			      "Cannot load ipsec symbols from ikev2 plugin!");
  return 0;
}

void
ikev2_ipsec_get_combined_counters (u32 index, vlib_counter_t *result)
{
  vlib_get_combined_counter (ikev2_ipsec_sa_counters, index, result);
}

void
ikev2_ipsec_punt_register (vlib_punt_hdl_t punt_hdl,
			   ipsec_punt_reason_type_t reason, const char *client)
{
  vlib_punt_register (punt_hdl, ikev2_ipsec_punt_reason[reason], client);
}

int
ikev2_ipsec_tun_protect_del (u32 sw_if_index, const ip_address_t *nh)
{
  return ipsec_tun_protect_del_fun (sw_if_index, nh);
}

int
ikev2_ipsec_sa_unlock_id (u32 id)
{
  return ipsec_sa_unlock_id_fun (id);
}

int
ikev2_ipsec_sa_add_and_lock (u32 id, u32 spi, ipsec_protocol_t proto,
			     ipsec_crypto_alg_t crypto_alg,
			     const ipsec_key_t *ck,
			     ipsec_integ_alg_t integ_alg,
			     const ipsec_key_t *ik, ipsec_sa_flags_t flags,
			     u32 salt, u16 src_port, u16 dst_port,
			     const tunnel_t *tun, u32 *sa_out_index)
{
  return ipsec_sa_add_and_lock_fun (id, spi, proto, crypto_alg, ck, integ_alg,
				    ik, flags, salt, src_port, dst_port, tun,
				    sa_out_index);
}

int
ikev2_ipsec_tun_protect_update (u32 sw_if_index, const ip_address_t *nh,
				u32 sa_out, u32 *sa_ins)
{
  return ipsec_tun_protect_update_fun (sw_if_index, nh, sa_out, sa_ins);
}

void
ikev2_ipsec_sa_walk (ipsec_sa_walk_cb_t cd, void *ctx)
{
  ipsec_sa_walk_fun (cd, ctx);
}

void
ikev2_ipsec_mk_key (ipsec_key_t *key, const u8 *data, u8 len)
{
  return ipsec_mk_key_fun (key, data, len);
}
