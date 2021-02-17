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
#ifndef __included_dpdk_ipsec_wrapper_h__
#define __included_dpdk_ipsec_wrapper_h__

#include <vlib/vlib.h>
#include <ipsec/ipsec.h>

extern vlib_combined_counter_main_t *dpdk_ipsec_sa_counters;
extern ipsec_main_t *dpdk_ipsec_main;
extern index_t **dpdk_ipsec_tun_protect_sa_by_adj_index;

always_inline index_t
dpdk_ipsec_tun_protect_get_sa_out (adj_index_t ai)
{
  ASSERT (vec_len (*dpdk_ipsec_tun_protect_sa_by_adj_index) > ai);
  ASSERT (INDEX_INVALID != (*dpdk_ipsec_tun_protect_sa_by_adj_index)[ai]);

  return ((*dpdk_ipsec_tun_protect_sa_by_adj_index)[ai]);
}

clib_error_t *dpdk_ipsec_wrapper_init ();

u8 *dpdk_ipsec_format_crypto_alg (u8 *s, va_list *args);
u8 *dpdk_ipsec_format_integ_alg (u8 *s, va_list *args);
u8 *dpdk_ipsec_format_esp_header (u8 *s, va_list *args);
u32 dpdk_ipsec_register_esp_backend (
  vlib_main_t *vm, ipsec_main_t *im, const char *name,
  const char *esp4_encrypt_node_name, const char *esp4_encrypt_node_tun_name,
  const char *esp4_decrypt_node_name, const char *esp4_decrypt_tun_node_name,
  const char *esp6_encrypt_node_name, const char *esp6_encrypt_node_tun_name,
  const char *esp6_decrypt_node_name, const char *esp6_decrypt_tun_node_name,
  const char *esp_mpls_encrypt_node_tun_name,
  check_support_cb_t esp_check_support_cb,
  add_del_sa_sess_cb_t esp_add_del_sa_sess_cb,
  enable_disable_cb_t enable_disable_cb);
int dpdk_ipsec_select_esp_backend (ipsec_main_t *im, u32 esp_backend_idx);

#endif /* __included_dpdk_ipsec_wrapper_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */