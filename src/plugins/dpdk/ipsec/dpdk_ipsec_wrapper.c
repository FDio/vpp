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

#define IPSEC_PLUGIN_NAME "ipsec_plugin.so"

#include <dpdk/ipsec/dpdk_ipsec_wrapper.h>
#include <vlib/unix/plugin.h>

vlib_combined_counter_main_t *dpdk_ipsec_sa_counters;
ipsec_main_t *dpdk_ipsec_main;
index_t **dpdk_ipsec_tun_protect_sa_by_adj_index;

typedef u32 (*ipsec_register_esp_backend_fun_t) (
  vlib_main_t *, ipsec_main_t *, const char *, const char *, const char *,
  const char *, const char *, const char *, const char *, const char *,
  const char *, const char *, check_support_cb_t, add_del_sa_sess_cb_t,
  enable_disable_cb_t);

typedef int (*ipsec_select_esp_backend_fun_t) (ipsec_main_t *, u32);

format_function_t *ipsec_format_crypto_alg_fun;
format_function_t *ipsec_format_integ_alg_fun;
format_function_t *ipsec_format_esp_header_fun;
ipsec_register_esp_backend_fun_t ipsec_register_esp_backend_fun;
ipsec_select_esp_backend_fun_t ipsec_select_esp_backend_fun;

clib_error_t *
dpdk_ipsec_wrapper_init ()
{
  dpdk_ipsec_sa_counters =
    vlib_get_plugin_symbol (IPSEC_PLUGIN_NAME, "ipsec_sa_counters");
  dpdk_ipsec_main = vlib_get_plugin_symbol (IPSEC_PLUGIN_NAME, "ipsec_main");
  dpdk_ipsec_tun_protect_sa_by_adj_index = vlib_get_plugin_symbol (
    IPSEC_PLUGIN_NAME, "ipsec_tun_protect_sa_by_adj_index");
  ipsec_format_crypto_alg_fun =
    vlib_get_plugin_symbol (IPSEC_PLUGIN_NAME, "format_ipsec_crypto_alg");
  ipsec_format_integ_alg_fun =
    vlib_get_plugin_symbol (IPSEC_PLUGIN_NAME, "format_ipsec_integ_alg");
  ipsec_format_esp_header_fun =
    vlib_get_plugin_symbol (IPSEC_PLUGIN_NAME, "format_esp_header");
  ipsec_register_esp_backend_fun =
    vlib_get_plugin_symbol (IPSEC_PLUGIN_NAME, "ipsec_register_esp_backend");
  ipsec_select_esp_backend_fun =
    vlib_get_plugin_symbol (IPSEC_PLUGIN_NAME, "ipsec_select_esp_backend");
  if (dpdk_ipsec_sa_counters == NULL || dpdk_ipsec_main == NULL ||
      dpdk_ipsec_tun_protect_sa_by_adj_index == NULL ||
      ipsec_format_crypto_alg_fun == NULL ||
      ipsec_format_integ_alg_fun == NULL ||
      ipsec_format_esp_header_fun == NULL ||
      ipsec_register_esp_backend_fun == NULL ||
      ipsec_select_esp_backend_fun == NULL)
    return clib_error_return (0,
			      "Cannot load ipsec symbols from dpdk plugin!");
  return 0;
}

u8 *
dpdk_ipsec_format_crypto_alg (u8 *s, va_list *args)
{
  return ipsec_format_crypto_alg_fun (s, args);
}

u8 *
dpdk_ipsec_format_integ_alg (u8 *s, va_list *args)
{
  return ipsec_format_integ_alg_fun (s, args);
}

u8 *
dpdk_ipsec_format_esp_header (u8 *s, va_list *args)
{
  return ipsec_format_esp_header_fun (s, args);
}

u32
dpdk_ipsec_register_esp_backend (
  vlib_main_t *vm, ipsec_main_t *im, const char *name,
  const char *esp4_encrypt_node_name, const char *esp4_encrypt_node_tun_name,
  const char *esp4_decrypt_node_name, const char *esp4_decrypt_tun_node_name,
  const char *esp6_encrypt_node_name, const char *esp6_encrypt_node_tun_name,
  const char *esp6_decrypt_node_name, const char *esp6_decrypt_tun_node_name,
  const char *esp_mpls_encrypt_node_tun_name,
  check_support_cb_t esp_check_support_cb,
  add_del_sa_sess_cb_t esp_add_del_sa_sess_cb,
  enable_disable_cb_t enable_disable_cb)
{
  return ipsec_register_esp_backend_fun (
    vm, im, name, esp4_encrypt_node_name, esp4_encrypt_node_tun_name,
    esp4_decrypt_node_name, esp4_decrypt_tun_node_name, esp6_encrypt_node_name,
    esp6_encrypt_node_tun_name, esp6_decrypt_node_name,
    esp6_decrypt_tun_node_name, esp_mpls_encrypt_node_tun_name,
    esp_check_support_cb, esp_add_del_sa_sess_cb, enable_disable_cb);
}
int
dpdk_ipsec_select_esp_backend (ipsec_main_t *im, u32 esp_backend_idx)
{
  return ipsec_select_esp_backend_fun (im, esp_backend_idx);
}