/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/crypto/crypto.h>

#include <wireguard/wireguard_send.h>
#include <wireguard/wireguard_key.h>
#include <wireguard/wireguard_if.h>
#include <wireguard/wireguard.h>

wg_main_t wg_main;
wg_async_post_next_t wg_encrypt_async_next;
wg_async_post_next_t wg_decrypt_async_next;

void
wg_set_async_mode (u32 is_enabled)
{
  vnet_crypto_request_async_mode (is_enabled);

  if (is_enabled)
    wg_op_mode_set_ASYNC ();
  else
    wg_op_mode_unset_ASYNC ();
}

static void
wireguard_register_post_node (vlib_main_t *vm)

{
  wg_async_post_next_t *eit;
  wg_async_post_next_t *dit;

  eit = &wg_encrypt_async_next;
  dit = &wg_decrypt_async_next;

  eit->wg4_post_next =
    vnet_crypto_register_post_node (vm, "wg4-output-tun-post-node");
  eit->wg6_post_next =
    vnet_crypto_register_post_node (vm, "wg6-output-tun-post-node");

  dit->wg4_post_next =
    vnet_crypto_register_post_node (vm, "wg4-input-post-node");
  dit->wg6_post_next =
    vnet_crypto_register_post_node (vm, "wg6-input-post-node");
}

static clib_error_t *
wg_init (vlib_main_t * vm)
{
  wg_main_t *wmp = &wg_main;

  wmp->vlib_main = vm;

  wmp->in4_fq_index = vlib_frame_queue_main_init (wg4_input_node.index, 0);
  wmp->in6_fq_index = vlib_frame_queue_main_init (wg6_input_node.index, 0);
  wmp->out4_fq_index =
    vlib_frame_queue_main_init (wg4_output_tun_node.index, 0);
  wmp->out6_fq_index =
    vlib_frame_queue_main_init (wg6_output_tun_node.index, 0);

  vlib_thread_main_t *tm = vlib_get_thread_main ();

  vec_validate_aligned (wmp->per_thread_data, tm->n_vlib_mains,
			CLIB_CACHE_LINE_BYTES);

  wg_timer_wheel_init ();
  wireguard_register_post_node (vm);
  wmp->op_mode_flags = 0;

  return (NULL);
}

VLIB_INIT_FUNCTION (wg_init);

/* *INDENT-OFF* */

VNET_FEATURE_INIT (wg4_output_tun, static) = {
  .arc_name = "ip4-output",
  .node_name = "wg4-output-tun",
  .runs_after = VNET_FEATURES ("gso-ip4"),
};

VNET_FEATURE_INIT (wg6_output_tun, static) = {
  .arc_name = "ip6-output",
  .node_name = "wg6-output-tun",
  .runs_after = VNET_FEATURES ("gso-ip6"),
};

VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Wireguard Protocol",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
