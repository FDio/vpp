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
#include <vnet/ipip/ipip.h>
#include <vpp/app/version.h>

#include <wireguard/wireguard_send.h>
#include <wireguard/wireguard_key.h>
#include <wireguard/wireguard_if.h>
#include <wireguard/wireguard.h>

wg_main_t wg_main;

static clib_error_t *
wg_init (vlib_main_t * vm)
{
  wg_main_t *wmp = &wg_main;

  wmp->vlib_main = vm;

  wmp->in_fq_index = vlib_frame_queue_main_init (wg_input_node.index, 0);
  wmp->out_fq_index =
    vlib_frame_queue_main_init (wg_output_tun_node.index, 0);

  vlib_thread_main_t *tm = vlib_get_thread_main ();

  vec_validate_aligned (wmp->per_thread_data, tm->n_vlib_mains,
			CLIB_CACHE_LINE_BYTES);

  wg_timer_wheel_init ();

  return (NULL);
}

VLIB_INIT_FUNCTION (wg_init);

/* *INDENT-OFF* */

VNET_FEATURE_INIT (wg_output_tun, static) =
{
  .arc_name = "ip4-output",
  .node_name = "wg-output-tun",
  .runs_after = VNET_FEATURES ("gso-ip4"),
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
