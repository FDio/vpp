/*
 * srv6_end.c
 *
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
#include <srv6-end/srv6_end.h>

static clib_error_t *
srv6_end_init (vlib_main_t * vm)
{
  srv6_end_main_t *sm = &srv6_end_main;
  vlib_node_t *node;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  // dpo_register_new_type ( )
  // sr_localsid_register_function ( )

  node = vlib_get_node_by_name (vm, (u8 *) "srv6-end-m-gtp4-e");
  sm->end_m_gtp4_e_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  sm->error_node_index = node->index;

  return 0;
}

/* *INDENT-OFF* */
// TODO: check if name matters !
VNET_FEATURE_INIT (srv6_end_m_gtp4_e, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "srv6-end-m-gtp4-e",
  .runs_before = 0,
};

VLIB_INIT_FUNCTION (srv6_end_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "SRV6 Endpoint",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
