/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/dpo/dpo.h>
#include <vnet/lisp-gpe/lisp_gpe.h>
#include <vnet/lisp-cp/control.h>

/**
 * The static array of LISP punt DPOs
 */
static dpo_id_t lisp_cp_dpos[DPO_PROTO_NUM];

const dpo_id_t *
lisp_cp_dpo_get (dpo_proto_t proto)
{
  /*
   * there are only two instances of this DPO type.
   * we can use the protocol as the index
   */
  return (&lisp_cp_dpos[proto]);
}

static u8 *
format_lisp_cp_dpo (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "lisp-cp-punt-%U", format_dpo_proto, index));
}

static void
lisp_cp_dpo_lock (dpo_id_t * dpo)
{
}

static void
lisp_cp_dpo_unlock (dpo_id_t * dpo)
{
}

const static dpo_vft_t lisp_cp_vft = {
  .dv_lock = lisp_cp_dpo_lock,
  .dv_unlock = lisp_cp_dpo_unlock,
  .dv_format = format_lisp_cp_dpo,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a LISP-CP
 *        object.
 *
 * this means that these graph nodes are ones from which a LISP-CP is the
 * parent object in the DPO-graph.
 */
const static char *const lisp_cp_ip4_nodes[] = {
  "lisp-cp-lookup-ip4",
  NULL,
};

const static char *const lisp_cp_ip6_nodes[] = {
  "lisp-cp-lookup-ip6",
  NULL,
};

const static char *const lisp_cp_ethernet_nodes[] = {
  "lisp-cp-lookup-l2",
  NULL,
};

const static char *const lisp_cp_nsh_nodes[] = {
  "lisp-cp-lookup-nsh",
  NULL,
};

const static char *const *const lisp_cp_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = lisp_cp_ip4_nodes,
  [DPO_PROTO_IP6] = lisp_cp_ip6_nodes,
  [DPO_PROTO_ETHERNET] = lisp_cp_ethernet_nodes,
  [DPO_PROTO_MPLS] = NULL,
  [DPO_PROTO_NSH] = lisp_cp_nsh_nodes,
};

clib_error_t *
lisp_cp_dpo_module_init (vlib_main_t * vm)
{
  dpo_proto_t dproto;

  /*
   * there are no exit arcs from the LIS-CP VLIB node, so we
   * pass NULL as said node array.
   */
  dpo_register (DPO_LISP_CP, &lisp_cp_vft, lisp_cp_nodes);

  FOR_EACH_DPO_PROTO (dproto)
  {
    dpo_set (&lisp_cp_dpos[dproto], DPO_LISP_CP, dproto, dproto);
  }

  return (NULL);
}

VLIB_INIT_FUNCTION (lisp_cp_dpo_module_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
