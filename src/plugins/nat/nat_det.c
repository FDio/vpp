/*
 * snat_det.c - deterministic NAT
 *
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 * @file
 * @brief deterministic NAT
 */

#include <nat/nat_det.h>


/**
 * @brief Add/delete deterministic NAT mapping.
 *
 * Create bijective mapping of inside address to outside address and port range
 * pairs, with the purpose of enabling deterministic NAT to reduce logging in
 * CGN deployments.
 *
 * @param sm       SNAT main.
 * @param in_addr  Inside network address.
 * @param in_plen  Inside network prefix length.
 * @param out_addr Outside network address.
 * @param out_plen Outside network prefix length.
 * @param is_add   If 0 delete, otherwise add.
 */
int
snat_det_add_map (snat_main_t * sm, ip4_address_t * in_addr, u8 in_plen,
		  ip4_address_t * out_addr, u8 out_plen, int is_add)
{
  snat_det_map_t *det_map;
  static snat_det_session_t empty_snat_det_session = { 0 };
  snat_interface_t *i;
  ip4_address_t in_cmp, out_cmp;
  u8 found = 0;

  in_cmp.as_u32 = in_addr->as_u32 & ip4_main.fib_masks[in_plen];
  out_cmp.as_u32 = out_addr->as_u32 & ip4_main.fib_masks[out_plen];
  vec_foreach (det_map, sm->det_maps)
  {
    /* Checking for overlapping addresses to be added here */
    if (det_map->in_addr.as_u32 == in_cmp.as_u32 &&
	det_map->in_plen == in_plen &&
	det_map->out_addr.as_u32 == out_cmp.as_u32 &&
	det_map->out_plen == out_plen)
      {
	found = 1;
	break;
      }
  }

  /* If found, don't add again */
  if (found && is_add)
    return VNET_API_ERROR_VALUE_EXIST;

  /* If not found, don't delete */
  if (!found && !is_add)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (is_add)
    {
      pool_get (sm->det_maps, det_map);
      memset (det_map, 0, sizeof (*det_map));
      det_map->in_addr.as_u32 = in_cmp.as_u32;
      det_map->in_plen = in_plen;
      det_map->out_addr.as_u32 = out_cmp.as_u32;
      det_map->out_plen = out_plen;
      det_map->sharing_ratio = (1 << (32 - in_plen)) / (1 << (32 - out_plen));
      det_map->ports_per_host = (65535 - 1023) / det_map->sharing_ratio;

      vec_validate_init_empty (det_map->sessions,
			       SNAT_DET_SES_PER_USER * (1 << (32 - in_plen)) -
			       1, empty_snat_det_session);
    }
  else
    {
      vec_free (det_map->sessions);
      vec_del1 (sm->det_maps, det_map - sm->det_maps);
    }

  /* Add/del external address range to FIB */
  /* *INDENT-OFF* */
  pool_foreach (i, sm->interfaces,
  ({
    if (nat_interface_is_inside(i))
      continue;

    snat_add_del_addr_to_fib(out_addr, out_plen, i->sw_if_index, is_add);
    break;
  }));
  /* *INDENT-ON* */
  return 0;
}

/**
 * @brief The 'nat-det-expire-walk' process's main loop.
 *
 * Check expire time for active sessions.
 */
static uword
snat_det_expire_walk_fn (vlib_main_t * vm, vlib_node_runtime_t * rt,
			 vlib_frame_t * f)
{
  snat_main_t *sm = &snat_main;
  snat_det_map_t *dm;
  snat_det_session_t *ses;

  while (sm->deterministic)
    {
      vlib_process_wait_for_event_or_clock (vm, 10.0);
      vlib_process_get_events (vm, NULL);
      u32 now = (u32) vlib_time_now (vm);
      /* *INDENT-OFF* */
      pool_foreach (dm, sm->det_maps,
      ({
        vec_foreach(ses, dm->sessions)
          {
            /* Delete if session expired */
            if (ses->in_port && (ses->expire < now))
              snat_det_ses_close (dm, ses);
          }
      }));
      /* *INDENT-ON* */
    }

  return 0;
}

static vlib_node_registration_t snat_det_expire_walk_node;

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (snat_det_expire_walk_node, static) = {
    .function = snat_det_expire_walk_fn,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name =
    "nat-det-expire-walk",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
