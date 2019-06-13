/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_io.h>

int
ipsec_add_del_spd (vlib_main_t * vm, u32 spd_id, int is_add)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_spd_t *spd = 0;
  uword *p;
  u32 spd_index, k, v;

  p = hash_get (im->spd_index_by_spd_id, spd_id);
  if (p && is_add)
    return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
  if (!p && !is_add)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (!is_add)			/* delete */
    {
      spd_index = p[0];
      spd = pool_elt_at_index (im->spds, spd_index);
      if (!spd)
	return VNET_API_ERROR_INVALID_VALUE;
      /* *INDENT-OFF* */
      hash_foreach (k, v, im->spd_index_by_sw_if_index, ({
        if (v == spd_index)
          ipsec_set_interface_spd(vm, k, spd_id, 0);
      }));
      /* *INDENT-ON* */
      hash_unset (im->spd_index_by_spd_id, spd_id);
#define _(s,v) vec_free(spd->policies[IPSEC_SPD_POLICY_##s]);
      foreach_ipsec_spd_policy_type
#undef _
	pool_put (im->spds, spd);
    }
  else				/* create new SPD */
    {
      pool_get (im->spds, spd);
      clib_memset (spd, 0, sizeof (*spd));
      spd_index = spd - im->spds;
      spd->id = spd_id;
      hash_set (im->spd_index_by_spd_id, spd_id, spd_index);
    }
  return 0;
}

int
ipsec_set_interface_spd (vlib_main_t * vm, u32 sw_if_index, u32 spd_id,
			 int is_add)
{
  ipsec_main_t *im = &ipsec_main;
  ip4_ipsec_config_t config;

  u32 spd_index;
  uword *p;

  p = hash_get (im->spd_index_by_spd_id, spd_id);
  if (!p)
    return VNET_API_ERROR_SYSCALL_ERROR_1;	/* no such spd-id */

  spd_index = p[0];

  p = hash_get (im->spd_index_by_sw_if_index, sw_if_index);
  if (p && is_add)
    return VNET_API_ERROR_SYSCALL_ERROR_1;	/* spd already assigned */

  if (is_add)
    {
      hash_set (im->spd_index_by_sw_if_index, sw_if_index, spd_index);
    }
  else
    {
      hash_unset (im->spd_index_by_sw_if_index, sw_if_index);
    }

  /* enable IPsec on TX */
  vnet_feature_enable_disable ("ip4-output", "ipsec4-output-feature",
			       sw_if_index, is_add, 0, 0);
  vnet_feature_enable_disable ("ip6-output", "ipsec6-output-feature",
			       sw_if_index, is_add, 0, 0);

  config.spd_index = spd_index;

  /* enable IPsec on RX */
  vnet_feature_enable_disable ("ip4-unicast", "ipsec4-input-feature",
			       sw_if_index, is_add, &config, sizeof (config));
  vnet_feature_enable_disable ("ip6-unicast", "ipsec6-input-feature",
			       sw_if_index, is_add, &config, sizeof (config));

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
