/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <igmp/igmp_group.h>
#include <igmp/igmp.h>

void
igmp_group_free_all_srcs (igmp_group_t * group)
{
  igmp_src_t *src;

  /* *INDENT-OFF* */
  FOR_EACH_SRC (src, group, IGMP_FILTER_MODE_INCLUDE,
    ({
      igmp_src_free(src);
    }));
  /* *INDENT-ON* */

  hash_free (group->igmp_src_by_key[IGMP_FILTER_MODE_INCLUDE]);
  hash_free (group->igmp_src_by_key[IGMP_FILTER_MODE_EXCLUDE]);
}

void
igmp_group_src_remove (igmp_group_t * group, igmp_src_t * src)
{
  hash_unset_mem (group->igmp_src_by_key[IGMP_FILTER_MODE_INCLUDE], src->key);
  hash_unset_mem (group->igmp_src_by_key[IGMP_FILTER_MODE_EXCLUDE], src->key);
}

igmp_src_t *
igmp_group_src_update (igmp_group_t * group,
		       const igmp_key_t * skey, igmp_mode_t mode)
{
  igmp_src_t *src;

  src = igmp_src_lookup (group, skey);

  if (NULL == src)
    {
      src = igmp_src_alloc (igmp_group_index (group), skey, mode);

      hash_set_mem (group->igmp_src_by_key[IGMP_FILTER_MODE_INCLUDE],
		    src->key, igmp_src_index (src));
    }
  else
    {
      igmp_src_refresh (src);
    }

  return (src);
}

void
igmp_group_clear (igmp_group_t * group)
{
  igmp_config_t *config;
  u32 ii;

  ASSERT (group);

  config = igmp_config_get (group->config);

  /* If interface is in ROUTER mode and IGMP proxy is enabled
   * remove mfib path.
   */
  if (config->mode == IGMP_MODE_ROUTER)
    {
      igmp_proxy_device_mfib_path_add_del (group, /* add */ 0);
    }

  IGMP_DBG ("clear-group: %U %U",
	    format_igmp_key, group->key,
	    format_vnet_sw_if_index_name,
	    vnet_get_main (), config->sw_if_index);

  igmp_group_free_all_srcs (group);

  for (ii = 0; ii < IGMP_GROUP_N_TIMERS; ii++)
    {
      igmp_timer_retire (&group->timers[ii]);
    }

  hash_unset_mem (config->igmp_group_by_key, group->key);
  clib_mem_free (group->key);
  pool_put (igmp_main.groups, group);
}

igmp_group_t *
igmp_group_alloc (igmp_config_t * config,
		  const igmp_key_t * gkey, igmp_filter_mode_t mode)
{
  igmp_main_t *im = &igmp_main;
  igmp_group_t *group;
  u32 ii;

  IGMP_DBG ("new-group: %U", format_igmp_key, gkey);
  pool_get (im->groups, group);
  memset (group, 0, sizeof (igmp_group_t));
  group->key = clib_mem_alloc (sizeof (igmp_key_t));
  clib_memcpy (group->key, gkey, sizeof (igmp_key_t));
  group->igmp_src_by_key[IGMP_FILTER_MODE_INCLUDE] =
    hash_create_mem (0, sizeof (igmp_key_t), sizeof (uword));
  group->igmp_src_by_key[IGMP_FILTER_MODE_EXCLUDE] =
    hash_create_mem (0, sizeof (igmp_key_t), sizeof (uword));
  group->router_filter_mode = mode;
  group->config = igmp_config_index (config);
  group->n_reports_sent = 0;

  for (ii = 0; ii < IGMP_GROUP_N_TIMERS; ii++)
    group->timers[ii] = IGMP_TIMER_ID_INVALID;

  hash_set_mem (config->igmp_group_by_key, group->key, group - im->groups);

  /* If interface is in ROUTER mode and IGMP proxy is enabled
   * add mfib path.
   */
  if (config->mode == IGMP_MODE_ROUTER)
    {
      igmp_proxy_device_mfib_path_add_del (group, /* add */ 1);
    }

  return (group);
}

/**
 * the set of present sources minus the new set
 */
ip46_address_t *
igmp_group_present_minus_new (igmp_group_t * group,
			      igmp_filter_mode_t mode,
			      const ip46_address_t * saddrs)
{
  const ip46_address_t *s1;
  ip46_address_t *pmn;
  igmp_src_t *src;
  u32 found;

  pmn = NULL;

  /* *INDENT-OFF* */
  if (0 == vec_len(saddrs))
    {
      FOR_EACH_SRC(src, group, mode,
        ({
          vec_add1(pmn, *src->key);
        }));
    }
  else
    {
      FOR_EACH_SRC(src, group, mode,
        ({
          found = 0;
          vec_foreach(s1, saddrs)
            {
              if (ip46_address_is_equal(s1, src->key))
                {
                  found = 1;
                  break;
                }
            }

          if (!found)
            vec_add1(pmn, *src->key);
        }));
    }
  /* *INDENT-ON* */

  return (pmn);
}

/**
 * the set of new sources minus the present set
 */
ip46_address_t *
igmp_group_new_minus_present (igmp_group_t * group,
			      igmp_filter_mode_t mode,
			      const ip46_address_t * saddrs)
{
  const ip46_address_t *s1;
  ip46_address_t *npm;
  igmp_src_t *src;
  u32 found;

  npm = NULL;

  /* *INDENT-OFF* */
  vec_foreach(s1, saddrs)
    {
      found = 0;
      FOR_EACH_SRC(src, group, mode,
        ({
          if (ip46_address_is_equal(s1, src->key))
            {
              found = 1;
              break;
            }
        }));

      if (!found)
        vec_add1(npm, *s1);
    }
  /* *INDENT-ON* */

  return (npm);
}

ip46_address_t *
igmp_group_new_intersect_present (igmp_group_t * group,
				  igmp_filter_mode_t mode,
				  const ip46_address_t * saddrs)
{
  ip46_address_t *intersect;
  const ip46_address_t *s1;
  igmp_src_t *src;

  intersect = NULL;

  /* *INDENT-OFF* */
  FOR_EACH_SRC(src, group, mode,
    ({
      vec_foreach(s1, saddrs)
        {
          if (s1->ip4.as_u32 == src->key->ip4.as_u32)
            {
              vec_add1(intersect, *s1);
              break;
            }
        }
    }));
  /* *INDENT-ON* */

  return (intersect);
}

u32
igmp_group_n_srcs (const igmp_group_t * group, igmp_filter_mode_t mode)
{
  return (hash_elts (group->igmp_src_by_key[mode]));
}


igmp_src_t *
igmp_src_lookup (igmp_group_t * group, const igmp_key_t * key)
{
  uword *p;
  igmp_src_t *src = NULL;
  if (!group)
    return NULL;

  p = hash_get_mem (group->igmp_src_by_key[IGMP_FILTER_MODE_INCLUDE], key);
  if (p)
    src = vec_elt_at_index (igmp_main.srcs, p[0]);

  return src;
}

u32
igmp_group_index (const igmp_group_t * g)
{
  return (g - igmp_main.groups);
}

igmp_group_t *
igmp_group_get (u32 index)
{
  return (pool_elt_at_index (igmp_main.groups, index));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
