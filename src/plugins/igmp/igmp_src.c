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

#include <igmp/igmp_src.h>
#include <igmp/igmp_group.h>
#include <igmp/igmp.h>

void
igmp_src_free (igmp_src_t * src)
{
  igmp_main_t *im = &igmp_main;

  IGMP_DBG ("free-src: (%U)", format_igmp_key, src->key);

  igmp_timer_retire (&src->timers[IGMP_SRC_TIMER_EXP]);

  clib_mem_free (src->key);
  pool_put (im->srcs, src);
}

static void
igmp_src_exp (u32 obj, void *dat)
{
  igmp_group_t *group;
  igmp_src_t *src;

  src = pool_elt_at_index (igmp_main.srcs, obj);
  group = igmp_group_get (src->group);

  IGMP_DBG ("src-exp: %U", format_igmp_key, src->key);

  igmp_timer_retire (&src->timers[IGMP_SRC_TIMER_EXP]);

  if (IGMP_MODE_ROUTER == src->mode)
    {
      igmp_config_t *config;
      igmp_group_t *group;

      /*
       * inform interest parties
       */
      group = igmp_group_get (src->group);
      config = igmp_config_get (group->config);

      igmp_event (IGMP_FILTER_MODE_EXCLUDE,
		  config->sw_if_index, src->key, group->key);

      igmp_proxy_device_block_src (config, group, src);
    }

  igmp_group_src_remove (group, src);
  igmp_src_free (src);

  if (0 == igmp_group_n_srcs (group, IGMP_FILTER_MODE_INCLUDE))
    igmp_group_clear (group);
}

igmp_src_t *
igmp_src_alloc (u32 group_index, const igmp_key_t * skey, igmp_mode_t mode)
{
  igmp_main_t *im = &igmp_main;
  igmp_src_t *src;

  IGMP_DBG ("new-src: (%U)", format_igmp_key, skey);

  pool_get (im->srcs, src);
  memset (src, 0, sizeof (igmp_src_t));
  src->mode = mode;
  src->key = clib_mem_alloc (sizeof (*skey));
  src->group = group_index;
  clib_memcpy (src->key, skey, sizeof (*skey));

  if (IGMP_MODE_ROUTER == mode)
    {
      igmp_config_t *config;
      igmp_group_t *group;
      /*
       * start a timer that determines whether the source is still
       * active on the link
       */
      src->timers[IGMP_SRC_TIMER_EXP] =
	igmp_timer_schedule (igmp_timer_type_get (IGMP_TIMER_SRC),
			     src - im->srcs, igmp_src_exp, NULL);

      /*
       * inform interest parties
       */
      group = igmp_group_get (src->group);
      config = igmp_config_get (group->config);

      igmp_event (IGMP_FILTER_MODE_INCLUDE,
		  config->sw_if_index, src->key, group->key);
    }
  else
    {
      src->timers[IGMP_SRC_TIMER_EXP] = IGMP_TIMER_ID_INVALID;
    }

  return (src);
}

void
igmp_src_refresh (igmp_src_t * src)
{
  IGMP_DBG ("refresh-src: (%U)", format_igmp_key, src->key);

  igmp_timer_retire (&src->timers[IGMP_SRC_TIMER_EXP]);

  src->timers[IGMP_SRC_TIMER_EXP] =
    igmp_timer_schedule (igmp_timer_type_get (IGMP_TIMER_SRC),
			 igmp_src_index (src), igmp_src_exp, NULL);
}

void
igmp_src_blocked (igmp_src_t * src)
{
  IGMP_DBG ("block-src: (%U)", format_igmp_key, src->key);

  igmp_timer_retire (&src->timers[IGMP_SRC_TIMER_EXP]);

  src->timers[IGMP_SRC_TIMER_EXP] =
    igmp_timer_schedule (igmp_timer_type_get (IGMP_TIMER_LEAVE),
			 igmp_src_index (src), igmp_src_exp, NULL);
}

u32
igmp_src_index (igmp_src_t * src)
{
  return (src - igmp_main.srcs);
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
